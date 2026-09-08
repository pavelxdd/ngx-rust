use std::env;
use std::fs::{self, File, read_to_string};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{ConfiguredCCompiler, NginxSource};
use crate::link::{
    NativeLinkInput, logical_makefile_lines, nginx_binary_objects, nginx_build_archives,
    nginx_native_link_inputs,
};

pub(super) fn build_test_library(
    nginx: &NginxSource,
    includes: &[PathBuf],
    defines: &[(String, Option<String>)],
    build_http: bool,
    c_compiler: &ConfiguredCCompiler,
) {
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "nginx-sys/test-link currently supports Linux only"
    );

    let makefile_path = nginx.build_dir.join("Makefile");
    let makefile = read_to_string(&makefile_path).expect("configured NGINX Makefile");
    let lines = logical_makefile_lines(&makefile);
    let objects = nginx_binary_objects(&lines);
    let mut sources = Vec::with_capacity(objects.len());
    let mut replaced_inputs = Vec::with_capacity(objects.len());
    let mut external_objects = 0;

    for object in objects {
        let Some(source) = object_source(&lines, &object) else {
            external_objects += 1;
            continue;
        };
        let source = resolve_makefile_path(nginx, &source);
        let Ok(source) = dunce::canonicalize(source) else {
            external_objects += 1;
            continue;
        };
        if !source.starts_with(&nginx.source_dir) && !source.starts_with(&nginx.build_dir) {
            external_objects += 1;
            continue;
        }
        replaced_inputs.push(object);
        if !source.ends_with("src/core/nginx.c") {
            println!("cargo:rerun-if-changed={}", source.display());
            sources.push(source);
        }
    }
    replaced_inputs.extend(
        nginx_build_archives(&lines, &nginx.source_dir, &nginx.build_dir)
            .unwrap_or_else(|error| panic!("{error}")),
    );
    if external_objects > 0 {
        println!(
            "cargo::warning=using {external_objects} configured object files without rebuilding their sources"
        );
    }

    let allocation_source = dunce::canonicalize(nginx.source_dir.join("src/os/unix/ngx_alloc.c"))
        .expect("configured nginx allocation source");
    let source_count = sources.len();
    sources.retain(|source| source != &allocation_source);
    assert_eq!(
        sources.len(),
        source_count - 1,
        "configured nginx allocation source appears exactly once"
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let wrapper = out_dir.join("nginx_test_main.c");
    let mut file = File::create(&wrapper).expect("NGINX test main wrapper");
    writeln!(file, "#define main ngx_test_main\n#include <nginx.c>")
        .expect("NGINX test main wrapper");
    sources.push(wrapper);

    let event_wrapper = out_dir.join("nginx_test_event.c");
    let mut file = File::create(&event_wrapper).expect("NGINX event test wrapper");
    file.write_all(
        br"#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

void
ngx_rs_test_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_add_timer(ev, timer);
}

void
ngx_rs_test_del_timer(ngx_event_t *ev)
{
    ngx_del_timer(ev);
}

void
ngx_rs_test_post_event(ngx_event_t *ev, ngx_queue_t *queue)
{
    ngx_post_event(ev, queue);
}

void
ngx_rs_test_delete_posted_event(ngx_event_t *ev)
{
    ngx_delete_posted_event(ev);
}
",
    )
    .expect("NGINX event test wrapper");
    sources.push(event_wrapper);

    if build_http {
        let request_wrapper = out_dir.join("nginx_test_http_request.c");
        let mut file = File::create(&request_wrapper).expect("NGINX HTTP request test wrapper");
        file.write_all(
            br"#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_uint_t
ngx_rs_test_http_request_flags(const ngx_http_request_t *request)
{
    ngx_uint_t flags = 0;

    flags |= request->header_only;
    flags |= request->keepalive << 1;
    flags |= request->header_sent << 2;
    flags |= request->internal << 3;
    flags |= request->expect_trailers << 4;

    return flags;
}

void
ngx_rs_test_http_request_set_internal(ngx_http_request_t *request, ngx_uint_t internal)
{
    request->internal = internal != 0;
}
",
        )
        .expect("NGINX HTTP request test wrapper");
        sources.push(request_wrapper);
    }

    let alloc_wrapper = out_dir.join("nginx_test_alloc.c");
    let mut file = File::create(&alloc_wrapper).expect("NGINX allocation test wrapper");
    file.write_all(
        br"#include <ngx_config.h>
#include <ngx_core.h>

#define ngx_alloc ngx_rs_test_real_alloc
#define ngx_calloc ngx_rs_test_real_calloc
#define ngx_memalign ngx_rs_test_real_memalign
#include <ngx_alloc.c>
#undef ngx_memalign
#undef ngx_calloc
#undef ngx_alloc

static void *ngx_rs_test_tracked_free;
static ngx_uint_t ngx_rs_test_tracked_free_count;
static _Thread_local ngx_uint_t ngx_rs_test_allocations_before_failure = (ngx_uint_t) -1;

static ngx_flag_t
ngx_rs_test_allocation_should_fail(void)
{
    if (ngx_rs_test_allocations_before_failure == (ngx_uint_t) -1) {
        return 0;
    }

    if (ngx_rs_test_allocations_before_failure == 0) {
        return 1;
    }

    ngx_rs_test_allocations_before_failure--;

    return 0;
}

void
ngx_rs_test_fail_allocations_after(ngx_uint_t successes)
{
    ngx_rs_test_allocations_before_failure = successes;
}

void
ngx_rs_test_reset_allocation_failures(void)
{
    ngx_rs_test_allocations_before_failure = (ngx_uint_t) -1;
}

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    if (ngx_rs_test_allocation_should_fail()) {
        return NULL;
    }

    return ngx_rs_test_real_alloc(size, log);
}

void *
ngx_calloc(size_t size, ngx_log_t *log)
{
    if (ngx_rs_test_allocation_should_fail()) {
        return NULL;
    }

    return ngx_rs_test_real_calloc(size, log);
}

void *
ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
{
    if (ngx_rs_test_allocation_should_fail()) {
        return NULL;
    }

    return ngx_rs_test_real_memalign(alignment, size, log);
}

void
ngx_rs_test_track_free(void *ptr)
{
    ngx_rs_test_tracked_free = ptr;
    ngx_rs_test_tracked_free_count = 0;
}

ngx_uint_t
ngx_rs_test_free_count(void)
{
    return ngx_rs_test_tracked_free_count;
}

void
ngx_rs_test_free(void *ptr)
{
    if (ptr == ngx_rs_test_tracked_free) {
        ngx_rs_test_tracked_free_count++;
    }

    ngx_free(ptr);
}
",
    )
    .expect("NGINX allocation test wrapper");
    sources.push(alloc_wrapper);

    let resolver_source = dunce::canonicalize(nginx.source_dir.join("src/core/ngx_resolver.c"))
        .expect("configured nginx resolver source");
    let source_count = sources.len();
    sources.retain(|source| source != &resolver_source);
    assert_eq!(
        sources.len(),
        source_count - 1,
        "configured nginx resolver source appears exactly once"
    );

    let resolver_wrapper = out_dir.join("nginx_test_resolver.c");
    let mut file = File::create(&resolver_wrapper).expect("NGINX resolver test wrapper");
    file.write_all(
        br"#define ngx_resolve_name_done ngx_rs_test_real_resolve_name_done
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_resolver.c>
#undef ngx_resolve_name_done

static ngx_uint_t ngx_rs_test_resolve_name_done_calls;

void
ngx_resolve_name_done(ngx_resolver_ctx_t *ctx)
{
    ngx_rs_test_resolve_name_done_calls++;
    ngx_rs_test_real_resolve_name_done(ctx);
}

void
ngx_rs_test_reset_resolve_name_done_count(void)
{
    ngx_rs_test_resolve_name_done_calls = 0;
}

ngx_uint_t
ngx_rs_test_resolve_name_done_count(void)
{
    return ngx_rs_test_resolve_name_done_calls;
}
",
    )
    .expect("NGINX resolver test wrapper");
    sources.push(resolver_wrapper);

    let mut build = cc::Build::new();
    build.include(nginx.source_dir.join("src/core"));
    build.include(nginx.source_dir.join("src/os/unix"));
    #[cfg(feature = "stream")]
    build.include(nginx.source_dir.join("src/stream"));
    for include in includes {
        let include = resolve_makefile_path(nginx, include.to_str().expect("Unicode include path"));
        if include.is_dir() {
            build.include(include);
        }
    }
    for (name, value) in defines {
        build.define(name, value.as_deref());
    }
    c_compiler.apply(&mut build);
    build.warnings(false);
    build.files(sources);
    build.compile("nginx_test");

    emit_nginx_link_libraries(nginx, &lines, &replaced_inputs);
}

fn object_source(lines: &[String], object: &str) -> Option<String> {
    lines.iter().find_map(|line| {
        let (target, dependencies) = line.split_once(':')?;
        if target.trim() != object {
            return None;
        }

        shlex::split(dependencies)?.into_iter().find(|dependency| {
            matches!(
                Path::new(dependency).extension().and_then(|extension| extension.to_str()),
                Some("c" | "cc" | "cpp" | "s" | "S")
            )
        })
    })
}

fn resolve_makefile_path(nginx: &NginxSource, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        return path;
    }

    let source_path = nginx.source_dir.join(&path);
    if source_path.exists() {
        return source_path;
    }

    let build_path = nginx.build_dir.join(&path);
    if build_path.exists() {
        return build_path;
    }

    panic!("NGINX Makefile path does not exist: {}", path.display());
}

fn emit_nginx_link_libraries(nginx: &NginxSource, lines: &[String], replaced_inputs: &[String]) {
    let inputs =
        nginx_native_link_inputs(lines, replaced_inputs).unwrap_or_else(|error| panic!("{error}"));

    for (position, input) in inputs.into_iter().enumerate() {
        match input {
            NativeLinkInput::SearchPath(path) => {
                let path = resolve_makefile_path(nginx, &path);
                println!("cargo::rustc-link-search=native={}", path.display());
            }
            NativeLinkInput::Library { name, whole_archive: false } => {
                println!("cargo::rustc-link-lib={name}");
            }
            NativeLinkInput::Library { name, whole_archive: true } => {
                println!("cargo::rustc-link-lib=static:+whole-archive={name}");
            }
            NativeLinkInput::Archive { path, whole_archive } => {
                emit_nginx_link_archive(nginx, &path, position, whole_archive);
            }
            NativeLinkInput::Object(path) => emit_nginx_link_object(nginx, &path, position),
        }
    }
}

fn emit_nginx_link_archive(
    nginx: &NginxSource,
    archive: &str,
    position: usize,
    whole_archive: bool,
) {
    let archive = dunce::canonicalize(resolve_makefile_path(nginx, archive))
        .expect("configured NGINX native archive");
    let file_name =
        archive.file_name().and_then(|name| name.to_str()).expect("Unicode archive name");
    let staged_name = format!("nginx_test_link_{position}_{file_name}");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let staged = out_dir.join(&staged_name);

    match fs::remove_file(&staged) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            panic!("failed to replace staged NGINX archive {}: {error}", staged.display())
        }
    }
    if fs::hard_link(&archive, &staged).is_err() {
        fs::copy(&archive, &staged).unwrap_or_else(|error| {
            panic!(
                "failed to stage NGINX archive {} as {}: {error}",
                archive.display(),
                staged.display()
            )
        });
    }

    println!("cargo:rerun-if-changed={}", archive.display());
    println!("cargo::rustc-link-search=native={}", out_dir.display());
    let modifiers = if whole_archive { "+whole-archive,+verbatim" } else { "+verbatim" };
    println!("cargo::rustc-link-lib=static:{modifiers}={staged_name}");
}

fn emit_nginx_link_object(nginx: &NginxSource, object: &str, position: usize) {
    let object = dunce::canonicalize(resolve_makefile_path(nginx, object))
        .expect("configured NGINX native object");
    let library = format!("nginx_test_link_object_{position}");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut build = cc::Build::new();
    build.object(&object);
    build.cargo_metadata(false);
    build.compile(&library);

    println!("cargo:rerun-if-changed={}", object.display());
    println!("cargo::rustc-link-search=native={}", out_dir.display());
    println!("cargo::rustc-link-lib=static:+whole-archive={library}");
}
