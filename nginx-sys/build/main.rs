extern crate bindgen;

mod link;
mod source;
#[cfg(feature = "test-link")]
mod test_link;

use core::error::Error as StdError;
use std::env;
use std::fs::{File, read_to_string};
use std::io::Write;
use std::path::{Path, PathBuf};

use link::logical_makefile_lines;
use source::NginxSource;
#[cfg(feature = "test-link")]
use test_link::build_test_library;

const ENV_VARS_TRIGGERING_RECOMPILE: &[&str] = &["OUT_DIR", "NGINX_BUILD_DIR", "NGINX_SOURCE_DIR"];

/// The feature flags set by the nginx configuration script.
///
/// This list is a subset of NGX_/NGX_HAVE_ macros known to affect the structure layout or module
/// avialiability.
///
/// The flags will be exposed to the buildscripts of _direct_ dependendents of this crate as
/// `DEP_NGINX_FEATURES` environment variable.
/// The list of recognized values will be exported as `DEP_NGINX_FEATURES_CHECK`.
const NGX_CONF_FEATURES: &[&str] = &[
    "api",
    "compat",
    "debug",
    "have_devpoll",
    "have_bindtodevice",
    "have_epollexclusive",
    "have_epollrdhup",
    "have_eventfd",
    "have_eventport",
    "have_file_aio",
    "have_inet6",
    "have_iocp",
    "have_kqueue",
    "have_memalign",
    "have_openat",
    "have_poll",
    "have_posix_memalign",
    "have_sched_yield",
    "have_sendfile",
    "have_so_mark",
    "have_unix_domain",
    "have_variadic_macros",
    "http",
    "http_cache",
    "http_dav",
    "http_gzip",
    "http_headers",
    "http_realip",
    "http_ssi",
    "http_ssl",
    "http_upstream_sid",
    "http_upstream_sticky",
    "http_upstream_zone",
    "http_v2",
    "http_v3",
    "http_x_forwarded_for",
    "mail",
    "mail_ssl",
    "openssl",
    "pcre",
    "pcre2",
    "quic",
    "ssl",
    "stat_stub",
    "stream",
    "stream_ssl",
    "stream_upstream_zone",
    "threads",
    "zone_sync",
];

/// The operating systems supported by the nginx configuration script
///
/// The detected value will be exposed to the buildsrcipts of _direct_ dependents of this crate as
/// `DEP_NGINX_OS` environment variable.
/// The list of recognized values will be exported as `DEP_NGINX_OS_CHECK`.
const NGX_CONF_OS: &[&str] =
    &["darwin", "freebsd", "gnu_hurd", "hpux", "linux", "solaris", "tru64", "win32"];

type BoxError = Box<dyn StdError>;

/// Function invoked when `cargo build` is executed.
/// This function will download NGINX and all supporting dependencies, verify their integrity,
/// extract them, execute autoconf `configure` for NGINX, compile NGINX and finally install
/// NGINX in a subdirectory with the project.
fn main() -> Result<(), BoxError> {
    // Hint cargo to rebuild if any of the these environment variables values change
    // because they will trigger a recompilation of NGINX with different parameters
    for var in ENV_VARS_TRIGGERING_RECOMPILE {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-changed=build/main.rs");
    println!("cargo:rerun-if-changed=build/link.rs");
    println!("cargo:rerun-if-changed=build/source.rs");
    #[cfg(feature = "test-link")]
    println!("cargo:rerun-if-changed=build/test_link.rs");
    println!("cargo:rerun-if-changed=build/wrapper.h");

    let nginx = NginxSource::from_env();
    println!("cargo:rerun-if-changed={}", nginx.build_dir.join("Makefile").to_string_lossy());
    println!(
        "cargo:rerun-if-changed={}",
        nginx.build_dir.join("ngx_auto_config.h").to_string_lossy()
    );
    // Read autoconf generated makefile for NGINX and generate Rust bindings based on its includes
    generate_binding(&nginx);
    Ok(())
}

impl NginxSource {
    fn from_env() -> Self {
        match Self::configured(env::var_os("NGINX_SOURCE_DIR"), env::var_os("NGINX_BUILD_DIR")) {
            Ok(Some(nginx)) => nginx,
            Ok(None) => Self::from_vendored(),
            Err(error) => panic!("{error}"),
        }
    }

    #[cfg(feature = "vendored")]
    fn from_vendored() -> Self {
        nginx_src::print_cargo_metadata();

        let out_dir = env::var("OUT_DIR").unwrap();
        let build_dir = PathBuf::from(out_dir).join("objs");
        let (source_dir, build_dir) = nginx_src::build(build_dir).expect("nginx-src build");

        Self { source_dir, build_dir }
    }

    #[cfg(not(feature = "vendored"))]
    fn from_vendored() -> Self {
        panic!(
            "\"nginx-sys/vendored\" feature is disabled and neither NGINX_SOURCE_DIR nor \
             NGINX_BUILD_DIR is set"
        );
    }
}

/// Generates Rust bindings for NGINX
fn generate_binding(nginx: &NginxSource) {
    let autoconf_makefile_path = nginx.build_dir.join("Makefile");
    let makefile = read_to_string(&autoconf_makefile_path).expect("configured NGINX Makefile");
    let makefile_lines = logical_makefile_lines(&makefile);
    let standard = c_standard(&makefile_lines);
    let c_compiler = ConfiguredCCompiler::from_makefile(&makefile_lines);
    let (includes, defines) = parse_makefile(&autoconf_makefile_path);
    let includes: Vec<_> = includes
        .into_iter()
        .map(|path| if path.is_absolute() { path } else { nginx.source_dir.join(path) })
        .collect();
    let mut clang_args: Vec<String> =
        includes.iter().map(|path| format!("-I{}", path.to_string_lossy())).collect();

    if let Some(standard) = &standard {
        clang_args.push(standard.clone());
    }

    clang_args.extend(
        defines.iter().map(
            |(n, ov)| {
                if let Some(v) = ov { format!("-D{n}={v}") } else { format!("-D{n}") }
            },
        ),
    );

    if cfg!(feature = "http") {
        clang_args.push("-DNGX_RS_FEATURE_HTTP".to_string());
    }

    if cfg!(feature = "mail") {
        clang_args.push("-DNGX_RS_FEATURE_MAIL".to_string());
    }

    if cfg!(feature = "stream") {
        clang_args.push("-DNGX_RS_FEATURE_STREAM".to_string());
    }

    let nginx_features =
        print_cargo_metadata(nginx, &includes, &defines).expect("cargo dependency metadata");
    let build_http =
        cfg!(feature = "http") && nginx_features.iter().any(|feature| feature == "http");

    // bindgen targets the latest known stable by default
    let rust_target: bindgen::RustTarget = env::var("CARGO_PKG_RUST_VERSION")
        .expect("rust-version set in Cargo.toml")
        .parse()
        .expect("rust-version is valid and supported by bindgen");

    let bindings = bindgen::Builder::default()
        .allowlist_function("ngx_.*")
        // Required by the platform adapters for errors, random values, and yielding.
        .allowlist_function(
            "^(GetLastError|SetLastError|SwitchToThread|WSAGetLastError|WSASetLastError|rand|random|sched_yield|usleep)$",
        )
        // Recursive allowlisting deliberately retains external types used in the NGINX ABI. They
        // must come from the headers selected by the configured NGINX build, not from a crate that
        // may select a different native library.
        .allowlist_type("ngx_.*")
        .allowlist_var("^(NGX|NGINX|ngx|nginx)_.*$")
        // Bindings will not compile on Linux without block listing this item
        // It is worth investigating why this is
        .blocklist_item("IPPORT_RESERVED")
        // will be restored later in build.rs
        .blocklist_item("NGX_ALIGNMENT")
        .generate_cstr(true)
        // The input header we would like to generate bindings for.
        .header("build/wrapper.h")
        .clang_args(clang_args)
        .layout_tests(false)
        .rust_target(rust_target)
        .rust_edition(bindgen::RustEdition::Edition2024)
        .wrap_unsafe_ops(true)
        .use_core()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_dir_env =
        env::var("OUT_DIR").expect("The required environment variable OUT_DIR was not set");
    let out_path = PathBuf::from(out_dir_env);
    bindings.write_to_file(out_path.join("bindings.rs")).expect("Couldn't write bindings!");

    build_event_shim(&includes, &defines, &c_compiler);

    if build_http {
        build_http_request_shim(&includes, &defines, &c_compiler);
    }

    #[cfg(feature = "test-link")]
    build_test_library(nginx, &includes, &defines, build_http, &c_compiler);
}

fn build_event_shim(
    includes: &[PathBuf],
    defines: &[(String, Option<String>)],
    c_compiler: &ConfiguredCCompiler,
) {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let shim = out_dir.join("nginx_event_shim.c");
    let mut file = File::create(&shim).expect("NGINX event shim");
    file.write_all(
        br"#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

void
ngx_rs_event_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_add_timer(ev, timer);
}

void
ngx_rs_event_del_timer(ngx_event_t *ev)
{
    ngx_del_timer(ev);
}

void
ngx_rs_event_post(ngx_event_t *ev, ngx_queue_t *queue)
{
    ngx_post_event(ev, queue);
}

void
ngx_rs_event_delete_posted(ngx_event_t *ev)
{
    ngx_delete_posted_event(ev);
}
",
    )
    .expect("NGINX event shim");

    let mut build = cc::Build::new();
    build.includes(includes).file(shim);
    for (name, value) in defines {
        build.define(name, value.as_deref());
    }
    c_compiler.apply(&mut build);
    build.warnings(false);
    build.compile("nginx_event_shim");
}

fn build_http_request_shim(
    includes: &[PathBuf],
    defines: &[(String, Option<String>)],
    c_compiler: &ConfiguredCCompiler,
) {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let shim = out_dir.join("nginx_http_request_shim.c");
    let mut file = File::create(&shim).expect("NGINX HTTP request shim");
    file.write_all(
        br"#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_uint_t
ngx_rs_http_request_is_internal(const ngx_http_request_t *request)
{
    return request->internal;
}

ngx_uint_t
ngx_rs_http_request_header_only(const ngx_http_request_t *request)
{
    return request->header_only;
}

ngx_uint_t
ngx_rs_http_request_done(const ngx_http_request_t *request)
{
    return request->done;
}

void
ngx_rs_http_request_set_done(ngx_http_request_t *request, ngx_uint_t done)
{
    request->done = done;
}

ngx_uint_t
ngx_rs_http_request_terminated(const ngx_http_request_t *request)
{
#if (nginx_version >= 1025004)
    return request->terminated;
#else
    return 0;
#endif
}

void
ngx_rs_http_request_set_terminated(ngx_http_request_t *request, ngx_uint_t terminated)
{
#if (nginx_version >= 1025004)
    request->terminated = terminated;
#else
    (void) request;
    (void) terminated;
#endif
}

ngx_uint_t
ngx_rs_http_request_keepalive(const ngx_http_request_t *request)
{
    return request->keepalive;
}

ngx_uint_t
ngx_rs_http_request_expect_trailers(const ngx_http_request_t *request)
{
    return request->expect_trailers;
}

void
ngx_rs_http_request_set_keepalive(ngx_http_request_t *request, ngx_uint_t keepalive)
{
    request->keepalive = keepalive != 0;
}

void
ngx_rs_http_request_set_header_only(ngx_http_request_t *request, ngx_uint_t header_only)
{
    request->header_only = header_only != 0;
}

void
ngx_rs_http_request_set_expect_trailers(ngx_http_request_t *request, ngx_uint_t expect_trailers)
{
    request->expect_trailers = expect_trailers != 0;
}

void
ngx_rs_http_request_set_header_sent(ngx_http_request_t *request, ngx_uint_t header_sent)
{
    request->header_sent = header_sent != 0;
}
",
    )
    .expect("NGINX HTTP request shim");

    let mut build = cc::Build::new();
    build.includes(includes).file(shim);
    for (name, value) in defines {
        build.define(name, value.as_deref());
    }
    c_compiler.apply(&mut build);
    build.warnings(false);
    build.compile("nginx_http_request_shim");
}

struct ConfiguredCCompiler {
    program: String,
    flags: Vec<String>,
}

impl ConfiguredCCompiler {
    fn from_makefile(lines: &[String]) -> Self {
        let mut compiler = shlex::split(makefile_variable(lines, "CC"))
            .expect("configured NGINX compiler command");
        assert!(!compiler.is_empty(), "configured NGINX compiler command is empty");
        let program = compiler.remove(0);
        let mut flags = compiler;

        let configured_flags =
            shlex::split(makefile_variable(lines, "CFLAGS")).expect("configured NGINX CFLAGS");
        let mut configured_flags = configured_flags.into_iter();
        while let Some(flag) = configured_flags.next() {
            if flag == "-I" || flag == "-D" {
                configured_flags.next().expect("configured NGINX CFLAGS argument");
            } else if !flag.starts_with("-I")
                && !flag.starts_with("-D")
                && !is_link_time_optimization_flag(&flag)
            {
                flags.push(flag);
            }
        }

        Self { program, flags }
    }

    fn apply(&self, build: &mut cc::Build) {
        build.compiler(&self.program);
        for flag in &self.flags {
            build.flag(flag);
        }
    }
}

// cc archives shim objects independently, without nginx's linker-plugin toolchain. LTO changes
// object representation but not the C ABI the shim must inherit.
fn is_link_time_optimization_flag(flag: &str) -> bool {
    flag.starts_with("-flto")
        || matches!(flag, "-ffat-lto-objects" | "-fno-fat-lto-objects" | "-fuse-linker-plugin")
}

fn makefile_variable<'a>(lines: &'a [String], name: &str) -> &'a str {
    lines
        .iter()
        .find_map(|line| {
            let value = line.strip_prefix(name)?.trim_start().strip_prefix('=')?;
            Some(value.trim())
        })
        .unwrap_or_else(|| panic!("configured NGINX Makefile has no {name}"))
}

fn c_standard(lines: &[String]) -> Option<String> {
    lines.iter().find_map(|line| {
        let flags = line.strip_prefix("CFLAGS")?.strip_prefix(" =")?;
        shlex::split(flags)?.into_iter().find_map(|flag| match flag.as_str() {
            "-std=c2y" => Some("-std=c2x".into()),
            "-std=gnu2y" => Some("-std=gnu2x".into()),
            _ if flag.starts_with("-std=") => Some(flag),
            _ => None,
        })
    })
}

/// Reads through the makefile generated by autoconf and finds all of the includes
/// and definitions used to compile nginx. This is used to generate the correct bindings
/// for the nginx source code.
pub fn parse_makefile(
    nginx_autoconf_makefile_path: &PathBuf,
) -> (Vec<PathBuf>, Vec<(String, Option<String>)>) {
    fn parse_line(
        includes: &mut Vec<String>,
        defines: &mut Vec<(String, Option<String>)>,
        line: &str,
    ) {
        let mut words = shlex::Shlex::new(line);

        while let Some(word) = words.next() {
            if let Some(inc) = word.strip_prefix("-I") {
                let value = if inc.is_empty() {
                    words.next().expect("-I argument")
                } else {
                    inc.to_string()
                };
                includes.push(value);
            } else if let Some(def) = word.strip_prefix("-D") {
                let def = if def.is_empty() {
                    words.next().expect("-D argument")
                } else {
                    def.to_string()
                };

                if let Some((name, value)) = def.split_once("=") {
                    defines.push((name.to_string(), Some(value.to_string())));
                } else {
                    defines.push((def.to_string(), None));
                }
            }
        }
    }

    let mut all_incs = vec![];
    let mut cflags_includes = vec![];

    let mut defines = vec![];

    let makefile_contents = match read_to_string(nginx_autoconf_makefile_path) {
        Ok(path) => path,
        Err(e) => {
            panic!(
                "Unable to read makefile from path [{}]. Error: {}",
                nginx_autoconf_makefile_path.to_string_lossy(),
                e
            );
        }
    };

    let lines = makefile_contents.lines();
    let mut line: String = "".to_string();
    for l in lines {
        if let Some(part) = l.strip_suffix("\\") {
            line += part;
            continue;
        }

        line += l;

        if let Some(tail) = line.strip_prefix("ALL_INCS") {
            parse_line(&mut all_incs, &mut defines, tail);
        } else if let Some(tail) = line.strip_prefix("CFLAGS") {
            parse_line(&mut cflags_includes, &mut defines, tail);
        }

        line.clear();
    }

    cflags_includes.extend(all_incs);

    (cflags_includes.into_iter().map(PathBuf::from).collect(), defines)
}

/// Collect info about the nginx configuration and expose it to the dependents via
/// `DEP_NGINX_...` variables.
pub fn print_cargo_metadata<T: AsRef<Path>>(
    nginx: &NginxSource,
    includes: &[T],
    defines: &[(String, Option<String>)],
) -> Result<Vec<String>, Box<dyn StdError>> {
    // Unquote and merge C string constants
    let unquote_re = regex::Regex::new(r#""(.*?[^\\])"\s*"#).unwrap();
    let unquote = |data: &str| -> String {
        unquote_re
            .captures_iter(data)
            .map(|c| c.get(1).unwrap().as_str())
            .collect::<Vec<_>>()
            .concat()
    };

    let mut ngx_features: Vec<String> = vec![];
    let mut ngx_os = String::new();

    let expanded = expand_definitions(includes, defines)?;
    for line in String::from_utf8(expanded)?.lines() {
        let Some((name, value)) =
            line.trim().strip_prefix("RUST_CONF_").and_then(|x| x.split_once('='))
        else {
            continue;
        };

        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();

        if name == "nginx_build" {
            println!("cargo::metadata=build={}", unquote(value));
        } else if name == "nginx_name" {
            println!("cargo::metadata=name={}", unquote(value));
        } else if name == "nginx_version" {
            println!("cargo::metadata=version={}", unquote(value));
        } else if name == "nginx_version_number" {
            println!("cargo::metadata=version_number={value}");
        } else if NGX_CONF_OS.contains(&name.as_str()) {
            ngx_os = name;
        } else if NGX_CONF_FEATURES.contains(&name.as_str()) && value != "0" {
            ngx_features.push(name);
        }
    }

    println!("cargo::metadata=build_dir={}", nginx.build_dir.to_str().expect("Unicode build path"));

    println!(
        "cargo::metadata=include={}",
        // The str conversion is necessary because cargo directives must be valid UTF-8
        env::join_paths(includes.iter().map(|x| x.as_ref()))?
            .to_str()
            .expect("Unicode include paths")
    );

    println!(
        "cargo:metadata=cflags={}",
        defines
            .iter()
            .map(|(n, ov)| if let Some(v) = ov { format!("-D{n}={v}") } else { format!("-D{n}") })
            .collect::<Vec<_>>()
            .join(" ")
    );

    // A quoted list of all recognized features to be passed to rustc-check-cfg.
    let values = NGX_CONF_FEATURES.join("\",\"");
    println!("cargo::metadata=features_check=\"{values}\"");
    println!("cargo::rustc-check-cfg=cfg(ngx_feature, values(\"{values}\"))");

    // A list of features enabled in the nginx build we're using
    println!("cargo::metadata=features={}", ngx_features.join(","));
    for feature in &ngx_features {
        println!("cargo::rustc-cfg=ngx_feature=\"{feature}\"");
    }

    // A quoted list of all recognized operating systems to be passed to rustc-check-cfg.
    let values = NGX_CONF_OS.join("\",\"");
    println!("cargo::metadata=os_check=\"{values}\"");
    println!("cargo::rustc-check-cfg=cfg(ngx_os, values(\"{values}\"))");
    // Current detected operating system
    println!("cargo::metadata=os={ngx_os}");
    println!("cargo::rustc-cfg=ngx_os=\"{ngx_os}\"");

    Ok(ngx_features)
}

fn expand_definitions<T: AsRef<Path>>(
    includes: &[T],
    defines: &[(String, Option<String>)],
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let path = PathBuf::from(env::var("OUT_DIR")?).join("expand.c");
    let mut writer = std::io::BufWriter::new(File::create(&path)?);

    write!(
        writer,
        "
#include <ngx_config.h>
#include <ngx_core.h>

/* C23 or Clang/GCC/MSVC >= 15.3 extension */
#if defined(__has_include)

#if __has_include(<ngx_http.h>)
RUST_CONF_HTTP=1
#endif

#if __has_include(<ngx_mail.h>)
RUST_CONF_MAIL=1
#endif

#if __has_include(<ngx_stream.h>)
RUST_CONF_STREAM=1
#endif

#else
/* fallback */
RUST_CONF_HTTP=1
#endif

RUST_CONF_NGINX_BUILD=NGINX_VER_BUILD
#if defined(NGINX_NAME)
RUST_CONF_NGINX_NAME=NGINX_NAME
#else
RUST_CONF_NGINX_NAME=\"nginx\"
#endif
RUST_CONF_NGINX_VERSION=NGINX_VER
RUST_CONF_NGINX_VERSION_NUMBER=nginx_version
"
    )?;

    for flag in NGX_CONF_FEATURES.iter().chain(NGX_CONF_OS.iter()) {
        let flag = flag.to_ascii_uppercase();
        write!(
            writer,
            "
#if defined(NGX_{flag})
RUST_CONF_{flag}=NGX_{flag}
#endif"
        )?;
    }

    writer.flush()?;
    drop(writer);

    let mut builder = cc::Build::new();

    builder.includes(includes).file(path);

    for def in defines {
        builder.define(&def.0, def.1.as_deref());
    }

    Ok(builder.try_expand()?)
}
