#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    source: PathBuf,
    cargo: PathBuf,
    cargo_log: PathBuf,
    rustc: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let source = temp.path().join("nginx source with spaces");
        let cargo = source.join("tool bin/fake cargo");
        let cargo_log = source.join("cargo calls.log");
        let rustc = source.join("tool bin/fake rustc");

        fs::create_dir_all(source.join("src/core")).unwrap();
        fs::create_dir_all(source.join("objs")).unwrap();
        fs::create_dir_all(source.join("auto")).unwrap();
        fs::create_dir_all(cargo.parent().unwrap()).unwrap();
        fs::write(source.join("src/core/nginx.h"), "").unwrap();
        fs::write(source.join("objs/ngx_auto_config.h"), "").unwrap();
        fs::write(source.join("objs/Makefile"), "").unwrap();
        fs::write(source.join("auto/rust"), include_str!("../examples/auto/rust")).unwrap();
        fs::write(source.join("auto/module"), "ngx_module=$ngx_module_name\n").unwrap();

        write_executable(
            &cargo,
            &format!(
                r#"#!/bin/sh
case "$1" in
    --version)
        echo "cargo 1.85.0 (fixture)"
        ;;
    metadata)
        locked=
        manifest=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --locked)
                    locked=1
                    ;;
                --manifest-path)
                    shift
                    manifest=$1
                    ;;
            esac
            shift
        done
        [ -n "$locked" ] || exit 2
        [ -r "$manifest" ] || exit 3
        [ -r "$(dirname "$manifest")/Cargo.lock" ] || exit 4
        ;;
    rustc)
        if [ "$CHECK_JOBSERVER" = 1 ]; then
            jobserver=
            case " $MAKEFLAGS " in
                *" --jobserver-auth="*)
                    jobserver=${{MAKEFLAGS#*--jobserver-auth=}}
                    ;;
                *" --jobserver-fds="*)
                    jobserver=${{MAKEFLAGS#*--jobserver-fds=}}
                    ;;
            esac
            jobserver=${{jobserver%% *}}
            case "$jobserver" in
                "")
                    ;;
                [0-9]*,[0-9]*)
                    read_fd=${{jobserver%,*}}
                    write_fd=${{jobserver#*,}}
                    eval ": <&$read_fd" || exit 6
                    eval ": >&$write_fd" || exit 7
                    ;;
                fifo:*)
                    [ -p "${{jobserver#fifo:}}" ] || exit 8
                    ;;
                *)
                    exit 9
                    ;;
            esac
        fi
        printf 'rustc' >> {}
        shift
        for arg in "$@"; do
            printf '\t%s' "$arg" >> {}
        done
        printf '\n' >> {}
        ;;
    *)
        exit 5
        ;;
esac
"#,
                shell_quote(&cargo_log),
                shell_quote(&cargo_log),
                shell_quote(&cargo_log)
            ),
        );

        write_executable(
            &rustc,
            "#!/bin/sh\n\
             [ \"$1\" = --print ] && [ \"$2\" = target-list ] || exit 1\n\
             printf '%s\\n' x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu\n",
        );

        Self { _temp: temp, source, cargo, cargo_log, rustc }
    }

    fn addon(&self, directory: &str, package: &str, target: &str, features: &[&str]) -> PathBuf {
        let addon = self.source.join(directory);
        fs::create_dir_all(addon.join("src")).unwrap();
        fs::write(addon.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();

        let mut manifest = format!(
            "[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [lib]\nname = \"{target}\"\npath = \"src/lib.rs\"\n"
        );
        if !features.is_empty() {
            manifest.push_str("[features]\n");
            for feature in features {
                manifest.push_str(&format!("{feature} = []\n"));
            }
        }
        fs::write(addon.join("Cargo.toml"), manifest).unwrap();
        fs::write(
            addon.join("Cargo.lock"),
            format!("version = 4\n\n[[package]]\nname = \"{package}\"\nversion = \"0.1.0\"\n"),
        )
        .unwrap();

        addon
    }

    fn run(&self, body: &str, env: &[(&str, &str)]) -> Output {
        let script = self.source.join("fixture.sh");
        fs::write(
            &script,
            format!(
                r#"#!/bin/sh
set -e
ngx_n=
ngx_c=
NGX_OBJS=objs
NGX_MAKEFILE=objs/Makefile
NGX_DEBUG=${{NGX_DEBUG:-NO}}
NGX_MACHINE=arm64
NGX_PLATFORM=Linux:fixture:aarch64
NGX_SYSTEM=Linux
NGX_CC_NAME=clang
NGX_CARGO=${{NGX_CARGO:-{}}}
RUSTC=${{RUSTC:-{}}}
NGX_RUSTC_OPT=
RUST_LIBS=
LINK_DEPS=
ngx_dirsep=/
ngx_modext=.so
. auto/rust
{}
"#,
                shell_quote(&self.cargo),
                shell_quote(&self.rustc),
                body
            ),
        )
        .unwrap();

        let mut command = Command::new("sh");
        command.arg(&script).current_dir(&self.source);
        command.envs(env.iter().copied());
        command.output().expect("run fixture")
    }

    fn make(&self) -> Output {
        Command::new("make")
            .args(["-f", "objs/Makefile", "all"])
            .current_dir(&self.source)
            .output()
            .expect("run generated Makefile")
    }

    fn make_parallel(&self) -> Output {
        Command::new("make")
            .args(["-j2", "-f", "objs/Makefile", "all"])
            .env("CHECK_JOBSERVER", "1")
            .current_dir(&self.source)
            .output()
            .expect("run generated Makefile in parallel")
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_failed_with(output: Output, message: &str) {
    assert!(!output.status.success(), "fixture unexpectedly succeeded");
    assert!(output_text(&output).contains(message), "missing error {message:?}");
}

fn register_module(
    addon_name: &str,
    addon: &Path,
    target: &str,
    module: &str,
    features: &str,
    link: &str,
) -> String {
    format!(
        r#"ngx_addon_name={addon_name}
ngx_addon_dir={addon_dir}
ngx_module_type=HTTP
ngx_module_name={module}
ngx_module_link={link}
ngx_module_deps=
ngx_module_libs=
ngx_rust_target_type=LIB
ngx_rust_target_name={target}
ngx_rust_target_features='{features}'
ngx_rust_module
"#,
        addon_dir = shell_quote(addon),
    )
}

fn emit_make(addon_name: &str, addon: &Path) -> String {
    format!(
        r#"ngx_addon_name={addon_name}
ngx_addon_dir={addon_dir}
ngx_cargo_manifest={manifest}
ngx_rust_make_modules
"#,
        addon_dir = shell_quote(addon),
        manifest = shell_quote(&addon.join("Cargo.toml")),
    )
}

#[test]
fn configures_three_manifests_and_rebuilds_every_archive() {
    let fixture = Fixture::new();
    let one = fixture.addon("addon one", "crate-one", "target_one", &["first"]);
    let two = fixture.addon("addon two", "crate-two", "target_two", &["second", "shared"]);
    let three = fixture.addon("addon three", "crate-three", "target_three", &["third"]);

    let body = format!(
        "{}{}{}{}{}{}\nprintf '\\nall:%s objs/ngx_http_three_module.so\\n' \"$LINK_DEPS\" >> \"$NGX_MAKEFILE\"\n",
        register_module("addon_one", &one, "target_one", "ngx_http_one_module", "first", "STATIC"),
        register_module(
            "addon_two",
            &two,
            "target_two",
            "ngx_http_two_module",
            "second shared",
            "STATIC",
        ),
        register_module(
            "addon_three",
            &three,
            "target_three",
            "ngx_http_three_module",
            "third",
            "DYNAMIC",
        ),
        emit_make("addon_one", &one),
        emit_make("addon_two", &two),
        emit_make("addon_three", &three),
    );
    let output = fixture.run(&body, &[("NGX_RUST_TARGET", "aarch64-unknown-linux-gnu")]);
    assert!(output.status.success(), "{}", output_text(&output));

    let makefile = fs::read_to_string(fixture.source.join("objs/Makefile")).unwrap();
    let config = fs::read_to_string(fixture.source.join("objs/.cargo/config.toml")).unwrap();
    assert!(config.contains("NGINX_BUILD_DIR = { value = \".\", force = true, relative = true }"));
    assert!(config.contains(&format!(
        "NGINX_SOURCE_DIR = {{ value = \"{}\", force = true }}",
        fixture.source.canonicalize().unwrap().display()
    )));
    assert!(makefile.contains("--profile \"ngx-release\""));
    assert!(makefile.contains("--target aarch64-unknown-linux-gnu"));
    assert!(makefile.contains("--no-default-features"));
    assert!(makefile.contains("--locked"));
    assert!(!makefile.contains("vendored"));
    for (addon, target) in
        [("addon_one", "target_one"), ("addon_two", "target_two"), ("addon_three", "target_three")]
    {
        assert!(makefile.contains(&format!(
            "objs/{addon}/aarch64-unknown-linux-gnu/ngx-release/lib{target}.a"
        )));
        assert!(makefile.contains(&format!("--target-dir \"objs/{addon}\"")));
    }
    assert!(
        makefile.contains(&format!("--manifest-path \"{}\"", one.join("Cargo.toml").display()))
    );
    assert!(
        makefile.contains(&format!("--manifest-path \"{}\"", two.join("Cargo.toml").display()))
    );
    assert!(
        makefile.contains(&format!("--manifest-path \"{}\"", three.join("Cargo.toml").display()))
    );
    assert!(makefile.contains("--features \"first\""));
    assert!(makefile.contains("--features \"second shared\""));
    assert!(makefile.contains("--features \"third\""));

    for expected_calls in [3, 6, 9] {
        let output = fixture.make();
        assert!(output.status.success(), "{}", output_text(&output));
        let calls = fs::read_to_string(&fixture.cargo_log)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("rustc\t"))
            .count();
        assert_eq!(calls, expected_calls);
        fs::write(two.join("src/lib.rs"), format!("pub fn fixture_{expected_calls}() {{}}\n"))
            .unwrap();
    }
}

#[test]
fn parallel_make_preserves_an_advertised_jobserver_for_cargo() {
    let fixture = Fixture::new();
    let addon = fixture.addon("one addon", "crate-one", "target_one", &[]);
    let body = format!(
        "{}{}\nprintf '\\nall: %s\\n' \"$LINK_DEPS\" >> \"$NGX_MAKEFILE\"\n",
        register_module("one", &addon, "target_one", "ngx_http_one_module", "", "STATIC"),
        emit_make("one", &addon),
    );
    let output = fixture.run(&body, &[]);
    assert!(output.status.success(), "{}", output_text(&output));

    let output = fixture.make_parallel();
    assert!(output.status.success(), "{}", output_text(&output));
}

#[test]
fn selects_debug_profile_for_one_manifest() {
    let fixture = Fixture::new();
    let addon = fixture.addon("one addon", "crate-one", "target_one", &[]);
    let body = format!(
        "{}{}",
        register_module("one", &addon, "target_one", "ngx_http_one_module", "", "STATIC"),
        emit_make("one", &addon),
    );
    let output = fixture.run(&body, &[("NGX_DEBUG", "YES")]);
    assert!(output.status.success(), "{}", output_text(&output));

    let makefile = fs::read_to_string(fixture.source.join("objs/Makefile")).unwrap();
    assert!(makefile.contains("--profile \"ngx-debug\""));
    assert!(!makefile.contains("--target \""));
}

#[test]
fn allows_manifest_without_registered_targets() {
    let fixture = Fixture::new();
    let addon = fixture.addon("one addon", "crate-one", "target_one", &[]);
    let output = fixture.run(&emit_make("one", &addon), &[]);
    assert!(output.status.success(), "{}", output_text(&output));
}

#[test]
fn rejects_missing_cargo() {
    let fixture = Fixture::new();
    let missing = fixture.source.join("missing cargo");
    let output = fixture.run("", &[("NGX_CARGO", missing.to_str().unwrap())]);
    assert_failed_with(output, "cargo binary is not available");
}

#[test]
fn rejects_missing_manifest_and_lock_data() {
    let fixture = Fixture::new();
    let addon = fixture.addon("one addon", "crate-one", "target_one", &[]);
    let registration =
        register_module("one", &addon, "target_one", "ngx_http_one_module", "", "STATIC");

    let missing_manifest = fixture.source.join("missing manifest/Cargo.toml");
    let body = format!(
        "{registration}ngx_addon_name=one\nngx_cargo_manifest={}\nngx_rust_make_modules\n",
        shell_quote(&missing_manifest)
    );
    assert_failed_with(fixture.run(&body, &[]), "Cargo manifest is not readable");

    fs::write(fixture.source.join("objs/Makefile"), "").unwrap();
    fs::remove_file(addon.join("Cargo.lock")).unwrap();
    let body = format!("{registration}{}", emit_make("one", &addon));
    assert_failed_with(fixture.run(&body, &[]), "Cargo manifest or lock data is invalid");
}

#[test]
fn rejects_missing_nginx_source_build_and_makefile() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.source.join("src/core/nginx.h")).unwrap();
    assert_failed_with(fixture.run("", &[]), "nginx source directory is not configured");

    let fixture = Fixture::new();
    fs::remove_file(fixture.source.join("objs/ngx_auto_config.h")).unwrap();
    assert_failed_with(fixture.run("", &[]), "nginx build directory is not configured");

    let fixture = Fixture::new();
    let addon = fixture.addon("one addon", "crate-one", "target_one", &[]);
    fs::remove_file(fixture.source.join("objs/Makefile")).unwrap();
    let body = format!(
        "{}{}",
        register_module("one", &addon, "target_one", "ngx_http_one_module", "", "STATIC"),
        emit_make("one", &addon),
    );
    assert_failed_with(fixture.run(&body, &[]), "nginx Makefile is not configured");
}

#[test]
fn rejects_duplicate_module_names() {
    let fixture = Fixture::new();
    let one = fixture.addon("one addon", "crate-one", "target_one", &[]);
    let two = fixture.addon("two addon", "crate-two", "target_two", &[]);
    let body = format!(
        "{}{}",
        register_module("one", &one, "target_one", "ngx_http_same_module", "", "STATIC"),
        register_module("two", &two, "target_two", "ngx_http_same_module", "", "STATIC"),
    );
    assert_failed_with(fixture.run(&body, &[]), "duplicate nginx module name");
}

#[test]
fn allows_matching_target_names_in_distinct_addons() {
    let fixture = Fixture::new();
    let one = fixture.addon("one addon", "crate-one", "same_target", &[]);
    let two = fixture.addon("two addon", "crate-two", "same_target", &[]);
    let body = format!(
        "{}{}{}{}\nprintf '\\nall: %s\\n' \"$LINK_DEPS\" >> \"$NGX_MAKEFILE\"\n",
        register_module("one", &one, "same_target", "ngx_http_one_module", "", "STATIC"),
        register_module("two", &two, "same_target", "ngx_http_two_module", "", "STATIC"),
        emit_make("one", &one),
        emit_make("two", &two),
    );
    let output = fixture.run(&body, &[]);
    assert!(output.status.success(), "{}", output_text(&output));

    let makefile = fs::read_to_string(fixture.source.join("objs/Makefile")).unwrap();
    for addon in ["one", "two"] {
        assert!(makefile.contains(&format!("objs/{addon}/ngx-release/libsame_target.a")));
        assert!(makefile.contains(&format!("--target-dir \"objs/{addon}\"")));
    }

    let output = fixture.make();
    assert!(output.status.success(), "{}", output_text(&output));
    let calls = fs::read_to_string(&fixture.cargo_log)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("rustc\t"))
        .count();
    assert_eq!(calls, 2);
}

#[test]
fn rejects_duplicate_target_name_within_one_addon() {
    let fixture = Fixture::new();
    let addon = fixture.addon("one addon", "crate-one", "same_target", &[]);
    let body = format!(
        "{}{}",
        register_module("one", &addon, "same_target", "ngx_http_one_module", "", "STATIC"),
        register_module("one", &addon, "same_target", "ngx_http_two_module", "", "STATIC"),
    );
    assert_failed_with(fixture.run(&body, &[]), "duplicate Rust target name");
}

#[test]
fn rejects_unsupported_profile_and_cross_target() {
    let fixture = Fixture::new();
    assert_failed_with(
        fixture.run("", &[("ngx_cargo_profile", "custom")]),
        "unsupported Rust profile",
    );

    let fixture = Fixture::new();
    assert_failed_with(
        fixture.run("", &[("NGX_RUST_TARGET", "unknown-fixture-target")]),
        "unsupported Rust target",
    );
}
