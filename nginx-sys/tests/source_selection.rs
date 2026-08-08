#[path = "../build/source.rs"]
mod source;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use source::NginxSource;
use tempfile::TempDir;

fn os_string(path: &Path) -> OsString {
    path.as_os_str().to_owned()
}

fn nginx_tree() -> (TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("temporary directory");
    let source = temp.path().join("nginx");
    let build = source.join("objs");

    fs::create_dir_all(source.join("src/core")).expect("source directories");
    fs::create_dir_all(&build).expect("build directory");
    fs::write(source.join("src/core/nginx.h"), "").expect("nginx.h");
    fs::write(build.join("ngx_auto_config.h"), "").expect("ngx_auto_config.h");
    fs::write(build.join("Makefile"), "").expect("Makefile");

    (temp, source, build)
}

#[test]
fn accepts_explicit_source_and_build_directories() {
    let (_temp, source, build) = nginx_tree();

    let nginx = NginxSource::configured(Some(os_string(&source)), Some(os_string(&build)))
        .expect("configured paths")
        .expect("external source");

    assert_eq!(nginx.source_dir, source.canonicalize().unwrap());
    assert_eq!(nginx.build_dir, build.canonicalize().unwrap());
}

#[test]
fn derives_objs_from_source_directory() {
    let (_temp, source, build) = nginx_tree();

    let nginx = NginxSource::configured(Some(os_string(&source)), None)
        .expect("configured source")
        .expect("external source");

    assert_eq!(nginx.source_dir, source.canonicalize().unwrap());
    assert_eq!(nginx.build_dir, build.canonicalize().unwrap());
}

#[test]
fn derives_source_parent_from_build_directory() {
    let (_temp, source, build) = nginx_tree();

    let nginx = NginxSource::configured(None, Some(os_string(&build)))
        .expect("configured build")
        .expect("external source");

    assert_eq!(nginx.source_dir, source.canonicalize().unwrap());
    assert_eq!(nginx.build_dir, build.canonicalize().unwrap());
}

#[test]
fn missing_external_paths_defer_to_feature_policy() {
    assert!(NginxSource::configured(None, None).unwrap().is_none());
}

#[test]
fn rejects_invalid_source_and_incomplete_build_directories() {
    let (temp, source, build) = nginx_tree();
    fs::remove_file(source.join("src/core/nginx.h")).unwrap();

    let error = NginxSource::configured(Some(os_string(&source)), Some(os_string(&build)))
        .err()
        .expect("invalid source");
    assert!(error.to_string().contains("Invalid nginx source directory"));

    fs::write(source.join("src/core/nginx.h"), "").unwrap();
    fs::remove_file(build.join("Makefile")).unwrap();
    let error = NginxSource::configured(Some(os_string(&source)), Some(os_string(&build)))
        .err()
        .expect("incomplete build");
    assert!(error.to_string().contains("Invalid nginx build directory"));

    let missing = temp.path().join("missing");
    let error =
        NginxSource::configured(Some(os_string(&missing)), None).err().expect("missing source");
    assert!(error.to_string().contains("Invalid nginx source directory"));
}
