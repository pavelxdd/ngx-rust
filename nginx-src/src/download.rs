extern crate duct;

use core::error::Error as StdError;
use core::sync::atomic::{AtomicU64, Ordering};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;
use std::{env, fs};

use flate2::read::GzDecoder;
use tar::Archive;

use crate::verifier::SignatureVerifier;

const NGINX_URL_PREFIX: &str = "https://nginx.org/download";
const OPENSSL_URL_PREFIX: &str = "https://github.com/openssl/openssl/releases/download";
const PCRE1_URL_PREFIX: &str = "https://sourceforge.net/projects/pcre/files/pcre";
const PCRE2_URL_PREFIX: &str = "https://github.com/PCRE2Project/pcre2/releases/download";
const ZLIB_URL_PREFIX: &str = "https://github.com/madler/zlib/releases/download";
const UBUNTU_KEYSEVER: &str = "hkps://keyserver.ubuntu.com";

struct SourceSpec<'a> {
    url: fn(&str) -> String,
    variable: &'a str,
    signature: &'a str,
    keyserver: &'a str,
    key_ids: &'a [&'a str],
}

const NGINX_SOURCE: SourceSpec = SourceSpec {
    url: |version| format!("{NGINX_URL_PREFIX}/nginx-{version}.tar.gz"),
    variable: "NGX_VERSION",
    signature: "asc",
    keyserver: UBUNTU_KEYSEVER,
    key_ids: &[
        // Key 1: Konstantin Pavlov's public key. For Nginx 1.25.3 and earlier
        "13C82A63B603576156E30A4EA0EA981B66B0D967",
        // Key 2: Sergey Kandaurov's public key. For Nginx 1.25.4
        "D6786CE303D9A9022998DC6CC8464D549AF75C0A",
        // Key 3: Maxim Dounin's public key. At least used for Nginx 1.18.0
        "B0F4253373F8F6F510D42178520A9993A1C052F8",
        // Key 4: Roman Arutyunyan's public key. For Nginx 1.25.5
        "43387825DDB1BB97EC36BA5D007C8D7C15D87369",
    ],
};

const DEPENDENCIES: &[(&str, SourceSpec)] = &[
    (
        "openssl",
        SourceSpec {
            url: |version| {
                if version.starts_with("1.") {
                    let ver_hyphened = version.replace('.', "_");
                    format!("{OPENSSL_URL_PREFIX}/OpenSSL_{ver_hyphened}/openssl-{version}.tar.gz")
                } else {
                    format!("{OPENSSL_URL_PREFIX}/openssl-{version}/openssl-{version}.tar.gz")
                }
            },
            variable: "OPENSSL_VERSION",
            signature: "asc",
            keyserver: UBUNTU_KEYSEVER,
            key_ids: &[
                "EFC0A467D613CB83C7ED6D30D894E2CE8B3D79F5",
                "A21FAB74B0088AA361152586B8EF1A6BA9DA2D5C",
                "8657ABB260F056B1E5190839D9C4D26D0E604491",
                "B7C1C14360F353A36862E4D5231C84CDDCC69C45",
                "95A9908DDFA16830BE9FB9003D30A3A9FF1360DC",
                "7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C",
                "E5E52560DD91C556DDBDA5D02064C53641C25E5D",
                "C1F33DD8CE1D4CC613AF14DA9195C48241FBF7DD",
                "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF",
            ],
        },
    ),
    (
        "pcre",
        SourceSpec {
            url: |version| {
                // We can distinguish pcre1/pcre2 by checking whether the second character is '.',
                // because the final version of pcre1 is 8.45 and the first one of pcre2 is 10.00.
                if version.chars().nth(1).is_some_and(|c| c == '.') {
                    format!("{PCRE1_URL_PREFIX}/{version}/pcre-{version}.tar.gz")
                } else {
                    format!("{PCRE2_URL_PREFIX}/pcre2-{version}/pcre2-{version}.tar.gz")
                }
            },
            variable: "PCRE2_VERSION",
            signature: "sig",
            keyserver: UBUNTU_KEYSEVER,
            key_ids: &[
                // Key 1: Phillip Hazel's public key. For PCRE2 10.44 and earlier
                "45F68D54BBE23FB3039B46E59766E084FB0F43D8",
                // Key 2: Nicholas Wilson's public key. For PCRE2 10.45
                "A95536204A3BB489715231282A98E77EB6F24CA8",
            ],
        },
    ),
    (
        "zlib",
        SourceSpec {
            url: |version| format!("{ZLIB_URL_PREFIX}/v{version}/zlib-{version}.tar.gz"),
            variable: "ZLIB_VERSION",
            signature: "asc",
            keyserver: UBUNTU_KEYSEVER,
            key_ids: &[
                // Key 1: Mark Adler's public key. For zlib 1.3.1 and earlier
                "5ED46A6721D365587791E2AA783FCD8E58BCAFBA",
            ],
        },
    ),
];

static VERIFIER: LazyLock<Option<SignatureVerifier>> = LazyLock::new(|| {
    SignatureVerifier::new().inspect_err(|err| eprintln!("GnuPG verifier: {err}")).ok()
});

static CACHE_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let base_dir = env::var("OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::current_dir().expect("Failed to get current directory"));
    // Choose `.cache` relative to the OUT_DIR of the caller (nginx-sys) as the default cache
    // directory. Environment variable `CACHE_DIR` overrides this.
    // Recommendation: set env "CACHE_DIR = { value = ".cache", relative = true }" in
    // `.cargo/config.toml` in your project
    let cache_dir = env::var("CACHE_DIR").map(PathBuf::from).unwrap_or(base_dir.join(".cache"));

    if !cache_dir.exists() {
        fs::create_dir_all(&cache_dir)
            .map_err(|err| format!("Failed to create {cache_dir:?}: {err}"))
            .unwrap();
    }

    cache_dir
});

/// Downloads a tarball from the specified URL into the `.cache` directory.
fn download(cache_dir: &Path, url: &str) -> Result<PathBuf, Box<dyn StdError + Send + Sync>> {
    fn proceed_with_download(file_path: &Path) -> bool {
        // File does not exist or is zero bytes
        !file_path.exists() || file_path.metadata().is_ok_and(|m| m.len() < 1)
    }
    let filename = url.split('/').next_back().unwrap();
    let file_path = cache_dir.join(filename);
    if proceed_with_download(&file_path) {
        println!("Downloading: {} -> {}", url, file_path.display());
        let mut response = ureq::get(url).call()?;
        let mut reader = response.body_mut().as_reader();
        let mut file = File::create(&file_path)?;
        std::io::copy(&mut reader, &mut file)?;
    }

    if !file_path.exists() {
        return Err(
            format!("Downloaded file was not written to the expected location: {url}",).into()
        );
    }
    Ok(file_path)
}

/// Gets a given tarball and signature file from a remote URL and copies it to the `.cache`
/// directory.
fn get_archive(cache_dir: &Path, source: &SourceSpec, version: &str) -> io::Result<PathBuf> {
    let archive_url = (source.url)(version);
    let archive = download(cache_dir, &archive_url).map_err(io::Error::other)?;

    if let Some(verifier) = &*VERIFIER {
        let signature = format!("{archive_url}.{}", source.signature);

        let verify = || -> io::Result<()> {
            let signature = download(cache_dir, &signature).map_err(io::Error::other)?;
            verifier.import_keys(source.keyserver, source.key_ids)?;
            verifier.verify_signature(&archive, &signature)?;
            Ok(())
        };

        if let Err(err) = verify() {
            let _ = fs::remove_file(&archive);
            let _ = fs::remove_file(&signature);
            return Err(err);
        }
    }

    Ok(archive)
}

const EXTRACTION_MARKER: &str = ".ngx-rust-extracted";
static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);

struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    fn create(base_dir: &Path, stem: &str) -> io::Result<Self> {
        for _ in 0..100 {
            let id = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
            let path = base_dir.join(format!(".{stem}.extracting-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("unable to create a staging directory for {stem}"),
        ))
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn invalid_archive(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn completed_extraction(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
        && fs::symlink_metadata(path.join(EXTRACTION_MARKER))
            .is_ok_and(|metadata| metadata.file_type().is_file())
}

fn remove_unmarked_extraction(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    if metadata.is_dir() { fs::remove_dir_all(path) } else { fs::remove_file(path) }
}

fn validate_archive_path(path: &Path, stem: &OsStr) -> io::Result<()> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(root)) if root == stem) {
        return Err(invalid_archive(format!(
            "archive entry is outside the expected {stem:?} root: {}",
            path.display()
        )));
    }

    for (index, component) in components.enumerate() {
        let Component::Normal(component) = component else {
            return Err(invalid_archive(format!(
                "archive entry contains an unsafe path: {}",
                path.display()
            )));
        };
        if index == 0 && component == OsStr::new(EXTRACTION_MARKER) {
            return Err(invalid_archive(format!(
                "archive entry uses reserved extraction marker: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

fn validate_symlink_target(path: &Path, target: &Path) -> io::Result<()> {
    let mut depth = path.parent().map_or(0, |parent| parent.components().count());
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 1 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_archive(format!(
                    "archive link escapes the expected root: {} -> {}",
                    path.display(),
                    target.display()
                )));
            }
        }
    }

    Ok(())
}

fn validate_archive_link<R: io::Read>(
    entry: &tar::Entry<'_, R>,
    path: &Path,
    stem: &OsStr,
) -> io::Result<()> {
    let entry_type = entry.header().entry_type();
    if !entry_type.is_symlink() && !entry_type.is_hard_link() {
        return Ok(());
    }

    let target = entry
        .link_name()?
        .ok_or_else(|| invalid_archive(format!("archive link has no target: {}", path.display())))?
        .into_owned();
    if entry_type.is_symlink() {
        validate_symlink_target(path, &target)
    } else {
        validate_archive_path(&target, stem)
    }
}

/// Extracts a tarball into a subdirectory based on the tarball's name under the source base
/// directory.
fn extract_archive(archive_path: &Path, extract_output_base_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(extract_output_base_dir)?;

    let filename = archive_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid_archive("unable to determine archive file name"))?;
    let stem = filename
        .strip_suffix(".tar.gz")
        .filter(|stem| matches!(Path::new(stem).components().next(), Some(Component::Normal(_))))
        .ok_or_else(|| invalid_archive(format!("unsupported archive file name: {filename}")))?;
    let archive_output_dir = extract_output_base_dir.join(stem);

    if completed_extraction(&archive_output_dir) {
        println!(
            "Archive [{}] already extracted to directory: {}",
            stem,
            archive_output_dir.display()
        );
        return Ok(archive_output_dir);
    }
    remove_unmarked_extraction(&archive_output_dir)?;

    let staging = StagingDir::create(extract_output_base_dir, stem)?;
    let archive_file = File::open(archive_path)?;
    let mut archive = Archive::new(GzDecoder::new(archive_file));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        validate_archive_path(&path, OsStr::new(stem))?;
        if path.components().count() == 1 && !entry.header().entry_type().is_dir() {
            return Err(invalid_archive(format!(
                "archive top-level entry is not a directory: {}",
                path.display()
            )));
        }
        validate_archive_link(&entry, &path, OsStr::new(stem))?;
        if !entry.unpack_in(&staging.path)? {
            return Err(invalid_archive(format!(
                "archive entry escapes the extraction root: {}",
                path.display()
            )));
        }
    }

    let staged_output_dir = staging.path.join(stem);
    if !fs::symlink_metadata(&staged_output_dir).is_ok_and(|metadata| metadata.file_type().is_dir())
    {
        return Err(invalid_archive(format!(
            "archive does not contain the expected {stem} directory"
        )));
    }

    let marker = staged_output_dir.join(EXTRACTION_MARKER);
    File::options().write(true).create_new(true).open(marker)?;

    if let Err(err) = fs::rename(&staged_output_dir, &archive_output_dir) {
        if completed_extraction(&archive_output_dir) {
            return Ok(archive_output_dir);
        }
        return Err(err);
    }

    Ok(archive_output_dir)
}

/// Downloads and extracts all requested sources.
pub fn prepare(source_dir: &Path, build_dir: &Path) -> io::Result<(PathBuf, Vec<String>)> {
    let extract_output_base_dir = build_dir.join("lib");
    if !extract_output_base_dir.exists() {
        fs::create_dir_all(&extract_output_base_dir)?;
    }

    let mut options = vec![];

    // Download NGINX only if NGX_VERSION is set.
    let source_dir = if let Ok(version) = env::var(NGINX_SOURCE.variable) {
        let archive_path = get_archive(&CACHE_DIR, &NGINX_SOURCE, version.as_str())?;
        let output_base_dir: PathBuf = env::var("OUT_DIR").unwrap().into();
        extract_archive(&archive_path, &output_base_dir)?
    } else {
        source_dir.to_path_buf()
    };

    for (name, source) in DEPENDENCIES {
        // Download dependencies if a corresponding DEPENDENCY_VERSION is set.
        let Ok(requested) = env::var(source.variable) else {
            continue;
        };

        let archive_path = get_archive(&CACHE_DIR, source, &requested)?;
        let output_dir = extract_archive(&archive_path, &extract_output_base_dir)?;
        let output_dir = output_dir.to_string_lossy();
        options.push(format!("--with-{name}={output_dir}"));
    }

    Ok((source_dir, options))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io;
    use std::path::PathBuf;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, EntryType, Header};
    use tempfile::TempDir;

    use super::extract_archive;

    struct TestEntry<'a> {
        path: &'a str,
        entry_type: EntryType,
        link_name: Option<&'a str>,
        contents: &'a [u8],
    }

    fn write_header_field(field: &mut [u8], value: &str) {
        assert!(value.len() < field.len());
        field.fill(0);
        field[..value.len()].copy_from_slice(value.as_bytes());
    }

    fn create_archive(temp_dir: &TempDir, entries: &[TestEntry<'_>]) -> io::Result<PathBuf> {
        let path = temp_dir.path().join("source.tar.gz");
        let encoder = GzEncoder::new(File::create(&path)?, Compression::default());
        let mut builder = Builder::new(encoder);

        for entry in entries {
            let mut header = Header::new_gnu();
            header.set_entry_type(entry.entry_type);
            header.set_mode(if entry.entry_type.is_dir() { 0o755 } else { 0o644 });
            header.set_size(entry.contents.len() as u64);

            // Builder's path setters reject traversal, so hostile fixtures write raw tar fields.
            let bytes = header.as_mut_bytes();
            write_header_field(&mut bytes[..100], entry.path);
            if let Some(link_name) = entry.link_name {
                write_header_field(&mut bytes[157..257], link_name);
            }
            header.set_cksum();
            builder.append(&header, entry.contents)?;
        }

        builder.into_inner()?.finish()?;
        Ok(path)
    }

    fn directory(path: &str) -> TestEntry<'_> {
        TestEntry { path, entry_type: EntryType::Directory, link_name: None, contents: &[] }
    }

    fn file<'a>(path: &'a str, contents: &'static [u8]) -> TestEntry<'a> {
        TestEntry { path, entry_type: EntryType::Regular, link_name: None, contents }
    }

    #[test]
    fn valid_archive_is_published_under_its_expected_root() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive =
            create_archive(&temp_dir, &[directory("source/"), file("source/README", b"complete")])?;
        let output = temp_dir.path().join("output");

        let extracted = extract_archive(&archive, &output)?;

        assert_eq!(extracted, output.join("source"));
        assert_eq!(fs::read(extracted.join("README"))?, b"complete");
        Ok(())
    }

    #[test]
    fn unexpected_top_level_root_is_rejected() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive =
            create_archive(&temp_dir, &[directory("other/"), file("other/README", b"unexpected")])?;
        let output = temp_dir.path().join("output");

        assert!(extract_archive(&archive, &output).is_err());
        assert!(!output.join("source").exists());
        Ok(())
    }

    #[test]
    fn traversal_does_not_escape_or_publish_a_partial_tree() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive = create_archive(
            &temp_dir,
            &[
                directory("source/"),
                file("source/README", b"partial"),
                file("source/../../escaped", b"escaped"),
            ],
        )?;
        let output = temp_dir.path().join("output");

        let extraction = std::panic::catch_unwind(|| extract_archive(&archive, &output));

        assert!(extraction.is_ok(), "malformed archives must return an error");
        assert!(extraction.expect("extract_archive panicked").is_err());
        assert!(!temp_dir.path().join("escaped").exists());
        assert!(!output.join("source").exists());
        assert_eq!(fs::read_dir(&output)?.count(), 0);
        Ok(())
    }

    #[test]
    fn archive_cannot_publish_its_own_completion_marker() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive = create_archive(
            &temp_dir,
            &[directory("source/"), file("source/.ngx-rust-extracted", b"forged")],
        )?;
        let output = temp_dir.path().join("output");

        assert!(extract_archive(&archive, &output).is_err());
        assert!(!output.join("source").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn escaping_symlink_is_rejected() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive = create_archive(
            &temp_dir,
            &[
                directory("source/"),
                TestEntry {
                    path: "source/link",
                    entry_type: EntryType::Symlink,
                    link_name: Some("../../outside"),
                    contents: &[],
                },
            ],
        )?;
        let output = temp_dir.path().join("output");

        assert!(extract_archive(&archive, &output).is_err());
        assert!(!output.join("source").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cannot_replace_the_expected_top_level_directory() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive = create_archive(
            &temp_dir,
            &[TestEntry {
                path: "source",
                entry_type: EntryType::Symlink,
                link_name: Some("."),
                contents: &[],
            }],
        )?;
        let output = temp_dir.path().join("output");

        assert!(extract_archive(&archive, &output).is_err());
        assert!(!output.join("source").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn relative_symlink_within_the_expected_root_is_extracted() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive = create_archive(
            &temp_dir,
            &[
                directory("source/"),
                directory("source/dir/"),
                file("source/target", b"target"),
                TestEntry {
                    path: "source/dir/link",
                    entry_type: EntryType::Symlink,
                    link_name: Some("../target"),
                    contents: &[],
                },
            ],
        )?;
        let output = temp_dir.path().join("output");

        let extracted = extract_archive(&archive, &output)?;

        assert_eq!(fs::read(extracted.join("dir/link"))?, b"target");
        Ok(())
    }

    #[test]
    fn escaping_hard_link_is_rejected() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive = create_archive(
            &temp_dir,
            &[
                directory("source/"),
                TestEntry {
                    path: "source/link",
                    entry_type: EntryType::Link,
                    link_name: Some("source/../../outside"),
                    contents: &[],
                },
            ],
        )?;
        let output = temp_dir.path().join("output");

        assert!(extract_archive(&archive, &output).is_err());
        assert!(!output.join("source").exists());
        Ok(())
    }

    #[test]
    fn unmarked_existing_tree_is_replaced() -> io::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let archive =
            create_archive(&temp_dir, &[directory("source/"), file("source/README", b"complete")])?;
        let output = temp_dir.path().join("output");
        let existing = output.join("source");
        fs::create_dir_all(&existing)?;
        fs::write(existing.join("partial"), b"stale")?;

        let extracted = extract_archive(&archive, &output)?;

        assert_eq!(fs::read(extracted.join("README"))?, b"complete");
        assert!(!extracted.join("partial").exists());
        Ok(())
    }
}
