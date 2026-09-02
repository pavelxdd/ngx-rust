#[cfg(any(feature = "test-link", test))]
use std::collections::HashSet;
#[cfg(any(feature = "test-link", test))]
use std::path::Path;

#[cfg(any(feature = "test-link", test))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum NativeLinkInput {
    SearchPath(String),
    Library { name: String, whole_archive: bool },
    Archive { path: String, whole_archive: bool },
    Object(String),
}

pub(crate) fn logical_makefile_lines(makefile: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut logical = String::new();

    for raw in makefile.lines() {
        let raw = raw.trim_end();
        if let Some(part) = raw.strip_suffix('\\') {
            logical.push_str(part);
            logical.push(' ');
        } else {
            logical.push_str(raw);
            lines.push(core::mem::take(&mut logical));
        }
    }
    if !logical.is_empty() {
        lines.push(logical);
    }

    lines
}

#[cfg(any(feature = "test-link", test))]
pub(crate) fn nginx_binary_dependencies(lines: &[String]) -> Result<Vec<String>, String> {
    lines
        .iter()
        .find_map(|line| {
            let (target, dependencies) = line.split_once(':')?;
            let target = Path::new(target.trim());
            if target.file_name()?.to_str()? != "nginx" {
                return None;
            }

            shlex::split(dependencies)
        })
        .ok_or_else(|| "NGINX binary dependency list is missing or malformed".to_owned())
}

#[cfg(any(feature = "test-link", test))]
pub(crate) fn nginx_build_archives(
    lines: &[String],
    source_dir: &Path,
    build_dir: &Path,
) -> Result<Vec<String>, String> {
    Ok(nginx_binary_dependencies(lines)?
        .into_iter()
        .filter(|dependency| {
            let path = Path::new(dependency);
            if path.extension().and_then(|extension| extension.to_str()) != Some("a") {
                return false;
            }
            let path = if path.is_absolute() { path.to_owned() } else { source_dir.join(path) };
            path.starts_with(build_dir)
        })
        .collect())
}

#[cfg(any(feature = "test-link", test))]
pub(crate) fn nginx_binary_objects(lines: &[String]) -> Vec<String> {
    let objects: Vec<_> = nginx_binary_dependencies(lines)
        .unwrap_or_else(|error| panic!("{error}"))
        .into_iter()
        .filter(|dependency| dependency.ends_with(".o"))
        .collect();
    assert!(!objects.is_empty(), "NGINX binary object list is empty");
    objects
}

#[cfg(any(feature = "test-link", test))]
pub(crate) fn nginx_native_link_inputs(
    lines: &[String],
    replaced_inputs: &[String],
) -> Result<Vec<NativeLinkInput>, String> {
    let replaced_inputs: HashSet<_> = replaced_inputs.iter().map(String::as_str).collect();
    let link = lines
        .iter()
        .find(|line| line.trim_start().starts_with("$(LINK) -o "))
        .ok_or_else(|| "NGINX link command is missing".to_owned())?;
    let mut words = shlex::split(link)
        .ok_or_else(|| "invalid NGINX link command arguments".to_owned())?
        .into_iter();

    if words.next().as_deref() != Some("$(LINK)") || words.next().as_deref() != Some("-o") {
        return Err("NGINX link command has an unsupported driver or output form".to_owned());
    }
    words.next().ok_or_else(|| "NGINX link command has no output path".to_owned())?;

    let mut inputs = Vec::new();
    let mut whole_archive = false;

    while let Some(word) = words.next() {
        if replaced_inputs.contains(word.as_str()) {
            continue;
        }

        if let Some(path) = word.strip_prefix("-L") {
            let path = if path.is_empty() {
                words.next().ok_or_else(|| "missing -L argument".to_owned())?
            } else {
                path.into()
            };
            inputs.push(NativeLinkInput::SearchPath(path));
            continue;
        }

        if let Some(name) = word.strip_prefix("-l") {
            let name = if name.is_empty() {
                words.next().ok_or_else(|| "missing -l argument".to_owned())?
            } else {
                name.into()
            };
            inputs.push(NativeLinkInput::Library { name, whole_archive });
            continue;
        }

        match word.as_str() {
            "-pthread" => {
                inputs.push(NativeLinkInput::Library { name: "pthread".to_owned(), whole_archive })
            }
            "-Wl,--whole-archive" => {
                if whole_archive {
                    return Err("nested -Wl,--whole-archive is unsupported".to_owned());
                }
                whole_archive = true;
            }
            "-Wl,--no-whole-archive" => {
                if !whole_archive {
                    return Err("unmatched -Wl,--no-whole-archive".to_owned());
                }
                whole_archive = false;
            }
            "-Wl,-Bsymbolic-functions"
            | "-Wl,-z,relro"
            | "-Wl,-z,now"
            | "-Wl,-E"
            | "-fuse-linker-plugin"
            | "-fno-fat-lto-objects"
            | "-fPIC" => {}
            _ if word.starts_with("-flto=") || word.starts_with("-flto-partition=") => {}
            _ if Path::new(&word).extension().and_then(|extension| extension.to_str())
                == Some("a") =>
            {
                inputs.push(NativeLinkInput::Archive { path: word, whole_archive });
            }
            _ if Path::new(&word).extension().and_then(|extension| extension.to_str())
                == Some("o") =>
            {
                inputs.push(NativeLinkInput::Object(word));
            }
            _ => return Err(format!("unsupported NGINX native link token: {word}")),
        }
    }

    if whole_archive {
        return Err("NGINX link command has no -Wl,--no-whole-archive".to_owned());
    }

    Ok(inputs)
}
