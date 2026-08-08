use core::error::Error as StdError;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

type BoxError = Box<dyn StdError>;

#[derive(Debug)]
pub struct NginxSource {
    pub(crate) source_dir: PathBuf,
    pub(crate) build_dir: PathBuf,
}

impl NginxSource {
    pub fn configured(
        source_dir: Option<OsString>,
        build_dir: Option<OsString>,
    ) -> Result<Option<Self>, BoxError> {
        match (source_dir, build_dir) {
            (Some(source_dir), Some(build_dir)) => Self::new(source_dir, build_dir).map(Some),
            (Some(source_dir), None) => {
                let build_dir = PathBuf::from(&source_dir).join("objs");
                Self::new(source_dir, build_dir).map(Some)
            }
            (None, Some(build_dir)) => {
                let source_dir = Path::new(&build_dir).parent().ok_or_else(|| {
                    format!("NGINX_BUILD_DIR has no source parent: {build_dir:?}")
                })?;
                Self::new(source_dir, &build_dir).map(Some)
            }
            (None, None) => Ok(None),
        }
    }

    pub fn new(
        source_dir: impl AsRef<Path>,
        build_dir: impl AsRef<Path>,
    ) -> Result<Self, BoxError> {
        let source_dir = Self::check_source_dir(source_dir)?;
        let build_dir = Self::check_build_dir(build_dir)?;

        Ok(Self { source_dir, build_dir })
    }

    fn check_source_dir(source_dir: impl AsRef<Path>) -> Result<PathBuf, BoxError> {
        match dunce::canonicalize(&source_dir) {
            Ok(path) if path.join("src/core/nginx.h").is_file() => Ok(path),
            Err(err) => {
                Err(format!("Invalid nginx source directory: {:?}. {err}", source_dir.as_ref())
                    .into())
            }
            _ => Err(format!(
                "Invalid nginx source directory: {:?}. NGINX_SOURCE_DIR is not specified or \
                 contains invalid value.",
                source_dir.as_ref()
            )
            .into()),
        }
    }

    fn check_build_dir(build_dir: impl AsRef<Path>) -> Result<PathBuf, BoxError> {
        match dunce::canonicalize(&build_dir) {
            Ok(path)
                if path.join("ngx_auto_config.h").is_file() && path.join("Makefile").is_file() =>
            {
                Ok(path)
            }
            Err(err) => {
                Err(format!("Invalid nginx build directory: {:?}. {err}", build_dir.as_ref())
                    .into())
            }
            _ => Err(format!(
                "Invalid nginx build directory: {:?}. NGINX_BUILD_DIR is not specified or \
                 contains invalid value.",
                build_dir.as_ref()
            )
            .into()),
        }
    }
}
