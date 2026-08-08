use core::error;
use core::ffi::{c_char, c_void};
use core::fmt;
use core::ptr;

use crate::core::NGX_CONF_ERROR;
use crate::core::*;
use crate::ffi::*;

/// MergeConfigError - configuration cannot be merged with levels above.
#[derive(Debug)]
pub enum MergeConfigError {
    /// No value provided for configuration argument
    NoValue,
    /// Module-specific configuration error
    Message(&'static str),
}

impl error::Error for MergeConfigError {}

impl fmt::Display for MergeConfigError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MergeConfigError::NoValue => "no value".fmt(fmt),
            MergeConfigError::Message(message) => message.fmt(fmt),
        }
    }
}

impl From<&'static str> for MergeConfigError {
    fn from(message: &'static str) -> Self {
        Self::Message(message)
    }
}

/// The `Merge` trait provides a method for merging configuration down through each level.
///
/// A module configuration should implement this trait for setting its configuration throughout
/// each level.
pub trait Merge {
    /// Module merge function.
    ///
    /// # Returns
    /// Result, Ok on success or MergeConfigError on failure. Merge errors are written to the
    /// configuration log before nginx rejects the configuration.
    fn merge(&mut self, prev: &Self) -> Result<(), MergeConfigError>;
}

impl Merge for () {
    fn merge(&mut self, _prev: &Self) -> Result<(), MergeConfigError> {
        Ok(())
    }
}

/// The `HTTPModule` trait provides the NGINX configuration stage interface.
///
/// These functions allocate structures, initialize them, and merge through the configuration
/// layers.
///
/// See <https://nginx.org/en/docs/dev/development_guide.html#adding_new_modules> for details.
pub trait HttpModule {
    /// Returns reference to a global variable of type [ngx_module_t] created for this module.
    fn module() -> &'static ngx_module_t;

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn preconfiguration(_cf: *mut ngx_conf_t) -> ngx_int_t {
        Status::NGX_OK.into()
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn postconfiguration(_cf: *mut ngx_conf_t) -> ngx_int_t {
        Status::NGX_OK.into()
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: super::HttpModuleMainConf,
        Self::MainConf: Default,
    {
        unsafe {
            let Some(pool) = Pool::from_raw((*cf).pool) else {
                return ptr::null_mut();
            };
            pool.allocate_with_cleanup(Self::MainConf::default)
                .map(|value| value.into_non_null().as_ptr())
                .unwrap_or(ptr::null_mut())
                .cast()
        }
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn init_main_conf(_cf: *mut ngx_conf_t, _conf: *mut c_void) -> *mut c_char
    where
        Self: super::HttpModuleMainConf,
        Self::MainConf: Default,
    {
        ptr::null_mut()
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn create_srv_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: super::HttpModuleServerConf,
        Self::ServerConf: Default,
    {
        unsafe {
            let Some(pool) = Pool::from_raw((*cf).pool) else {
                return ptr::null_mut();
            };
            pool.allocate_with_cleanup(Self::ServerConf::default)
                .map(|value| value.into_non_null().as_ptr())
                .unwrap_or(ptr::null_mut())
                .cast()
        }
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn merge_srv_conf(
        cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: super::HttpModuleServerConf,
        Self::ServerConf: Merge,
    {
        let prev = unsafe { &*(prev as *mut Self::ServerConf) };
        let conf = unsafe { &mut *(conf as *mut Self::ServerConf) };
        match conf.merge(prev) {
            Ok(_) => ptr::null_mut(),
            Err(error) => {
                crate::ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "failed to merge server configuration: {error}"
                );
                NGX_CONF_ERROR as _
            }
        }
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn create_loc_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: super::HttpModuleLocationConf,
        Self::LocationConf: Default,
    {
        unsafe {
            let Some(pool) = Pool::from_raw((*cf).pool) else {
                return ptr::null_mut();
            };
            pool.allocate_with_cleanup(Self::LocationConf::default)
                .map(|value| value.into_non_null().as_ptr())
                .unwrap_or(ptr::null_mut())
                .cast()
        }
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn merge_loc_conf(
        cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: super::HttpModuleLocationConf,
        Self::LocationConf: Merge,
    {
        let prev = unsafe { &*(prev as *mut Self::LocationConf) };
        let conf = unsafe { &mut *(conf as *mut Self::LocationConf) };
        match conf.merge(prev) {
            Ok(_) => ptr::null_mut(),
            Err(error) => {
                crate::ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "failed to merge location configuration: {error}"
                );
                NGX_CONF_ERROR as _
            }
        }
    }
}

/// Associates one request-context type with an HTTP module.
///
/// # Safety
///
/// The module's request context slot must be null or point to a valid initialized
/// [`RequestContext`](Self::RequestContext) value allocated with a cleanup handler from the
/// request pool. The value must remain registered with that pool until it is removed.
pub unsafe trait HttpModuleRequestContext: HttpModule {
    /// Value stored in the module's per-request context slot.
    type RequestContext: 'static;
}
