use core::error;
use core::ffi::{c_char, c_void};
use core::fmt;
use core::ptr::{self, NonNull};

use crate::core::NGX_CONF_ERROR;
use crate::core::*;
use crate::ffi::*;

/// MergeConfigError - configuration cannot be merged with levels above.
#[derive(Debug)]
pub enum MergeConfigError {
    /// No value provided for configuration argument
    NoValue,
}

impl error::Error for MergeConfigError {}

impl fmt::Display for MergeConfigError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MergeConfigError::NoValue => "no value".fmt(fmt),
        }
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
    /// Result, Ok on success or MergeConfigError on failure.
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
            let pool = Pool::from_ngx_pool((*cf).pool);
            pool.allocate_with_cleanup(Self::MainConf::default)
                .map(NonNull::as_ptr)
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
            let pool = Pool::from_ngx_pool((*cf).pool);
            pool.allocate_with_cleanup(Self::ServerConf::default)
                .map(NonNull::as_ptr)
                .unwrap_or(ptr::null_mut())
                .cast()
        }
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn merge_srv_conf(
        _cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: super::HttpModuleServerConf,
        Self::ServerConf: Merge,
    {
        unsafe {
            let prev = &mut *(prev as *mut Self::ServerConf);
            let conf = &mut *(conf as *mut Self::ServerConf);
            match conf.merge(prev) {
                Ok(_) => ptr::null_mut(),
                Err(_) => NGX_CONF_ERROR as _,
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
            let pool = Pool::from_ngx_pool((*cf).pool);
            pool.allocate_with_cleanup(Self::LocationConf::default)
                .map(NonNull::as_ptr)
                .unwrap_or(ptr::null_mut())
                .cast()
        }
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn merge_loc_conf(
        _cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: super::HttpModuleLocationConf,
        Self::LocationConf: Merge,
    {
        unsafe {
            let prev = &mut *(prev as *mut Self::LocationConf);
            let conf = &mut *(conf as *mut Self::LocationConf);
            match conf.merge(prev) {
                Ok(_) => ptr::null_mut(),
                Err(_) => NGX_CONF_ERROR as _,
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
    type RequestContext;
}
