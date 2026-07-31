use core::error;
use core::ffi::{c_char, c_void};
use core::fmt;
use core::ptr::{self, NonNull};

use crate::core::{NGX_CONF_ERROR, Pool, Status};
use crate::ffi::{NGX_LOG_EMERG, ngx_conf_t, ngx_int_t, ngx_module_t};
use crate::stream::{StreamModuleMainConf, StreamModuleServerConf};

/// Error returned when child configuration cannot be merged with its parent.
#[derive(Debug)]
pub enum MergeConfigError {
    /// A required value is missing.
    NoValue,
    /// A module-specific static error message.
    Message(&'static str),
}

impl error::Error for MergeConfigError {}

impl fmt::Display for MergeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoValue => "no value".fmt(formatter),
            Self::Message(message) => message.fmt(formatter),
        }
    }
}

impl From<&'static str> for MergeConfigError {
    fn from(message: &'static str) -> Self {
        Self::Message(message)
    }
}

/// Merges a child configuration value with its parent.
pub trait Merge {
    /// Applies inherited values or returns a configuration error.
    fn merge(&mut self, parent: &Self) -> Result<(), MergeConfigError>;
}

impl Merge for () {
    fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
        Ok(())
    }
}

/// Defines a concrete NGINX Stream module and its configuration lifecycle.
pub trait StreamModule {
    /// Returns the global module descriptor.
    fn module() -> &'static ngx_module_t;

    /// Runs before nginx parses the Stream configuration block.
    ///
    /// # Safety
    /// `cf` must be null or point to a valid nginx configuration parser state.
    unsafe extern "C" fn preconfiguration(_cf: *mut ngx_conf_t) -> ngx_int_t {
        Status::NGX_OK.into()
    }

    /// Runs after nginx parses the Stream configuration block.
    ///
    /// # Safety
    /// `cf` must be null or point to a valid nginx configuration parser state.
    unsafe extern "C" fn postconfiguration(_cf: *mut ngx_conf_t) -> ngx_int_t {
        Status::NGX_OK.into()
    }

    /// Allocates the module's main configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime.
    unsafe extern "C" fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: StreamModuleMainConf,
        Self::MainConf: Default,
    {
        let Some(cf) = (unsafe { cf.as_ref() }) else {
            return ptr::null_mut();
        };
        let Some(pool) = NonNull::new(cf.pool) else {
            return ptr::null_mut();
        };
        let pool = unsafe { Pool::from_ngx_pool(pool.as_ptr()) };
        unsafe { pool.allocate_with_cleanup(Self::MainConf::default) }
            .map(NonNull::as_ptr)
            .unwrap_or(ptr::null_mut())
            .cast()
    }

    /// Initializes the module's main configuration after parsing.
    ///
    /// # Safety
    /// `cf` and `conf` must be the valid pointers supplied by nginx for this module.
    unsafe extern "C" fn init_main_conf(_cf: *mut ngx_conf_t, _conf: *mut c_void) -> *mut c_char
    where
        Self: StreamModuleMainConf,
    {
        ptr::null_mut()
    }

    /// Allocates the module's server configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime.
    unsafe extern "C" fn create_srv_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: StreamModuleServerConf,
        Self::ServerConf: Default,
    {
        let Some(cf) = (unsafe { cf.as_ref() }) else {
            return ptr::null_mut();
        };
        let Some(pool) = NonNull::new(cf.pool) else {
            return ptr::null_mut();
        };
        let pool = unsafe { Pool::from_ngx_pool(pool.as_ptr()) };
        unsafe { pool.allocate_with_cleanup(Self::ServerConf::default) }
            .map(NonNull::as_ptr)
            .unwrap_or(ptr::null_mut())
            .cast()
    }

    /// Merges the module's server configuration with its parent.
    ///
    /// # Safety
    /// `prev` and `conf` must point to distinct initialized values of `Self::ServerConf` supplied
    /// by nginx. `cf`, when non-null, must point to the active configuration parser state.
    unsafe extern "C" fn merge_srv_conf(
        cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: StreamModuleServerConf,
        Self::ServerConf: Merge,
    {
        let Some(parent) = (unsafe { prev.cast::<Self::ServerConf>().as_ref() }) else {
            return NGX_CONF_ERROR;
        };
        let Some(child) = (unsafe { conf.cast::<Self::ServerConf>().as_mut() }) else {
            return NGX_CONF_ERROR;
        };

        match child.merge(parent) {
            Ok(()) => ptr::null_mut(),
            Err(error) => {
                if !cf.is_null() {
                    crate::ngx_conf_log_error!(
                        NGX_LOG_EMERG,
                        cf,
                        "failed to merge server configuration: {error}"
                    );
                }
                NGX_CONF_ERROR
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use core::ffi::c_void;
    #[cfg(feature = "test-link")]
    use core::mem;
    use core::ptr;
    #[cfg(feature = "test-link")]
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{Merge, MergeConfigError, StreamModule};
    use crate::core::{NGX_CONF_ERROR, Status};
    use crate::ffi::ngx_module_t;
    #[cfg(feature = "test-link")]
    use crate::ffi::{ngx_conf_t, ngx_create_pool, ngx_destroy_pool, ngx_log_t};
    use crate::stream::StreamModuleServerConf;

    fn test_module() -> &'static ngx_module_t {
        Box::leak(Box::new(ngx_module_t::default()))
    }

    #[derive(Default)]
    struct ServerConf(u32);

    impl Merge for ServerConf {
        fn merge(&mut self, parent: &Self) -> Result<(), MergeConfigError> {
            self.0 += parent.0;
            Ok(())
        }
    }

    struct TestStreamModule;

    impl StreamModule for TestStreamModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl StreamModuleServerConf for TestStreamModule {
        type ServerConf = ServerConf;
    }

    #[test]
    fn default_configuration_hooks_accept_the_configuration() {
        assert_eq!(
            unsafe { TestStreamModule::preconfiguration(ptr::null_mut()) },
            Status::NGX_OK.0
        );
        assert_eq!(
            unsafe { TestStreamModule::postconfiguration(ptr::null_mut()) },
            Status::NGX_OK.0
        );
    }

    #[test]
    fn server_configuration_merge_updates_the_child() {
        let mut parent = ServerConf(2);
        let mut child = ServerConf(3);

        let result = unsafe {
            TestStreamModule::merge_srv_conf(
                ptr::null_mut(),
                (&raw mut parent).cast::<c_void>(),
                (&raw mut child).cast::<c_void>(),
            )
        };

        assert!(result.is_null());
        assert_eq!(child.0, 5);
    }

    struct RejectConf;

    impl Merge for RejectConf {
        fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
            Err(MergeConfigError::NoValue)
        }
    }

    struct RejectStreamModule;

    impl StreamModule for RejectStreamModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl StreamModuleServerConf for RejectStreamModule {
        type ServerConf = RejectConf;
    }

    #[test]
    fn rejected_server_configuration_returns_nginx_error() {
        let mut parent = RejectConf;
        let mut child = RejectConf;

        let result = unsafe {
            RejectStreamModule::merge_srv_conf(
                ptr::null_mut(),
                (&raw mut parent).cast::<c_void>(),
                (&raw mut child).cast::<c_void>(),
            )
        };

        assert_eq!(result, NGX_CONF_ERROR);
    }

    #[cfg(feature = "test-link")]
    static ALLOCATED_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    #[derive(Default)]
    struct AllocatedConf;

    #[cfg(feature = "test-link")]
    impl Drop for AllocatedConf {
        fn drop(&mut self) {
            ALLOCATED_CONF_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct AllocationStreamModule;

    #[cfg(feature = "test-link")]
    impl StreamModule for AllocationStreamModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleServerConf for AllocationStreamModule {
        type ServerConf = AllocatedConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn server_configuration_is_dropped_with_its_nginx_pool() {
        ALLOCATED_CONF_DROPS.store(0, Ordering::Relaxed);
        let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
        let pool = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!pool.is_null());
        let mut cf = unsafe { mem::zeroed::<ngx_conf_t>() };
        cf.pool = pool;

        let conf = unsafe { AllocationStreamModule::create_srv_conf(&raw mut cf) };
        assert!(!conf.is_null());
        assert_eq!(ALLOCATED_CONF_DROPS.load(Ordering::Relaxed), 0);

        unsafe { ngx_destroy_pool(pool) };
        assert_eq!(ALLOCATED_CONF_DROPS.load(Ordering::Relaxed), 1);
    }
}
