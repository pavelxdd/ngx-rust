use core::error;
use core::ffi::{CStr, c_char, c_void};
use core::fmt;
use core::ptr::{self, NonNull};

use crate::core::{ModuleDescriptor, NGX_CONF_ERROR, Pool, Status};
use crate::ffi::{NGX_LOG_EMERG, ngx_conf_t, ngx_int_t};
use crate::stream::{StreamConfigurationParser, StreamModuleMainConf, StreamModuleServerConf};

/// Error returned when child configuration cannot be merged with its parent.
#[derive(Debug)]
pub enum MergeConfigError {
    /// A required value is missing.
    NoValue,
    /// A module-specific static error message.
    Message(&'static CStr),
}

impl error::Error for MergeConfigError {}

impl fmt::Display for MergeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoValue => "no value".fmt(formatter),
            Self::Message(message) => match message.to_str() {
                Ok(message) => message.fmt(formatter),
                Err(_) => "invalid configuration error".fmt(formatter),
            },
        }
    }
}

impl From<&'static CStr> for MergeConfigError {
    fn from(message: &'static CStr) -> Self {
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

/// Initializes a module's main configuration after parsing.
pub trait InitMainConf {
    /// Applies post-parse validation or returns a static nginx configuration error.
    fn init_main_conf(&mut self) -> Result<(), MergeConfigError>;
}

/// # Safety
///
/// `cf.pool` must not be reset before the pool is destroyed.
unsafe fn configuration_pool(cf: &ngx_conf_t) -> Option<Pool<'_>> {
    let pool = NonNull::new(cf.pool)?;
    unsafe { Pool::from_raw(pool.as_ptr()) }
}

/// # Safety
///
/// `cf` must point to a live nginx parser state whose pool is not reset before destruction.
unsafe fn allocate_configuration<T>(cf: *mut ngx_conf_t) -> *mut c_void
where
    T: Default + 'static,
{
    let Some(cf) = (unsafe { cf.as_ref() }) else {
        return ptr::null_mut();
    };
    let Some(pool) = (unsafe { configuration_pool(cf) }) else {
        return ptr::null_mut();
    };

    pool.allocate_with_cleanup(T::default)
        .map(|value| value.into_non_null().as_ptr())
        .unwrap_or(ptr::null_mut())
        .cast()
}

fn configuration_callback_status(
    configuration: *mut ngx_conf_t,
    callback: impl for<'scope> FnOnce(&mut StreamConfigurationParser<'scope>) -> ngx_int_t,
) -> ngx_int_t {
    unsafe { StreamConfigurationParser::with_raw(configuration, callback) }
        .unwrap_or(Status::NGX_ERROR.0)
}

fn log_configuration_error(cf: *mut ngx_conf_t, action: &str, error: &dyn fmt::Display) {
    let Some(configuration) = NonNull::new(cf) else {
        return;
    };
    if !configuration.as_ptr().is_aligned() || unsafe { configuration.as_ref().log.is_null() } {
        return;
    }

    crate::ngx_conf_log_error!(NGX_LOG_EMERG, cf, "failed to {action}: {error}");
}

/// Defines a concrete NGINX Stream module and its configuration lifecycle.
///
/// # Safety
/// `module()` must return this type's real live global module descriptor. Nginx must have
/// initialized its module and context indexes before any typed configuration or session access.
pub unsafe trait StreamModule {
    /// Returns the opaque identity of the global module descriptor.
    fn module() -> ModuleDescriptor;

    /// Runs before nginx parses the Stream configuration block.
    fn preconfigure(_parser: &mut StreamConfigurationParser<'_>) -> ngx_int_t {
        Status::NGX_OK.0
    }

    /// Runs after nginx parses the Stream configuration block.
    fn postconfigure(_parser: &mut StreamConfigurationParser<'_>) -> ngx_int_t {
        Status::NGX_OK.0
    }

    /// C-compatible adapter for [`Self::preconfigure`].
    ///
    /// # Safety
    /// `configuration` must point to the live nginx Stream parser state for this callback.
    unsafe extern "C" fn preconfiguration(configuration: *mut ngx_conf_t) -> ngx_int_t {
        configuration_callback_status(configuration, Self::preconfigure)
    }

    /// C-compatible adapter for [`Self::postconfigure`].
    ///
    /// # Safety
    /// `configuration` must point to the live nginx Stream parser state for this callback.
    unsafe extern "C" fn postconfiguration(configuration: *mut ngx_conf_t) -> ngx_int_t {
        configuration_callback_status(configuration, Self::postconfigure)
    }

    /// Allocates the module's main configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime and is not reset before it is destroyed.
    unsafe extern "C" fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: StreamModuleMainConf,
        Self::MainConf: Default,
    {
        unsafe { allocate_configuration::<Self::MainConf>(cf) }
    }

    /// Initializes the module's main configuration after parsing.
    ///
    /// # Safety
    /// `cf` and `conf` must be the valid pointers supplied by nginx for this module.
    unsafe extern "C" fn init_main_conf(cf: *mut ngx_conf_t, conf: *mut c_void) -> *mut c_char
    where
        Self: StreamModuleMainConf,
        Self::MainConf: InitMainConf,
    {
        let Some(conf) = (unsafe { conf.cast::<Self::MainConf>().as_mut() }) else {
            return NGX_CONF_ERROR;
        };

        match conf.init_main_conf() {
            Ok(()) => ptr::null_mut(),
            Err(error) => {
                log_configuration_error(cf, "initialize main configuration", &error);
                NGX_CONF_ERROR
            }
        }
    }

    /// Allocates the module's server configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime and is not reset before it is destroyed.
    unsafe extern "C" fn create_srv_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: StreamModuleServerConf,
        Self::ServerConf: Default,
    {
        unsafe { allocate_configuration::<Self::ServerConf>(cf) }
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
        if prev.is_null() || conf.is_null() || prev == conf {
            return NGX_CONF_ERROR;
        }
        let parent = unsafe { &*prev.cast::<Self::ServerConf>() };
        let child = unsafe { &mut *conf.cast::<Self::ServerConf>() };

        match child.merge(parent) {
            Ok(()) => ptr::null_mut(),
            Err(error) => {
                log_configuration_error(cf, "merge server configuration", &error);
                NGX_CONF_ERROR
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{boxed::Box, vec::Vec};
    use core::ffi::c_void;
    use core::mem;
    use core::ptr;
    use core::slice;
    #[cfg(feature = "test-link")]
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{InitMainConf, Merge, MergeConfigError, StreamModule};
    use crate::core::{ModuleDescriptor, NGX_CONF_ERROR, Status};
    use crate::ffi::ngx_module_t;
    #[cfg(feature = "test-link")]
    use crate::ffi::{
        NGX_LOG_EMERG, ngx_conf_t, ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_pool_t,
        ngx_uint_t,
    };
    use crate::stream::{StreamModuleMainConf, StreamModuleServerConf};

    #[cfg(feature = "test-link")]
    #[derive(Default)]
    struct ConfigLogCapture {
        records: Vec<(ngx_uint_t, Vec<u8>)>,
    }

    #[cfg(feature = "test-link")]
    impl ConfigLogCapture {
        fn assert_single(&self, message: &[u8]) {
            assert_eq!(self.records.len(), 1);
            assert_eq!(self.records[0].0, NGX_LOG_EMERG as _);
            assert!(self.records[0].1.windows(message.len()).any(|record| record == message));
        }
    }

    #[cfg(feature = "test-link")]
    unsafe extern "C" fn capture_config_log(
        log: *mut ngx_log_t,
        level: ngx_uint_t,
        bytes: *mut u8,
        len: usize,
    ) {
        let Some(log) = (unsafe { log.as_mut() }) else {
            return;
        };
        let Some(capture) = (unsafe { log.wdata.cast::<ConfigLogCapture>().as_mut() }) else {
            return;
        };
        if bytes.is_null() {
            return;
        }
        capture.records.push((level, unsafe { slice::from_raw_parts(bytes, len) }.to_vec()));
    }

    fn test_module() -> ModuleDescriptor {
        ModuleDescriptor::from_test(ngx_module_t::default())
    }

    #[derive(Default)]
    struct MainConf {
        initialized: bool,
    }

    impl InitMainConf for MainConf {
        fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
            self.initialized = true;
            Ok(())
        }
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

    unsafe impl StreamModule for TestStreamModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl StreamModuleMainConf for TestStreamModule {
        type MainConf = MainConf;
    }

    unsafe impl StreamModuleServerConf for TestStreamModule {
        type ServerConf = ServerConf;
    }

    #[test]
    fn default_configuration_hooks_reject_null_parser_context() {
        assert_eq!(
            unsafe { TestStreamModule::preconfiguration(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );
        assert_eq!(
            unsafe { TestStreamModule::postconfiguration(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );

        let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
        assert_eq!(
            unsafe { TestStreamModule::preconfiguration(&raw mut configuration) },
            Status::NGX_OK.0
        );
        assert_eq!(
            unsafe { TestStreamModule::postconfiguration(&raw mut configuration) },
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

    #[test]
    fn configuration_hooks_reject_null_values_and_aliases() {
        assert!(unsafe { TestStreamModule::create_main_conf(ptr::null_mut()) }.is_null());
        assert!(unsafe { TestStreamModule::create_srv_conf(ptr::null_mut()) }.is_null());
        assert_eq!(
            unsafe { TestStreamModule::init_main_conf(ptr::null_mut(), ptr::null_mut()) },
            NGX_CONF_ERROR
        );

        let mut configuration = ServerConf::default();
        assert_eq!(
            unsafe {
                TestStreamModule::merge_srv_conf(
                    ptr::null_mut(),
                    (&raw mut configuration).cast(),
                    (&raw mut configuration).cast(),
                )
            },
            NGX_CONF_ERROR
        );
    }

    struct RejectMainConf;

    impl InitMainConf for RejectMainConf {
        fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
            Err(MergeConfigError::Message(c"init rejected"))
        }
    }

    struct RejectMainModule;

    unsafe impl StreamModule for RejectMainModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl StreamModuleMainConf for RejectMainModule {
        type MainConf = RejectMainConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn main_configuration_initialization_logs_once_and_returns_the_silent_sentinel() {
        let mut pool = TestPool::new();
        let mut capture = ConfigLogCapture::default();
        pool._log.log_level = NGX_LOG_EMERG as _;
        pool._log.writer = Some(capture_config_log);
        pool._log.wdata = (&raw mut capture).cast();
        let mut parser = pool.configuration();
        let mut configuration = RejectMainConf;

        assert_eq!(
            unsafe {
                RejectMainModule::init_main_conf(&raw mut parser, (&raw mut configuration).cast())
            },
            NGX_CONF_ERROR
        );
        capture.assert_single(b"failed to initialize main configuration: init rejected");
    }

    struct RejectConf;

    impl Merge for RejectConf {
        fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
            Err(MergeConfigError::NoValue)
        }
    }

    struct RejectStreamModule;

    unsafe impl StreamModule for RejectStreamModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl StreamModuleServerConf for RejectStreamModule {
        type ServerConf = RejectConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn rejected_server_configuration_logs_no_value_once() {
        let mut pool = TestPool::new();
        let mut capture = ConfigLogCapture::default();
        pool._log.log_level = NGX_LOG_EMERG as _;
        pool._log.writer = Some(capture_config_log);
        pool._log.wdata = (&raw mut capture).cast();
        let mut parser = pool.configuration();
        let mut parent = RejectConf;
        let mut child = RejectConf;

        assert_eq!(
            unsafe {
                RejectStreamModule::merge_srv_conf(
                    &raw mut parser,
                    (&raw mut parent).cast::<c_void>(),
                    (&raw mut child).cast::<c_void>(),
                )
            },
            NGX_CONF_ERROR
        );
        capture.assert_single(b"failed to merge server configuration: no value");
    }

    struct StaticRejectConf;

    impl Merge for StaticRejectConf {
        fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
            Err(MergeConfigError::Message(c"merge rejected"))
        }
    }

    struct StaticRejectStreamModule;

    unsafe impl StreamModule for StaticRejectStreamModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl StreamModuleServerConf for StaticRejectStreamModule {
        type ServerConf = StaticRejectConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn server_configuration_merge_logs_static_message_once() {
        let mut pool = TestPool::new();
        let mut capture = ConfigLogCapture::default();
        pool._log.log_level = NGX_LOG_EMERG as _;
        pool._log.writer = Some(capture_config_log);
        pool._log.wdata = (&raw mut capture).cast();
        let mut parser = pool.configuration();
        let mut parent = StaticRejectConf;
        let mut child = StaticRejectConf;

        assert_eq!(
            unsafe {
                StaticRejectStreamModule::merge_srv_conf(
                    &raw mut parser,
                    (&raw mut parent).cast(),
                    (&raw mut child).cast(),
                )
            },
            NGX_CONF_ERROR
        );
        capture.assert_single(b"failed to merge server configuration: merge rejected");
    }

    #[cfg(feature = "test-link")]
    static MAIN_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "test-link")]
    static SERVER_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    #[derive(Default)]
    struct AllocatedMainConf {
        initialized: bool,
    }

    #[cfg(feature = "test-link")]
    impl InitMainConf for AllocatedMainConf {
        fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
            self.initialized = true;
            Ok(())
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for AllocatedMainConf {
        fn drop(&mut self) {
            MAIN_CONF_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    #[derive(Default)]
    struct AllocatedServerConf;

    #[cfg(feature = "test-link")]
    impl Drop for AllocatedServerConf {
        fn drop(&mut self) {
            SERVER_CONF_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct AllocationStreamModule;

    #[cfg(feature = "test-link")]
    unsafe impl StreamModule for AllocationStreamModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleMainConf for AllocationStreamModule {
        type MainConf = AllocatedMainConf;
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleServerConf for AllocationStreamModule {
        type ServerConf = AllocatedServerConf;
    }

    #[cfg(feature = "test-link")]
    struct TestPool {
        raw: *mut ngx_pool_t,
        _log: Box<ngx_log_t>,
    }

    #[cfg(feature = "test-link")]
    impl TestPool {
        fn new() -> Self {
            let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
            let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!raw.is_null());
            Self { raw, _log: log }
        }

        fn configuration(&self) -> ngx_conf_t {
            let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
            configuration.pool = self.raw;
            configuration.log = ptr::from_ref(&*self._log).cast_mut();
            configuration
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn configuration_pool_owns_initialized_main_and_server_values_once() {
        MAIN_CONF_DROPS.store(0, Ordering::Relaxed);
        SERVER_CONF_DROPS.store(0, Ordering::Relaxed);
        let pool = TestPool::new();
        let mut configuration = pool.configuration();

        let main = unsafe { AllocationStreamModule::create_main_conf(&raw mut configuration) };
        let server = unsafe { AllocationStreamModule::create_srv_conf(&raw mut configuration) };
        assert!(!main.is_null());
        assert!(!server.is_null());
        assert!(!unsafe { (*main.cast::<AllocatedMainConf>()).initialized });
        assert!(
            unsafe { AllocationStreamModule::init_main_conf(&raw mut configuration, main) }
                .is_null()
        );
        assert!(unsafe { (*main.cast::<AllocatedMainConf>()).initialized });
        assert_eq!(MAIN_CONF_DROPS.load(Ordering::Relaxed), 0);
        assert_eq!(SERVER_CONF_DROPS.load(Ordering::Relaxed), 0);

        drop(pool);
        assert_eq!(MAIN_CONF_DROPS.load(Ordering::Relaxed), 1);
        assert_eq!(SERVER_CONF_DROPS.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "test-link")]
    #[repr(align(64))]
    #[derive(Default)]
    struct OverAlignedConf;

    #[cfg(feature = "test-link")]
    struct OverAlignedStreamModule;

    #[cfg(feature = "test-link")]
    unsafe impl StreamModule for OverAlignedStreamModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleServerConf for OverAlignedStreamModule {
        type ServerConf = OverAlignedConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn cleanup_rejection_does_not_publish_configuration() {
        let pool = TestPool::new();
        let mut configuration = pool.configuration();
        let cleanup = unsafe { (*pool.raw).cleanup };

        assert!(
            unsafe { OverAlignedStreamModule::create_srv_conf(&raw mut configuration) }.is_null()
        );
        assert_eq!(unsafe { (*pool.raw).cleanup }, cleanup);
    }
}
