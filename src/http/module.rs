use core::error;
use core::ffi::{CStr, c_char, c_void};
use core::fmt;
use core::ptr::{self, NonNull};

#[cfg(feature = "std")]
use core::panic::AssertUnwindSafe;
#[cfg(feature = "std")]
use std::panic::catch_unwind;

use crate::core::{NGX_CONF_ERROR, Pool, Status};
use crate::ffi::{NGX_LOG_EMERG, ngx_conf_t, ngx_int_t, ngx_module_t};
use crate::http::{HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf};

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

impl MergeConfigError {
    fn as_conf_result(&self) -> *mut c_char {
        match self {
            Self::NoValue => NGX_CONF_ERROR,
            Self::Message(message) => message.as_ptr().cast_mut(),
        }
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

unsafe fn checked_ref<'a, T>(pointer: *mut T) -> Option<&'a T> {
    let pointer = NonNull::new(pointer)?;
    if !pointer.as_ptr().is_aligned() {
        return None;
    }

    Some(unsafe { pointer.as_ref() })
}

unsafe fn checked_mut<'a, T>(pointer: *mut T) -> Option<&'a mut T> {
    let mut pointer = NonNull::new(pointer)?;
    if !pointer.as_ptr().is_aligned() {
        return None;
    }

    Some(unsafe { pointer.as_mut() })
}

fn configuration_pool(cf: &ngx_conf_t) -> Option<Pool<'_>> {
    unsafe { Pool::from_raw(cf.pool) }
}

fn allocate_configuration<T>(cf: *mut ngx_conf_t) -> *mut c_void
where
    T: Default + 'static,
{
    let Some(cf) = (unsafe { checked_ref(cf) }) else {
        return ptr::null_mut();
    };
    let Some(pool) = configuration_pool(cf) else {
        return ptr::null_mut();
    };

    #[cfg(feature = "std")]
    {
        match pool.try_allocate_with_cleanup(|| -> Result<T, ()> {
            catch_unwind(AssertUnwindSafe(T::default)).map_err(|_| ())
        }) {
            Ok(value) => value.into_non_null().as_ptr().cast(),
            Err(_) => ptr::null_mut(),
        }
    }

    #[cfg(not(feature = "std"))]
    {
        pool.allocate_with_cleanup(T::default)
            .map(|value| value.into_non_null().as_ptr().cast())
            .unwrap_or(ptr::null_mut())
    }
}

fn log_merge_error(cf: *mut ngx_conf_t, level: &str, error: &MergeConfigError) {
    let Some(configuration) = (unsafe { checked_ref(cf) }) else {
        return;
    };
    if configuration.log.is_null() {
        return;
    }

    crate::ngx_conf_log_error!(NGX_LOG_EMERG, cf, "failed to merge {level} configuration: {error}",);
}

fn init_configuration<T>(cf: *mut ngx_conf_t, conf: *mut c_void) -> *mut c_char
where
    T: InitMainConf,
{
    if unsafe { checked_ref(cf) }.is_none() {
        return NGX_CONF_ERROR;
    }
    let Some(conf) = (unsafe { checked_mut(conf.cast::<T>()) }) else {
        return NGX_CONF_ERROR;
    };

    #[cfg(feature = "std")]
    {
        match catch_unwind(AssertUnwindSafe(|| conf.init_main_conf())) {
            Ok(Ok(())) => ptr::null_mut(),
            Ok(Err(error)) => error.as_conf_result(),
            Err(_) => NGX_CONF_ERROR,
        }
    }

    #[cfg(not(feature = "std"))]
    {
        match conf.init_main_conf() {
            Ok(()) => ptr::null_mut(),
            Err(error) => error.as_conf_result(),
        }
    }
}

fn merge_configuration<T>(
    cf: *mut ngx_conf_t,
    prev: *mut c_void,
    conf: *mut c_void,
    level: &str,
) -> *mut c_char
where
    T: Merge,
{
    if unsafe { checked_ref(cf) }.is_none() || prev.is_null() || conf.is_null() || prev == conf {
        return NGX_CONF_ERROR;
    }
    let Some(parent) = (unsafe { checked_ref(prev.cast::<T>()) }) else {
        return NGX_CONF_ERROR;
    };
    let Some(child) = (unsafe { checked_mut(conf.cast::<T>()) }) else {
        return NGX_CONF_ERROR;
    };

    #[cfg(feature = "std")]
    let result = catch_unwind(AssertUnwindSafe(|| child.merge(parent)));
    #[cfg(not(feature = "std"))]
    let result = Ok::<_, ()>(child.merge(parent));

    match result {
        Ok(Ok(())) => ptr::null_mut(),
        Ok(Err(error)) => {
            log_merge_error(cf, level, &error);
            error.as_conf_result()
        }
        Err(_) => NGX_CONF_ERROR,
    }
}

/// Defines a concrete nginx HTTP module and its configuration lifecycle.
///
/// # Safety
/// `module()` must return this type's real live global module descriptor. Nginx must have
/// initialized its module and context indexes before any typed configuration access. Callback
/// implementations must not unwind across nginx's C ABI.
pub unsafe trait HttpModule {
    /// Returns the global module descriptor.
    fn module() -> &'static ngx_module_t;

    /// Runs before nginx parses the HTTP configuration block.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state.
    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        if unsafe { checked_ref(cf) }.is_none() {
            return Status::NGX_ERROR.into();
        }

        Status::NGX_OK.into()
    }

    /// Runs after nginx parses the HTTP configuration block.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state.
    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        if unsafe { checked_ref(cf) }.is_none() {
            return Status::NGX_ERROR.into();
        }

        Status::NGX_OK.into()
    }

    /// Allocates the module's main configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime.
    unsafe extern "C" fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: HttpModuleMainConf,
        Self::MainConf: Default,
    {
        allocate_configuration::<Self::MainConf>(cf)
    }

    /// Initializes the module's main configuration after parsing.
    ///
    /// # Safety
    /// `cf` and `conf` must be the valid pointers supplied by nginx for this module.
    unsafe extern "C" fn init_main_conf(cf: *mut ngx_conf_t, conf: *mut c_void) -> *mut c_char
    where
        Self: HttpModuleMainConf,
        Self::MainConf: InitMainConf,
    {
        init_configuration::<Self::MainConf>(cf, conf)
    }

    /// Allocates the module's server configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime.
    unsafe extern "C" fn create_srv_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: HttpModuleServerConf,
        Self::ServerConf: Default,
    {
        allocate_configuration::<Self::ServerConf>(cf)
    }

    /// Merges the module's server configuration with its parent.
    ///
    /// # Safety
    /// `prev` and `conf` must point to distinct initialized values of `Self::ServerConf` supplied
    /// by nginx. `cf` must point to the active configuration parser state.
    unsafe extern "C" fn merge_srv_conf(
        cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: HttpModuleServerConf,
        Self::ServerConf: Merge,
    {
        merge_configuration::<Self::ServerConf>(cf, prev, conf, "server")
    }

    /// Allocates the module's location configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime.
    unsafe extern "C" fn create_loc_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: HttpModuleLocationConf,
        Self::LocationConf: Default,
    {
        allocate_configuration::<Self::LocationConf>(cf)
    }

    /// Merges the module's location configuration with its parent.
    ///
    /// # Safety
    /// `prev` and `conf` must point to distinct initialized values of `Self::LocationConf`
    /// supplied by nginx. `cf` must point to the active configuration parser state.
    unsafe extern "C" fn merge_loc_conf(
        cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: HttpModuleLocationConf,
        Self::LocationConf: Merge,
    {
        merge_configuration::<Self::LocationConf>(cf, prev, conf, "location")
    }
}

/// Associates one request-context type with an HTTP module.
///
/// # Safety
/// The module's request context slot must be null or point to a valid initialized value allocated
/// with a cleanup handler from the request pool. The value must remain registered with that pool
/// until it is removed.
pub unsafe trait HttpModuleRequestContext: HttpModule {
    /// Value stored in the module's per-request context slot.
    type RequestContext: 'static;
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use core::ffi::c_void;
    use core::mem;
    use core::ptr;
    #[cfg(feature = "test-link")]
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{HttpModule, InitMainConf, Merge, MergeConfigError};
    use crate::core::{NGX_CONF_ERROR, Status};
    use crate::ffi::{ngx_conf_t, ngx_module_t};
    #[cfg(feature = "test-link")]
    use crate::ffi::{ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_pool_t, ngx_uint_t};
    use crate::http::{HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf};

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    fn test_module() -> &'static ngx_module_t {
        Box::leak(Box::new(ngx_module_t::default()))
    }

    #[derive(Default)]
    struct MainConf {
        initialized: bool,
        _alignment: u32,
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

    #[derive(Default)]
    struct LocationConf(u32);

    impl Merge for LocationConf {
        fn merge(&mut self, parent: &Self) -> Result<(), MergeConfigError> {
            self.0 += parent.0;
            Ok(())
        }
    }

    struct TestHttpModule;

    unsafe impl HttpModule for TestHttpModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl HttpModuleMainConf for TestHttpModule {
        type MainConf = MainConf;
    }

    unsafe impl HttpModuleServerConf for TestHttpModule {
        type ServerConf = ServerConf;
    }

    unsafe impl HttpModuleLocationConf for TestHttpModule {
        type LocationConf = LocationConf;
    }

    #[test]
    fn default_configuration_hooks_reject_null_and_misaligned_parser_contexts() {
        assert_eq!(
            unsafe { TestHttpModule::preconfiguration(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );
        assert_eq!(
            unsafe { TestHttpModule::postconfiguration(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );

        let misaligned = ptr::without_provenance_mut::<ngx_conf_t>(1);
        assert_eq!(unsafe { TestHttpModule::preconfiguration(misaligned) }, Status::NGX_ERROR.0);
        assert_eq!(unsafe { TestHttpModule::postconfiguration(misaligned) }, Status::NGX_ERROR.0);

        let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
        assert_eq!(
            unsafe { TestHttpModule::preconfiguration(&raw mut configuration) },
            Status::NGX_OK.0
        );
        assert_eq!(
            unsafe { TestHttpModule::postconfiguration(&raw mut configuration) },
            Status::NGX_OK.0
        );
    }

    #[test]
    fn configuration_callbacks_reject_null_misaligned_and_aliasing_values() {
        assert!(unsafe { TestHttpModule::create_main_conf(ptr::null_mut()) }.is_null());
        assert!(unsafe { TestHttpModule::create_srv_conf(ptr::null_mut()) }.is_null());
        assert!(unsafe { TestHttpModule::create_loc_conf(ptr::null_mut()) }.is_null());

        let misaligned = ptr::without_provenance_mut::<ngx_conf_t>(1);
        assert!(unsafe { TestHttpModule::create_main_conf(misaligned) }.is_null());
        assert!(unsafe { TestHttpModule::create_srv_conf(misaligned) }.is_null());
        assert!(unsafe { TestHttpModule::create_loc_conf(misaligned) }.is_null());

        let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
        let mut main = MainConf::default();
        assert_eq!(
            unsafe {
                TestHttpModule::init_main_conf(
                    ptr::without_provenance_mut(1),
                    (&raw mut main).cast(),
                )
            },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe { TestHttpModule::init_main_conf(&raw mut parser, ptr::null_mut()) },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe {
                TestHttpModule::init_main_conf(
                    &raw mut parser,
                    ptr::without_provenance_mut::<c_void>(1),
                )
            },
            NGX_CONF_ERROR
        );

        let mut server = ServerConf::default();
        assert_eq!(
            unsafe {
                TestHttpModule::merge_srv_conf(
                    &raw mut parser,
                    ptr::null_mut(),
                    (&raw mut server).cast(),
                )
            },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe {
                TestHttpModule::merge_srv_conf(
                    &raw mut parser,
                    (&raw mut server).cast(),
                    ptr::null_mut(),
                )
            },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe {
                TestHttpModule::merge_srv_conf(
                    &raw mut parser,
                    ptr::without_provenance_mut(1),
                    (&raw mut server).cast(),
                )
            },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe {
                TestHttpModule::merge_srv_conf(
                    &raw mut parser,
                    (&raw mut server).cast(),
                    (&raw mut server).cast(),
                )
            },
            NGX_CONF_ERROR
        );

        let mut location = LocationConf::default();
        assert_eq!(
            unsafe {
                TestHttpModule::merge_loc_conf(
                    &raw mut parser,
                    ptr::null_mut(),
                    (&raw mut location).cast(),
                )
            },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe {
                TestHttpModule::merge_loc_conf(
                    &raw mut parser,
                    (&raw mut location).cast(),
                    ptr::null_mut(),
                )
            },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe {
                TestHttpModule::merge_loc_conf(
                    &raw mut parser,
                    (&raw mut location).cast(),
                    ptr::without_provenance_mut(1),
                )
            },
            NGX_CONF_ERROR
        );
        assert_eq!(
            unsafe {
                TestHttpModule::merge_loc_conf(
                    &raw mut parser,
                    (&raw mut location).cast(),
                    (&raw mut location).cast(),
                )
            },
            NGX_CONF_ERROR
        );
    }

    #[test]
    fn main_initialization_and_server_location_merges_update_values() {
        let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
        let mut main = MainConf::default();
        assert!(
            unsafe { TestHttpModule::init_main_conf(&raw mut parser, (&raw mut main).cast()) }
                .is_null()
        );
        assert!(main.initialized);

        let mut server_parent = ServerConf(2);
        let mut server_child = ServerConf(3);
        assert!(
            unsafe {
                TestHttpModule::merge_srv_conf(
                    &raw mut parser,
                    (&raw mut server_parent).cast(),
                    (&raw mut server_child).cast(),
                )
            }
            .is_null()
        );
        assert_eq!(server_child.0, 5);

        let mut location_parent = LocationConf(5);
        let mut location_child = LocationConf(8);
        assert!(
            unsafe {
                TestHttpModule::merge_loc_conf(
                    &raw mut parser,
                    (&raw mut location_parent).cast(),
                    (&raw mut location_child).cast(),
                )
            }
            .is_null()
        );
        assert_eq!(location_child.0, 13);
    }

    struct RejectMainConf;

    impl InitMainConf for RejectMainConf {
        fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
            Err(MergeConfigError::Message(c"init rejected"))
        }
    }

    struct RejectMainModule;

    unsafe impl HttpModule for RejectMainModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl HttpModuleMainConf for RejectMainModule {
        type MainConf = RejectMainConf;
    }

    #[test]
    fn main_initialization_preserves_a_static_error_message() {
        let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
        let mut configuration = RejectMainConf;

        assert_eq!(
            unsafe {
                RejectMainModule::init_main_conf(&raw mut parser, (&raw mut configuration).cast())
            },
            c"init rejected".as_ptr().cast_mut()
        );
    }

    struct RejectServerConf;

    impl Merge for RejectServerConf {
        fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
            Err(MergeConfigError::Message(c"server rejected"))
        }
    }

    struct RejectServerModule;

    unsafe impl HttpModule for RejectServerModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl HttpModuleServerConf for RejectServerModule {
        type ServerConf = RejectServerConf;
    }

    struct RejectLocationConf;

    impl Merge for RejectLocationConf {
        fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
            Err(MergeConfigError::Message(c"location rejected"))
        }
    }

    struct RejectLocationModule;

    unsafe impl HttpModule for RejectLocationModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl HttpModuleLocationConf for RejectLocationModule {
        type LocationConf = RejectLocationConf;
    }

    #[test]
    fn server_and_location_merges_preserve_static_error_messages() {
        let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
        let mut server_parent = RejectServerConf;
        let mut server_child = RejectServerConf;
        assert_eq!(
            unsafe {
                RejectServerModule::merge_srv_conf(
                    &raw mut parser,
                    (&raw mut server_parent).cast(),
                    (&raw mut server_child).cast(),
                )
            },
            c"server rejected".as_ptr().cast_mut()
        );

        let mut location_parent = RejectLocationConf;
        let mut location_child = RejectLocationConf;
        assert_eq!(
            unsafe {
                RejectLocationModule::merge_loc_conf(
                    &raw mut parser,
                    (&raw mut location_parent).cast(),
                    (&raw mut location_child).cast(),
                )
            },
            c"location rejected".as_ptr().cast_mut()
        );
    }

    #[cfg(feature = "test-link")]
    static MAIN_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "test-link")]
    static SERVER_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "test-link")]
    static LOCATION_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);

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
    #[derive(Default)]
    struct AllocatedLocationConf;

    #[cfg(feature = "test-link")]
    impl Drop for AllocatedLocationConf {
        fn drop(&mut self) {
            LOCATION_CONF_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct AllocationHttpModule;

    #[cfg(feature = "test-link")]
    unsafe impl HttpModule for AllocationHttpModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl HttpModuleMainConf for AllocationHttpModule {
        type MainConf = AllocatedMainConf;
    }

    #[cfg(feature = "test-link")]
    unsafe impl HttpModuleServerConf for AllocationHttpModule {
        type ServerConf = AllocatedServerConf;
    }

    #[cfg(feature = "test-link")]
    unsafe impl HttpModuleLocationConf for AllocationHttpModule {
        type LocationConf = AllocatedLocationConf;
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
            configuration.log = (&raw const *self._log).cast_mut();
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
    fn configuration_pool_owns_main_server_and_location_values_once() {
        MAIN_CONF_DROPS.store(0, Ordering::Relaxed);
        SERVER_CONF_DROPS.store(0, Ordering::Relaxed);
        LOCATION_CONF_DROPS.store(0, Ordering::Relaxed);
        let pool = TestPool::new();
        let mut configuration = pool.configuration();

        let main = unsafe { AllocationHttpModule::create_main_conf(&raw mut configuration) };
        let server = unsafe { AllocationHttpModule::create_srv_conf(&raw mut configuration) };
        let location = unsafe { AllocationHttpModule::create_loc_conf(&raw mut configuration) };
        assert!(!main.is_null());
        assert!(!server.is_null());
        assert!(!location.is_null());
        assert!(!unsafe { (*main.cast::<AllocatedMainConf>()).initialized });
        assert!(
            unsafe { AllocationHttpModule::init_main_conf(&raw mut configuration, main) }.is_null()
        );
        assert!(unsafe { (*main.cast::<AllocatedMainConf>()).initialized });
        assert_eq!(MAIN_CONF_DROPS.load(Ordering::Relaxed), 0);
        assert_eq!(SERVER_CONF_DROPS.load(Ordering::Relaxed), 0);
        assert_eq!(LOCATION_CONF_DROPS.load(Ordering::Relaxed), 0);

        drop(pool);
        assert_eq!(MAIN_CONF_DROPS.load(Ordering::Relaxed), 1);
        assert_eq!(SERVER_CONF_DROPS.load(Ordering::Relaxed), 1);
        assert_eq!(LOCATION_CONF_DROPS.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "test-link")]
    #[repr(align(64))]
    #[derive(Default)]
    struct OverAlignedConf;

    #[cfg(feature = "test-link")]
    struct OverAlignedHttpModule;

    #[cfg(feature = "test-link")]
    unsafe impl HttpModule for OverAlignedHttpModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl HttpModuleMainConf for OverAlignedHttpModule {
        type MainConf = OverAlignedConf;
    }

    #[cfg(feature = "test-link")]
    unsafe impl HttpModuleServerConf for OverAlignedHttpModule {
        type ServerConf = OverAlignedConf;
    }

    #[cfg(feature = "test-link")]
    unsafe impl HttpModuleLocationConf for OverAlignedHttpModule {
        type LocationConf = OverAlignedConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn cleanup_rejection_does_not_publish_configuration() {
        let pool = TestPool::new();
        let mut configuration = pool.configuration();
        let cleanup = unsafe { (*pool.raw).cleanup };

        assert!(
            unsafe { OverAlignedHttpModule::create_main_conf(&raw mut configuration) }.is_null()
        );
        assert!(
            unsafe { OverAlignedHttpModule::create_srv_conf(&raw mut configuration) }.is_null()
        );
        assert!(
            unsafe { OverAlignedHttpModule::create_loc_conf(&raw mut configuration) }.is_null()
        );
        assert_eq!(unsafe { (*pool.raw).cleanup }, cleanup);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn cleanup_allocation_failure_does_not_publish_configuration() {
        let pool = TestPool::new();
        let mut configuration = pool.configuration();
        let cleanup = unsafe { (*pool.raw).cleanup };
        unsafe { (*pool.raw).max = 0 };

        for successes in 0..=1 {
            unsafe { ngx_rs_test_fail_allocations_after(successes) };
            let main = unsafe { AllocationHttpModule::create_main_conf(&raw mut configuration) };
            unsafe { ngx_rs_test_reset_allocation_failures() };

            assert!(main.is_null());
            assert_eq!(unsafe { (*pool.raw).cleanup }, cleanup);
        }
    }

    #[cfg(all(feature = "std", feature = "test-link"))]
    struct PanicDefaultConf;

    #[cfg(all(feature = "std", feature = "test-link"))]
    impl Default for PanicDefaultConf {
        fn default() -> Self {
            panic!("default panic")
        }
    }

    #[cfg(all(feature = "std", feature = "test-link"))]
    struct PanicDefaultModule;

    #[cfg(all(feature = "std", feature = "test-link"))]
    unsafe impl HttpModule for PanicDefaultModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    #[cfg(all(feature = "std", feature = "test-link"))]
    unsafe impl HttpModuleMainConf for PanicDefaultModule {
        type MainConf = PanicDefaultConf;
    }

    #[cfg(all(feature = "std", feature = "test-link"))]
    #[test]
    fn default_panic_does_not_publish_or_leave_a_cleanup_entry() {
        let pool = TestPool::new();
        let mut configuration = pool.configuration();
        let cleanup = unsafe { (*pool.raw).cleanup };

        assert!(unsafe { PanicDefaultModule::create_main_conf(&raw mut configuration) }.is_null());
        assert_eq!(unsafe { (*pool.raw).cleanup }, cleanup);
    }

    #[cfg(feature = "std")]
    struct PanicInitConf;

    #[cfg(feature = "std")]
    impl InitMainConf for PanicInitConf {
        fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
            panic!("init panic")
        }
    }

    #[cfg(feature = "std")]
    struct PanicInitModule;

    #[cfg(feature = "std")]
    unsafe impl HttpModule for PanicInitModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    #[cfg(feature = "std")]
    unsafe impl HttpModuleMainConf for PanicInitModule {
        type MainConf = PanicInitConf;
    }

    #[cfg(feature = "std")]
    #[test]
    fn init_panic_returns_nginx_configuration_error() {
        let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
        let mut configuration = PanicInitConf;

        assert_eq!(
            unsafe {
                PanicInitModule::init_main_conf(&raw mut parser, (&raw mut configuration).cast())
            },
            NGX_CONF_ERROR
        );
    }

    #[cfg(feature = "std")]
    struct PanicMergeConf;

    #[cfg(feature = "std")]
    impl Merge for PanicMergeConf {
        fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
            panic!("merge panic")
        }
    }

    #[cfg(feature = "std")]
    struct PanicMergeModule;

    #[cfg(feature = "std")]
    unsafe impl HttpModule for PanicMergeModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    #[cfg(feature = "std")]
    unsafe impl HttpModuleServerConf for PanicMergeModule {
        type ServerConf = PanicMergeConf;
    }

    #[cfg(feature = "std")]
    unsafe impl HttpModuleLocationConf for PanicMergeModule {
        type LocationConf = PanicMergeConf;
    }

    #[cfg(feature = "std")]
    #[test]
    fn server_and_location_merge_panics_return_nginx_configuration_error() {
        let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
        let mut server_parent = PanicMergeConf;
        let mut server_child = PanicMergeConf;
        assert_eq!(
            unsafe {
                PanicMergeModule::merge_srv_conf(
                    &raw mut parser,
                    (&raw mut server_parent).cast(),
                    (&raw mut server_child).cast(),
                )
            },
            NGX_CONF_ERROR
        );

        let mut location_parent = PanicMergeConf;
        let mut location_child = PanicMergeConf;
        assert_eq!(
            unsafe {
                PanicMergeModule::merge_loc_conf(
                    &raw mut parser,
                    (&raw mut location_parent).cast(),
                    (&raw mut location_child).cast(),
                )
            },
            NGX_CONF_ERROR
        );
    }
}
