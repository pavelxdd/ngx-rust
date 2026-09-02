use core::error;
use core::ffi::{CStr, c_char, c_void};
use core::fmt;
use core::marker::PhantomData;
use core::pin::Pin;
use core::ptr::{self, NonNull};

use crate::core::{ModuleDescriptor, NGX_CONF_ERROR, Pool, Status};
use crate::ffi::{NGX_LOG_EMERG, ngx_conf_t, ngx_cycle_t, ngx_int_t};
use crate::http::{
    HttpConfigError, HttpConfigurationParser, HttpModuleLocationConf, HttpModuleMainConf,
    HttpModuleServerConf,
};

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
///
/// A merge callback must not panic; panics terminate the worker process.
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
///
/// An initialization callback must not panic; panics terminate the worker process.
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

/// Failure returned while creating a process-callback cycle view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCycleError {
    /// The process callback did not receive a cycle.
    NullCycle,
    /// The process callback cycle does not satisfy nginx alignment.
    MisalignedCycle,
}

/// Checked callback-scoped access to an nginx process cycle.
///
/// ```compile_fail
/// use ngx::ffi::ngx_cycle_t;
/// use ngx::http::ProcessCycle;
///
/// unsafe fn escape(raw: *mut ngx_cycle_t) -> ProcessCycle<'static> {
///     unsafe { ProcessCycle::with_raw(raw, |cycle| cycle) }.unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_cycle_t;
/// use ngx::http::ProcessCycle;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *mut ngx_cycle_t) {
///     let _ = unsafe { ProcessCycle::with_raw(raw, |cycle| require_send(cycle)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_cycle_t;
/// use ngx::http::ProcessCycle;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// unsafe fn reject(raw: *mut ngx_cycle_t) {
///     let _ = unsafe { ProcessCycle::with_raw(raw, |cycle| require_sync(&cycle)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_cycle_t;
/// use ngx::http::{HttpModuleMainConf, ProcessCycle};
///
/// unsafe fn escape<M: HttpModuleMainConf>(raw: *mut ngx_cycle_t) -> &'static M::MainConf {
///     unsafe { ProcessCycle::with_raw(raw, |cycle| cycle.main_conf::<M>().unwrap().unwrap()) }
///         .unwrap()
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct ProcessCycle<'callback> {
    raw: NonNull<ngx_cycle_t>,
    _callback: PhantomData<&'callback ngx_cycle_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl ProcessCycle<'_> {
    /// Creates a checked process-cycle view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `cycle` must point to a live initialized nginx process cycle for `'callback`. The view must
    /// remain on its owning worker thread and not outlive the callback that supplied it.
    pub unsafe fn from_raw(cycle: *mut ngx_cycle_t) -> Result<Self, ProcessCycleError> {
        let raw = NonNull::new(cycle).ok_or(ProcessCycleError::NullCycle)?;
        if !raw.as_ptr().is_aligned() {
            return Err(ProcessCycleError::MisalignedCycle);
        }

        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with a process-cycle view that cannot escape the nginx callback through a
    /// safe value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    pub unsafe fn with_raw<R>(
        cycle: *mut ngx_cycle_t,
        f: impl for<'scope> FnOnce(ProcessCycle<'scope>) -> R,
    ) -> Result<R, ProcessCycleError> {
        let cycle = unsafe { Self::from_raw(cycle) }?;
        Ok(f(cycle))
    }

    /// Returns the native cycle pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the target nginx API's aliasing and callback-lifetime requirements.
    pub unsafe fn as_ptr(&self) -> *mut ngx_cycle_t {
        self.raw.as_ptr()
    }

    pub(crate) fn raw(&self) -> &ngx_cycle_t {
        unsafe { self.raw.as_ref() }
    }

    /// Shared main configuration for module `M` from this process callback's cycle.
    pub fn main_conf<M>(&self) -> Result<Option<&M::MainConf>, HttpConfigError>
    where
        M: HttpModuleMainConf,
    {
        unsafe { M::main_conf_from_cycle(self.raw(), nginx_sys::ngx_http_max_module) }
    }
}

fn process_callback_status(
    cycle: *mut ngx_cycle_t,
    callback: impl for<'scope> FnOnce(ProcessCycle<'scope>) -> ngx_int_t,
) -> ngx_int_t {
    unsafe { ProcessCycle::with_raw(cycle, callback) }.unwrap_or(Status::NGX_ERROR.0)
}

fn process_exit_callback(
    cycle: *mut ngx_cycle_t,
    callback: impl for<'scope> FnOnce(ProcessCycle<'scope>),
) {
    let _ = unsafe { ProcessCycle::with_raw(cycle, callback) };
}

pub(crate) fn configuration_callback_status(
    configuration: *mut ngx_conf_t,
    callback: impl for<'scope> FnOnce(&mut HttpConfigurationParser<'scope>) -> ngx_int_t,
) -> ngx_int_t {
    unsafe { HttpConfigurationParser::with_raw(configuration, callback) }
        .unwrap_or(Status::NGX_ERROR.0)
}

/// C-compatible adapter for an HTTP module preconfiguration callback.
///
/// Raw parser pointers cannot invoke module hooks through safe Rust:
///
/// ```compile_fail
/// use ngx::ffi::ngx_conf_t;
/// use ngx::http::{HttpModule, preconfiguration};
///
/// fn invoke<M: HttpModule>(parser: *mut ngx_conf_t) {
///     preconfiguration::<M>(parser);
/// }
/// ```
///
/// # Safety
///
/// `cf` must point to a live nginx configuration parser state for this callback invocation.
/// Null and misaligned pointers return `NGX_ERROR`. A module callback must not panic; panics
/// terminate the worker process.
pub unsafe extern "C" fn preconfiguration<M>(cf: *mut ngx_conf_t) -> ngx_int_t
where
    M: HttpModule,
{
    configuration_callback_status(cf, M::preconfigure)
}

/// C-compatible adapter for an HTTP module postconfiguration callback.
///
/// # Safety
///
/// `cf` must point to a live nginx configuration parser state for this callback invocation.
/// Null and misaligned pointers return `NGX_ERROR`. A module callback must not panic; panics
/// terminate the worker process.
pub unsafe extern "C" fn postconfiguration<M>(cf: *mut ngx_conf_t) -> ngx_int_t
where
    M: HttpModule,
{
    configuration_callback_status(cf, M::postconfigure)
}

/// C-compatible adapter for an HTTP module worker-start callback.
///
/// # Safety
///
/// `cycle` must point to the live nginx cycle supplied for this process callback. Null and
/// misaligned pointers return `NGX_ERROR`. A module callback must not panic; panics terminate the
/// worker process.
pub unsafe extern "C" fn init_process<M>(cycle: *mut ngx_cycle_t) -> ngx_int_t
where
    M: HttpModule,
{
    process_callback_status(cycle, M::init_process)
}

/// C-compatible adapter for an HTTP module worker-stop callback.
///
/// # Safety
///
/// `cycle` must point to the live nginx cycle supplied for this process callback. Null and
/// misaligned pointers are ignored. A module callback must not panic; panics terminate the worker
/// process.
pub unsafe extern "C" fn exit_process<M>(cycle: *mut ngx_cycle_t)
where
    M: HttpModule,
{
    process_exit_callback(cycle, M::exit_process)
}

/// C-compatible postconfiguration callback that registers one typed HTTP phase handler.
///
/// # Safety
///
/// `cf` must point to a live nginx configuration parser state for this callback invocation.
pub unsafe extern "C" fn phase_handler_postconfiguration<H>(cf: *mut ngx_conf_t) -> ngx_int_t
where
    H: crate::http::HttpRequestHandler,
{
    configuration_callback_status(cf, |parser| {
        crate::http::add_phase_handler::<H>(parser)
            .map_or(Status::NGX_ERROR.0, |_| Status::NGX_OK.0)
    })
}

/// # Safety
///
/// `cf.pool` must not be reset before the pool is destroyed.
unsafe fn configuration_pool(cf: &ngx_conf_t) -> Option<Pool<'_>> {
    unsafe { Pool::from_raw(cf.pool) }
}

/// # Safety
///
/// `cf` must point to a live nginx parser state whose pool is not reset before destruction.
unsafe fn allocate_configuration<T>(cf: *mut ngx_conf_t) -> *mut c_void
where
    T: Default + 'static,
{
    let Some(cf) = (unsafe { checked_ref(cf) }) else {
        return ptr::null_mut();
    };
    let Some(pool) = (unsafe { configuration_pool(cf) }) else {
        return ptr::null_mut();
    };

    pool.allocate_with_cleanup(T::default)
        .map(|value| value.into_non_null().as_ptr().cast())
        .unwrap_or(ptr::null_mut())
}

fn log_configuration_error(cf: *mut ngx_conf_t, action: &str, error: &dyn fmt::Display) {
    let Some(configuration) = (unsafe { checked_ref(cf) }) else {
        return;
    };
    if configuration.log.is_null() {
        return;
    }

    crate::ngx_conf_log_error!(NGX_LOG_EMERG, cf, "failed to {action}: {error}");
}

fn log_merge_error(cf: *mut ngx_conf_t, level: &str, error: &dyn fmt::Display) {
    let Some(configuration) = (unsafe { checked_ref(cf) }) else {
        return;
    };
    if configuration.log.is_null() {
        return;
    }

    crate::ngx_conf_log_error!(NGX_LOG_EMERG, cf, "failed to merge {level} configuration: {error}");
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

    match conf.init_main_conf() {
        Ok(()) => ptr::null_mut(),
        Err(error) => {
            log_configuration_error(cf, "initialize main configuration", &error);
            NGX_CONF_ERROR
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

    match child.merge(parent) {
        Ok(()) => ptr::null_mut(),
        Err(error) => {
            log_merge_error(cf, level, &error);
            NGX_CONF_ERROR
        }
    }
}

/// Defines a concrete nginx HTTP module and its configuration lifecycle.
///
/// # Safety
/// `module()` must return this type's real live global module descriptor. Nginx must have
/// initialized its module and context indexes before any typed configuration access. No callback
/// may panic; a panic terminates the worker process. Callback
/// implementations must not unwind across nginx's C ABI.
pub unsafe trait HttpModule {
    /// Returns the opaque identity of the global module descriptor.
    fn module() -> ModuleDescriptor;

    /// Runs before nginx parses the HTTP configuration block.
    ///
    /// The module descriptor must use [`preconfiguration`] as its FFI callback.
    fn preconfigure(_parser: &mut HttpConfigurationParser<'_>) -> ngx_int_t {
        Status::NGX_OK.0
    }

    /// Runs after nginx parses the HTTP configuration block.
    ///
    /// The module descriptor must use [`postconfiguration`] as its FFI callback.
    fn postconfigure(_parser: &mut HttpConfigurationParser<'_>) -> ngx_int_t {
        Status::NGX_OK.0
    }

    /// Runs after nginx starts this worker process.
    ///
    /// The module descriptor must use [`init_process`] as its FFI callback. Return `NGX_ERROR` to
    /// reject worker startup.
    fn init_process(_cycle: ProcessCycle<'_>) -> ngx_int_t {
        Status::NGX_OK.0
    }

    /// Runs before nginx stops this worker process.
    ///
    /// The module descriptor must use [`exit_process`] as its FFI callback. Implementations must
    /// tolerate repeated calls because nginx can stop an already-drained worker during reload.
    fn exit_process(_cycle: ProcessCycle<'_>) {}

    /// Allocates the module's main configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime and is not reset before it is destroyed.
    unsafe extern "C" fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: HttpModuleMainConf,
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
        Self: HttpModuleMainConf,
        Self::MainConf: InitMainConf,
    {
        init_configuration::<Self::MainConf>(cf, conf)
    }

    /// Allocates the module's server configuration in nginx's configuration pool.
    ///
    /// # Safety
    /// `cf` must point to a valid nginx configuration parser state whose pool remains alive for
    /// the configuration lifetime and is not reset before it is destroyed.
    unsafe extern "C" fn create_srv_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: HttpModuleServerConf,
        Self::ServerConf: Default,
    {
        unsafe { allocate_configuration::<Self::ServerConf>(cf) }
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
    /// the configuration lifetime and is not reset before it is destroyed.
    unsafe extern "C" fn create_loc_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: HttpModuleLocationConf,
        Self::LocationConf: Default,
    {
        unsafe { allocate_configuration::<Self::LocationConf>(cf) }
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

    /// Cancels context-owned work before the request pool drops the context.
    ///
    /// The request context slot is already empty when this hook runs, so it cannot obtain a new
    /// request borrow. The default is sufficient when the context's owned values clean themselves
    /// up in [`Drop`].
    fn cleanup(_context: Pin<&mut Self::RequestContext>) {}
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{boxed::Box, vec::Vec};
    use core::ffi::c_void;
    use core::mem;
    use core::ptr;
    use core::slice;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        HttpModule, InitMainConf, Merge, MergeConfigError, ProcessCycle, exit_process,
        init_process, postconfiguration, preconfiguration,
    };
    use crate::core::{ModuleDescriptor, NGX_CONF_ERROR, Status};
    #[cfg(feature = "test-link")]
    use crate::ffi::{
        NGX_LOG_EMERG, ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_pool_t, ngx_uint_t,
    };
    use crate::ffi::{ngx_conf_t, ngx_cycle_t, ngx_int_t, ngx_module_t};
    use crate::http::{HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf};

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    #[cfg(feature = "test-link")]
    #[derive(Default)]
    struct ConfigLogCapture {
        records: Vec<(ngx_uint_t, Vec<u8>)>,
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
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    static PROCESS_STARTS: AtomicUsize = AtomicUsize::new(0);
    static PROCESS_STOPS: AtomicUsize = AtomicUsize::new(0);

    struct ProcessModule;

    unsafe impl HttpModule for ProcessModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }

        fn init_process(_cycle: ProcessCycle<'_>) -> ngx_int_t {
            PROCESS_STARTS.fetch_add(1, Ordering::Relaxed);
            Status::NGX_OK.0
        }

        fn exit_process(_cycle: ProcessCycle<'_>) {
            PROCESS_STOPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct FailingProcessModule;

    unsafe impl HttpModule for FailingProcessModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }

        fn init_process(_cycle: ProcessCycle<'_>) -> ngx_int_t {
            Status::NGX_ERROR.0
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
    fn process_callbacks_reject_invalid_cycles_and_preserve_ffi_statuses() {
        PROCESS_STARTS.store(0, Ordering::Relaxed);
        PROCESS_STOPS.store(0, Ordering::Relaxed);

        assert_eq!(unsafe { init_process::<ProcessModule>(ptr::null_mut()) }, Status::NGX_ERROR.0);
        unsafe { exit_process::<ProcessModule>(ptr::null_mut()) };
        assert_eq!(PROCESS_STARTS.load(Ordering::Relaxed), 0);
        assert_eq!(PROCESS_STOPS.load(Ordering::Relaxed), 0);

        let misaligned = ptr::without_provenance_mut::<ngx_cycle_t>(1);
        assert_eq!(unsafe { init_process::<ProcessModule>(misaligned) }, Status::NGX_ERROR.0);
        unsafe { exit_process::<ProcessModule>(misaligned) };
        assert_eq!(PROCESS_STARTS.load(Ordering::Relaxed), 0);
        assert_eq!(PROCESS_STOPS.load(Ordering::Relaxed), 0);

        let mut cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
        assert_eq!(unsafe { init_process::<ProcessModule>(&raw mut cycle) }, Status::NGX_OK.0);
        assert_eq!(
            unsafe { init_process::<FailingProcessModule>(&raw mut cycle) },
            Status::NGX_ERROR.0
        );
        unsafe { exit_process::<ProcessModule>(&raw mut cycle) };
        unsafe { exit_process::<ProcessModule>(&raw mut cycle) };
        assert_eq!(PROCESS_STARTS.load(Ordering::Relaxed), 1);
        assert_eq!(PROCESS_STOPS.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn default_configuration_hooks_reject_null_and_misaligned_parser_contexts() {
        assert_eq!(
            unsafe { preconfiguration::<TestHttpModule>(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );
        assert_eq!(
            unsafe { postconfiguration::<TestHttpModule>(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );

        let misaligned = ptr::without_provenance_mut::<ngx_conf_t>(1);
        assert_eq!(unsafe { preconfiguration::<TestHttpModule>(misaligned) }, Status::NGX_ERROR.0);
        assert_eq!(unsafe { postconfiguration::<TestHttpModule>(misaligned) }, Status::NGX_ERROR.0);

        let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
        assert_eq!(
            unsafe { preconfiguration::<TestHttpModule>(&raw mut configuration) },
            Status::NGX_OK.0
        );
        assert_eq!(
            unsafe { postconfiguration::<TestHttpModule>(&raw mut configuration) },
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
            Err(MergeConfigError::NoValue)
        }
    }

    struct RejectMainModule;

    unsafe impl HttpModule for RejectMainModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl HttpModuleMainConf for RejectMainModule {
        type MainConf = RejectMainConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn main_initialization_logs_no_value_once_and_returns_the_silent_sentinel() {
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
        assert_eq!(capture.records.len(), 1);
        assert_eq!(capture.records[0].0, NGX_LOG_EMERG as _);
        assert!(
            capture.records[0]
                .1
                .windows(b"failed to initialize main configuration: no value".len())
                .any(|message| message == b"failed to initialize main configuration: no value")
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
        fn module() -> ModuleDescriptor {
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
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl HttpModuleLocationConf for RejectLocationModule {
        type LocationConf = RejectLocationConf;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn server_and_location_merges_log_messages_once_and_return_the_silent_sentinel() {
        let mut pool = TestPool::new();
        let mut capture = ConfigLogCapture::default();
        pool._log.log_level = NGX_LOG_EMERG as _;
        pool._log.writer = Some(capture_config_log);
        pool._log.wdata = (&raw mut capture).cast();
        let mut parser = pool.configuration();
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
            NGX_CONF_ERROR
        );
        assert_eq!(capture.records.len(), 1);
        assert_eq!(capture.records[0].0, NGX_LOG_EMERG as _);
        assert!(
            capture.records[0]
                .1
                .windows(b"failed to merge server configuration: server rejected".len())
                .any(|message| message == b"failed to merge server configuration: server rejected")
        );

        capture.records.clear();
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
            NGX_CONF_ERROR
        );
        assert_eq!(capture.records.len(), 1);
        assert_eq!(capture.records[0].0, NGX_LOG_EMERG as _);
        assert!(
            capture.records[0]
                .1
                .windows(b"failed to merge location configuration: location rejected".len())
                .any(|message| message
                    == b"failed to merge location configuration: location rejected")
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
        fn module() -> ModuleDescriptor {
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
        fn module() -> ModuleDescriptor {
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
}
