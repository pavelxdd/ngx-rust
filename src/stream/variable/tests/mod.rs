#[cfg(feature = "test-link")]
use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "test-link")]
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "test-link")]
use std::sync::MutexGuard;

#[cfg(feature = "test-link")]
use super::StreamVariablePoolBytes;
use super::{
    StreamPrefixVariableHandler, StreamVariableFlags, StreamVariableHandler, StreamVariableOutput,
    StreamVariableOutputError, add_prefix_variable, add_variable, raw_get_handler,
    raw_prefix_get_handler,
};
use crate::core::{NgxStr, Status};
use crate::ffi::{NGX_ERROR, NGX_STREAM_OK, ngx_int_t, ngx_stream_session_t, ngx_variable_value_t};
#[cfg(feature = "test-link")]
use crate::ffi::{
    NGX_OK, NGX_STREAM_MODULE, NGX_STREAM_VAR_INDEXED, ngx_array_t, ngx_conf_t, ngx_connection_t,
    ngx_create_pool, ngx_destroy_pool, ngx_hash_key_lc, ngx_hash_key_t, ngx_log_t, ngx_pool_t,
    ngx_stream_conf_ctx_t, ngx_stream_core_main_conf_t, ngx_stream_get_indexed_variable,
    ngx_stream_get_variable, ngx_stream_get_variable_index, ngx_stream_get_variable_pt,
    ngx_stream_variable_t, ngx_stream_variables_add_core_vars, ngx_stream_variables_init_vars,
    ngx_uint_t,
};
use crate::stream::{Session, StreamConfigurationParser};

#[cfg(feature = "test-link")]
unsafe extern "C" {
    fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
    fn ngx_rs_test_reset_allocation_failures();
}

struct TestVariable;

static TEST_VARIABLE_VALUE: &[u8] = b"detected";
static PREFIX_VARIABLE_VALUE: &[u8] = b"prefix";
static RAW_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
static RAW_VARIABLE_DATA: AtomicUsize = AtomicUsize::new(0);

struct CountingVariable;

impl StreamVariableHandler for CountingVariable {
    type Output = Status;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        RAW_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
        value.set_empty();
        Status::NGX_OK
    }
}

struct DataVariable;

impl StreamVariableHandler for DataVariable {
    type Output = Status;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        data: usize,
    ) -> Self::Output {
        RAW_VARIABLE_DATA.store(data, Ordering::Relaxed);
        value.set_empty();
        Status::NGX_DECLINED
    }
}

#[cfg(feature = "test-link")]
static PREFIX_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
struct PrefixVariable;

#[cfg(feature = "test-link")]
impl StreamPrefixVariableHandler for PrefixVariable {
    type Output = Status;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        name: &NgxStr,
    ) -> Self::Output {
        assert_eq!(name.as_bytes(), b"ngx_rs_native_prefix_suffix");
        PREFIX_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
        value.set_static(PREFIX_VARIABLE_VALUE).unwrap();
        Status::NGX_OK
    }
}

#[cfg(feature = "test-link")]
struct CountingPrefixVariable;

#[cfg(feature = "test-link")]
impl StreamPrefixVariableHandler for CountingPrefixVariable {
    type Output = Status;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        _name: &NgxStr,
    ) -> Self::Output {
        value.set_empty();
        Status::NGX_OK
    }
}

#[cfg(feature = "test-link")]
struct DataPrefixVariable;

#[cfg(feature = "test-link")]
impl StreamPrefixVariableHandler for DataPrefixVariable {
    type Output = Status;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        _name: &NgxStr,
    ) -> Self::Output {
        value.set_empty();
        Status::NGX_OK
    }
}

struct RawStatusVariable;

impl StreamVariableHandler for RawStatusVariable {
    type Output = ngx_int_t;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        value.set_empty();
        NGX_STREAM_OK as _
    }
}

struct OptionalStatusVariable;

impl StreamVariableHandler for OptionalStatusVariable {
    type Output = Option<Status>;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        value.set_empty();
        Some(Status::NGX_AGAIN)
    }
}

struct SuccessfulMissingVariable;

impl StreamVariableHandler for SuccessfulMissingVariable {
    type Output = Status;

    fn get(
        _session: &mut Session<'_>,
        _value: &mut StreamVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        Status::NGX_OK
    }
}

struct MissingStatusVariable;

impl StreamVariableHandler for MissingStatusVariable {
    type Output = Option<Status>;

    fn get(
        _session: &mut Session<'_>,
        _value: &mut StreamVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        None
    }
}

struct ResultStatusVariable;

impl StreamVariableHandler for ResultStatusVariable {
    type Output = Result<Status, Status>;

    fn get(
        _session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        value.set_empty();
        Ok(Status::NGX_DECLINED)
    }
}

struct ErrorStatusVariable;

impl StreamVariableHandler for ErrorStatusVariable {
    type Output = Result<Status, Status>;

    fn get(
        _session: &mut Session<'_>,
        _value: &mut StreamVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        Err(Status::NGX_AGAIN)
    }
}

fn poisoned_value() -> ngx_variable_value_t {
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };
    value.set_len(17);
    value.set_valid(0);
    value.set_no_cacheable(0);
    value.set_not_found(1);
    value.set_escape(1);
    value.data = NonNull::<u8>::dangling().as_ptr();
    value
}

fn misaligned_ptr<T>(storage: &mut [u8]) -> *mut T {
    let alignment = core::mem::align_of::<T>();
    assert!(alignment > 1);
    let offset = storage.as_mut_ptr().align_offset(alignment);
    assert!(offset + 1 < storage.len());
    unsafe { storage.as_mut_ptr().add(offset + 1).cast() }
}

fn raw_handler_status<H>() -> ngx_int_t
where
    H: StreamVariableHandler,
{
    let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    unsafe { raw_get_handler::<H>(&raw mut session, &raw mut value, 0) }
}

fn assert_found(raw: &ngx_variable_value_t, bytes: &[u8], cacheable: bool, data: *mut u8) {
    assert_eq!(raw.len() as usize, bytes.len());
    assert_eq!(raw.valid(), 1);
    assert_eq!(raw.no_cacheable(), (!cacheable).into());
    assert_eq!(raw.not_found(), 0);
    assert_eq!(raw.escape(), 0);
    assert_eq!(raw.data, data);
    if !bytes.is_empty() {
        assert_eq!(unsafe { core::slice::from_raw_parts(raw.data, raw.len() as usize) }, bytes);
    }
}

fn assert_not_found(raw: &ngx_variable_value_t) {
    assert_eq!(raw.len(), 0);
    assert_eq!(raw.valid(), 0);
    assert_eq!(raw.no_cacheable(), 1);
    assert_eq!(raw.not_found(), 1);
    assert_eq!(raw.escape(), 0);
    assert!(raw.data.is_null());
}

#[cfg(feature = "test-link")]
struct TestPool {
    raw: *mut ngx_pool_t,
    _log: Box<ngx_log_t>,
}

#[cfg(feature = "test-link")]
impl TestPool {
    fn new() -> Self {
        let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
        let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!raw.is_null());
        Self { raw, _log: log }
    }
}

#[cfg(feature = "test-link")]
impl Drop for TestPool {
    fn drop(&mut self) {
        unsafe { ngx_destroy_pool(self.raw) };
    }
}

#[cfg(feature = "test-link")]
struct VariableGlobalState {
    max_module: ngx_uint_t,
    stream_max_module: ngx_uint_t,
    cacheline_size: ngx_uint_t,
    stream_module_index: ngx_uint_t,
    stream_core_module_type: ngx_uint_t,
    stream_core_module_index: ngx_uint_t,
    stream_core_module_context_index: ngx_uint_t,
}

#[cfg(feature = "test-link")]
struct VariableGlobals {
    _guard: MutexGuard<'static, ()>,
    previous: VariableGlobalState,
}

#[cfg(feature = "test-link")]
impl VariableGlobals {
    fn new() -> Self {
        let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe {
            VariableGlobalState {
                max_module: nginx_sys::ngx_max_module,
                stream_max_module: nginx_sys::ngx_stream_max_module,
                cacheline_size: nginx_sys::ngx_cacheline_size,
                stream_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_stream_module)).index,
                stream_core_module_type: (*core::ptr::addr_of!(nginx_sys::ngx_stream_core_module))
                    .type_,
                stream_core_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_stream_core_module))
                    .index,
                stream_core_module_context_index: (*core::ptr::addr_of!(
                    nginx_sys::ngx_stream_core_module
                ))
                .ctx_index,
            }
        };

        unsafe {
            nginx_sys::ngx_max_module = 1;
            nginx_sys::ngx_stream_max_module = 1;
            nginx_sys::ngx_cacheline_size = 64;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_module)).index = 0;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).type_ =
                NGX_STREAM_MODULE as _;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).index = 0;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).ctx_index = 0;
        }

        Self { _guard: guard, previous }
    }
}

#[cfg(feature = "test-link")]
impl Drop for VariableGlobals {
    fn drop(&mut self) {
        unsafe {
            nginx_sys::ngx_max_module = self.previous.max_module;
            nginx_sys::ngx_stream_max_module = self.previous.stream_max_module;
            nginx_sys::ngx_cacheline_size = self.previous.cacheline_size;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_module)).index =
                self.previous.stream_module_index;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).type_ =
                self.previous.stream_core_module_type;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).index =
                self.previous.stream_core_module_index;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).ctx_index =
                self.previous.stream_core_module_context_index;
        }
    }
}

#[cfg(feature = "test-link")]
struct VariableFixture {
    _globals: VariableGlobals,
    main: Box<ngx_stream_core_main_conf_t>,
    _main_conf: Box<[*mut c_void; 1]>,
    _context: Box<ngx_stream_conf_ctx_t>,
    cf: Box<ngx_conf_t>,
    _pool: TestPool,
}

#[cfg(feature = "test-link")]
impl VariableFixture {
    fn new() -> Self {
        let globals = VariableGlobals::new();
        let mut pool = TestPool::new();
        let mut main =
            Box::new(unsafe { MaybeUninit::<ngx_stream_core_main_conf_t>::zeroed().assume_init() });
        main.variables_hash_max_size = 1024;
        main.variables_hash_bucket_size = 64;
        let mut main_conf: Box<[*mut c_void; 1]> = Box::new([(&raw mut *main).cast()]);
        let mut context = Box::new(ngx_stream_conf_ctx_t {
            main_conf: main_conf.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
        });
        let mut cf = Box::new(unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() });
        cf.pool = pool.raw;
        cf.temp_pool = pool.raw;
        cf.log = &raw mut *pool._log;
        cf.ctx = (&raw mut *context).cast();
        assert_eq!(unsafe { ngx_stream_variables_add_core_vars(&raw mut *cf) }, NGX_OK as _);

        Self { _globals: globals, main, _main_conf: main_conf, _context: context, cf, _pool: pool }
    }

    fn configuration(&mut self) -> StreamConfigurationParser<'_> {
        StreamConfigurationParser::from_test_callback(&mut self.cf)
    }

    fn finalize_variables(&mut self) {
        assert_eq!(unsafe { ngx_stream_variables_init_vars(&raw mut *self.cf) }, NGX_OK as _);
    }

    fn with_session<R>(&mut self, f: impl for<'scope> FnOnce(&mut Session<'scope>) -> R) -> R {
        let mut values = Vec::with_capacity(self.main.variables.nelts);
        for _ in 0..self.main.variables.nelts {
            values.push(unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() });
        }
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = self._pool.raw;
        connection.log = self.cf.log;
        let mut raw = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        raw.connection = &raw mut *connection;
        raw.main_conf = self._main_conf.as_mut_ptr();
        raw.variables = values.as_mut_ptr();

        unsafe { Session::with_raw(&raw mut raw, |mut session| f(&mut session)) }.unwrap()
    }

    fn exact_variables(&self) -> &[ngx_hash_key_t] {
        let variables_keys = self.main.variables_keys;
        assert!(!variables_keys.is_null());
        array_values(unsafe { &(*variables_keys).keys })
    }

    fn prefix_variables(&self) -> &[ngx_stream_variable_t] {
        array_values(&self.main.prefix_variables)
    }

    fn exact_variable(&self, name: &[u8]) -> &ngx_stream_variable_t {
        let key = self.exact_variables().iter().find(|key| key.key.as_bytes() == name).unwrap();
        assert!(!key.value.is_null());
        unsafe { &*key.value.cast() }
    }

    fn prefix_variable(&self, name: &[u8]) -> &ngx_stream_variable_t {
        self.prefix_variables().iter().find(|variable| variable.name.as_bytes() == name).unwrap()
    }
}

#[cfg(feature = "test-link")]
fn array_values<T>(array: &ngx_array_t) -> &[T] {
    if array.nelts == 0 {
        return &[];
    }

    assert!(!array.elts.is_null());
    unsafe { core::slice::from_raw_parts(array.elts.cast(), array.nelts) }
}

#[cfg(feature = "test-link")]
fn same_handler(left: ngx_stream_get_variable_pt, right: ngx_stream_get_variable_pt) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => core::ptr::fn_addr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(feature = "test-link")]
fn assert_handler<H>(variable: &ngx_stream_variable_t, data: usize)
where
    H: StreamVariableHandler,
{
    assert!(same_handler(variable.get_handler, Some(raw_get_handler::<H>)));
    assert_eq!(variable.data, data);
}

#[cfg(feature = "test-link")]
fn assert_prefix_handler<H>(variable: &ngx_stream_variable_t)
where
    H: StreamPrefixVariableHandler,
{
    assert!(same_handler(variable.get_handler, Some(raw_prefix_get_handler::<H>)));
}

#[cfg(feature = "test-link")]
fn with_session<R>(owner: &TestPool, f: impl for<'scope> FnOnce(&mut Session<'scope>) -> R) -> R {
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut raw = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    raw.connection = &raw mut *connection;

    unsafe { Session::with_raw(&raw mut raw, |mut session| f(&mut session)) }.unwrap()
}

impl StreamVariableHandler for TestVariable {
    type Output = Status;

    fn get(
        session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        data: usize,
    ) -> Self::Output {
        unsafe { (*session.as_ptr()).status = data as _ };
        value.set_static(TEST_VARIABLE_VALUE).unwrap();
        Status::NGX_OK
    }
}

mod dispatch;
mod registration;
mod value;
