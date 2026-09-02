#[cfg(feature = "test-link")]
use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "test-link")]
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "test-link")]
use std::sync::MutexGuard;

use super::{
    HttpPrefixVariableHandler, HttpVariableCacheInvalidation, HttpVariableFlags,
    HttpVariableHandler, HttpVariableIndex, HttpVariableIndexError, HttpVariableLookupError,
    HttpVariableOutput, HttpVariableOutputError, HttpVariablePoolBytes, HttpVariableRequest,
    HttpVariableSetter, HttpVariableValueRef, add_prefix_variable, add_variable,
    add_variable_with_setter, get_variable_index, raw_get_handler, raw_prefix_get_handler,
    raw_set_handler,
};
use crate::core::{NgxStr, Status};
use crate::ffi::{
    NGX_ERROR, NGX_HTTP_MODULE, ngx_conf_t, ngx_http_core_main_conf_t, ngx_http_request_t,
    ngx_int_t, ngx_variable_value_t,
};
use crate::http::{HttpConfigurationParser, RequestRef, RequestRefMut};

#[cfg(feature = "test-link")]
use crate::ffi::{
    NGX_CORE_MODULE, NGX_HTTP_VAR_INDEXED, NGX_OK, ngx_array_t, ngx_connection_t, ngx_create_pool,
    ngx_destroy_pool, ngx_hash_key_lc, ngx_hash_key_t, ngx_http_conf_ctx_t, ngx_http_get_variable,
    ngx_http_get_variable_pt, ngx_http_variable_t, ngx_http_variables_add_core_vars,
    ngx_http_variables_init_vars, ngx_log_t, ngx_pool_t, ngx_uint_t,
};

#[cfg(feature = "test-link")]
unsafe extern "C" {
    fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
    fn ngx_rs_test_reset_allocation_failures();
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

fn assert_found(raw: &ngx_variable_value_t, bytes: &[u8], cacheable: bool, data: *mut u8) {
    assert_eq!(raw.len() as usize, bytes.len());
    assert_eq!(raw.valid(), 1);
    assert_eq!(raw.no_cacheable(), (!cacheable).into());
    assert_eq!(raw.not_found(), 0);
    assert_eq!(raw.escape(), 0);
    assert_eq!(raw.data, data);

    let value = unsafe { HttpVariableValueRef::from_raw(raw) }.unwrap();
    assert_eq!(value.bytes(), Some(bytes));
    assert!(value.is_valid());
    assert_eq!(value.is_cacheable(), cacheable);
    assert!(!value.is_not_found());
    assert!(!value.is_escaped());
}

fn assert_not_found(raw: &ngx_variable_value_t) {
    assert_eq!(raw.len(), 0);
    assert_eq!(raw.valid(), 0);
    assert_eq!(raw.no_cacheable(), 1);
    assert_eq!(raw.not_found(), 1);
    assert_eq!(raw.escape(), 0);
    assert!(raw.data.is_null());

    let value = unsafe { HttpVariableValueRef::from_raw(raw) }.unwrap();
    assert_eq!(value.bytes(), None);
    assert!(!value.is_valid());
    assert!(!value.is_cacheable());
    assert!(value.is_not_found());
    assert!(!value.is_escaped());
}

struct CountingVariable;

static RAW_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
static RAW_VARIABLE_DATA: AtomicUsize = AtomicUsize::new(0);

impl HttpVariableHandler for CountingVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        RAW_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
        value.set_empty();
        Status::NGX_OK
    }
}

struct SuccessfulMissingVariable;

impl HttpVariableHandler for SuccessfulMissingVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        _value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        Status::NGX_OK
    }
}

struct DataVariable;

impl HttpVariableHandler for DataVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
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
impl HttpPrefixVariableHandler for PrefixVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
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
impl HttpPrefixVariableHandler for CountingPrefixVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        _name: &NgxStr,
    ) -> Self::Output {
        value.set_empty();
        Status::NGX_OK
    }
}

#[cfg(feature = "test-link")]
struct DataPrefixVariable;

#[cfg(feature = "test-link")]
impl HttpPrefixVariableHandler for DataPrefixVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        _name: &NgxStr,
    ) -> Self::Output {
        value.set_empty();
        Status::NGX_OK
    }
}

static RAW_SET_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
static RAW_SET_VARIABLE_DATA: AtomicUsize = AtomicUsize::new(0);

struct SetVariable;

impl HttpVariableSetter for SetVariable {
    fn set(_request: &RequestRef<'_>, value: HttpVariableValueRef<'_>, data: usize) {
        assert_eq!(value.bytes(), Some(&b"set value"[..]));
        assert!(value.is_valid());
        assert!(value.is_cacheable());
        RAW_SET_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
        RAW_SET_VARIABLE_DATA.store(data, Ordering::Relaxed);
    }
}

struct CountingSetter;

impl HttpVariableSetter for CountingSetter {
    fn set(_request: &RequestRef<'_>, _value: HttpVariableValueRef<'_>, data: usize) {
        let calls = unsafe { &*(data as *const AtomicUsize) };
        calls.fetch_add(1, Ordering::Relaxed);
    }
}

struct TestVariable;

static TEST_VARIABLE_VALUE: &[u8] = b"detected";
static PREFIX_VARIABLE_VALUE: &[u8] = b"prefix";

impl HttpVariableHandler for TestVariable {
    type Output = Status;

    fn get(
        request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        data: usize,
    ) -> Self::Output {
        unsafe { (*request.as_ptr()).headers_out.status = data as _ };
        value.set_static(TEST_VARIABLE_VALUE).unwrap();
        Status::NGX_OK
    }
}

struct RawStatusVariable;

impl HttpVariableHandler for RawStatusVariable {
    type Output = ngx_int_t;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        value.set_empty();
        Status::NGX_OK.0
    }
}

struct OptionalStatusVariable;

impl HttpVariableHandler for OptionalStatusVariable {
    type Output = Option<Status>;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        value.set_empty();
        Some(Status::NGX_AGAIN)
    }
}

struct MissingStatusVariable;

impl HttpVariableHandler for MissingStatusVariable {
    type Output = Option<Status>;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        _value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        None
    }
}

struct ResultStatusVariable;

impl HttpVariableHandler for ResultStatusVariable {
    type Output = Result<Status, Status>;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        value.set_empty();
        Ok(Status::NGX_DECLINED)
    }
}

struct ErrorStatusVariable;

impl HttpVariableHandler for ErrorStatusVariable {
    type Output = Result<Status, Status>;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        _value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        Err(Status::NGX_AGAIN)
    }
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
    H: HttpVariableHandler,
{
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    unsafe { raw_get_handler::<H>(&raw mut request, &raw mut value, 0) }
}

#[cfg(feature = "test-link")]
struct TestPool {
    raw: *mut ngx_pool_t,
    log: Box<ngx_log_t>,
}

#[cfg(feature = "test-link")]
impl TestPool {
    fn new() -> Self {
        let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
        let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!raw.is_null());
        Self { raw, log }
    }
}

#[cfg(feature = "test-link")]
impl Drop for TestPool {
    fn drop(&mut self) {
        unsafe { ngx_destroy_pool(self.raw) };
    }
}

#[cfg(feature = "test-link")]
fn with_request<R>(
    owner: &TestPool,
    f: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
) -> R {
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    request.pool = owner.raw;

    unsafe { RequestRefMut::with_raw(&raw mut request, |mut request| f(&mut request)) }.unwrap()
}

#[cfg(feature = "test-link")]
struct VariableGlobalState {
    max_module: ngx_uint_t,
    http_max_module: ngx_uint_t,
    cacheline_size: ngx_uint_t,
    http_module_type: ngx_uint_t,
    http_module_index: ngx_uint_t,
    http_core_module_type: ngx_uint_t,
    http_core_module_index: ngx_uint_t,
    http_core_module_context_index: ngx_uint_t,
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
                http_max_module: nginx_sys::ngx_http_max_module,
                cacheline_size: nginx_sys::ngx_cacheline_size,
                http_module_type: (*core::ptr::addr_of!(nginx_sys::ngx_http_module)).type_,
                http_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_http_module)).index,
                http_core_module_type: (*core::ptr::addr_of!(nginx_sys::ngx_http_core_module))
                    .type_,
                http_core_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_http_core_module))
                    .index,
                http_core_module_context_index: (*core::ptr::addr_of!(
                    nginx_sys::ngx_http_core_module
                ))
                .ctx_index,
            }
        };

        unsafe {
            nginx_sys::ngx_max_module = 1;
            nginx_sys::ngx_http_max_module = 1;
            nginx_sys::ngx_cacheline_size = 64;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).type_ = NGX_CORE_MODULE as _;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index = 0;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).type_ =
                NGX_HTTP_MODULE as _;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).index = 0;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).ctx_index = 0;
        }

        Self { _guard: guard, previous }
    }
}

#[cfg(feature = "test-link")]
impl Drop for VariableGlobals {
    fn drop(&mut self) {
        unsafe {
            nginx_sys::ngx_max_module = self.previous.max_module;
            nginx_sys::ngx_http_max_module = self.previous.http_max_module;
            nginx_sys::ngx_cacheline_size = self.previous.cacheline_size;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).type_ =
                self.previous.http_module_type;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index =
                self.previous.http_module_index;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).type_ =
                self.previous.http_core_module_type;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).index =
                self.previous.http_core_module_index;
            (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).ctx_index =
                self.previous.http_core_module_context_index;
        }
    }
}

#[cfg(feature = "test-link")]
struct VariableConfiguration {
    main: Box<ngx_http_core_main_conf_t>,
    main_conf: Box<[*mut c_void; 1]>,
    _context: Box<ngx_http_conf_ctx_t>,
    cf: Box<ngx_conf_t>,
}

#[cfg(feature = "test-link")]
impl VariableConfiguration {
    fn new(pool: &mut TestPool) -> Self {
        let mut main =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init() });
        main.variables_hash_max_size = 1024;
        main.variables_hash_bucket_size = 64;
        let mut main_conf: Box<[*mut c_void; 1]> = Box::new([(&raw mut *main).cast()]);
        let mut context = Box::new(ngx_http_conf_ctx_t {
            main_conf: main_conf.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
            loc_conf: ptr::null_mut(),
        });
        let mut cf = Box::new(unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() });
        cf.pool = pool.raw;
        cf.temp_pool = pool.raw;
        cf.log = &raw mut *pool.log;
        cf.ctx = (&raw mut *context).cast();
        assert_eq!(unsafe { ngx_http_variables_add_core_vars(&raw mut *cf) }, NGX_OK as _);

        Self { main, main_conf, _context: context, cf }
    }

    fn configuration(&mut self) -> HttpConfigurationParser<'_> {
        HttpConfigurationParser::from_test_callback(&mut self.cf)
    }

    fn finalize_variables(&mut self) {
        assert_eq!(unsafe { ngx_http_variables_init_vars(&raw mut *self.cf) }, NGX_OK as _);
    }

    fn exact_variables(&self) -> &[ngx_hash_key_t] {
        let variables_keys = self.main.variables_keys;
        assert!(!variables_keys.is_null());
        array_values(unsafe { &(*variables_keys).keys })
    }

    fn prefix_variables(&self) -> &[ngx_http_variable_t] {
        array_values(&self.main.prefix_variables)
    }

    fn exact_variable(&self, name: &[u8]) -> &ngx_http_variable_t {
        let key = self.exact_variables().iter().find(|key| key.key.as_bytes() == name).unwrap();
        assert!(!key.value.is_null());
        unsafe { &*key.value.cast() }
    }

    fn prefix_variable(&self, name: &[u8]) -> &ngx_http_variable_t {
        self.prefix_variables().iter().find(|variable| variable.name.as_bytes() == name).unwrap()
    }

    fn indexed_variable_mut(&mut self, index: usize) -> &mut ngx_http_variable_t {
        assert!(index < self.main.variables.nelts);
        assert!(!self.main.variables.elts.is_null());
        unsafe { &mut *self.main.variables.elts.cast::<ngx_http_variable_t>().add(index) }
    }

    fn with_request<R>(
        &mut self,
        f: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
    ) -> R {
        let mut values = Vec::with_capacity(self.main.variables.nelts);
        for _ in 0..self.main.variables.nelts {
            values.push(unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() });
        }
        self.with_request_variables(values.as_mut_ptr(), f)
    }

    fn with_request_variables<R>(
        &mut self,
        variables: *mut ngx_variable_value_t,
        f: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
    ) -> R {
        let mut connection: Box<ngx_connection_t> =
            Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        connection.log = self.cf.log;
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        request.main = &raw mut request;
        request.connection = &raw mut *connection;
        request.pool = self.cf.pool;
        request.main_conf = self.main_conf.as_mut_ptr();
        request.variables = variables;

        unsafe { RequestRefMut::with_raw(&raw mut request, |mut request| f(&mut request)) }.unwrap()
    }
}

#[cfg(feature = "test-link")]
struct VariableFixture {
    _globals: VariableGlobals,
    pool: TestPool,
    configuration: VariableConfiguration,
}

#[cfg(feature = "test-link")]
impl VariableFixture {
    fn new() -> Self {
        let globals = VariableGlobals::new();
        let mut pool = TestPool::new();
        let configuration = VariableConfiguration::new(&mut pool);
        Self { _globals: globals, pool, configuration }
    }

    fn configuration(&mut self) -> HttpConfigurationParser<'_> {
        self.configuration.configuration()
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
fn same_handler(left: ngx_http_get_variable_pt, right: ngx_http_get_variable_pt) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => core::ptr::fn_addr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(feature = "test-link")]
fn assert_handler<H>(variable: &ngx_http_variable_t, data: usize)
where
    H: HttpVariableHandler,
{
    assert!(same_handler(variable.get_handler, Some(raw_get_handler::<H>)));
    assert_eq!(variable.data, data);
}

#[cfg(feature = "test-link")]
fn assert_prefix_handler<H>(variable: &ngx_http_variable_t)
where
    H: HttpPrefixVariableHandler,
{
    assert!(same_handler(variable.get_handler, Some(raw_prefix_get_handler::<H>)));
}

#[cfg(feature = "test-link")]
static INDEXED_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
struct IndexedVariable;

#[cfg(feature = "test-link")]
impl HttpVariableHandler for IndexedVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        INDEXED_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
        value.set_static(b"indexed").unwrap();
        Status::NGX_OK
    }
}

#[cfg(feature = "test-link")]
struct NestedVariable;

#[cfg(feature = "test-link")]
impl HttpVariableHandler for NestedVariable {
    type Output = Status;

    fn get(
        request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        data: usize,
    ) -> Self::Output {
        // The fixture keeps the boxed index alive until after every registered callback.
        let nested_index = unsafe { &*(data as *const HttpVariableIndex) };
        {
            let nested = request.get_cached(nested_index).unwrap();
            assert_eq!(nested.bytes(), Some(&b"indexed"[..]));
        }

        value.set_static(b"outer").unwrap();
        Status::NGX_OK
    }
}

#[cfg(feature = "test-link")]
struct FailingVariable;

#[cfg(feature = "test-link")]
impl HttpVariableHandler for FailingVariable {
    type Output = Status;

    fn get(
        _request: &mut HttpVariableRequest<'_, '_>,
        _value: &mut HttpVariableOutput<'_>,
        _data: usize,
    ) -> Self::Output {
        Status::NGX_ERROR
    }
}

mod dispatch;
mod index;
mod registration;
mod value;
