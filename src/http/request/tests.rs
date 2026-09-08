extern crate alloc;

use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(all(feature = "test-link", unix))]
use core::ffi::c_int;
use core::ffi::c_void;
#[cfg(feature = "test-link")]
use core::marker::PhantomPinned;
#[cfg(all(feature = "test-link", unix))]
use core::mem::ManuallyDrop;
use core::mem::{self, MaybeUninit};
#[cfg(feature = "test-link")]
use core::pin::Pin;
#[cfg(feature = "test-link")]
use core::ptr;
use core::ptr::NonNull;
use core::slice;
#[cfg(feature = "test-link")]
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "test-link")]
use std::path::{Path, PathBuf};
#[cfg(feature = "test-link")]
use std::sync::MutexGuard;
#[cfg(all(feature = "test-link", unix))]
use std::{
    fs::File,
    os::{
        fd::FromRawFd,
        unix::fs::{FileExt, PermissionsExt},
    },
};
#[cfg(feature = "test-link")]
use tempfile::TempDir;

use super::*;
use crate::collections::NgxList;
use crate::core::*;
#[cfg(feature = "test-link")]
use crate::event::{PostedEvent, PostedEventCallback, PostedQueue, Timer, TimerCallback};
use crate::ffi::*;
use crate::http::HttpModule;
use crate::http::status::*;
use crate::http::{HttpConfigError, HttpModuleRequestContext, UpstreamStateError};
#[cfg(feature = "test-link")]
use crate::log::LogRef;

#[cfg(feature = "test-link")]
use crate::ffi::{
    ngx_create_pool, ngx_current_msec, ngx_cycle_t, ngx_destroy_pool, ngx_event_expire_timers,
    ngx_event_move_posted_next, ngx_event_process_posted, ngx_event_timer_init,
    ngx_http_conf_ctx_t, ngx_http_core_srv_conf_t, ngx_http_output_header_filter_pt,
    ngx_http_phase_handler_t, ngx_log_t, ngx_palloc, ngx_pool_t, ngx_posted_events,
    ngx_posted_next_events, ngx_queue_init, ngx_reset_pool, ngx_rs_http_request_set_header_only,
    ngx_rs_http_request_set_terminated, ngx_uint_t,
};

#[cfg(feature = "test-link")]
unsafe extern "C" {
    fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
    fn ngx_rs_test_reset_allocation_failures();
    fn ngx_rs_test_http_request_flags(request: *const ngx_http_request_t) -> ngx_uint_t;
    fn ngx_rs_test_http_request_set_internal(
        request: *mut ngx_http_request_t,
        internal: ngx_uint_t,
    );
}

#[cfg(all(feature = "test-link", unix))]
unsafe extern "C" {
    fn fcntl(fd: ngx_fd_t, command: c_int) -> c_int;
}

#[cfg(all(feature = "test-link", unix))]
const F_GETFD: c_int = 1;

struct TestContextModule;

unsafe impl HttpModule for TestContextModule {
    fn module() -> ModuleDescriptor {
        ModuleDescriptor::from_test(ngx_module_t {
            type_: NGX_HTTP_MODULE as _,
            index: 0,
            ctx_index: 0,
            ..ngx_module_t::default()
        })
    }
}

unsafe impl HttpModuleRequestContext for TestContextModule {
    type RequestContext = u32;
}

#[cfg(feature = "test-link")]
static PINNED_CONTEXT_CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static PINNED_CONTEXT_CLEANUPS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static PINNED_CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static PINNED_CONTEXT_DROP_SAW_INVALIDATED_SLOT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "test-link")]
static EVENT_CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static TIMER_CONTEXT_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static POSTED_CONTEXT_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static BODY_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static BODY_CALLBACK_ACTIVE: AtomicBool = AtomicBool::new(true);

#[cfg(feature = "test-link")]
struct BodyCallback;

#[cfg(feature = "test-link")]
impl HttpClientBodyHandler for BodyCallback {
    fn is_active(_request: RequestRef<'_>) -> bool {
        BODY_CALLBACK_ACTIVE.load(Ordering::Relaxed)
    }

    fn body_read(request: &mut RequestRefMut<'_>) {
        assert!(request.request_body().is_ok());
        BODY_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
unsafe extern "C" fn blocked_request_handler(_request: *mut ngx_http_request_t) {}

#[cfg(feature = "test-link")]
unsafe extern "C" fn pending_body_recv(
    connection: *mut ngx_connection_t,
    _buffer: *mut u8,
    _size: usize,
) -> isize {
    unsafe { (*(*connection).read).set_ready(0) };
    NGX_AGAIN as _
}

#[cfg(feature = "test-link")]
unsafe extern "C" fn test_request_body_filter(
    _request: *mut ngx_http_request_t,
    _chain: *mut ngx_chain_t,
) -> ngx_int_t {
    NGX_OK as _
}

#[cfg(feature = "test-link")]
struct PinnedContext {
    value: u32,
    slot: *mut *mut c_void,
    _pin: PhantomPinned,
}

#[cfg(feature = "test-link")]
impl Drop for PinnedContext {
    fn drop(&mut self) {
        PINNED_CONTEXT_DROP_SAW_INVALIDATED_SLOT
            .store(unsafe { (*self.slot).is_null() }, Ordering::Relaxed);
        PINNED_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
struct PinnedContextModule;

#[cfg(feature = "test-link")]
unsafe impl HttpModule for PinnedContextModule {
    fn module() -> ModuleDescriptor {
        ModuleDescriptor::from_test(ngx_module_t {
            type_: NGX_HTTP_MODULE as _,
            index: 0,
            ctx_index: 0,
            ..ngx_module_t::default()
        })
    }
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleRequestContext for PinnedContextModule {
    type RequestContext = PinnedContext;

    fn cleanup(context: Pin<&mut Self::RequestContext>) {
        assert!(unsafe { (*context.as_ref().get_ref().slot).is_null() });
        PINNED_CONTEXT_CLEANUPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
type TimerContextCallback = for<'callback> fn(TimerCallback<'callback, ()>);

#[cfg(feature = "test-link")]
fn timer_context_callback(_timer: TimerCallback<'_, ()>) {
    TIMER_CONTEXT_CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(feature = "test-link")]
type PostedContextCallback = for<'callback> fn(PostedEventCallback<'callback, ()>);

#[cfg(feature = "test-link")]
fn posted_context_callback(_event: PostedEventCallback<'_, ()>) {
    POSTED_CONTEXT_CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(feature = "test-link")]
struct EventContext {
    timer: Timer<'static, (), TimerContextCallback>,
    posted: PostedEvent<'static, (), PostedContextCallback>,
}

#[cfg(feature = "test-link")]
impl Drop for EventContext {
    fn drop(&mut self) {
        EVENT_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
fn static_log_ref() -> LogRef<'static> {
    let log = Box::leak(Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() }));
    unsafe { LogRef::from_raw(log) }.expect("test logger")
}

#[cfg(feature = "test-link")]
struct EventContextModule;

#[cfg(feature = "test-link")]
unsafe impl HttpModule for EventContextModule {
    fn module() -> ModuleDescriptor {
        ModuleDescriptor::from_test(ngx_module_t {
            type_: NGX_HTTP_MODULE as _,
            index: 0,
            ctx_index: 0,
            ..ngx_module_t::default()
        })
    }
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleRequestContext for EventContextModule {
    type RequestContext = EventContext;
}

#[cfg(feature = "test-link")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstructorError {
    Rejected,
}

fn zeroed_request() -> ngx_http_request_t {
    unsafe { MaybeUninit::zeroed().assume_init() }
}

fn zeroed_pool() -> ngx_pool_t {
    unsafe { MaybeUninit::zeroed().assume_init() }
}

fn initialize_request(raw: &mut ngx_http_request_t) {
    raw.signature = NGX_HTTP_MODULE as _;
    if raw.main.is_null() {
        raw.main = raw;
    }
}

fn request_from(raw: &mut ngx_http_request_t) -> RequestRefMut<'_> {
    initialize_request(raw);
    unsafe { RequestRefMut::from_raw(raw).unwrap() }
}

#[cfg(feature = "test-link")]
fn pinned_context(slot: *mut *mut c_void) -> PinnedContext {
    PinnedContext { value: 41, slot, _pin: PhantomPinned }
}

#[cfg(feature = "test-link")]
fn reset_pinned_context_state() {
    PINNED_CONTEXT_CONSTRUCTIONS.store(0, Ordering::Relaxed);
    PINNED_CONTEXT_CLEANUPS.store(0, Ordering::Relaxed);
    PINNED_CONTEXT_DROPS.store(0, Ordering::Relaxed);
    PINNED_CONTEXT_DROP_SAW_INVALIDATED_SLOT.store(false, Ordering::Relaxed);
}

#[cfg(feature = "test-link")]
fn reset_event_context_state() {
    EVENT_CONTEXT_DROPS.store(0, Ordering::Relaxed);
    TIMER_CONTEXT_CALLBACKS.store(0, Ordering::Relaxed);
    POSTED_CONTEXT_CALLBACKS.store(0, Ordering::Relaxed);
    unsafe {
        assert_eq!(ngx_event_timer_init(ptr::null_mut()), 0);
        ngx_current_msec = 0;
        ngx_queue_init(&raw mut ngx_posted_events);
        ngx_queue_init(&raw mut ngx_posted_next_events);
    }
}

#[cfg(feature = "test-link")]
unsafe extern "C" fn stop_phase_engine(
    _request: *mut ngx_http_request_t,
    _phase: *mut ngx_http_phase_handler_t,
) -> ngx_int_t {
    NGX_OK as _
}

#[cfg(feature = "test-link")]
unsafe extern "C" fn accept_header(_request: *mut ngx_http_request_t) -> ngx_int_t {
    NGX_OK as _
}

#[cfg(feature = "test-link")]
struct HeaderFilterGuard(ngx_http_output_header_filter_pt);

#[cfg(feature = "test-link")]
impl HeaderFilterGuard {
    fn install() -> Self {
        let previous = unsafe { nginx_sys::ngx_http_top_header_filter };
        unsafe { nginx_sys::ngx_http_top_header_filter = Some(accept_header) };
        Self(previous)
    }
}

#[cfg(feature = "test-link")]
impl Drop for HeaderFilterGuard {
    fn drop(&mut self) {
        unsafe { nginx_sys::ngx_http_top_header_filter = self.0 };
    }
}

http_request_handler!(callback_status_handler, |_: &mut RequestRefMut<'_>| { Status::NGX_AGAIN });
http_request_handler!(callback_inferred_request_handler, |request| {
    let _ = request.status();
    Status::NGX_OK
});
http_subrequest_handler!(
    callback_status_subrequest_handler,
    |_: &mut RequestRefMut<'_>, _: *mut c_void, _: ngx_int_t| HTTPStatus::NO_CONTENT
);
http_variable_get!(
    callback_status_variable_handler,
    |_: &mut RequestRefMut<'_>, _: *mut ngx_variable_value_t, _: usize| Status::NGX_DONE
);

#[cfg(feature = "test-link")]
struct RequestGlobals {
    _guard: MutexGuard<'static, ()>,
    max_module: ngx_uint_t,
    http_max_module: ngx_uint_t,
    core_module_type: ngx_uint_t,
    core_module_index: ngx_uint_t,
    core_module_context_index: ngx_uint_t,
    request_body_filter: nginx_sys::ngx_http_request_body_filter_pt,
}

#[cfg(feature = "test-link")]
impl RequestGlobals {
    fn new(module_slots: ngx_uint_t, http_slots: ngx_uint_t) -> Self {
        let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let (
            max_module,
            http_max_module,
            core_module_type,
            core_module_index,
            core_module_context_index,
            request_body_filter,
        ) = unsafe {
            let module = &raw const nginx_sys::ngx_http_core_module;
            (
                nginx_sys::ngx_max_module,
                nginx_sys::ngx_http_max_module,
                (*module).type_,
                (*module).index,
                (*module).ctx_index,
                nginx_sys::ngx_http_top_request_body_filter,
            )
        };
        unsafe {
            nginx_sys::ngx_max_module = module_slots;
            nginx_sys::ngx_http_max_module = http_slots;
        }
        Self {
            _guard: guard,
            max_module,
            http_max_module,
            core_module_type,
            core_module_index,
            core_module_context_index,
            request_body_filter,
        }
    }
}

#[cfg(feature = "test-link")]
impl Drop for RequestGlobals {
    fn drop(&mut self) {
        unsafe {
            nginx_sys::ngx_max_module = self.max_module;
            nginx_sys::ngx_http_max_module = self.http_max_module;
            let module = &raw mut nginx_sys::ngx_http_core_module;
            (*module).type_ = self.core_module_type;
            (*module).index = self.core_module_index;
            (*module).ctx_index = self.core_module_context_index;
            nginx_sys::ngx_http_top_request_body_filter = self.request_body_filter;
        }
    }
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

    fn log(&mut self) -> NonNull<ngx_log_t> {
        NonNull::from(&mut *self._log)
    }

    fn disarm(&mut self) {
        self.raw = ptr::null_mut();
    }
}

#[cfg(feature = "test-link")]
impl Drop for TestPool {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }
}

#[cfg(feature = "test-link")]
fn poisoned_header_list(headers: &mut ngx_list_t, pool: *mut ngx_pool_t) {
    let size = mem::size_of::<ngx_table_elt_t>();
    let storage = unsafe { ngx_palloc(pool, size) };
    assert!(!storage.is_null());
    unsafe {
        ptr::write_bytes(storage, 0xa5, size);
        ngx_reset_pool(pool);
    }
    create_header_list(headers, pool, 1).unwrap();
    assert_eq!(headers.part.elts, storage);
}

#[cfg(feature = "test-link")]
struct TerminalRequestFixture {
    _globals: RequestGlobals,
    request_pool: TestPool,
    connection_pool: TestPool,
    _log: Box<ngx_log_t>,
    _log_context: Box<ngx_http_log_ctx_t>,
    _read: Box<ngx_event_t>,
    _write: Box<ngx_event_t>,
    connection: Box<ngx_connection_t>,
    _core: Box<ngx_http_core_loc_conf_t>,
    _loc_conf: Box<[*mut c_void; 1]>,
    _main_conf: Box<ngx_http_core_main_conf_t>,
    _main_conf_slots: Box<[*mut c_void; 1]>,
    request: Box<ngx_http_request_t>,
}

#[cfg(feature = "test-link")]
impl TerminalRequestFixture {
    fn new() -> Self {
        let globals = RequestGlobals::new(1, 1);
        unsafe {
            let module = &raw mut nginx_sys::ngx_http_core_module;
            (*module).type_ = NGX_HTTP_MODULE as _;
            (*module).index = 0;
            (*module).ctx_index = 0;
        }

        let request_pool = TestPool::new();
        let connection_pool = TestPool::new();
        let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
        let mut log_context =
            Box::new(unsafe { MaybeUninit::<ngx_http_log_ctx_t>::zeroed().assume_init() });
        log.data = (&raw mut *log_context).cast();
        let mut read = Box::new(unsafe { MaybeUninit::<ngx_event_t>::zeroed().assume_init() });
        let mut write = Box::new(unsafe { MaybeUninit::<ngx_event_t>::zeroed().assume_init() });
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = connection_pool.raw;
        connection.log = &raw mut *log;
        connection.read = &raw mut *read;
        connection.write = &raw mut *write;
        connection.fd = -1;

        let mut core =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_loc_conf_t>::zeroed().assume_init() });
        core.keepalive_timeout = 0;
        core.lingering_close = 0;
        core.error_log = &raw mut *log;
        let mut loc_conf = Box::new([(&raw mut *core).cast::<c_void>()]);
        let mut main_conf =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init() });
        let mut main_conf_slots = Box::new([(&raw mut *main_conf).cast::<c_void>()]);
        let mut request = Box::new(zeroed_request());
        initialize_request(&mut request);
        request.parent = &raw mut *request;
        request.pool = request_pool.raw;
        request.connection = &raw mut *connection;
        connection.data = (&raw mut *request).cast();
        request.loc_conf = loc_conf.as_mut_ptr();
        request.main_conf = main_conf_slots.as_mut_ptr();
        request.set_logged(1);
        request.set_count(1);

        Self {
            _globals: globals,
            request_pool,
            connection_pool,
            _log: log,
            _log_context: log_context,
            _read: read,
            _write: write,
            connection,
            _core: core,
            _loc_conf: loc_conf,
            _main_conf: main_conf,
            _main_conf_slots: main_conf_slots,
            request,
        }
    }

    fn hold(&mut self, hold: &mut Option<RequestHold>) {
        // SAFETY: this fixture keeps the hold with its request and explicitly finishes it.
        unsafe { request_from(&mut self.request).hold(hold) }.unwrap();
    }

    fn disarm_nginx_pools(&mut self) {
        self.request_pool.disarm();
        self.connection_pool.disarm();
        assert!(self.request.pool.is_null());
        assert_eq!(self.request.count(), 0);
        assert_ne!(self.connection.destroyed(), 0);
    }
}

#[cfg(feature = "test-link")]
struct TempFileFixture {
    _globals: RequestGlobals,
    pool: TestPool,
    temp_dir: TempDir,
    path_name: Vec<u8>,
    path: Box<ngx_path_t>,
    core: Box<ngx_http_core_loc_conf_t>,
    _slots: Box<[*mut c_void; 1]>,
    connection: Box<ngx_connection_t>,
    request: ngx_http_request_t,
}

#[cfg(feature = "test-link")]
impl TempFileFixture {
    fn new() -> Self {
        let globals = RequestGlobals::new(1, 1);
        unsafe {
            let module = &raw mut nginx_sys::ngx_http_core_module;
            (*module).type_ = NGX_HTTP_MODULE as _;
            (*module).index = 0;
            (*module).ctx_index = 0;
        }

        let mut pool = TestPool::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let mut path_name = temp_dir.path().to_str().unwrap().as_bytes().to_vec();
        let mut path: Box<ngx_path_t> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        path.name = ngx_str_t { len: path_name.len(), data: path_name.as_mut_ptr() };

        let mut core: Box<ngx_http_core_loc_conf_t> =
            Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        core.client_body_temp_path = &raw mut *path;
        let mut slots = Box::new([(&raw mut *core).cast::<c_void>()]);

        let mut connection: Box<ngx_connection_t> =
            Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        connection.log = pool.log().as_ptr();

        let mut request = zeroed_request();
        request.pool = pool.raw;
        request.parent = &raw mut request;
        request.connection = &raw mut *connection;
        request.loc_conf = slots.as_mut_ptr();
        initialize_request(&mut request);

        Self {
            _globals: globals,
            pool,
            temp_dir,
            path_name,
            path,
            core,
            _slots: slots,
            connection,
            request,
        }
    }

    fn set_path(&mut self, path: &Path) {
        self.path_name = path.to_str().unwrap().as_bytes().to_vec();
        self.path.name = ngx_str_t { len: self.path_name.len(), data: self.path_name.as_mut_ptr() };
    }
}

#[cfg(feature = "test-link")]
fn chain_ref(chain: PoolChain<'_>) -> ChainRef<'_> {
    unsafe { ChainRef::from_raw(chain.into_raw()) }.unwrap()
}

#[cfg(feature = "test-link")]
fn pool_file_buffer<'pool>(
    pool: &Pool<'pool>,
    fd: ngx_fd_t,
    start: off_t,
    end: off_t,
    flags: BufferFlags,
) -> (PoolBuffer<'pool>, NonNull<ngx_file_t>) {
    let mut file = NonNull::new(pool.calloc_type::<ngx_file_t>()).unwrap();
    let mut buffer = NonNull::new(pool.calloc_type::<ngx_buf_t>()).unwrap();
    unsafe {
        file.as_mut().fd = fd;
        let native = buffer.as_mut();
        native.file = file.as_ptr();
        native.file_pos = start;
        native.file_last = end;
        native.set_in_file(1);
        native.set_flush(u32::from(flags.flush));
        native.set_sync(u32::from(flags.sync));
        native.set_last_buf(u32::from(flags.last_buf));
        native.set_last_in_chain(u32::from(flags.last_in_chain));
    }
    (unsafe { pool.owned_buffer_from_raw(buffer) }, file)
}

#[cfg(feature = "test-link")]
fn temp_file_path(temp: &ngx_temp_file_t) -> PathBuf {
    let name = unsafe { slice::from_raw_parts(temp.file.name.data, temp.file.name.len) };
    PathBuf::from(core::str::from_utf8(name).unwrap())
}

#[cfg(all(feature = "test-link", unix))]
fn temp_file_bytes(temp: &ngx_temp_file_t) -> Vec<u8> {
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(temp.file.fd) });
    let mut bytes = alloc::vec![0; usize::try_from(temp.offset).unwrap()];
    let read = file.read_at(&mut bytes, 0).unwrap();
    bytes.truncate(read);
    bytes
}

#[test]
fn callback_scoped_request_rejects_null_and_misaligned_raw_pointers() {
    assert!(matches!(
        unsafe { RequestRefMut::from_raw(core::ptr::null_mut()) },
        Err(RequestError::NullRequest)
    ));

    let misaligned = core::ptr::without_provenance_mut::<ngx_http_request_t>(1);
    assert!(matches!(
        unsafe { RequestRefMut::from_raw(misaligned) },
        Err(RequestError::MisalignedRequest)
    ));

    let mut raw = zeroed_request();
    assert!(matches!(
        unsafe { RequestRefMut::from_raw(&raw mut raw) },
        Err(RequestError::InvalidRequestSignature)
    ));
}

#[test]
fn main_request_validation_rejects_missing_invalid_and_foreign_links() {
    let mut missing = zeroed_request();
    missing.signature = NGX_HTTP_MODULE as _;
    let missing = unsafe { RequestRefMut::from_raw(&raw mut missing).unwrap() };
    assert!(matches!(missing.main(), Err(RequestError::MissingMain)));

    let mut misaligned = zeroed_request();
    misaligned.signature = NGX_HTTP_MODULE as _;
    misaligned.main = core::ptr::without_provenance_mut(1);
    let misaligned = unsafe { RequestRefMut::from_raw(&raw mut misaligned).unwrap() };
    assert!(matches!(misaligned.main(), Err(RequestError::MisalignedMain)));

    let mut invalid_main = zeroed_request();
    let mut invalid = zeroed_request();
    invalid.signature = NGX_HTTP_MODULE as _;
    invalid.main = &raw mut invalid_main;
    let invalid = unsafe { RequestRefMut::from_raw(&raw mut invalid).unwrap() };
    assert!(matches!(invalid.main(), Err(RequestError::InvalidMainSignature)));

    let mut main = zeroed_request();
    initialize_request(&mut main);
    let mut foreign = zeroed_request();
    foreign.signature = NGX_HTTP_MODULE as _;
    foreign.main = &raw mut main;
    let foreign = unsafe { RequestRefMut::from_raw(&raw mut foreign).unwrap() };
    assert!(matches!(foreign.main(), Err(RequestError::ForeignMain)));

    let mut parent = zeroed_request();
    initialize_request(&mut parent);
    parent.parent = &raw mut main;
    let mut child = zeroed_request();
    child.signature = NGX_HTTP_MODULE as _;
    child.main = &raw mut main;
    child.parent = &raw mut parent;
    let child = unsafe { RequestRefMut::from_raw(&raw mut child).unwrap() };
    assert!(matches!(child.main(), Err(RequestError::ForeignMain)));
}

#[test]
fn deepest_native_subrequest_chain_resolves_to_main() {
    let request_count = usize::try_from(NGX_HTTP_MAX_SUBREQUESTS).unwrap() + 2;
    let mut requests = (0..request_count).map(|_| Box::new(zeroed_request())).collect::<Vec<_>>();
    let main = ptr::from_mut(requests[0].as_mut());
    initialize_request(requests[0].as_mut());

    for index in 1..requests.len() {
        let parent = ptr::from_mut(requests[index - 1].as_mut());
        let child = requests[index].as_mut();
        child.signature = NGX_HTTP_MODULE as _;
        child.main = main;
        child.parent = parent;
    }

    let deepest = request_from(requests.last_mut().unwrap());
    assert_eq!(deepest.main().unwrap().raw, NonNull::new(main).unwrap());
}

#[test]
fn request_views_validate_pool_connection_and_logger_pointers() {
    let mut missing_pool = zeroed_request();
    assert!(matches!(request_from(&mut missing_pool).pool(), Err(RequestError::MissingPool)));

    let mut misaligned_pool = zeroed_request();
    misaligned_pool.pool = core::ptr::without_provenance_mut(1);
    assert!(matches!(request_from(&mut misaligned_pool).pool(), Err(RequestError::MisalignedPool)));

    let mut missing_connection = zeroed_request();
    assert_eq!(
        request_from(&mut missing_connection).connection(),
        Err(RequestError::Connection(ConnectionError::NullConnection))
    );

    let mut misaligned_connection = zeroed_request();
    misaligned_connection.connection = core::ptr::without_provenance_mut(1);
    assert_eq!(
        request_from(&mut misaligned_connection).connection(),
        Err(RequestError::Connection(ConnectionError::MisalignedConnection))
    );

    let mut connection: ngx_connection_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut missing_log = zeroed_request();
    missing_log.connection = &raw mut connection;
    assert_eq!(request_from(&mut missing_log).log(), Ok(None));

    connection.log = core::ptr::without_provenance_mut(1);
    let mut invalid_log = zeroed_request();
    invalid_log.connection = &raw mut connection;
    assert_eq!(
        request_from(&mut invalid_log).log(),
        Err(RequestError::Connection(ConnectionError::MisalignedLog))
    );
}

#[test]
fn request_fields_return_checked_strings_counters_and_status() {
    let path = b"/path";
    let uri = b"/path?query=1";
    let agent = b"curl/8";
    let mut user_agent: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    user_agent.value = ngx_str_t { len: agent.len(), data: agent.as_ptr().cast_mut() };

    let mut raw = zeroed_request();
    raw.uri = ngx_str_t { len: path.len(), data: path.as_ptr().cast_mut() };
    raw.unparsed_uri = ngx_str_t { len: uri.len(), data: uri.as_ptr().cast_mut() };
    raw.headers_in.user_agent = &raw mut user_agent;
    raw.method = NGX_HTTP_GET as _;
    raw.headers_out.status = HTTPStatus::NO_CONTENT.into();
    raw.start_sec = 1_700_000_000;
    raw.start_msec = 250;
    raw.request_length = 4096;

    let request = request_from(&mut raw);
    assert_eq!(request.path().unwrap().as_bytes(), path);
    assert_eq!(request.unparsed_uri().unwrap().as_bytes(), uri);
    assert_eq!(request.user_agent().unwrap().unwrap().as_bytes(), agent);
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.status(), Some(HTTPStatus::NO_CONTENT));
    assert_eq!(request.start_sec(), Ok(1_700_000_000));
    assert_eq!(request.start_msec(), 250);
    assert_eq!(request.request_length(), Ok(4096));

    let mut malformed = zeroed_request();
    malformed.uri.len = 1;
    assert_eq!(request_from(&mut malformed).path(), Err(RequestError::MissingStringData));

    let mut negative = zeroed_request();
    negative.start_sec = -1;
    negative.request_length = -1;
    let negative = request_from(&mut negative);
    assert_eq!(negative.start_sec(), Err(RequestError::NegativeStartTime));
    assert_eq!(negative.request_length(), Err(RequestError::NegativeCounter));
}

#[test]
fn request_fields_accept_empty_uri_parts_and_method_variants() {
    let mut empty = zeroed_request();
    let empty = request_from(&mut empty);
    assert_eq!(empty.path().unwrap().as_bytes(), b"");
    assert_eq!(empty.unparsed_uri().unwrap().as_bytes(), b"");

    let mut post = zeroed_request();
    post.method = NGX_HTTP_POST as _;
    assert_eq!(request_from(&mut post).method(), Method::POST);

    let mut patch = zeroed_request();
    patch.method = NGX_HTTP_PATCH as _;
    assert_eq!(request_from(&mut patch).method(), Method::PATCH);
}

#[test]
fn request_upstream_states_use_checked_array_views() {
    let mut attempts =
        [unsafe { MaybeUninit::<ngx_http_upstream_state_t>::zeroed().assume_init() }, unsafe {
            MaybeUninit::<ngx_http_upstream_state_t>::zeroed().assume_init()
        }];
    attempts[0].status = 502;
    attempts[1].status = 503;
    let mut states = ngx_array_t {
        elts: attempts.as_mut_ptr().cast(),
        nelts: attempts.len(),
        size: core::mem::size_of::<ngx_http_upstream_state_t>(),
        nalloc: attempts.len(),
        pool: core::ptr::null_mut(),
    };
    let mut raw = zeroed_request();
    initialize_request(&mut raw);
    raw.upstream_states = &raw mut states;

    let request = request_from(&mut raw);
    let states = request.upstream_states().unwrap().unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states.get(0).unwrap().status(), Some(502));
    assert_eq!(
        request.view().upstream_states().unwrap().unwrap().get(1).unwrap().status(),
        Some(503)
    );

    let mut malformed = zeroed_request();
    initialize_request(&mut malformed);
    malformed.upstream_states = core::ptr::without_provenance_mut::<ngx_array_t>(1);
    assert!(matches!(
        request_from(&mut malformed).upstream_states(),
        Err(UpstreamStateError::MisalignedArray)
    ));
}

#[test]
fn callback_boundaries_convert_statuses_and_reject_invalid_requests() {
    let mut raw = zeroed_request();
    initialize_request(&mut raw);

    assert_eq!(unsafe { callback_status_handler(&raw mut raw) }, NGX_AGAIN as _);
    assert_eq!(unsafe { callback_inferred_request_handler(&raw mut raw) }, NGX_OK as _);
    assert_eq!(
        unsafe { callback_status_subrequest_handler(&raw mut raw, core::ptr::null_mut(), 0) },
        HTTPStatus::NO_CONTENT.0 as _
    );
    assert_eq!(
        unsafe { callback_status_variable_handler(&raw mut raw, core::ptr::null_mut(), 0) },
        NGX_DONE as _
    );
    assert_eq!(
        unsafe { request_callback_status(core::ptr::null_mut(), |_| Status::NGX_OK) },
        NGX_ERROR as _
    );
}

#[test]
fn header_iterator_returns_keys_and_values() {
    let mut headers: [ngx_table_elt_t; 2] = unsafe { MaybeUninit::zeroed().assume_init() };
    headers[0].hash = 1;
    headers[0].key = crate::ngx_string!("X-First");
    headers[0].value = crate::ngx_string!("one");
    headers[1].hash = 1;
    headers[1].key = crate::ngx_string!("X-Second");
    headers[1].value = crate::ngx_string!("two");

    let mut raw = ngx_list_t {
        last: core::ptr::null_mut(),
        part: ngx_list_part_t {
            elts: headers.as_mut_ptr().cast(),
            nelts: headers.len(),
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: headers.len(),
        pool: core::ptr::null_mut(),
    };
    raw.last = &raw mut raw.part;

    let values: Vec<_> = unsafe { list_iterator(&raw) }
        .map(|(key, value)| (key.to_str().unwrap(), value.to_str().unwrap()))
        .collect();

    assert_eq!(values, [("X-First", "one"), ("X-Second", "two")]);
}

#[test]
fn checked_header_views_keep_raw_bytes_and_skip_disabled_entries() {
    let input_key = [b'X', b'-', 0xff];
    let input_value = [0, 0xff];
    let input_lowcase = [b'x', b'-', 0xff];
    let mut input_headers = [MaybeUninit::<ngx_table_elt_t>::uninit()];
    let input_header = input_headers[0].as_mut_ptr();
    unsafe {
        ptr::addr_of_mut!((*input_header).hash).write(17);
        ptr::addr_of_mut!((*input_header).key)
            .write(ngx_str_t { len: input_key.len(), data: input_key.as_ptr().cast_mut() });
        ptr::addr_of_mut!((*input_header).value)
            .write(ngx_str_t { len: input_value.len(), data: input_value.as_ptr().cast_mut() });
        ptr::addr_of_mut!((*input_header).lowcase_key).write(input_lowcase.as_ptr().cast_mut());
    }

    let mut empty_headers = [MaybeUninit::<ngx_table_elt_t>::uninit()];
    let mut disabled_headers = [MaybeUninit::<ngx_table_elt_t>::uninit()];
    unsafe { ptr::addr_of_mut!((*disabled_headers[0].as_mut_ptr()).hash).write(0) };

    let mut disabled_part = ngx_list_part_t {
        elts: disabled_headers.as_mut_ptr().cast(),
        nelts: disabled_headers.len(),
        next: core::ptr::null_mut(),
    };
    let mut empty_part = ngx_list_part_t {
        elts: empty_headers.as_mut_ptr().cast(),
        nelts: 0,
        next: &raw mut disabled_part,
    };
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut disabled_part,
        part: ngx_list_part_t {
            elts: input_headers.as_mut_ptr().cast(),
            nelts: input_headers.len(),
            next: &raw mut empty_part,
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };

    let request = request_from(&mut raw);
    let input = request.headers_in().unwrap();
    let headers: Vec<_> = input.iter().collect();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].key(), input_key);
    assert_eq!(headers[0].value(), input_value);
    assert_eq!(headers[0].lowercase_key(), Some(input_lowcase.as_slice()));
    assert_eq!(headers[0].hash(), 17);
    assert!(headers[0].is_enabled());

    let output_key = [b'Y', 0xfe];
    let output_value = [0xff, b'!'];
    let mut output_headers = [MaybeUninit::<ngx_table_elt_t>::uninit()];
    let output_header = output_headers[0].as_mut_ptr();
    unsafe {
        ptr::addr_of_mut!((*output_header).hash).write(23);
        ptr::addr_of_mut!((*output_header).key)
            .write(ngx_str_t { len: output_key.len(), data: output_key.as_ptr().cast_mut() });
        ptr::addr_of_mut!((*output_header).value)
            .write(ngx_str_t { len: output_value.len(), data: output_value.as_ptr().cast_mut() });
    }
    raw.headers_out.headers = ngx_list_t {
        last: &raw mut raw.headers_out.headers.part,
        part: ngx_list_part_t {
            elts: output_headers.as_mut_ptr().cast(),
            nelts: output_headers.len(),
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: output_headers.len(),
        pool: core::ptr::null_mut(),
    };

    let request = request_from(&mut raw);
    let output = request.headers_out().unwrap();
    let header = output.iter().next().unwrap();
    assert_eq!(header.key(), output_key);
    assert_eq!(header.value(), output_value);
    assert_eq!(header.lowercase_key(), None);
    assert_eq!(header.hash(), 23);
}

#[cfg(feature = "test-link")]
#[test]
fn native_post_push_failure_is_skipped_before_partial_header_fields() {
    let mut fixture = TerminalRequestFixture::new();
    fixture._core.etag = 1;
    fixture.request.headers_out.last_modified_time = 1;
    fixture.request.headers_out.content_length_n = 1;
    poisoned_header_list(&mut fixture.request.headers_out.headers, fixture.request_pool.raw);

    unsafe {
        (*fixture.request_pool.raw).d.last = (*fixture.request_pool.raw).d.end;
        (*fixture.request_pool.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let status = unsafe { ngx_http_set_etag(&raw mut *fixture.request) };
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert_eq!(status, NGX_ERROR as ngx_int_t);
    assert_eq!(fixture.request.headers_out.headers.part.nelts, 1);
    let request = request_from(&mut fixture.request);
    assert!(request.headers_out().unwrap().is_empty());
    assert_eq!(request.headers_out_iterator().count(), 0);
}

#[test]
fn checked_header_views_reject_invalid_list_and_string_state() {
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut raw.headers_in.headers.part,
        part: ngx_list_part_t {
            elts: core::ptr::null_mut(),
            nelts: 1,
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_in(), Err(HeaderListError::InvalidList)));

    let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut raw.headers_in.headers.part,
        part: ngx_list_part_t {
            elts: (&raw mut header).cast(),
            nelts: 2,
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_in(), Err(HeaderListError::InvalidList)));

    let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut raw.headers_in.headers.part,
        part: ngx_list_part_t {
            elts: (&raw mut header).cast(),
            nelts: 1,
            next: &raw mut raw.headers_in.headers.part,
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_in(), Err(HeaderListError::InvalidList)));

    let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    header.hash = 1;
    header.key.len = 1;
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut raw.headers_in.headers.part,
        part: ngx_list_part_t {
            elts: (&raw mut header).cast(),
            nelts: 1,
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_in(), Err(HeaderListError::MissingKeyData)));

    let key = *b"X";
    let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    header.hash = 1;
    header.key = ngx_str_t { len: key.len(), data: key.as_ptr().cast_mut() };
    header.value.len = 1;
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut raw.headers_in.headers.part,
        part: ngx_list_part_t {
            elts: (&raw mut header).cast(),
            nelts: 1,
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_in(), Err(HeaderListError::MissingValueData)));

    let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    header.hash = 1;
    header.key.len = isize::MAX as usize + 1;
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut raw.headers_in.headers.part,
        part: ngx_list_part_t {
            elts: (&raw mut header).cast(),
            nelts: 1,
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_in(), Err(HeaderListError::KeyTooLong)));

    let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    header.hash = 1;
    header.key = ngx_str_t { len: key.len(), data: key.as_ptr().cast_mut() };
    header.value.len = isize::MAX as usize + 1;
    let mut raw = zeroed_request();
    raw.headers_in.headers = ngx_list_t {
        last: &raw mut raw.headers_in.headers.part,
        part: ngx_list_part_t {
            elts: (&raw mut header).cast(),
            nelts: 1,
            next: core::ptr::null_mut(),
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_in(), Err(HeaderListError::ValueTooLong)));

    let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut raw = zeroed_request();
    raw.headers_out.headers = ngx_list_t {
        last: &raw mut raw.headers_out.headers.part,
        part: ngx_list_part_t {
            elts: (&raw mut header).cast(),
            nelts: 1,
            next: &raw mut raw.headers_out.headers.part,
        },
        size: core::mem::size_of::<ngx_table_elt_t>(),
        nalloc: 1,
        pool: core::ptr::null_mut(),
    };
    assert!(matches!(request_from(&mut raw).headers_out(), Err(HeaderListError::InvalidList)));
}

#[cfg(feature = "test-link")]
#[test]
fn direct_header_additions_initialize_poisoned_entries() {
    for input in [true, false] {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        if input {
            poisoned_header_list(&mut raw.headers_in.headers, owner.raw);
        } else {
            poisoned_header_list(&mut raw.headers_out.headers, owner.raw);
        }

        let mut request = request_from(&mut raw);
        let result = if input {
            unsafe { request.add_header_in("X-Direct", "input") }
        } else {
            request.add_header_out("X-Direct", "output")
        };
        assert_eq!(result, Ok(()));

        let entry = if input {
            unsafe { &*raw.headers_in.headers.part.elts.cast::<ngx_table_elt_t>() }
        } else {
            unsafe { &*raw.headers_out.headers.part.elts.cast::<ngx_table_elt_t>() }
        };
        assert!(entry.next.is_null());
        {
            let request = request_from(&mut raw);
            let headers =
                if input { request.headers_in().unwrap() } else { request.headers_out().unwrap() };
            let header = headers.iter().next().unwrap();
            assert_eq!(header.key(), b"X-Direct");
            assert_eq!(
                header.value(),
                if input { b"input".as_slice() } else { b"output".as_slice() }
            );
        }
        let request = request_from(&mut raw);
        assert_eq!(
            if input {
                request.headers_in_iterator().count()
            } else {
                request.headers_out_iterator().count()
            },
            1
        );
    }
}

#[cfg(feature = "test-link")]
#[test]
fn direct_header_allocation_failures_preserve_the_readable_list() {
    for input in [true, false] {
        let mut reached_success = false;

        for successes in 0..7 {
            let owner = TestPool::new();
            let mut raw = zeroed_request();
            raw.pool = owner.raw;
            if input {
                poisoned_header_list(&mut raw.headers_in.headers, owner.raw);
            } else {
                poisoned_header_list(&mut raw.headers_out.headers, owner.raw);
            }
            {
                let mut request = request_from(&mut raw);
                if input {
                    unsafe { request.add_header_in("X-Existing", "old") }.unwrap();
                } else {
                    request.add_header_out("X-Existing", "old").unwrap();
                }
            }
            let headers = if input { &raw.headers_in.headers } else { &raw.headers_out.headers };
            let original = (headers.part.elts, headers.part.nelts, headers.part.next, headers.last);

            unsafe {
                (*owner.raw).d.last = (*owner.raw).d.end;
                (*owner.raw).max = 0;
                ngx_rs_test_fail_allocations_after(successes);
            }
            let result = {
                let mut request = request_from(&mut raw);
                if input {
                    unsafe { request.add_header_in("X-Replacement", "new") }
                } else {
                    request.add_header_out("X-Replacement", "new")
                }
            };
            unsafe { ngx_rs_test_reset_allocation_failures() };

            let headers = if input { &raw.headers_in.headers } else { &raw.headers_out.headers };
            if result.is_ok() {
                {
                    let request = request_from(&mut raw);
                    let headers = if input {
                        request.headers_in().unwrap()
                    } else {
                        request.headers_out().unwrap()
                    };
                    let mut headers = headers.iter();
                    assert_eq!(headers.next().unwrap().key(), b"X-Existing");
                    let added = headers.next().unwrap();
                    assert_eq!(added.key(), b"X-Replacement");
                    assert_eq!(added.value(), b"new");
                    assert!(headers.next().is_none());
                }
                let added = unsafe {
                    if input {
                        (*raw.headers_in.headers.part.next).elts.cast::<ngx_table_elt_t>()
                    } else {
                        (*raw.headers_out.headers.part.next).elts.cast::<ngx_table_elt_t>()
                    }
                };
                assert!(unsafe { (*added).next.is_null() });
                let request = request_from(&mut raw);
                assert_eq!(
                    if input {
                        request.headers_in_iterator().count()
                    } else {
                        request.headers_out_iterator().count()
                    },
                    2
                );
                reached_success = true;
                break;
            }
            assert_eq!(result, Err(RequestError::Allocation));
            assert_eq!(
                (headers.part.elts, headers.part.nelts, headers.part.next, headers.last,),
                original
            );
            {
                let request = request_from(&mut raw);
                let headers = if input {
                    request.headers_in().unwrap()
                } else {
                    request.headers_out().unwrap()
                };
                let mut headers = headers.iter();
                let existing = headers.next().unwrap();
                assert_eq!(existing.key(), b"X-Existing");
                assert_eq!(existing.value(), b"old");
                assert!(unsafe { (*original.0.cast::<ngx_table_elt_t>()).next.is_null() });
                assert!(headers.next().is_none());
            }
            let request = request_from(&mut raw);
            assert_eq!(
                if input {
                    request.headers_in_iterator().count()
                } else {
                    request.headers_out_iterator().count()
                },
                1
            );
        }

        assert!(reached_success);
    }
}

#[cfg(feature = "test-link")]
#[test]
fn input_header_builder_copies_bytes_binds_slots_and_keeps_duplicates() {
    let owner = TestPool::new();
    let source_key = [b'X', 0xff];
    let source_value = [0, 0xfe];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    let standard_headers = [
        (b"Host".as_slice(), b"example.test".as_slice()),
        (b"Content-Length".as_slice(), b"7".as_slice()),
        (b"Content-Type".as_slice(), b"application/test".as_slice()),
        (b"User-Agent".as_slice(), b"agent".as_slice()),
        (b"Referer".as_slice(), b"https://example.test/".as_slice()),
        (b"Authorization".as_slice(), b"Basic token".as_slice()),
        (b"Proxy-Authorization".as_slice(), b"Basic proxy".as_slice()),
        (b"Cookie".as_slice(), b"a=b".as_slice()),
        (b"Expect".as_slice(), b"100-continue".as_slice()),
        (b"Range".as_slice(), b"bytes=0-1".as_slice()),
        (b"If-Modified-Since".as_slice(), b"Wed, 21 Oct 2015 07:28:00 GMT".as_slice()),
        (b"If-Unmodified-Since".as_slice(), b"Wed, 21 Oct 2015 07:28:00 GMT".as_slice()),
        (b"If-Match".as_slice(), b"one".as_slice()),
        (b"If-None-Match".as_slice(), b"two".as_slice()),
        (b"If-Range".as_slice(), b"three".as_slice()),
        (b"Content-Range".as_slice(), b"bytes 0-1/2".as_slice()),
    ];

    {
        let mut request = request_from(&mut raw);
        let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
        for (key, value) in standard_headers {
            headers.add(key, value).unwrap();
        }
        headers.add(&source_key, &source_value).unwrap();
        headers.add(b"X-Duplicate", b"one").unwrap();
        headers.add(b"X-Duplicate", b"two").unwrap();
        headers.commit();
    }

    let mut expected_lowcase = [0; 2];
    let expected_hash = unsafe {
        ngx_hash_strlow(
            expected_lowcase.as_mut_ptr(),
            source_key.as_ptr().cast_mut(),
            source_key.len(),
        )
    };
    let request = request_from(&mut raw);
    let headers = request.headers_in().unwrap();
    let source = headers.iter().find(|header| header.key() == source_key).unwrap();
    assert_eq!(source.value(), source_value);
    assert_eq!(source.lowercase_key(), Some(expected_lowcase.as_slice()));
    assert_eq!(source.hash(), expected_hash);
    assert_ne!(source.key().as_ptr(), source_key.as_ptr());
    assert_ne!(source.value().as_ptr(), source_value.as_ptr());
    assert_eq!(headers.iter().filter(|header| header.key() == b"X-Duplicate").count(), 2);

    assert_eq!(raw.headers_in.count, standard_headers.len() + 3);
    assert_eq!(
        unsafe { checked_ngx_str(raw.headers_in.server) }.unwrap().as_bytes(),
        b"example.test"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.host).value) }.unwrap().as_bytes(),
        b"example.test"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.content_length).value) }.unwrap().as_bytes(),
        b"7"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.content_type).value) }.unwrap().as_bytes(),
        b"application/test"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.user_agent).value) }.unwrap().as_bytes(),
        b"agent"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.referer).value) }.unwrap().as_bytes(),
        b"https://example.test/"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.authorization).value) }.unwrap().as_bytes(),
        b"Basic token"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.proxy_authorization).value) }.unwrap().as_bytes(),
        b"Basic proxy"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.cookie).value) }.unwrap().as_bytes(),
        b"a=b"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.expect).value) }.unwrap().as_bytes(),
        b"100-continue"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.range).value) }.unwrap().as_bytes(),
        b"bytes=0-1"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.if_modified_since).value) }.unwrap().as_bytes(),
        b"Wed, 21 Oct 2015 07:28:00 GMT"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.if_unmodified_since).value) }.unwrap().as_bytes(),
        b"Wed, 21 Oct 2015 07:28:00 GMT"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.if_match).value) }.unwrap().as_bytes(),
        b"one"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.if_none_match).value) }.unwrap().as_bytes(),
        b"two"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.if_range).value) }.unwrap().as_bytes(),
        b"three"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.content_range).value) }.unwrap().as_bytes(),
        b"bytes 0-1/2"
    );
    assert_eq!(raw.headers_in.content_length_n, -1);
    assert_eq!(raw.headers_in.keep_alive_n, -1);
}

#[cfg(feature = "test-link")]
#[test]
fn input_header_builder_terminates_nonempty_and_empty_native_storage() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    {
        let mut request = request_from(&mut raw);
        let mut headers = unsafe { request.headers_in_builder(2) }.unwrap();
        headers.add(b"Host", b"example.test").unwrap();
        headers.add(b"User-Agent", b"").unwrap();
        headers.commit();
    }

    unsafe {
        for header in [&*raw.headers_in.host, &*raw.headers_in.user_agent] {
            assert!(!header.key.data.is_null());
            assert!(!header.value.data.is_null());
            assert_eq!(*header.key.data.add(header.key.len), 0);
            assert_eq!(*header.value.data.add(header.value.len), 0);
        }
    }
}

#[cfg(feature = "test-link")]
#[test]
fn output_header_builder_binds_slots_and_preserves_response_state() {
    let owner = TestPool::new();
    let content_type = b"application/test";
    let status_line = b"201 Created";
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.headers_out.status = 201;
    raw.headers_out.status_line =
        ngx_str_t { len: status_line.len(), data: status_line.as_ptr().cast_mut() };
    raw.headers_out.content_length_n = 91;
    raw.headers_out.content_offset = 7;
    raw.headers_out.date_time = 11;
    raw.headers_out.last_modified_time = 13;

    let standard_headers = [
        (b"Server".as_slice(), b"ngx".as_slice()),
        (b"Date".as_slice(), b"Wed, 21 Oct 2015 07:28:00 GMT".as_slice()),
        (b"Content-Encoding".as_slice(), b"identity".as_slice()),
        (b"Location".as_slice(), b"/next".as_slice()),
        (b"Refresh".as_slice(), b"1".as_slice()),
        (b"Last-Modified".as_slice(), b"Wed, 21 Oct 2015 07:28:00 GMT".as_slice()),
        (b"Content-Range".as_slice(), b"bytes 0-1/2".as_slice()),
        (b"Accept-Ranges".as_slice(), b"bytes".as_slice()),
        (b"WWW-Authenticate".as_slice(), b"Basic".as_slice()),
        (b"Proxy-Authenticate".as_slice(), b"Basic".as_slice()),
        (b"Expires".as_slice(), b"0".as_slice()),
        (b"ETag".as_slice(), b"tag".as_slice()),
        (b"Cache-Control".as_slice(), b"no-cache".as_slice()),
        (b"Link".as_slice(), b"</next>; rel=next".as_slice()),
    ];

    {
        let mut request = request_from(&mut raw);
        let mut headers = request.headers_out_builder(1).unwrap();
        headers.add(b"Content-Type", content_type).unwrap();
        headers.set_content_length(91).unwrap();
        for (key, value) in standard_headers {
            headers.add(key, value).unwrap();
        }
        headers.add(b"X-Duplicate", b"one").unwrap();
        headers.add(b"X-Duplicate", b"two").unwrap();
        headers.commit();
    }

    assert_eq!(raw.headers_out.status, 201);
    assert_eq!(raw.headers_out.status_line.len, status_line.len());
    assert_eq!(raw.headers_out.status_line.data, status_line.as_ptr().cast_mut());
    assert_eq!(raw.headers_out.content_length_n, 91);
    assert_eq!(raw.headers_out.content_offset, 7);
    assert_eq!(raw.headers_out.date_time, 11);
    assert_eq!(raw.headers_out.last_modified_time, 13);
    assert_eq!(
        unsafe { checked_ngx_str(raw.headers_out.content_type) }.unwrap().as_bytes(),
        content_type
    );
    assert_eq!(raw.headers_out.content_type_len, content_type.len());
    assert_ne!(raw.headers_out.content_type.data, content_type.as_ptr().cast_mut());
    assert!(raw.headers_out.content_type_lowcase.is_null());
    assert_eq!(raw.headers_out.content_type_hash, 0);
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.server).value) }.unwrap().as_bytes(),
        b"ngx"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.date).value) }.unwrap().as_bytes(),
        b"Wed, 21 Oct 2015 07:28:00 GMT"
    );
    assert!(raw.headers_out.content_length.is_null());
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.content_encoding).value) }.unwrap().as_bytes(),
        b"identity"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.location).value) }.unwrap().as_bytes(),
        b"/next"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.refresh).value) }.unwrap().as_bytes(),
        b"1"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.last_modified).value) }.unwrap().as_bytes(),
        b"Wed, 21 Oct 2015 07:28:00 GMT"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.content_range).value) }.unwrap().as_bytes(),
        b"bytes 0-1/2"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.accept_ranges).value) }.unwrap().as_bytes(),
        b"bytes"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.www_authenticate).value) }.unwrap().as_bytes(),
        b"Basic"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.proxy_authenticate).value) }.unwrap().as_bytes(),
        b"Basic"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.expires).value) }.unwrap().as_bytes(),
        b"0"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.etag).value) }.unwrap().as_bytes(),
        b"tag"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.cache_control).value) }.unwrap().as_bytes(),
        b"no-cache"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.link).value) }.unwrap().as_bytes(),
        b"</next>; rel=next"
    );

    let request = request_from(&mut raw);
    let headers = request.headers_out().unwrap();
    assert_eq!(
        headers
            .iter()
            .filter(|header| {
                header.key().eq_ignore_ascii_case(b"Content-Type")
                    || header.key().eq_ignore_ascii_case(b"Content-Length")
                    || header.key().eq_ignore_ascii_case(b"Transfer-Encoding")
            })
            .count(),
        0
    );
    assert_eq!(headers.iter().filter(|header| header.key() == b"X-Duplicate").count(), 2);
}

#[cfg(feature = "test-link")]
#[test]
fn output_header_builders_require_typed_framing_without_partial_publication() {
    for clean in [false, true] {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        create_header_list(&mut raw.headers_out.headers, owner.raw, 1).unwrap();
        append_pool_header(&mut raw.headers_out.headers, owner.raw, b"X-Original", b"kept")
            .unwrap();
        raw.headers_out.content_length_n = 91;

        {
            let mut request = request_from(&mut raw);
            let mut headers = if clean {
                request.clean_headers_out_builder(1).unwrap()
            } else {
                request.headers_out_builder(1).unwrap()
            };
            assert_eq!(
                headers.add(b"Content-Length", b"7"),
                Err(HeaderBuildError::ManagedOutputFraming)
            );
            assert_eq!(
                headers.add(b"Transfer-Encoding", b"chunked"),
                Err(HeaderBuildError::ManagedOutputFraming)
            );
        }

        assert_eq!(raw.headers_out.content_length_n, 91);
        let request = request_from(&mut raw);
        let header_list = request.headers_out().unwrap();
        let headers = header_list.iter().collect::<Vec<_>>();
        assert_eq!(headers.len(), 1);
        assert_eq!(
            (headers[0].key(), headers[0].value()),
            (b"X-Original".as_slice(), b"kept".as_slice())
        );
    }
}

#[cfg(feature = "test-link")]
#[test]
fn typed_output_content_length_synchronizes_builder_and_direct_state() {
    for clean in [false, true] {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        raw.headers_out.content_length_n = 91;

        {
            let mut request = request_from(&mut raw);
            let mut headers = if clean {
                request.clean_headers_out_builder(1).unwrap()
            } else {
                request.headers_out_builder(1).unwrap()
            };
            headers.set_content_length(7).unwrap();
            headers.commit();
        }

        assert_eq!(raw.headers_out.content_length_n, 7);
        assert!(raw.headers_out.content_length.is_null());
        assert!(request_from(&mut raw).headers_out().unwrap().is_empty());
    }

    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    create_header_list(&mut raw.headers_out.headers, owner.raw, 2).unwrap();
    let content_length =
        append_pool_header(&mut raw.headers_out.headers, owner.raw, b"Content-Length", b"91")
            .unwrap();
    let transfer_encoding = append_pool_header(
        &mut raw.headers_out.headers,
        owner.raw,
        b"Transfer-Encoding",
        b"chunked",
    )
    .unwrap();
    raw.headers_out.content_length = content_length.as_ptr();
    raw.headers_out.content_length_n = 91;
    raw.set_chunked(1);

    let mut request = request_from(&mut raw);
    request.set_content_length_n(7).unwrap();

    assert_eq!(raw.headers_out.content_length_n, 7);
    assert!(raw.headers_out.content_length.is_null());
    assert_eq!(raw.chunked(), 0);
    assert_eq!(unsafe { (*content_length.as_ptr()).hash }, 0);
    assert_eq!(unsafe { (*transfer_encoding.as_ptr()).hash }, 0);
}

#[cfg(feature = "test-link")]
#[test]
fn direct_output_header_add_rejects_native_framing_ownership() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    create_header_list(&mut raw.headers_out.headers, owner.raw, 1).unwrap();

    let mut request = request_from(&mut raw);
    assert_eq!(
        request.add_header_out("Content-Length", "invalid"),
        Err(RequestError::ManagedOutputFraming)
    );
    assert_eq!(
        request.add_header_out("Transfer-Encoding", "chunked"),
        Err(RequestError::ManagedOutputFraming)
    );
    assert!(request.headers_out().unwrap().is_empty());
}

#[cfg(feature = "test-link")]
#[test]
fn output_header_builder_publishes_trailers_and_expectation() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    create_header_list(&mut raw.headers_out.trailers, owner.raw, 1).unwrap();

    {
        let mut request = request_from(&mut raw);
        let mut headers = request.clean_headers_out_builder(1).unwrap();
        headers.add_trailer(b"Digest", b"sha-256=value").unwrap();
        headers.add_trailer(b"X-Trace", b"one").unwrap();
        headers.commit();
    }

    assert!(request_from(&mut raw).expect_trailers());
    let request = request_from(&mut raw);
    let trailers = request.trailers_out().unwrap();
    let mut trailers = trailers.iter();
    let digest = trailers.next().expect("Digest trailer");
    assert_eq!((digest.key(), digest.value()), (b"Digest".as_slice(), b"sha-256=value".as_slice()));
    let trace = trailers.next().expect("X-Trace trailer");
    assert_eq!((trace.key(), trace.value()), (b"X-Trace".as_slice(), b"one".as_slice()));
    assert!(trailers.next().is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn output_trailer_builder_replaces_only_the_trailer_set() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.headers_out.status = 201;

    {
        let mut request = request_from(&mut raw);
        let mut trailers = request.trailers_out_builder(1).unwrap();
        trailers.add(b"X-Original", b"old").unwrap();
        trailers.commit();
    }
    {
        let mut request = request_from(&mut raw);
        let mut trailers = request.trailers_out_builder(1).unwrap();
        trailers.add(b"Digest", b"sha-256=value").unwrap();
        trailers.add(b"X-Trace", b"one").unwrap();
        trailers.commit();
    }

    assert_eq!(raw.headers_out.status, 201);
    assert!(request_from(&mut raw).expect_trailers());
    let request = request_from(&mut raw);
    let trailers = request.trailers_out().unwrap();
    let fields = trailers
        .iter()
        .map(|trailer| (trailer.key().to_vec(), trailer.value().to_vec()))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            (b"Digest".to_vec(), b"sha-256=value".to_vec()),
            (b"X-Trace".to_vec(), b"one".to_vec()),
        ]
    );

    {
        let mut request = request_from(&mut raw);
        request.trailers_out_builder(1).unwrap().commit();
    }
    assert_eq!(raw.headers_out.status, 201);
    assert!(!request_from(&mut raw).expect_trailers());
    assert!(request_from(&mut raw).trailers_out().unwrap().iter().next().is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn abandoned_clean_output_header_candidate_does_not_mutate_live_trailers() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    {
        let mut request = request_from(&mut raw);
        let mut trailers = request.trailers_out_builder(1).unwrap();
        trailers.add(b"X-Original", b"old").unwrap();
        trailers.commit();
    }
    {
        let mut request = request_from(&mut raw);
        let mut headers = request.clean_headers_out_builder(1).unwrap();
        headers.add_trailer(b"X-Candidate", b"new").unwrap();
    }

    let request = request_from(&mut raw);
    let trailers = request.trailers_out().unwrap();
    let trailer = trailers.iter().next().expect("original trailer");
    assert_eq!((trailer.key(), trailer.value()), (b"X-Original".as_slice(), b"old".as_slice()));
}

#[cfg(feature = "test-link")]
#[test]
fn output_header_builder_resets_response_metadata_on_request() {
    let owner = TestPool::new();
    let status_line = b"201 Created";
    let mut override_charset = ngx_str_t::empty();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.headers_out.status = 201;
    raw.headers_out.status_line =
        ngx_str_t { len: status_line.len(), data: status_line.as_ptr().cast_mut() };
    raw.headers_out.override_charset = &raw mut override_charset;
    raw.headers_out.content_length_n = 91;
    raw.headers_out.content_offset = 7;
    raw.headers_out.date_time = 11;
    raw.headers_out.last_modified_time = 13;
    request_from(&mut raw).set_expect_trailers(true);

    {
        let mut request = request_from(&mut raw);
        let mut headers = request.clean_headers_out_builder(1).unwrap();
        headers.add(b"Content-Type", b"text/plain").unwrap();
        headers.add(b"Location", b"/next").unwrap();
        headers.commit();
    }

    assert_eq!(raw.headers_out.status, 0);
    assert!(raw.headers_out.status_line.data.is_null());
    assert_eq!(raw.headers_out.status_line.len, 0);
    assert!(raw.headers_out.override_charset.is_null());
    assert_eq!(raw.headers_out.content_length_n, -1);
    assert_eq!(raw.headers_out.content_offset, 0);
    assert_eq!(raw.headers_out.date_time, 0);
    assert_eq!(raw.headers_out.last_modified_time, -1);
    assert!(!request_from(&mut raw).expect_trailers());
    assert_eq!(raw.headers_out.trailers.part.nelts, 0);
    assert!(raw.headers_out.trailers.part.next.is_null());
    assert_eq!(raw.headers_out.trailers.last, &raw mut raw.headers_out.trailers.part);
    assert_eq!(
        unsafe { checked_ngx_str(raw.headers_out.content_type) }.unwrap().as_bytes(),
        b"text/plain"
    );
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_out.location).value) }.unwrap().as_bytes(),
        b"/next"
    );
}

#[cfg(feature = "test-link")]
#[test]
fn request_pool_prepares_a_body_before_output_headers_commit() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    let mut request = request_from(&mut raw);
    let pool = request.pool().unwrap();
    let buffer = pool.copy_buffer(b"body", BufferFlags::default()).unwrap();
    let mut body = pool.chain();
    body.append(buffer).unwrap();
    let body = body.into_raw();

    {
        let mut headers = request.clean_headers_out_builder(1).unwrap();
        headers.add(b"Content-Type", b"text/plain").unwrap();
        headers.commit();
    }

    assert!(!body.is_null());
}

#[cfg(feature = "test-link")]
#[test]
fn request_body_builder_copies_bytes_and_replaces_framing() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    {
        let mut request = request_from(&mut raw);
        let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
        headers.add(b"Host", b"example.test").unwrap();
        headers.add(b"Content-Length", b"99").unwrap();
        headers.add(b"Transfer-Encoding", b"chunked").unwrap();
        headers.commit();
    }

    raw.headers_in.content_length_n = 99;
    raw.headers_in.set_chunked(1);
    let mut previous_body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut previous_temp_file: ngx_temp_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    previous_body.temp_file = &raw mut previous_temp_file;
    raw.request_body = &raw mut previous_body;
    let mut bytes = *b"new";
    {
        let mut request = request_from(&mut raw);
        let mut body = request.request_body_builder().unwrap();
        body.append_copy(&bytes).unwrap();
        bytes.fill(b'!');
        body.commit().unwrap();
    }

    assert!(!raw.request_body.is_null());
    assert!(!ptr::eq(raw.request_body, &raw mut previous_body));
    assert!(unsafe { (*raw.request_body).temp_file }.is_null());
    assert_eq!(raw.headers_in.content_length_n, 3);
    assert_eq!(raw.headers_in.chunked(), 0);
    assert!(raw.headers_in.transfer_encoding.is_null());
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.content_length).value) }.unwrap().as_bytes(),
        b"3"
    );

    let request = request_from(&mut raw);
    let body = request.request_body().unwrap().unwrap();
    assert_eq!(body.size().unwrap().bytes(), 3);
    assert_eq!(
        body.chain().unwrap().iter().next().unwrap().unwrap().bytes(),
        Ok(Some(b"new".as_slice()))
    );
    let headers = request.headers_in().unwrap();
    let fields = headers
        .iter()
        .map(|header| (header.key().to_vec(), header.value().to_vec()))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            (b"Host".to_vec(), b"example.test".to_vec()),
            (b"Content-Length".to_vec(), b"3".to_vec()),
        ]
    );
}

#[cfg(feature = "test-link")]
#[test]
fn request_body_framing_keeps_builtin_slots_in_the_live_header_list() {
    fn assert_slots_are_live(raw: &ngx_http_request_t, expect_multiple_parts: bool) {
        let headers =
            checked_header_list(&raw.headers_in.headers, HttpHeaderSource::Input).unwrap();
        let entries = unsafe { NgxList::<ngx_table_elt_t>::raw_iter(headers.headers).unwrap() }
            .map(NonNull::as_ptr)
            .collect::<Vec<_>>();
        let second_cookie = unsafe { (*raw.headers_in.cookie).next };

        assert_eq!(!raw.headers_in.headers.part.next.is_null(), expect_multiple_parts);
        for slot in [
            raw.headers_in.host,
            raw.headers_in.user_agent,
            raw.headers_in.authorization,
            raw.headers_in.cookie,
            second_cookie,
            raw.headers_in.content_length,
        ] {
            assert!(!slot.is_null());
            assert!(entries.contains(&slot));
        }
    }

    for capacity in [10, 2] {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;

        {
            let mut request = request_from(&mut raw);
            let mut headers = unsafe { request.headers_in_builder(capacity) }.unwrap();
            headers.add(b"Host", b"example.test").unwrap();
            headers.add(b"User-Agent", b"agent").unwrap();
            headers.add(b"Authorization", b"scheme token").unwrap();
            headers.add(b"Cookie", b"first=1").unwrap();
            headers.add(b"Cookie", b"second=2").unwrap();
            headers.add(b"Content-Length", b"99").unwrap();
            headers.add(b"Transfer-Encoding", b"chunked").unwrap();
            headers.commit();

            let mut body = request.request_body_builder().unwrap();
            body.append_copy(b"body").unwrap();
            body.commit().unwrap();
        }
        assert_slots_are_live(&raw, capacity == 2);

        request_from(&mut raw).clear_request_body().unwrap();
        assert_slots_are_live(&raw, capacity == 2);
    }
}

#[cfg(feature = "test-link")]
#[test]
fn input_header_builder_publishes_replacement_body_and_framing_together() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    let mut previous_body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut previous_temp_file: ngx_temp_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    previous_body.temp_file = &raw mut previous_temp_file;
    raw.request_body = &raw mut previous_body;

    {
        let mut request = request_from(&mut raw);
        let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
        headers.add(b"Host", b"example.test").unwrap();
        headers.add(b"X-Keep", b"kept").unwrap();
        headers.add(b"Content-Length", b"99").unwrap();
        headers.add(b"Transfer-Encoding", b"chunked").unwrap();
        let mut body = headers.request_body_candidate().unwrap();
        body.append_copy(b"replacement").unwrap();
        headers.commit_with_body(body).unwrap();
    }

    assert!(!raw.request_body.is_null());
    assert!(!ptr::eq(raw.request_body, &raw mut previous_body));
    assert!(unsafe { (*raw.request_body).temp_file }.is_null());
    assert_eq!(raw.headers_in.count, 5);
    assert_eq!(raw.headers_in.content_length_n, 11);
    assert_eq!(raw.headers_in.chunked(), 0);
    assert!(raw.headers_in.transfer_encoding.is_null());
    assert_eq!(
        unsafe { checked_ngx_str((*raw.headers_in.content_length).value) }.unwrap().as_bytes(),
        b"11"
    );

    let request = request_from(&mut raw);
    let body = request.request_body().unwrap().unwrap();
    assert_eq!(body.size().unwrap().bytes(), 11);
    assert_eq!(
        body.chain().unwrap().iter().next().unwrap().unwrap().bytes(),
        Ok(Some(b"replacement".as_slice()))
    );
    let headers = request.headers_in().unwrap();
    let fields = headers
        .iter()
        .map(|header| (header.key().to_vec(), header.value().to_vec(), header.is_enabled()))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            (b"Host".to_vec(), b"example.test".to_vec(), true),
            (b"X-Keep".to_vec(), b"kept".to_vec(), true),
            (b"Content-Length".to_vec(), b"11".to_vec(), true),
        ]
    );
    let content_length = headers
        .iter()
        .find(|header| header.is_enabled() && header.key() == b"Content-Length")
        .unwrap();
    assert_eq!(content_length.lowercase_key(), Some(b"content-length".as_slice()));
    assert_ne!(content_length.hash(), 0);
    unsafe {
        let content_length = &*raw.headers_in.content_length;
        assert_eq!(*content_length.key.data.add(content_length.key.len), 0);
        assert_eq!(*content_length.value.data.add(content_length.value.len), 0);
    }
}

#[cfg(feature = "test-link")]
#[test]
fn input_header_builder_clears_body_and_replaces_framing_together() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    let mut previous_temp_file: ngx_temp_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut previous_buffer: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut previous_chain: ngx_chain_t = unsafe { MaybeUninit::zeroed().assume_init() };
    previous_chain.buf = &raw mut previous_buffer;
    let mut previous_body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    previous_body.temp_file = &raw mut previous_temp_file;
    previous_body.bufs = &raw mut previous_chain;
    raw.request_body = &raw mut previous_body;

    {
        let mut request = request_from(&mut raw);
        let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
        headers.add(b"Host", b"example.test").unwrap();
        headers.add(b"X-Keep", b"kept").unwrap();
        headers.add(b"Content-Length", b"99").unwrap();
        headers.add(b"Transfer-Encoding", b"chunked").unwrap();
        headers.commit_without_body().unwrap();
    }

    assert!(raw.request_body.is_null());
    assert_eq!(raw.headers_in.count, 5);
    assert_eq!(raw.headers_in.content_length_n, 0);
    assert_eq!(raw.headers_in.chunked(), 0);
    assert!(raw.headers_in.transfer_encoding.is_null());

    let request = request_from(&mut raw);
    let headers = request.headers_in().unwrap();
    let fields = headers
        .iter()
        .map(|header| (header.key().to_vec(), header.value().to_vec(), header.is_enabled()))
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            (b"Host".to_vec(), b"example.test".to_vec(), true),
            (b"X-Keep".to_vec(), b"kept".to_vec(), true),
            (b"Content-Length".to_vec(), b"0".to_vec(), true),
        ]
    );
    let content_length = headers
        .iter()
        .find(|header| header.is_enabled() && header.key() == b"Content-Length")
        .unwrap();
    assert_eq!(content_length.lowercase_key(), Some(b"content-length".as_slice()));
    assert_ne!(content_length.hash(), 0);
}

#[cfg(feature = "test-link")]
#[test]
fn input_header_builder_publishes_body_with_an_empty_header_list() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    {
        let mut request = request_from(&mut raw);
        let headers = unsafe { request.headers_in_builder(1) }.unwrap();
        let mut body = headers.request_body_candidate().unwrap();
        body.append_copy(b"body").unwrap();
        headers.commit_with_body(body).unwrap();
    }

    assert_eq!(raw.headers_in.count, 1);
    assert_eq!(raw.headers_in.content_length_n, 4);
    assert_eq!(raw.headers_in.chunked(), 0);
    assert!(raw.headers_in.transfer_encoding.is_null());
    let request = request_from(&mut raw);
    let headers = request.headers_in().unwrap();
    let content_length = headers.iter().next().unwrap();
    assert_eq!(content_length.key(), b"Content-Length");
    assert_eq!(content_length.value(), b"4");
    assert_eq!(content_length.lowercase_key(), Some(b"content-length".as_slice()));
    assert_ne!(content_length.hash(), 0);
    let body = request.request_body().unwrap().unwrap();
    assert_eq!(body.size().unwrap().bytes(), 4);
    assert_eq!(
        body.chain().unwrap().iter().next().unwrap().unwrap().bytes(),
        Ok(Some(b"body".as_slice()))
    );
}

#[cfg(feature = "test-link")]
#[test]
fn input_header_builder_keeps_live_request_when_combined_body_allocation_fails() {
    let mut reached_success = false;

    for successes in 0..64 {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        {
            let mut request = request_from(&mut raw);
            let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
            headers.add(b"Host", b"example.test").unwrap();
            headers.add(b"Content-Length", b"7").unwrap();
            headers.add(b"Transfer-Encoding", b"chunked").unwrap();
            headers.commit();
        }
        raw.headers_in.content_length_n = 7;
        raw.headers_in.set_chunked(1);
        let mut previous_temp_file: ngx_temp_file_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
        let mut previous_body: ngx_http_request_body_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
        previous_body.temp_file = &raw mut previous_temp_file;
        raw.request_body = &raw mut previous_body;
        let original = (
            raw.request_body,
            raw.headers_in.headers.part.elts,
            raw.headers_in.headers.part.nelts,
            raw.headers_in.headers.part.next,
            raw.headers_in.headers.last,
            raw.headers_in.headers.size,
            raw.headers_in.headers.nalloc,
            raw.headers_in.headers.pool,
            raw.headers_in.content_length,
            raw.headers_in.transfer_encoding,
            raw.headers_in.count,
            raw.headers_in.content_length_n,
        );
        let original_host = raw.headers_in.host;
        let original_chunked = raw.headers_in.chunked();

        unsafe {
            (*owner.raw).max = 0;
            ngx_rs_test_fail_allocations_after(successes);
        }
        let result = (|| -> Result<(), RequestBodyBuildError> {
            let mut request = request_from(&mut raw);
            let mut headers = unsafe { request.headers_in_builder(1) }?;
            headers.add(b"Host", b"replacement.test")?;
            headers.add(b"X-Replaced", b"yes")?;
            let mut body = headers.request_body_candidate()?;
            body.append_copy(b"replacement")?;
            headers.commit_with_body(body)
        })();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        if result.is_ok() {
            reached_success = true;
            break;
        }
        assert!(matches!(
            result,
            Err(RequestBodyBuildError::HeaderBuild(HeaderBuildError::Allocation)
                | RequestBodyBuildError::Buffer(BufferError::Allocation)
                | RequestBodyBuildError::Chain(ChainError::Allocation)
                | RequestBodyBuildError::Allocation)
        ));
        assert_eq!(
            (
                raw.request_body,
                raw.headers_in.headers.part.elts,
                raw.headers_in.headers.part.nelts,
                raw.headers_in.headers.part.next,
                raw.headers_in.headers.last,
                raw.headers_in.headers.size,
                raw.headers_in.headers.nalloc,
                raw.headers_in.headers.pool,
                raw.headers_in.content_length,
                raw.headers_in.transfer_encoding,
                raw.headers_in.count,
                raw.headers_in.content_length_n,
            ),
            original
        );
        assert_eq!(raw.headers_in.host, original_host);
        assert_eq!(raw.headers_in.chunked(), original_chunked);
    }

    assert!(reached_success);
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_rejects_missing_pool_configuration_path_and_log() {
    {
        let mut fixture = TempFileFixture::new();
        fixture.request.pool = ptr::null_mut();
        assert!(matches!(
            request_from(&mut fixture.request).temp_file(),
            Err(RequestTempFileError::Request(RequestError::MissingPool))
        ));
    }

    {
        let mut fixture = TempFileFixture::new();
        fixture.request.loc_conf = ptr::null_mut();
        assert!(matches!(
            request_from(&mut fixture.request).temp_file(),
            Err(RequestTempFileError::MissingCoreLocationConfiguration)
        ));
    }

    {
        let mut fixture = TempFileFixture::new();
        fixture.core.client_body_temp_path = ptr::null_mut();
        assert!(matches!(
            request_from(&mut fixture.request).temp_file(),
            Err(RequestTempFileError::MissingTempPath)
        ));
    }

    {
        let mut fixture = TempFileFixture::new();
        fixture.connection.log = ptr::null_mut();
        assert!(matches!(
            request_from(&mut fixture.request).temp_file(),
            Err(RequestTempFileError::MissingLog)
        ));
    }

    {
        let mut fixture = TempFileFixture::new();
        unsafe { nginx_sys::ngx_http_core_module.type_ = NGX_CORE_MODULE as _ };
        assert!(matches!(
            request_from(&mut fixture.request).temp_file(),
            Err(RequestTempFileError::Configuration(HttpConfigError::WrongModuleType))
        ));
    }
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_reuses_stable_metadata_with_clean_pool_cleanup() {
    let deleted_path;
    #[cfg(unix)]
    let fd;
    {
        let mut fixture = TempFileFixture::new();
        {
            let flags = BufferFlags { flush: true, last_in_chain: true, ..BufferFlags::default() };
            let request = request_from(&mut fixture.request);
            let pool = request.pool().unwrap();
            let mut input = pool.chain();
            input.append(pool.copy_buffer(b"body", flags).unwrap()).unwrap();
            let mut writer = request.temp_file().unwrap();

            assert!(writer.state.temp_file.is_none());

            let output = writer.append(chain_ref(input)).unwrap();
            let temp = writer.state.temp_file.unwrap();
            let native = unsafe { temp.as_ref() };
            assert_ne!(native.file.fd, NGX_INVALID_FILE as _);
            assert_eq!(native.offset, 4);
            assert_eq!(native.access, 0o600);
            assert_eq!(native.clean(), 1);

            let output_buffer = output.iter().next().unwrap().unwrap();
            assert_eq!(output_buffer.flags(), flags);
            let output_file = output_buffer.file().unwrap().unwrap();
            assert_eq!(output_file.start(), 0);
            assert_eq!(output_file.end(), 4);
            assert_eq!(unsafe { (*output_file.file_ptr()).fd }, native.file.fd);
            let native_file = unsafe { &raw mut (*temp.as_ptr()).file };
            assert_eq!(output_file.file_ptr(), native_file);
            assert!(output.iter().nth(1).is_none());

            let path = temp_file_path(native);
            assert!(!path.exists());
            #[cfg(unix)]
            {
                let file = ManuallyDrop::new(unsafe { File::from_raw_fd(native.file.fd) });
                assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
                assert_eq!(temp_file_bytes(native), b"body");
            }
            deleted_path = path;
            #[cfg(unix)]
            {
                fd = native.file.fd;
            }
        }

        let TempFileFixture { pool, temp_dir, .. } = fixture;
        drop(pool);
        assert!(!deleted_path.exists());
        #[cfg(unix)]
        assert_eq!(unsafe { fcntl(fd, F_GETFD) }, -1);
        drop(temp_dir);
    }
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_keeps_zero_and_multiple_append_offsets() {
    let mut fixture = TempFileFixture::new();
    let zero_flags = BufferFlags { sync: true, ..BufferFlags::default() };
    let second_flags = BufferFlags { flush: true, last_buf: true, ..BufferFlags::default() };
    let request = request_from(&mut fixture.request);
    let pool = request.pool().unwrap();
    let mut empty_input = pool.chain();
    empty_input.append(pool.temporary_buffer(1, zero_flags).unwrap()).unwrap();
    let mut first_input = pool.chain();
    first_input.append(pool.copy_buffer(b"one", BufferFlags::default()).unwrap()).unwrap();
    let mut second_input = pool.chain();
    second_input.append(pool.copy_buffer(b"two", second_flags).unwrap()).unwrap();
    let mut writer = request.temp_file().unwrap();

    let empty_output = writer.append(chain_ref(empty_input)).unwrap();
    assert!(writer.state.temp_file.is_none());
    let empty_output = empty_output.iter().next().unwrap().unwrap();
    assert_eq!(empty_output.flags(), zero_flags);
    assert!(matches!(empty_output.kind(), Ok(BufferView::Control(_))));

    let first_output = writer.append(chain_ref(first_input)).unwrap();
    let second_output = writer.append(chain_ref(second_input)).unwrap();
    let temp = writer.state.temp_file.unwrap();
    let native = unsafe { temp.as_ref() };
    assert_eq!(native.offset, 6);
    assert_eq!(first_output.iter().next().unwrap().unwrap().file().unwrap().unwrap().start(), 0);
    let second_output = second_output.iter().next().unwrap().unwrap();
    let second_file = second_output.file().unwrap().unwrap();
    assert_eq!(second_file.start(), 3);
    assert_eq!(second_file.end(), 6);
    assert_eq!(second_output.flags(), second_flags);
    #[cfg(unix)]
    assert_eq!(temp_file_bytes(native), b"onetwo");
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_state_reuses_one_pool_owned_handle_across_callback_scopes() {
    let mut fixture = TempFileFixture::new();
    let mut state = {
        let request = request_from(&mut fixture.request);
        let pool = request.pool().unwrap();
        pool.allocate_with_cleanup(|| request.temp_file_state().unwrap()).unwrap().into_non_null()
    };

    let first = unsafe {
        RequestRefMut::with_raw(&raw mut fixture.request, |request| {
            let pool = request.pool().unwrap();
            let input = pool.copy_buffer(b"one", BufferFlags::default()).unwrap();
            let output =
                state.as_mut().append_buffer(&request, input.view(), input.view().flags()).unwrap();
            let file = output.iter().next().unwrap().unwrap().file().unwrap().unwrap();
            (file.start(), file.end())
        })
    }
    .unwrap();

    let second = unsafe {
        RequestRefMut::with_raw(&raw mut fixture.request, |request| {
            let pool = request.pool().unwrap();
            let input = pool.copy_buffer(b"two", BufferFlags::default()).unwrap();
            let output =
                state.as_mut().append_buffer(&request, input.view(), input.view().flags()).unwrap();
            let file = output.iter().next().unwrap().unwrap().file().unwrap().unwrap();
            (file.start(), file.end())
        })
    }
    .unwrap();

    let temp = unsafe { state.as_ref().temp_file.unwrap() };
    let native = unsafe { temp.as_ref() };
    assert_eq!(first, (0, 3));
    assert_eq!(second, (3, 6));
    assert_eq!(native.offset, 6);
    #[cfg(unix)]
    assert_eq!(temp_file_bytes(native), b"onetwo");
    let path = temp_file_path(native);
    #[cfg(unix)]
    let fd = native.file.fd;

    let TempFileFixture { pool, temp_dir, .. } = fixture;
    drop(pool);
    assert!(!path.exists());
    #[cfg(unix)]
    assert_eq!(unsafe { fcntl(fd, F_GETFD) }, -1);
    drop(temp_dir);
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_state_release_closes_and_disarms_the_pool_cleanup() {
    let mut fixture = TempFileFixture::new();
    let mut state = request_from(&mut fixture.request).temp_file_state().unwrap();
    unsafe {
        RequestRefMut::with_raw(&raw mut fixture.request, |request| {
            let pool = request.pool().unwrap();
            let input = pool.copy_buffer(b"body", BufferFlags::default()).unwrap();
            state.append_buffer(&request, input.view(), input.view().flags()).unwrap();
        })
    }
    .unwrap();
    let mut temp_file = state.temp_file.unwrap();
    let fd = unsafe { temp_file.as_ref().file.fd };
    #[cfg(unix)]
    assert_ne!(unsafe { fcntl(fd, F_GETFD) }, -1);

    unsafe { state.release(&request_from(&mut fixture.request)) }.unwrap();

    assert_eq!(unsafe { temp_file.as_mut().file.fd }, NGX_INVALID_FILE as _);
    #[cfg(unix)]
    assert_eq!(unsafe { fcntl(fd, F_GETFD) }, -1);
    let mut cleanup = unsafe { (*fixture.pool.raw).cleanup };
    let mut cleanup_still_armed = false;
    while let Some(current) = NonNull::new(cleanup) {
        let cleanup_ref = unsafe { current.as_ref() };
        cleanup = cleanup_ref.next;
        let Some(handler) = cleanup_ref.handler else {
            continue;
        };
        if !is_temp_file_cleanup_handler(handler) {
            continue;
        }
        let Some(file) = NonNull::new(cleanup_ref.data.cast::<ngx_pool_cleanup_file_t>()) else {
            continue;
        };
        if unsafe { file.as_ref().fd } == fd {
            cleanup_still_armed = true;
        }
    }
    assert!(!cleanup_still_armed);
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_state_release_reports_a_missing_pool_cleanup() {
    let mut fixture = TempFileFixture::new();
    let mut state = request_from(&mut fixture.request).temp_file_state().unwrap();
    unsafe {
        RequestRefMut::with_raw(&raw mut fixture.request, |request| {
            let pool = request.pool().unwrap();
            let input = pool.copy_buffer(b"body", BufferFlags::default()).unwrap();
            state.append_buffer(&request, input.view(), input.view().flags()).unwrap();
        })
    }
    .unwrap();
    let fd = unsafe { state.temp_file.unwrap().as_ref().file.fd };
    let mut cleanup = unsafe { (*fixture.pool.raw).cleanup };
    let (mut cleanup, handler) = loop {
        let mut current = NonNull::new(cleanup).expect("temp-file cleanup");
        let cleanup_ref = unsafe { current.as_mut() };
        cleanup = cleanup_ref.next;
        let Some(handler) = cleanup_ref.handler else {
            continue;
        };
        if !is_temp_file_cleanup_handler(handler) {
            continue;
        }
        let file = NonNull::new(cleanup_ref.data.cast::<ngx_pool_cleanup_file_t>())
            .expect("temp-file cleanup data");
        if unsafe { file.as_ref().fd } == fd {
            cleanup_ref.handler = None;
            break (current, handler);
        }
    };

    assert_eq!(
        unsafe { state.release(&request_from(&mut fixture.request)) },
        Err(RequestTempFileError::MissingCleanup)
    );
    #[cfg(unix)]
    assert_ne!(unsafe { fcntl(fd, F_GETFD) }, -1);
    unsafe { cleanup.as_mut().handler = Some(handler) };
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_state_release_without_a_created_file_is_a_noop() {
    let mut fixture = TempFileFixture::new();
    let state = request_from(&mut fixture.request).temp_file_state().unwrap();

    assert_eq!(unsafe { state.release(&request_from(&mut fixture.request)) }, Ok(()));
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_state_copies_a_short_buffer_reborrow() {
    let mut fixture = TempFileFixture::new();
    let mut state = request_from(&mut fixture.request).temp_file_state().unwrap();

    let offsets = unsafe {
        RequestRefMut::with_raw(&raw mut fixture.request, |request| {
            let pool = request.pool().unwrap();
            let input = pool.copy_buffer(b"body", BufferFlags::default()).unwrap();
            let output = state.append_buffer(&request, input.view(), input.view().flags()).unwrap();
            let file = output.iter().next().unwrap().unwrap().file().unwrap().unwrap();
            (file.start(), file.end())
        })
    }
    .unwrap();

    assert_eq!(offsets, (0, 4));
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_state_rejects_a_different_request() {
    let mut fixture = TempFileFixture::new();
    let mut state = request_from(&mut fixture.request).temp_file_state().unwrap();
    let mut other = zeroed_request();
    other.pool = fixture.pool.raw;
    other.connection = &raw mut *fixture.connection;
    other.loc_conf = fixture.request.loc_conf;
    initialize_request(&mut other);
    let request = request_from(&mut other);
    let pool = request.pool().unwrap();
    let input = pool.copy_buffer(b"body", BufferFlags::default()).unwrap();

    assert!(matches!(
        state.append_buffer(&request, input.view(), input.view().flags()),
        Err(RequestTempFileError::ForeignRequest)
    ));
    assert!(state.temp_file.is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_handle_rejects_stale_generation_before_pool_state_access() {
    let mut fixture = TempFileFixture::new();
    let mut state = request_from(&mut fixture.request).temp_file_state().unwrap();
    advance_request_generation(state.request);
    state.state.path = NonNull::dangling();
    state.state.log = NonNull::dangling();
    state.temp_file = Some(NonNull::dangling());
    let request = request_from(&mut fixture.request);
    let pool = request.pool().unwrap();
    let input = pool.control_buffer(BufferFlags::default()).unwrap();

    assert!(matches!(
        state.append_buffer(&request, input.view(), input.view().flags()),
        Err(RequestTempFileError::ForeignRequest)
    ));
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_handle_rejects_replaced_owner_at_the_same_request_addresses() {
    let mut fixture = TempFileFixture::new();
    let mut state = request_from(&mut fixture.request).temp_file_state().unwrap();
    let pool = unsafe { Pool::from_raw(fixture.pool.raw) }.unwrap();
    let main = NonNull::new(&raw mut fixture.request).unwrap();
    let registry = find_request_context_registry(NonNull::new(pool.as_ptr()).unwrap()).unwrap();
    let original_owner = unsafe { registry.as_ref().owner };
    remove_request_context_registry(&pool, registry, main);
    let (replacement, created) = get_or_create_request_context_registry(&pool, main).unwrap();
    assert!(created);
    assert_ne!(unsafe { replacement.as_ref().owner }, original_owner);
    assert_eq!(state.request, main);
    assert_eq!(state.pool, fixture.pool.raw);

    state.state.path = NonNull::dangling();
    state.state.log = NonNull::dangling();
    state.temp_file = Some(NonNull::dangling());
    let request = request_from(&mut fixture.request);
    let input = pool.control_buffer(BufferFlags::default()).unwrap();

    assert!(matches!(
        state.append_buffer(&request, input.view(), input.view().flags()),
        Err(RequestTempFileError::ForeignRequest)
    ));
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_copies_file_and_mixed_chain_segments_in_order() {
    let mut fixture = TempFileFixture::new();
    let memory_flags = BufferFlags { flush: true, ..BufferFlags::default() };
    let file_flags = BufferFlags { sync: true, ..BufferFlags::default() };
    let control_flags = BufferFlags { last_in_chain: true, ..BufferFlags::default() };
    let last_flags = BufferFlags { last_buf: true, ..BufferFlags::default() };
    let request = request_from(&mut fixture.request);
    let pool = request.pool().unwrap();
    let (file, source_file) = pool_file_buffer(&pool, 47, 7, 10, file_flags);
    let mut input = pool.chain();
    input.append(pool.copy_buffer(b"left", memory_flags).unwrap()).unwrap();
    input.append(file).unwrap();
    input.append(pool.control_buffer(control_flags).unwrap()).unwrap();
    input.append(pool.copy_buffer(b"right", last_flags).unwrap()).unwrap();
    let mut writer = request.temp_file().unwrap();

    let output = writer.append(chain_ref(input)).unwrap();
    let temp = writer.state.temp_file.unwrap();
    let native = unsafe { temp.as_ref() };
    assert_eq!(native.offset, 9);
    #[cfg(unix)]
    assert_eq!(temp_file_bytes(native), b"leftright");

    let mut output = output.iter();
    let first = output.next().unwrap().unwrap();
    assert_eq!(first.flags(), memory_flags);
    let first_file = first.file().unwrap().unwrap();
    assert_eq!((first_file.start(), first_file.end()), (0, 4));
    assert_eq!(unsafe { (*first_file.file_ptr()).fd }, native.file.fd);

    let file = output.next().unwrap().unwrap();
    assert_eq!(file.flags(), file_flags);
    let file_view = file.file().unwrap().unwrap();
    assert_eq!((file_view.start(), file_view.end()), (7, 10));
    assert_eq!(unsafe { (*file_view.file_ptr()).fd }, unsafe { source_file.as_ref().fd });
    assert_eq!(file_view.file_ptr(), source_file.as_ptr());

    let control = output.next().unwrap().unwrap();
    assert_eq!(control.flags(), control_flags);
    assert!(matches!(control.kind(), Ok(BufferView::Control(_))));

    let last = output.next().unwrap().unwrap();
    assert_eq!(last.flags(), last_flags);
    let last_file = last.file().unwrap().unwrap();
    assert_eq!((last_file.start(), last_file.end()), (4, 9));
    assert_eq!(unsafe { (*last_file.file_ptr()).fd }, native.file.fd);
    assert!(output.next().is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_copies_file_ranges_without_creating_a_temp_file() {
    let mut fixture = TempFileFixture::new();
    let flags = BufferFlags { sync: true, last_in_chain: true, ..BufferFlags::default() };
    let request = request_from(&mut fixture.request);
    let pool = request.pool().unwrap();
    let (file, source_file) = pool_file_buffer(&pool, 49, 11, 16, flags);
    let mut input = pool.chain();
    input.append(file).unwrap();
    let mut writer = request.temp_file().unwrap();

    let output = writer.append(chain_ref(input)).unwrap();
    assert!(writer.state.temp_file.is_none());
    let output = output.iter().next().unwrap().unwrap();
    assert_eq!(output.flags(), flags);
    let file = output.file().unwrap().unwrap();
    assert_eq!((file.start(), file.end()), (11, 16));
    assert_eq!(unsafe { (*file.file_ptr()).fd }, unsafe { source_file.as_ref().fd });
    assert_eq!(file.file_ptr(), source_file.as_ptr());
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_validates_all_input_before_writing() {
    let mut fixture = TempFileFixture::new();
    let request = request_from(&mut fixture.request);
    let pool = request.pool().unwrap();
    let (invalid, _) = pool_file_buffer(&pool, 48, -1, 1, BufferFlags::default());
    let mut input = pool.chain();
    input.append(pool.copy_buffer(b"valid", BufferFlags::default()).unwrap()).unwrap();
    input.append(invalid).unwrap();
    let mut writer = request.temp_file().unwrap();

    assert!(matches!(
        writer.append(chain_ref(input)),
        Err(RequestTempFileError::Buffer(BufferError::InvalidFileRange))
    ));
    assert!(writer.state.temp_file.is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_reports_numeric_short_open_and_write_failures() {
    assert_eq!(temp_file_range(-1, 0), Err(RequestTempFileError::NegativeOffset));
    assert_eq!(temp_file_range(off_t::MAX, 1), Err(RequestTempFileError::OffsetOverflow));
    assert_eq!(temp_file_range(0, usize::MAX), Err(RequestTempFileError::LengthOverflow));
    assert_eq!(
        check_temp_file_write(4, 3),
        Err(RequestTempFileError::ShortWrite { expected: 4, written: 3 })
    );

    {
        let mut fixture = TempFileFixture::new();
        let missing = fixture.temp_dir.path().join("missing");
        fixture.set_path(&missing);
        let request = request_from(&mut fixture.request);
        let pool = request.pool().unwrap();
        let mut input = pool.chain();
        input.append(pool.copy_buffer(b"body", BufferFlags::default()).unwrap()).unwrap();
        let mut writer = request.temp_file().unwrap();

        assert!(matches!(writer.append(chain_ref(input)), Err(RequestTempFileError::Write)));
        assert_eq!(
            unsafe { writer.state.temp_file.unwrap().as_ref().file.fd },
            NGX_INVALID_FILE as _
        );
    }

    {
        let mut fixture = TempFileFixture::new();
        let request = request_from(&mut fixture.request);
        let pool = request.pool().unwrap();
        let mut first_input = pool.chain();
        first_input.append(pool.copy_buffer(b"first", BufferFlags::default()).unwrap()).unwrap();
        let mut second_input = pool.chain();
        second_input.append(pool.copy_buffer(b"second", BufferFlags::default()).unwrap()).unwrap();
        let mut writer = request.temp_file().unwrap();
        writer.append(chain_ref(first_input)).unwrap();
        let mut temp = writer.state.temp_file.unwrap();
        let offset = unsafe { temp.as_ref().offset };
        let advanced_offset = offset + 2;
        unsafe {
            temp.as_mut().file.offset = advanced_offset;
            temp.as_mut().file.fd = NGX_INVALID_FILE as ngx_fd_t - 1;
        }

        assert!(matches!(writer.append(chain_ref(second_input)), Err(RequestTempFileError::Write)));
        assert_eq!(unsafe { temp.as_ref().offset }, advanced_offset);
    }
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_allocation_failures_do_not_return_partial_output() {
    let mut reached_success = false;

    for successes in 0..32 {
        let mut fixture = TempFileFixture::new();
        let request = request_from(&mut fixture.request);
        let pool = request.pool().unwrap();
        let mut input = pool.chain();
        input.append(pool.copy_buffer(b"body", BufferFlags::default()).unwrap()).unwrap();
        let input = chain_ref(input);
        unsafe {
            (*fixture.pool.raw).max = 0;
            ngx_rs_test_fail_allocations_after(successes);
        }
        let result = (|| -> Result<(), RequestTempFileError> {
            let mut writer = request.temp_file()?;
            writer.append(input).map(|_| ())
        })();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        if result.is_ok() {
            reached_success = true;
            break;
        }
    }

    assert!(reached_success);
}

#[cfg(feature = "test-link")]
#[test]
fn temp_file_writer_skips_unpublished_memory_after_output_allocation_failure() {
    let mut observed_unpublished_write = false;

    for successes in 0..32 {
        let mut fixture = TempFileFixture::new();
        let request = request_from(&mut fixture.request);
        let pool = request.pool().unwrap();
        let mut first_input = pool.chain();
        first_input.append(pool.copy_buffer(b"first", BufferFlags::default()).unwrap()).unwrap();
        let mut second_input = pool.chain();
        second_input.append(pool.copy_buffer(b"second", BufferFlags::default()).unwrap()).unwrap();
        let mut writer = request.temp_file().unwrap();

        unsafe {
            (*fixture.pool.raw).max = 0;
            ngx_rs_test_fail_allocations_after(successes);
        }
        let failed = writer.append(chain_ref(first_input));
        unsafe { ngx_rs_test_reset_allocation_failures() };

        let Some(temp) = writer.state.temp_file else {
            continue;
        };
        let start = unsafe { temp.as_ref().offset };
        if failed.is_ok() || start == 0 {
            continue;
        }

        let output = writer.append(chain_ref(second_input)).unwrap();
        let file = output.iter().next().unwrap().unwrap().file().unwrap().unwrap();
        assert_eq!((file.start(), file.end()), (start, start + 6));
        #[cfg(unix)]
        assert_eq!(temp_file_bytes(unsafe { temp.as_ref() }), b"firstsecond");
        observed_unpublished_write = true;
        break;
    }

    assert!(observed_unpublished_write);
}

#[test]
fn request_body_views_cover_absent_empty_and_control_chains() {
    let mut raw = zeroed_request();
    assert!(request_from(&mut raw).request_body().unwrap().is_none());

    let mut empty: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut raw = zeroed_request();
    raw.request_body = &raw mut empty;
    let request = request_from(&mut raw);
    let body = request.request_body().unwrap().unwrap();
    assert!(body.chain().unwrap().iter().next().is_none());
    assert_eq!(body.size().unwrap(), RequestBodySize { bytes: 0, saturated: false });

    let mut control: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    control.set_flush(1);
    let mut link = ngx_chain_t { buf: &raw mut control, next: core::ptr::null_mut() };
    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    body.bufs = &raw mut link;
    let mut raw = zeroed_request();
    raw.request_body = &raw mut body;

    let request = request_from(&mut raw);
    let body = request.request_body().unwrap().unwrap();
    assert_eq!(body.size().unwrap(), RequestBodySize { bytes: 0, saturated: false });
    assert!(matches!(
        body.chain().unwrap().iter().next().unwrap().unwrap().kind(),
        Ok(BufferView::Control(ControlView { .. }))
    ));
}

#[test]
fn request_body_views_cover_memory_file_and_mixed_chains() {
    let mut raw = zeroed_request();
    let mut memory = *b"abc";
    let mut memory_buffer: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    memory_buffer.start = memory.as_mut_ptr();
    memory_buffer.pos = memory.as_mut_ptr();
    memory_buffer.last = unsafe { memory.as_mut_ptr().add(memory.len()) };
    memory_buffer.end = memory_buffer.last;
    memory_buffer.set_memory(1);

    let mut file: ngx_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut file_buffer: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    file_buffer.file = &raw mut file;
    file_buffer.file_pos = 7;
    file_buffer.file_last = 12;
    file_buffer.set_in_file(1);

    let mut control: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    control.set_sync(1);
    let mut control_link = ngx_chain_t { buf: &raw mut control, next: core::ptr::null_mut() };
    let mut file_link = ngx_chain_t { buf: &raw mut file_buffer, next: &raw mut control_link };
    let mut memory_link = ngx_chain_t { buf: &raw mut memory_buffer, next: &raw mut file_link };

    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    body.bufs = &raw mut memory_link;
    raw.request_body = &raw mut body;

    let request = request_from(&mut raw);
    let body = request.request_body().unwrap().unwrap();
    assert_eq!(body.size().unwrap(), RequestBodySize { bytes: 8, saturated: false });

    let mut chain = body.chain().unwrap().iter();
    assert!(matches!(chain.next().unwrap().unwrap().kind(), Ok(BufferView::Memory(b"abc"))));
    assert!(matches!(
        chain.next().unwrap().unwrap().kind(),
        Ok(BufferView::File(view)) if view.start() == 7 && view.end() == 12
    ));
    assert!(matches!(
        chain.next().unwrap().unwrap().kind(),
        Ok(BufferView::Control(ControlView { .. }))
    ));
    assert!(chain.next().is_none());
}

#[test]
fn request_body_size_rejects_invalid_chains_and_saturates() {
    let mut null_buffer_link = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    body.bufs = &raw mut null_buffer_link;
    let mut raw = zeroed_request();
    raw.request_body = &raw mut body;
    assert!(matches!(
        request_from(&mut raw).request_body().unwrap().unwrap().size(),
        Err(RequestBodyError::Chain(ChainError::NullBuffer))
    ));

    let mut file: ngx_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut invalid_file: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    invalid_file.file = &raw mut file;
    invalid_file.file_pos = -1;
    invalid_file.file_last = 0;
    invalid_file.set_in_file(1);
    let mut invalid_file_link = ngx_chain_t { buf: &raw mut invalid_file, next: ptr::null_mut() };
    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    body.bufs = &raw mut invalid_file_link;
    let mut raw = zeroed_request();
    raw.request_body = &raw mut body;
    assert!(matches!(
        request_from(&mut raw).request_body().unwrap().unwrap().size(),
        Err(RequestBodyError::Chain(ChainError::Buffer(BufferError::InvalidFileRange)))
    ));

    let mut memory = *b"bad";
    let mut invalid_memory: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    invalid_memory.pos = unsafe { memory.as_mut_ptr().add(memory.len()) };
    invalid_memory.last = memory.as_mut_ptr();
    invalid_memory.set_memory(1);
    let mut invalid_memory_link =
        ngx_chain_t { buf: &raw mut invalid_memory, next: ptr::null_mut() };
    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    body.bufs = &raw mut invalid_memory_link;
    let mut raw = zeroed_request();
    raw.request_body = &raw mut body;
    assert!(matches!(
        request_from(&mut raw).request_body().unwrap().unwrap().size(),
        Err(RequestBodyError::Chain(ChainError::Buffer(BufferError::InvalidMemoryRange)))
    ));

    let mut file: ngx_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut first: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut second: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut third: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    for buffer in [&mut first, &mut second, &mut third] {
        buffer.file = &raw mut file;
        buffer.file_pos = 0;
        buffer.file_last = off_t::MAX;
        buffer.set_in_file(1);
    }
    let mut third_link = ngx_chain_t { buf: &raw mut third, next: ptr::null_mut() };
    let mut second_link = ngx_chain_t { buf: &raw mut second, next: &raw mut third_link };
    let mut first_link = ngx_chain_t { buf: &raw mut first, next: &raw mut second_link };
    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    body.bufs = &raw mut first_link;
    let mut raw = zeroed_request();
    raw.request_body = &raw mut body;
    assert_eq!(
        request_from(&mut raw).request_body().unwrap().unwrap().size(),
        Ok(RequestBodySize { bytes: usize::MAX, saturated: true })
    );

    let mut file: ngx_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut first: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut second: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut third: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    for buffer in [&mut first, &mut second, &mut third] {
        buffer.file = &raw mut file;
        buffer.file_pos = 0;
        buffer.file_last = off_t::MAX;
        buffer.set_in_file(1);
    }
    let mut null_buffer_link = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
    let mut third_link = ngx_chain_t { buf: &raw mut third, next: &raw mut null_buffer_link };
    let mut second_link = ngx_chain_t { buf: &raw mut second, next: &raw mut third_link };
    let mut first_link = ngx_chain_t { buf: &raw mut first, next: &raw mut second_link };
    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    body.bufs = &raw mut first_link;
    let mut raw = zeroed_request();
    raw.request_body = &raw mut body;
    assert!(matches!(
        request_from(&mut raw).request_body().unwrap().unwrap().size(),
        Err(RequestBodyError::Chain(ChainError::NullBuffer))
    ));

    let mut storage = [0_u8;
        core::mem::size_of::<ngx_http_request_body_t>()
            + core::mem::align_of::<ngx_http_request_body_t>()];
    let mut raw = zeroed_request();
    raw.request_body = unsafe { storage.as_mut_ptr().add(1).cast() };
    assert_eq!(request_from(&mut raw).request_body(), Err(RequestBodyError::MisalignedBody));
}

#[test]
fn client_body_read_status_preserves_native_return_classes() {
    assert_eq!(ClientBodyReadStatus::from_raw(NGX_OK as ngx_int_t), ClientBodyReadStatus::Ok);
    assert_eq!(ClientBodyReadStatus::from_raw(NGX_AGAIN as ngx_int_t), ClientBodyReadStatus::Again);
    assert_eq!(ClientBodyReadStatus::from_raw(NGX_DONE as ngx_int_t), ClientBodyReadStatus::Done);
    assert_eq!(
        ClientBodyReadStatus::from_raw(HTTPStatus::BAD_REQUEST.0 as ngx_int_t),
        ClientBodyReadStatus::Special(HTTPStatus::BAD_REQUEST)
    );
    assert_eq!(
        ClientBodyReadStatus::from_raw(NGX_ERROR as ngx_int_t),
        ClientBodyReadStatus::Error(Status::NGX_ERROR)
    );
}

#[test]
fn request_hold_rejects_reentry_and_is_removed_before_continuation() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;
    main.set_count(1);

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;

    let mut request = request_from(&mut raw);
    assert!(hold.is_none());
    assert_eq!(main.count(), 1);
    unsafe { request.hold(&mut hold) }.unwrap();
    assert_eq!(main.count(), 2);
    assert_eq!(unsafe { request.hold(&mut hold) }, Err(RequestHoldError::AlreadyHeld));

    let continuation = RequestHold::take(&mut hold, request).unwrap();
    assert!(hold.is_none());
    drop(continuation);

    let request = request_from(&mut raw);
    assert!(matches!(RequestHold::take(&mut hold, request), Err(RequestHoldError::Missing)));
    assert_eq!(main.count(), 1);
}

#[test]
fn request_hold_preserves_nginx_reference_reserve() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;
    let mut request = request_from(&mut raw);

    assert_eq!(unsafe { request.hold(&mut hold) }, Err(RequestHoldError::InactiveMain));
    assert!(hold.is_none());

    let native_limit = u32::from(u16::MAX) - 1000;
    main.set_count(native_limit - 1);
    assert_eq!(unsafe { request.hold(&mut hold) }, Ok(()));
    assert_eq!(main.count(), native_limit);
    assert!(RequestHold::cancel(&mut hold));
    assert_eq!(main.count(), native_limit - 1);

    main.set_count(native_limit);
    assert_eq!(unsafe { request.hold(&mut hold) }, Err(RequestHoldError::CountOverflow));
    assert!(hold.is_none());
    assert_eq!(main.count(), native_limit);
}

#[cfg(feature = "test-link")]
#[test]
fn request_hold_reserve_survives_native_body_read_and_redirect_increments() {
    let mut fixture = TerminalRequestFixture::new();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    fixture.request.ctx = slots.as_mut_ptr();
    let native_limit = u32::from(u16::MAX) - 1000;
    fixture.request.set_count(native_limit);
    fixture.request.headers_in.content_length_n = -1;
    let mut hold = None;

    let mut request = request_from(&mut fixture.request);
    assert_eq!(unsafe { request.hold(&mut hold) }, Err(RequestHoldError::CountOverflow));
    assert!(hold.is_none());
    assert_eq!(fixture.request.count(), native_limit);

    BODY_CALLBACKS.store(0, Ordering::Relaxed);
    BODY_CALLBACK_ACTIVE.store(true, Ordering::Relaxed);
    let mut request = request_from(&mut fixture.request);
    let start = request.read_client_body::<BodyCallback>();
    assert_eq!(start.status(), &ClientBodyReadStatus::Ok);
    assert_eq!(unsafe { start.request.raw.as_ref().count() }, native_limit + 1);
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 1);
    start.release();
    assert_eq!(fixture.request.count(), native_limit);

    let mut phase_handlers =
        Box::new([unsafe { MaybeUninit::<ngx_http_phase_handler_t>::zeroed().assume_init() }]);
    phase_handlers[0].checker = Some(stop_phase_engine);
    fixture._main_conf.phase_engine.handlers = phase_handlers.as_mut_ptr();
    fixture._main_conf.phase_engine.server_rewrite_index = 0;
    let mut http_context = Box::new(ngx_http_conf_ctx_t {
        main_conf: fixture._main_conf_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: fixture._loc_conf.as_mut_ptr(),
    });
    let mut server =
        Box::new(unsafe { MaybeUninit::<ngx_http_core_srv_conf_t>::zeroed().assume_init() });
    server.ctx = &raw mut *http_context;
    let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
    http_context.srv_conf = server_slots.as_mut_ptr();
    fixture.request.srv_conf = server_slots.as_mut_ptr();
    fixture.request.set_uri_changes(2);

    let mut request = request_from(&mut fixture.request);
    assert_eq!(request.internal_redirect("/redirect"), Ok(Status::NGX_DONE));
    assert_eq!(unsafe { request.raw.as_ref().count() }, native_limit + 1);
    request.finalize(Status::NGX_DONE).unwrap();
    assert_eq!(fixture.request.count(), native_limit);
    assert!(hold.is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn internal_redirect_cancels_registered_context_before_native_slot_reset() {
    let mut fixture = TerminalRequestFixture::new();
    reset_pinned_context_state();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    fixture.request.ctx = slots.as_mut_ptr();

    {
        let mut request = request_from(&mut fixture.request);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
    }

    let mut phase_handlers =
        Box::new([unsafe { MaybeUninit::<ngx_http_phase_handler_t>::zeroed().assume_init() }]);
    phase_handlers[0].checker = Some(stop_phase_engine);
    fixture._main_conf.phase_engine.handlers = phase_handlers.as_mut_ptr();
    fixture._main_conf.phase_engine.server_rewrite_index = 0;
    let mut http_context = Box::new(ngx_http_conf_ctx_t {
        main_conf: fixture._main_conf_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: fixture._loc_conf.as_mut_ptr(),
    });
    let mut server =
        Box::new(unsafe { MaybeUninit::<ngx_http_core_srv_conf_t>::zeroed().assume_init() });
    server.ctx = &raw mut *http_context;
    let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
    http_context.srv_conf = server_slots.as_mut_ptr();
    fixture.request.srv_conf = server_slots.as_mut_ptr();
    fixture.request.set_uri_changes(2);

    let mut request = request_from(&mut fixture.request);
    assert_eq!(request.internal_redirect("/redirect"), Ok(Status::NGX_DONE));
    assert!(request.is_internal());
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    assert!(PINNED_CONTEXT_DROP_SAW_INVALIDATED_SLOT.load(Ordering::Relaxed));
    request.finalize(Status::NGX_DONE).unwrap();
}

#[cfg(feature = "test-link")]
#[test]
fn redirect_uri_allocation_failure_preserves_registered_context() {
    let mut fixture = TerminalRequestFixture::new();
    reset_pinned_context_state();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    fixture.request.ctx = slots.as_mut_ptr();

    {
        let mut request = request_from(&mut fixture.request);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
    }
    unsafe {
        (*fixture.request_pool.raw).d.last = (*fixture.request_pool.raw).d.end;
        (*fixture.request_pool.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let result = request_from(&mut fixture.request).internal_redirect("/redirect");
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert_eq!(result, Err(RequestError::Allocation));
    assert!(!slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 0);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 0);
    let mut request = request_from(&mut fixture.request);
    assert_eq!(request.remove_module_context::<PinnedContextModule>(), Ok(true));
}

#[cfg(feature = "test-link")]
#[test]
fn named_redirect_cancels_registered_context_before_location_reentry() {
    let mut fixture = TerminalRequestFixture::new();
    reset_pinned_context_state();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    fixture.request.ctx = slots.as_mut_ptr();

    {
        let mut request = request_from(&mut fixture.request);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
    }

    let mut phase_handlers =
        Box::new([unsafe { MaybeUninit::<ngx_http_phase_handler_t>::zeroed().assume_init() }]);
    phase_handlers[0].checker = Some(stop_phase_engine);
    fixture._main_conf.phase_engine.handlers = phase_handlers.as_mut_ptr();
    fixture._main_conf.phase_engine.location_rewrite_index = 0;
    let mut named =
        Box::new(unsafe { MaybeUninit::<ngx_http_core_loc_conf_t>::zeroed().assume_init() });
    named.name =
        ngx_str_t { len: b"@replacement".len(), data: b"@replacement".as_ptr().cast_mut() };
    named.loc_conf = fixture._loc_conf.as_mut_ptr();
    let mut named_locations = Box::new([&raw mut *named, ptr::null_mut()]);
    let mut http_context = Box::new(ngx_http_conf_ctx_t {
        main_conf: fixture._main_conf_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: fixture._loc_conf.as_mut_ptr(),
    });
    let mut server =
        Box::new(unsafe { MaybeUninit::<ngx_http_core_srv_conf_t>::zeroed().assume_init() });
    server.ctx = &raw mut *http_context;
    server.named_locations = named_locations.as_mut_ptr();
    let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
    http_context.srv_conf = server_slots.as_mut_ptr();
    fixture.request.srv_conf = server_slots.as_mut_ptr();
    fixture.request.main_conf = fixture._main_conf_slots.as_mut_ptr();
    fixture.request.uri = ngx_str_t { len: b"/source".len(), data: b"/source".as_ptr().cast_mut() };
    fixture.request.set_uri_changes(2);

    let mut request = request_from(&mut fixture.request);
    assert_eq!(request.internal_redirect("@replacement"), Ok(Status::NGX_DONE));
    assert!(request.is_internal());
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    request.finalize(Status::NGX_DONE).unwrap();
}

#[cfg(feature = "test-link")]
#[test]
fn missing_named_location_cancels_registered_context_before_terminal_response() {
    let mut fixture = TerminalRequestFixture::new();
    let _header_filter = HeaderFilterGuard::install();
    reset_pinned_context_state();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    fixture.request.ctx = slots.as_mut_ptr();
    fixture.request.method = NGX_HTTP_HEAD as _;
    unsafe { ngx_rs_http_request_set_header_only(&raw mut *fixture.request, 1) };

    {
        let mut request = request_from(&mut fixture.request);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
    }

    let mut http_context = Box::new(ngx_http_conf_ctx_t {
        main_conf: fixture._main_conf_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: fixture._loc_conf.as_mut_ptr(),
    });
    let mut server =
        Box::new(unsafe { MaybeUninit::<ngx_http_core_srv_conf_t>::zeroed().assume_init() });
    server.ctx = &raw mut *http_context;
    let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
    http_context.srv_conf = server_slots.as_mut_ptr();
    fixture.request.srv_conf = server_slots.as_mut_ptr();
    fixture.request.uri = ngx_str_t { len: b"/source".len(), data: b"/source".as_ptr().cast_mut() };
    fixture.request.set_uri_changes(2);

    let mut request = request_from(&mut fixture.request);
    assert_eq!(request.internal_redirect("@missing"), Ok(Status::NGX_DONE));
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn conditional_filter_finalization_cancels_the_cleared_context() {
    let mut fixture = TerminalRequestFixture::new();
    let _header_filter = HeaderFilterGuard::install();
    reset_pinned_context_state();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    fixture.request.ctx = slots.as_mut_ptr();
    fixture.request.method = NGX_HTTP_HEAD as _;
    unsafe { ngx_rs_http_request_set_header_only(&raw mut *fixture.request, 1) };

    {
        let mut request = request_from(&mut fixture.request);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
    }

    let status = unsafe {
        request_callback_status(&raw mut *fixture.request, |request| {
            let request = request.as_ptr();
            Status(ngx_http_filter_finalize_request(
                request,
                ptr::null_mut(),
                NGX_HTTP_PRECONDITION_FAILED as _,
            ))
        })
    };

    assert_eq!(status, NGX_ERROR as _);
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[test]
fn request_hold_cannot_continue_a_different_subrequest() {
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.set_count(1);

    let mut first = zeroed_request();
    first.main = &raw mut main;
    first.parent = &raw mut main;
    let mut second = zeroed_request();
    second.main = &raw mut main;
    second.parent = &raw mut main;
    let mut hold = None;

    let mut first = request_from(&mut first);
    unsafe { first.hold(&mut hold) }.unwrap();
    let second = request_from(&mut second);
    assert!(matches!(RequestHold::take(&mut hold, second), Err(RequestHoldError::ForeignRequest)));
    assert!(hold.is_some());
    assert_eq!(main.count(), 2);
}

#[cfg(feature = "test-link")]
#[test]
fn request_hold_allows_terminal_finalization_with_its_only_live_reference() {
    let mut fixture = TerminalRequestFixture::new();
    let mut hold = None;
    fixture.hold(&mut hold);
    fixture.request.set_count(1);

    let mut continuation =
        RequestHold::take(&mut hold, request_from(&mut fixture.request)).unwrap();
    continuation
        .finalize(Status::NGX_DONE)
        .expect("terminal finalization accepts the held reference");
    fixture.disarm_nginx_pools();
}

#[cfg(feature = "test-link")]
#[test]
fn finalization_after_output_releases_an_extra_hold_before_entering_nginx() {
    let mut fixture = TerminalRequestFixture::new();
    let mut hold = None;
    fixture.hold(&mut hold);
    assert_eq!(fixture.request.count(), 2);

    let mut continuation =
        RequestHold::take(&mut hold, request_from(&mut fixture.request)).unwrap();
    continuation
        .finalize_after_output(Status::NGX_DONE)
        .expect("output finalization releases the held reference");
    fixture.disarm_nginx_pools();
}

#[cfg(feature = "test-link")]
#[test]
fn finalization_after_output_preserves_parent_reference_for_last_subrequest() {
    let mut fixture = TerminalRequestFixture::new();
    let mut main = Box::new(zeroed_request());
    initialize_request(&mut main);
    main.parent = &raw mut *main;
    main.pool = fixture.request.pool;
    main.connection = fixture.request.connection;
    main.loc_conf = fixture.request.loc_conf;
    main.main_conf = fixture.request.main_conf;
    main.set_count(1);
    main.set_blocked(1);
    fixture.request.main = &raw mut *main;
    fixture.request.parent = &raw mut *main;

    let mut hold = None;
    fixture.hold(&mut hold);
    assert_eq!(main.count(), 2);

    let mut continuation =
        RequestHold::take(&mut hold, request_from(&mut fixture.request)).unwrap();
    continuation
        .finalize_after_output(Status::NGX_DONE)
        .expect("last subrequest finalization keeps the parent writer live");

    assert_eq!(main.count(), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn finalization_after_output_transfers_the_only_live_hold_to_nginx() {
    let mut fixture = TerminalRequestFixture::new();
    let mut hold = None;
    fixture.hold(&mut hold);
    fixture.request.set_count(1);

    let mut continuation =
        RequestHold::take(&mut hold, request_from(&mut fixture.request)).unwrap();
    continuation
        .finalize_after_output(Status::NGX_DONE)
        .expect("output finalization transfers the only live reference");
    fixture.disarm_nginx_pools();
}

#[test]
fn phase_resume_rejects_the_only_live_hold() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;
    main.set_count(1);

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;
    {
        let mut request = request_from(&mut raw);
        unsafe { request.hold(&mut hold) }.unwrap();
    }
    main.set_count(1);

    let mut continuation = RequestHold::take(&mut hold, request_from(&mut raw)).unwrap();
    assert_eq!(
        continuation.resume_preaccess(),
        Err(RequestContinuationError::Hold(RequestHoldError::InactiveMain))
    );
    main.set_count(2);
    continuation.cancel().unwrap();
    assert_eq!(main.count(), 1);
}

#[test]
fn request_hold_termination_release_does_not_reenter_native_finalization() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;
    main.set_count(1);
    unsafe { ngx_rs_http_request_set_terminated(&raw mut main, 1) };

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;
    {
        let mut request = request_from(&mut raw);
        unsafe { request.hold(&mut hold) }.unwrap();
    }
    main.set_count(1);

    assert!(RequestHold::cancel(&mut hold));
    assert_eq!(main.count(), 1);
}

#[test]
fn request_hold_rejects_zero_main_request_count() {
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.set_count(1);

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;
    {
        let mut request = request_from(&mut raw);
        unsafe { request.hold(&mut hold) }.unwrap();
    }
    main.set_count(0);

    let request = request_from(&mut raw);
    assert!(matches!(RequestHold::take(&mut hold, request), Err(RequestHoldError::InactiveMain)));
    assert!(hold.is_some());
}

#[test]
fn request_continuation_cancellation_prevents_reentry() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;
    main.set_count(1);

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;

    let mut request = request_from(&mut raw);
    unsafe { request.hold(&mut hold) }.unwrap();
    let mut continuation = RequestHold::take(&mut hold, request).unwrap();

    assert_eq!(continuation.cancel(), Ok(()));
    assert_eq!(continuation.cancel(), Err(RequestContinuationError::Consumed));
    assert_eq!(main.count(), 1);
}

#[test]
fn request_hold_cleanup_disarms_once_without_releasing() {
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.set_count(1);

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;
    let mut request = request_from(&mut raw);
    unsafe { request.hold(&mut hold) }.unwrap();

    assert!(unsafe { RequestHold::disarm_for_cleanup(&mut hold) });
    assert!(!unsafe { RequestHold::disarm_for_cleanup(&mut hold) });
    assert_eq!(main.count(), 2);
}

#[test]
fn cancelled_continuation_rejects_nonterminal_and_terminal_operations() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;
    main.set_count(1);

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;

    let mut output_pool = zeroed_pool();
    let output_pool = unsafe { Pool::from_raw(&raw mut output_pool).unwrap() };
    let mut request = request_from(&mut raw);
    unsafe { request.hold(&mut hold) }.unwrap();
    let mut continuation = RequestHold::take(&mut hold, request).unwrap();
    continuation.cancel().unwrap();

    assert_eq!(continuation.send_header(), Err(RequestContinuationError::Consumed));
    assert_eq!(
        continuation.output_filter(output_pool.chain()),
        Err(RequestContinuationError::Consumed)
    );
    assert_eq!(
        continuation.finalize(HTTPStatus::BAD_REQUEST),
        Err(RequestContinuationError::Consumed)
    );
    assert_eq!(main.count(), 1);

    let mut resume_main = zeroed_request();
    initialize_request(&mut resume_main);
    resume_main.pool = &raw mut pool;
    resume_main.set_count(1);
    let mut resume_raw = zeroed_request();
    resume_raw.main = &raw mut resume_main;
    resume_raw.parent = &raw mut resume_main;
    let mut resume_hold = None;
    let mut request = request_from(&mut resume_raw);
    unsafe { request.hold(&mut resume_hold) }.unwrap();
    let mut continuation = RequestHold::take(&mut resume_hold, request).unwrap();
    continuation.cancel().unwrap();

    assert_eq!(continuation.resume_preaccess(), Err(RequestContinuationError::Consumed));
}

#[test]
fn terminal_operations_reject_requests_without_connections() {
    let mut output_pool = zeroed_pool();
    let output_pool = unsafe { Pool::from_raw(&raw mut output_pool).unwrap() };
    let mut raw = zeroed_request();
    let mut request = request_from(&mut raw);
    let expected = RequestError::Connection(ConnectionError::NullConnection);

    assert_eq!(request.send_header(), Err(expected));
    assert_eq!(request.output_filter(output_pool.chain()), Err(expected));

    let mut finalize_raw = zeroed_request();
    assert_eq!(request_from(&mut finalize_raw).finalize(HTTPStatus::BAD_REQUEST), Err(expected));

    let mut resume_raw = zeroed_request();
    assert_eq!(
        request_from(&mut resume_raw).resume_preaccess(),
        Err(RequestPhaseResumeError::Request(expected))
    );
}

#[test]
fn invalidated_continuations_reject_terminal_operations() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;
    main.set_count(1);

    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    let mut hold = None;
    let expected = RequestError::Connection(ConnectionError::NullConnection);
    let mut request = request_from(&mut raw);
    unsafe { request.hold(&mut hold) }.unwrap();
    let mut continuation = RequestHold::take(&mut hold, request).unwrap();

    assert_eq!(
        continuation.finalize(HTTPStatus::BAD_REQUEST),
        Err(RequestContinuationError::Request(expected))
    );
    assert_eq!(main.count(), 2);
    assert!(continuation.restore(&mut hold).is_ok());
    assert!(hold.is_some());
    assert!(RequestHold::cancel(&mut hold));
    assert_eq!(main.count(), 1);

    let mut resume_pool = zeroed_pool();
    let mut resume_main = zeroed_request();
    initialize_request(&mut resume_main);
    resume_main.pool = &raw mut resume_pool;
    resume_main.set_count(1);
    let mut resume_raw = zeroed_request();
    resume_raw.main = &raw mut resume_main;
    resume_raw.parent = &raw mut resume_main;
    let mut resume_hold = None;
    let mut request = request_from(&mut resume_raw);
    unsafe { request.hold(&mut resume_hold) }.unwrap();
    let mut continuation = RequestHold::take(&mut resume_hold, request).unwrap();

    assert_eq!(
        continuation.resume_preaccess(),
        Err(RequestContinuationError::Phase(RequestPhaseResumeError::Request(expected)))
    );
    assert_eq!(resume_main.count(), 2);
    continuation.cancel().unwrap();
    assert_eq!(resume_main.count(), 1);
}

#[test]
fn continuation_rejects_nonconsuming_finalization_without_losing_ownership() {
    let mut pool = zeroed_pool();
    let mut main = zeroed_request();
    initialize_request(&mut main);
    main.pool = &raw mut pool;
    main.set_count(1);
    let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
    let mut raw = zeroed_request();
    raw.main = &raw mut main;
    raw.parent = &raw mut main;
    raw.connection = &raw mut connection;
    let mut hold = None;
    let mut request = request_from(&mut raw);
    unsafe { request.hold(&mut hold) }.unwrap();
    let mut continuation = RequestHold::take(&mut hold, request).unwrap();

    assert_eq!(
        continuation.finalize(Status::NGX_DECLINED),
        Err(RequestContinuationError::NonConsumingStatus)
    );
    assert_eq!(main.count(), 2);
    continuation.cancel().unwrap();
    assert_eq!(main.count(), 1);
}

#[test]
fn preaccess_resume_prepares_the_next_phase_handler() {
    let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
    let mut raw = zeroed_request();
    raw.connection = &raw mut connection;
    raw.phase_handler = 7;
    {
        let mut request = request_from(&mut raw);
        request.prepare_preaccess_resume().unwrap();
    }

    assert_eq!(raw.phase_handler, 8);
    let expected: unsafe extern "C" fn(*mut ngx_http_request_t) = ngx_http_core_run_phases;
    assert!(matches!(
        raw.write_event_handler,
        Some(handler) if core::ptr::fn_addr_eq(handler, expected)
    ));
}

#[test]
fn preaccess_resume_rejects_invalid_phase_indices_without_mutation() {
    let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
    let mut raw = zeroed_request();
    raw.connection = &raw mut connection;
    raw.phase_handler = -1;

    {
        let mut request = request_from(&mut raw);
        assert_eq!(
            request.prepare_preaccess_resume(),
            Err(RequestPhaseResumeError::NegativePhaseHandler)
        );
    }
    assert_eq!(raw.phase_handler, -1);
    assert!(raw.write_event_handler.is_none());

    raw.phase_handler = ngx_int_t::MAX;
    {
        let mut request = request_from(&mut raw);
        assert_eq!(
            request.prepare_preaccess_resume(),
            Err(RequestPhaseResumeError::PhaseHandlerOverflow)
        );
    }
    assert_eq!(raw.phase_handler, ngx_int_t::MAX);
    assert!(raw.write_event_handler.is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn internal_redirect_rejects_replacement_read_and_stale_body_callback() {
    let mut fixture = TerminalRequestFixture::new();
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    fixture.request.ctx = contexts.as_mut_ptr();
    let mut header_storage = [0_u8; 16];
    let mut header: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    header.start = header_storage.as_mut_ptr();
    header.pos = header_storage.as_mut_ptr();
    header.last = header_storage.as_mut_ptr();
    header.end = unsafe { header_storage.as_mut_ptr().add(header_storage.len()) };
    fixture.request.header_in = &raw mut header;
    fixture.request.headers_in.content_length_n = 4;
    fixture._core.client_body_buffer_size = 8;
    fixture._core.client_body_timeout = 0;
    fixture.connection.recv = Some(pending_body_recv);
    fixture._read.set_active(1);
    fixture._read.set_ready(1);
    fixture._read.set_timer_set(1);
    fixture._read.timer.key = unsafe { ngx_current_msec };
    unsafe { nginx_sys::ngx_http_top_request_body_filter = Some(test_request_body_filter) };
    BODY_CALLBACKS.store(0, Ordering::Relaxed);
    BODY_CALLBACK_ACTIVE.store(true, Ordering::Relaxed);

    let mut request = request_from(&mut fixture.request);
    let start = request.read_client_body::<BodyCallback>();
    assert_eq!(start.status(), &ClientBodyReadStatus::Again);
    assert_eq!(unsafe { start.request.raw.as_ref().count() }, 2);
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 0);
    start.release();
    assert_eq!(fixture.request.count(), 1);
    let body = NonNull::new(fixture.request.request_body).expect("pending native body");
    assert_eq!(unsafe { body.as_ref().rest }, 4);

    let mut phase_handlers =
        Box::new([unsafe { MaybeUninit::<ngx_http_phase_handler_t>::zeroed().assume_init() }]);
    phase_handlers[0].checker = Some(stop_phase_engine);
    fixture._main_conf.phase_engine.handlers = phase_handlers.as_mut_ptr();
    fixture._main_conf.phase_engine.server_rewrite_index = 0;
    let mut http_context = Box::new(ngx_http_conf_ctx_t {
        main_conf: fixture._main_conf_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: fixture._loc_conf.as_mut_ptr(),
    });
    let mut server =
        Box::new(unsafe { MaybeUninit::<ngx_http_core_srv_conf_t>::zeroed().assume_init() });
    server.ctx = &raw mut *http_context;
    let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
    http_context.srv_conf = server_slots.as_mut_ptr();
    fixture.request.srv_conf = server_slots.as_mut_ptr();
    fixture.request.set_uri_changes(2);

    let mut request = request_from(&mut fixture.request);
    assert_eq!(request.internal_redirect("/replacement"), Ok(Status::NGX_DONE));
    request.finalize(Status::NGX_DONE).unwrap();
    assert_eq!(fixture.request.count(), 1);

    let mut request = request_from(&mut fixture.request);
    let start = request.read_client_body::<BodyCallback>();
    assert_eq!(start.status(), &ClientBodyReadStatus::Again);
    assert!(!start.release_required);
    start.release();
    assert_eq!(fixture.request.count(), 1);
    assert_eq!(fixture.request.request_body, body.as_ptr());
    assert_eq!(unsafe { body.as_ref().rest }, 4);

    fixture.request.set_blocked(1);
    fixture.request.write_event_handler = Some(blocked_request_handler);
    fixture._read.set_timer_set(0);
    unsafe {
        (*body.as_ptr()).rest = 0;
        (*body.as_ptr()).set_last_saved(1);
    }
    let late_callback = unsafe { body.as_ref().post_handler }.expect("native body callback");
    unsafe { late_callback(&raw mut *fixture.request) };
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 0);
    assert_ne!(unsafe { ngx_rs_http_request_terminated(&raw mut *fixture.request) }, 0);
    assert_eq!(fixture.request.count(), 1);
    fixture.request.set_blocked(0);
    fixture.request.write_event_handler = None;
}

#[cfg(feature = "test-link")]
#[test]
fn client_body_read_invokes_once_and_releases_each_start_reference() {
    let mut fixture = TerminalRequestFixture::new();
    fixture.request.headers_in.content_length_n = -1;

    BODY_CALLBACKS.store(0, Ordering::Relaxed);
    BODY_CALLBACK_ACTIVE.store(true, Ordering::Relaxed);
    let mut request = request_from(&mut fixture.request);
    let start = request.read_client_body::<BodyCallback>();
    assert_eq!(start.status(), &ClientBodyReadStatus::Ok);
    assert_eq!(unsafe { start.request.raw.as_ref().count() }, 2);
    start.release();
    assert_eq!(fixture.request.count(), 1);
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 1);
    assert!(!fixture.request.request_body.is_null());

    BODY_CALLBACK_ACTIVE.store(false, Ordering::Relaxed);
    let mut request = request_from(&mut fixture.request);
    let start = request.read_client_body::<BodyCallback>();
    assert_eq!(start.status(), &ClientBodyReadStatus::Ok);
    assert_eq!(unsafe { start.request.raw.as_ref().count() }, 2);
    start.release();
    assert_eq!(fixture.request.count(), 1);
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 1);

    BODY_CALLBACK_ACTIVE.store(true, Ordering::Relaxed);
    let mut request = request_from(&mut fixture.request);
    let start = request.read_client_body::<BodyCallback>();
    assert_eq!(start.status(), &ClientBodyReadStatus::Ok);
    assert_eq!(unsafe { start.request.raw.as_ref().count() }, 2);
    start.release();
    assert_eq!(fixture.request.count(), 1);
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 2);

    BODY_CALLBACK_ACTIVE.store(false, Ordering::Relaxed);
    unsafe { raw_client_body_handler::<BodyCallback>(&raw mut *fixture.request) };
    unsafe { raw_client_body_handler::<BodyCallback>(ptr::null_mut()) };
    let mut storage = [0_u8;
        core::mem::size_of::<ngx_http_request_t>() + core::mem::align_of::<ngx_http_request_t>()];
    unsafe { raw_client_body_handler::<BodyCallback>(storage.as_mut_ptr().add(1).cast()) };
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 2);

    request_from(&mut fixture.request).finalize(Status::NGX_DONE).unwrap();
    fixture.disarm_nginx_pools();
}

#[cfg(feature = "test-link")]
#[test]
fn inherited_subrequest_body_releases_to_the_main_request_baseline() {
    let mut fixture = TerminalRequestFixture::new();
    let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    fixture.request.request_body = &raw mut body;
    fixture.request.set_count(2);
    let mut child = Box::new(zeroed_request());
    child.main = &raw mut *fixture.request;
    child.parent = &raw mut *fixture.request;
    child.pool = fixture.request.pool;
    child.connection = fixture.request.connection;
    child.loc_conf = fixture.request.loc_conf;
    child.main_conf = fixture.request.main_conf;
    child.request_body = &raw mut body;
    child.set_logged(1);

    BODY_CALLBACKS.store(0, Ordering::Relaxed);
    BODY_CALLBACK_ACTIVE.store(true, Ordering::Relaxed);
    let mut request = request_from(&mut child);
    let start = request.read_client_body::<BodyCallback>();
    assert_eq!(start.status(), &ClientBodyReadStatus::Ok);
    assert_eq!(fixture.request.count(), 3);
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 1);

    start.release();
    assert_eq!(fixture.request.count(), 2);
    request_from(&mut child).finalize(Status::NGX_DONE).unwrap();
    assert_eq!(fixture.request.count(), 1);

    request_from(&mut fixture.request).finalize(Status::NGX_DONE).unwrap();
    fixture.disarm_nginx_pools();
}

#[cfg(feature = "test-link")]
#[test]
fn client_body_read_registration_failure_does_not_acquire_native_count() {
    let _globals = RequestGlobals::new(0, 0);
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.headers_in.content_length_n = -1;
    BODY_CALLBACKS.store(0, Ordering::Relaxed);
    unsafe {
        (*owner.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let mut request = request_from(&mut raw);
    let start = request.read_client_body::<BodyCallback>();
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert_eq!(start.status(), &ClientBodyReadStatus::Error(Status::NGX_ERROR));
    assert_eq!(unsafe { start.request.raw.as_ref().count() }, 0);
    start.release();
    assert_eq!(raw.count(), 0);
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "test-link")]
#[test]
fn client_body_read_propagates_native_special_response_without_callback() {
    let _globals = RequestGlobals::new(0, 0);
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.headers_in.content_length_n = -1;
    BODY_CALLBACKS.store(0, Ordering::Relaxed);
    BODY_CALLBACK_ACTIVE.store(true, Ordering::Relaxed);
    initialize_request(&mut raw);
    let id =
        register_client_body_read(NonNull::from(&mut raw), raw_client_body_handler::<BodyCallback>)
            .unwrap()
            .expect("body operation");
    clear_client_body_read(NonNull::from(&mut raw), id, raw_client_body_handler::<BodyCallback>);
    unsafe {
        (*owner.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let mut request = request_from(&mut raw);
    let start = request.read_client_body::<BodyCallback>();
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert_eq!(start.status(), &ClientBodyReadStatus::Special(HTTPStatus::INTERNAL_SERVER_ERROR));
    start.release();
    assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "test-link")]
#[test]
fn request_body_builder_publishes_empty_body_and_clear_removes_old_body_state() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    {
        let mut request = request_from(&mut raw);
        unsafe { request.headers_in_builder(1) }.unwrap().commit();
    }

    let mut old_temp_file: ngx_temp_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut old_buffer: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut old_chain: ngx_chain_t = unsafe { MaybeUninit::zeroed().assume_init() };
    old_chain.buf = &raw mut old_buffer;
    let mut old_body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
    old_body.temp_file = &raw mut old_temp_file;
    old_body.bufs = &raw mut old_chain;
    raw.request_body = &raw mut old_body;

    {
        let mut request = request_from(&mut raw);
        request.clear_request_body().unwrap();
    }
    assert!(raw.request_body.is_null());
    assert_eq!(raw.headers_in.content_length_n, 0);
    assert_eq!(raw.headers_in.chunked(), 0);
    assert!(raw.headers_in.transfer_encoding.is_null());

    {
        let mut request = request_from(&mut raw);
        request.request_body_builder().unwrap().commit().unwrap();
    }
    assert!(!raw.request_body.is_null());
    assert!(!ptr::eq(raw.request_body, &raw mut old_body));
    assert!(unsafe { (*raw.request_body).bufs }.is_null());
    assert!(unsafe { (*raw.request_body).temp_file }.is_null());
    assert_eq!(raw.headers_in.content_length_n, 0);
}

#[cfg(feature = "test-link")]
#[test]
fn request_body_builder_keeps_file_metadata_and_control_links() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    {
        let mut request = request_from(&mut raw);
        unsafe { request.headers_in_builder(1) }.unwrap().commit();
    }

    let mut file: ngx_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut source: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
    source.file = &raw mut file;
    source.file_pos = 2;
    source.file_last = 8;
    source.set_in_file(1);
    let source = unsafe { BufferRef::from_raw(&raw const source) }.unwrap();
    let pool = unsafe { Pool::from_raw(owner.raw) }.unwrap();
    let file_buffer = pool.file_buffer_slice(source, 1..4, BufferFlags::default()).unwrap();

    {
        let mut request = request_from(&mut raw);
        let mut body = request.request_body_builder().unwrap();
        body.append_copy(b"ab").unwrap();
        body.append(file_buffer).unwrap();
        body.append_control(BufferFlags { sync: true, ..BufferFlags::default() }).unwrap();
        body.commit().unwrap();
    }

    let request = request_from(&mut raw);
    let body = request.request_body().unwrap().unwrap();
    assert_eq!(body.size().unwrap(), RequestBodySize { bytes: 5, saturated: false });
    let mut chain = body.chain().unwrap().iter();
    assert_eq!(chain.next().unwrap().unwrap().bytes(), Ok(Some(b"ab".as_slice())));
    match chain.next().unwrap().unwrap().kind().unwrap() {
        BufferView::File(view) => {
            assert_eq!(view.start(), 3);
            assert_eq!(view.end(), 6);
            assert!(ptr::eq(view.file_ptr(), &raw mut file));
        }
        other => panic!("expected file buffer, got {other:?}"),
    }
    assert!(matches!(
        chain.next().unwrap().unwrap().kind(),
        Ok(BufferView::Control(ControlView { .. }))
    ));
    assert!(chain.next().is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn request_body_builder_rejects_a_buffer_from_another_pool_before_publication() {
    let owner = TestPool::new();
    let foreign_owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    {
        let mut request = request_from(&mut raw);
        unsafe { request.headers_in_builder(1) }.unwrap().commit();
    }
    let foreign_pool = unsafe { Pool::from_raw(foreign_owner.raw) }.unwrap();
    let foreign_buffer = foreign_pool.copy_buffer(b"foreign", BufferFlags::default()).unwrap();

    let result = {
        let mut request = request_from(&mut raw);
        let mut body = request.request_body_builder().unwrap();
        body.append(foreign_buffer)
    };
    assert_eq!(
        result,
        Err(RequestBodyBuildError::Chain(ChainError::Buffer(BufferError::ForeignPool)))
    );
    assert!(raw.request_body.is_null());
}

#[cfg(feature = "test-link")]
#[test]
fn request_body_builder_keeps_live_body_and_framing_when_each_allocation_fails() {
    let mut reached_success = false;

    for successes in 0..64 {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        {
            let mut request = request_from(&mut raw);
            let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
            headers.add(b"Host", b"example.test").unwrap();
            headers.add(b"Content-Length", b"7").unwrap();
            headers.add(b"Transfer-Encoding", b"chunked").unwrap();
            headers.commit();
        }
        raw.headers_in.content_length_n = 7;
        raw.headers_in.set_chunked(1);
        let mut old_temp_file: ngx_temp_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut old_body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
        old_body.temp_file = &raw mut old_temp_file;
        raw.request_body = &raw mut old_body;
        let original = (
            raw.request_body,
            raw.headers_in.headers.part.elts,
            raw.headers_in.headers.part.nelts,
            raw.headers_in.headers.part.next,
            raw.headers_in.headers.last,
            raw.headers_in.headers.size,
            raw.headers_in.headers.nalloc,
            raw.headers_in.headers.pool,
            raw.headers_in.count,
            raw.headers_in.content_length,
            raw.headers_in.transfer_encoding,
            raw.headers_in.content_length_n,
        );
        let original_chunked = raw.headers_in.chunked();

        unsafe {
            (*owner.raw).max = 0;
            ngx_rs_test_fail_allocations_after(successes);
        }
        let result = (|| {
            let mut request = request_from(&mut raw);
            let mut body = request.request_body_builder()?;
            body.append_copy(b"replacement")?;
            body.commit()
        })();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        if result.is_ok() {
            reached_success = true;
            break;
        }
        assert!(matches!(
            result,
            Err(RequestBodyBuildError::Buffer(BufferError::Allocation)
                | RequestBodyBuildError::Chain(ChainError::Allocation)
                | RequestBodyBuildError::HeaderBuild(HeaderBuildError::Allocation)
                | RequestBodyBuildError::Allocation)
        ));
        assert_eq!(
            (
                raw.request_body,
                raw.headers_in.headers.part.elts,
                raw.headers_in.headers.part.nelts,
                raw.headers_in.headers.part.next,
                raw.headers_in.headers.last,
                raw.headers_in.headers.size,
                raw.headers_in.headers.nalloc,
                raw.headers_in.headers.pool,
                raw.headers_in.count,
                raw.headers_in.content_length,
                raw.headers_in.transfer_encoding,
                raw.headers_in.content_length_n,
            ),
            original
        );
        assert_eq!(raw.headers_in.chunked(), original_chunked);
    }

    assert!(reached_success);
}

#[cfg(feature = "test-link")]
#[test]
fn input_header_builder_keeps_live_headers_when_each_pool_allocation_fails() {
    let mut reached_success = false;

    for successes in 0..32 {
        let owner = TestPool::new();
        let mut old_header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        raw.headers_in.host = &raw mut old_header;
        raw.headers_in.count = 41;
        raw.headers_in.content_length_n = 42;
        raw.headers_in.keep_alive_n = 43;
        let original = (
            raw.headers_in.headers.part.elts,
            raw.headers_in.headers.part.nelts,
            raw.headers_in.headers.part.next,
            raw.headers_in.headers.last,
            raw.headers_in.headers.size,
            raw.headers_in.headers.nalloc,
            raw.headers_in.headers.pool,
            raw.headers_in.host,
            raw.headers_in.count,
            raw.headers_in.content_length_n,
            raw.headers_in.keep_alive_n,
        );

        unsafe {
            (*owner.raw).max = 0;
            ngx_rs_test_fail_allocations_after(successes);
        }
        let result = (|| {
            let mut request = request_from(&mut raw);
            let mut headers = unsafe { request.headers_in_builder(1) }?;
            headers.add(b"X-First", b"one")?;
            headers.add(b"X-Second", b"two")?;
            headers.commit();
            Ok::<(), HeaderBuildError>(())
        })();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        if result.is_ok() {
            reached_success = true;
            break;
        }
        assert_eq!(result, Err(HeaderBuildError::Allocation));
        assert_eq!(
            (
                raw.headers_in.headers.part.elts,
                raw.headers_in.headers.part.nelts,
                raw.headers_in.headers.part.next,
                raw.headers_in.headers.last,
                raw.headers_in.headers.size,
                raw.headers_in.headers.nalloc,
                raw.headers_in.headers.pool,
                raw.headers_in.host,
                raw.headers_in.count,
                raw.headers_in.content_length_n,
                raw.headers_in.keep_alive_n,
            ),
            original
        );
    }

    assert!(reached_success);
}

#[cfg(feature = "test-link")]
#[test]
fn output_header_builder_keeps_live_headers_when_each_pool_allocation_fails() {
    let mut reached_success = false;

    for successes in 0..32 {
        let owner = TestPool::new();
        let mut old_header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        raw.headers_out.server = &raw mut old_header;
        raw.headers_out.status = 201;
        raw.headers_out.content_length_n = 42;
        let original = (
            raw.headers_out.headers.part.elts,
            raw.headers_out.headers.part.nelts,
            raw.headers_out.headers.part.next,
            raw.headers_out.headers.last,
            raw.headers_out.headers.size,
            raw.headers_out.headers.nalloc,
            raw.headers_out.headers.pool,
            raw.headers_out.server,
            raw.headers_out.status,
            raw.headers_out.content_length_n,
        );

        unsafe {
            (*owner.raw).max = 0;
            ngx_rs_test_fail_allocations_after(successes);
        }
        let result = (|| {
            let mut request = request_from(&mut raw);
            let mut headers = request.headers_out_builder(1)?;
            headers.add(b"Content-Type", b"text/plain")?;
            headers.add(b"X-First", b"one")?;
            headers.add(b"X-Second", b"two")?;
            headers.commit();
            Ok::<(), HeaderBuildError>(())
        })();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        if result.is_ok() {
            reached_success = true;
            break;
        }
        assert_eq!(result, Err(HeaderBuildError::Allocation));
        assert_eq!(
            (
                raw.headers_out.headers.part.elts,
                raw.headers_out.headers.part.nelts,
                raw.headers_out.headers.part.next,
                raw.headers_out.headers.last,
                raw.headers_out.headers.size,
                raw.headers_out.headers.nalloc,
                raw.headers_out.headers.pool,
                raw.headers_out.server,
                raw.headers_out.status,
                raw.headers_out.content_length_n,
            ),
            original
        );
    }

    assert!(reached_success);
}

#[cfg(feature = "test-link")]
#[test]
fn header_builders_copy_temporary_bytes_before_publication() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    {
        let mut request = request_from(&mut raw);
        let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
        {
            let mut key = *b"X-In";
            let mut value = *b"input";
            headers.add(&key, &value).unwrap();
            key.fill(b'!');
            value.fill(b'!');
        }
        headers.commit();
    }

    {
        let mut request = request_from(&mut raw);
        let mut headers = request.headers_out_builder(1).unwrap();
        {
            let mut value = *b"text/plain";
            headers.add(b"Content-Type", &value).unwrap();
            value.fill(b'!');
        }
        headers.commit();
    }

    let request = request_from(&mut raw);
    let headers = request.headers_in().unwrap();
    let input = headers.iter().next().unwrap();
    assert_eq!(input.key(), b"X-In");
    assert_eq!(input.value(), b"input");
    assert_eq!(
        unsafe { checked_ngx_str(raw.headers_out.content_type) }.unwrap().as_bytes(),
        b"text/plain"
    );
}

#[cfg(feature = "test-link")]
#[test]
fn header_builders_publish_empty_lists() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;

    {
        let mut request = request_from(&mut raw);
        unsafe { request.headers_in_builder(1) }.unwrap().commit();
    }

    assert_eq!(raw.headers_in.count, 0);
    assert_eq!(raw.headers_in.content_length_n, -1);
    assert_eq!(raw.headers_in.keep_alive_n, -1);
    assert!(request_from(&mut raw).headers_in().unwrap().is_empty());

    {
        let mut request = request_from(&mut raw);
        request.headers_out_builder(1).unwrap().commit();
    }

    assert!(request_from(&mut raw).headers_out().unwrap().is_empty());
}

#[cfg(feature = "test-link")]
#[test]
fn header_builders_reject_unrepresentable_capacity() {
    let owner = TestPool::new();
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    let capacity = isize::MAX as usize / core::mem::size_of::<ngx_table_elt_t>() + 1;
    let mut request = request_from(&mut raw);

    assert!(matches!(
        unsafe { request.headers_in_builder(0) },
        Err(HeaderBuildError::InvalidCapacity)
    ));
    assert!(matches!(request.headers_out_builder(0), Err(HeaderBuildError::InvalidCapacity)));
    assert!(matches!(
        unsafe { request.headers_in_builder(capacity) },
        Err(HeaderBuildError::InvalidCapacity)
    ));
    assert!(matches!(
        request.headers_out_builder(capacity),
        Err(HeaderBuildError::InvalidCapacity)
    ));
}

#[test]
fn request_metrics_read_nginx_fields() {
    let mut raw = zeroed_request();
    raw.start_sec = 1_700_000_000;
    raw.start_msec = 250;
    raw.request_length = 4096;

    let request = request_from(&mut raw);
    assert_eq!(request.start_sec(), Ok(1_700_000_000));
    assert_eq!(request.start_msec(), 250);
    assert_eq!(request.request_length(), Ok(4096));
}

#[test]
fn bytes_sent_reads_the_client_connection() {
    let mut connection: ngx_connection_t = unsafe { MaybeUninit::zeroed().assume_init() };
    connection.sent = 8192;

    let mut raw = zeroed_request();
    raw.connection = &raw mut connection;

    assert_eq!(request_from(&mut raw).bytes_sent(), Ok(8192));
}

#[test]
fn bytes_sent_rejects_a_negative_client_counter() {
    let mut connection: ngx_connection_t = unsafe { MaybeUninit::zeroed().assume_init() };
    connection.sent = -1;
    let mut raw = zeroed_request();
    raw.connection = &raw mut connection;

    assert_eq!(
        request_from(&mut raw).bytes_sent(),
        Err(RequestError::Connection(ConnectionError::NegativeBytesSent))
    );
}

#[cfg(feature = "test-link")]
#[test]
fn internal_redirect_flag_is_exposed() {
    let mut raw = zeroed_request();

    assert!(!request_from(&mut raw).is_internal());

    unsafe { ngx_rs_test_http_request_set_internal(&raw mut raw, 1) };
    assert!(request_from(&mut raw).is_internal());
}

#[cfg(feature = "test-link")]
#[test]
fn request_bitfields_match_nginx_c_abi() {
    let mut raw = zeroed_request();
    let mut request = request_from(&mut raw);
    request.set_header_only(true);
    request.set_keepalive(true);
    request.set_header_sent(true);
    request.set_expect_trailers(true);
    unsafe { ngx_rs_test_http_request_set_internal(request.as_ptr(), 1) };

    assert!(request.is_internal());
    assert!(request.header_only());
    assert!(request.keepalive());
    assert!(request.expect_trailers());
    assert_eq!(unsafe { ngx_rs_test_http_request_flags(request.as_ptr()) }, 31);
}

#[test]
fn subrequests_available_reports_the_remaining_nested_budget() {
    let mut raw = zeroed_request();

    raw.set_subrequests(3);
    assert_eq!(request_from(&mut raw).subrequests_available(), 3);

    raw.set_subrequests(1);
    assert_eq!(request_from(&mut raw).subrequests_available(), 1);

    raw.set_subrequests(0);
    assert_eq!(request_from(&mut raw).subrequests_available(), 0);
}

#[test]
fn result_converts_the_selected_branch_into_handler_status() {
    let mut raw = zeroed_request();
    let request = request_from(&mut raw);
    let success: Result<Status, HTTPStatus> = Ok(Status::NGX_AGAIN);
    let error: Result<Status, HTTPStatus> = Err(HTTPStatus::BAD_REQUEST);

    assert_eq!(success.into_handler_status(&request.view()), Status::NGX_AGAIN.0);
    assert_eq!(error.into_handler_status(&request.view()), 400);
}

#[test]
fn main_returns_the_same_main_request() {
    let mut raw = zeroed_request();
    let request = request_from(&mut raw);

    assert!(request.is_main().unwrap());
    let first = request.view();
    let second = request.view();
    assert_eq!(unsafe { first.as_ptr() }, unsafe { second.as_ptr() });
    assert_eq!(unsafe { request.main().unwrap().as_ptr() }, unsafe { request.as_ptr() });
}

#[test]
fn main_returns_the_parent_of_a_subrequest() {
    let mut raw_main = zeroed_request();
    initialize_request(&mut raw_main);
    let mut raw_subrequest = zeroed_request();
    initialize_request(&mut raw_subrequest);
    raw_subrequest.main = &raw mut raw_main;
    raw_subrequest.parent = &raw mut raw_main;

    let request = request_from(&mut raw_subrequest);
    let main = unsafe { request.main().unwrap().as_ptr() };

    assert_eq!(main, &raw const raw_main);
}

#[test]
fn main_returns_the_root_of_nested_subrequests() {
    let mut raw_main = zeroed_request();
    initialize_request(&mut raw_main);
    let mut raw_parent = zeroed_request();
    initialize_request(&mut raw_parent);
    raw_parent.main = &raw mut raw_main;
    raw_parent.parent = &raw mut raw_main;
    let mut raw_child = zeroed_request();
    initialize_request(&mut raw_child);
    raw_child.main = &raw mut raw_main;
    raw_child.parent = &raw mut raw_parent;

    let request = request_from(&mut raw_child);

    assert_eq!(unsafe { request.main().unwrap().as_ptr() }, &raw const raw_main);
}

#[test]
fn main_mut_updates_the_parent_of_a_subrequest() {
    let _globals = RequestGlobals::new(1, 1);
    let mut context = 41u32;
    let mut contexts = [(&raw mut context).cast()];
    let mut raw_main = zeroed_request();
    initialize_request(&mut raw_main);
    raw_main.ctx = contexts.as_mut_ptr();
    let mut raw_subrequest = zeroed_request();
    initialize_request(&mut raw_subrequest);
    raw_subrequest.main = &raw mut raw_main;
    raw_subrequest.parent = &raw mut raw_main;

    let mut request = request_from(&mut raw_subrequest);
    let mut main = request.main_mut().unwrap();
    *main.module_context_mut::<TestContextModule>().unwrap().unwrap() = 42;

    assert_eq!(context, 42);
}

#[test]
fn into_main_consumes_a_subrequest_view() {
    let mut raw_main = zeroed_request();
    initialize_request(&mut raw_main);
    let mut raw_subrequest = zeroed_request();
    initialize_request(&mut raw_subrequest);
    raw_subrequest.main = &raw mut raw_main;
    raw_subrequest.parent = &raw mut raw_main;

    let main = request_from(&mut raw_subrequest).into_main().unwrap();

    assert_eq!(unsafe { main.as_ptr() }, &raw mut raw_main);
}

#[cfg(feature = "test-link")]
#[test]
fn request_context_slots_validate_missing_and_misaligned_storage() {
    let _globals = RequestGlobals::new(1, 1);

    let mut missing = zeroed_request();
    assert_eq!(
        request_from(&mut missing).module_context::<TestContextModule>(),
        Err(RequestContextError::MissingSlots)
    );

    let mut misaligned_slots = zeroed_request();
    misaligned_slots.ctx = core::ptr::without_provenance_mut(1);
    assert_eq!(
        request_from(&mut misaligned_slots).module_context::<TestContextModule>(),
        Err(RequestContextError::MisalignedSlots)
    );

    let mut slots = [core::ptr::without_provenance_mut::<c_void>(1)];
    let mut misaligned_context = zeroed_request();
    misaligned_context.ctx = slots.as_mut_ptr();
    assert_eq!(
        request_from(&mut misaligned_context).module_context::<TestContextModule>(),
        Err(RequestContextError::MisalignedContext)
    );
}

#[cfg(feature = "test-link")]
#[test]
fn request_context_slots_reject_unavailable_module_indexes() {
    let _globals = RequestGlobals::new(0, 0);
    let mut raw = zeroed_request();

    assert_eq!(
        request_from(&mut raw).module_context::<TestContextModule>(),
        Err(RequestContextError::Configuration(HttpConfigError::ModuleIndexOutOfBounds))
    );
    assert!(matches!(
        request_from(&mut raw).get_or_insert_pinned_module_context_with::<PinnedContextModule>(
            || { pinned_context(ptr::null_mut()) }
        ),
        Err(RequestContextError::Configuration(HttpConfigError::ModuleIndexOutOfBounds))
    ));
}

#[cfg(feature = "test-link")]
#[test]
fn module_context_reads_the_associated_context_type() {
    let _globals = RequestGlobals::new(1, 1);
    let mut context = 41u32;
    let mut contexts = [(&raw mut context).cast()];
    let mut raw = zeroed_request();
    raw.ctx = contexts.as_mut_ptr();

    assert_eq!(request_from(&mut raw).module_context::<TestContextModule>(), Ok(Some(&41)));
}

#[cfg(feature = "test-link")]
#[test]
fn module_context_mut_updates_the_associated_context_type() {
    let _globals = RequestGlobals::new(1, 1);
    let mut context = 41u32;
    let mut contexts = [(&raw mut context).cast()];
    let mut raw = zeroed_request();
    raw.ctx = contexts.as_mut_ptr();

    *request_from(&mut raw).module_context_mut::<TestContextModule>().unwrap().unwrap() = 42;

    assert_eq!(context, 42);
}

#[cfg(feature = "test-link")]
#[test]
fn pinned_request_context_reuses_its_stable_pool_address_and_invalidates_before_drop() {
    let _globals = RequestGlobals::new(1, 1);
    reset_pinned_context_state();
    let owner = TestPool::new();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.ctx = slots.as_mut_ptr();

    let address = {
        let mut request = request_from(&mut raw);
        assert!(request.pinned_module_context_mut::<PinnedContextModule>().unwrap().is_none());

        let address = {
            let mut context = request
                .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                    PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                    pinned_context(slots.as_mut_ptr())
                })
                .unwrap();
            let address = NonNull::from(context.as_ref().get_ref()).as_ptr();
            unsafe { context.as_mut().get_unchecked_mut().value = 99 };
            address
        };

        let context = request.pinned_module_context_mut::<PinnedContextModule>().unwrap().unwrap();
        assert_eq!(NonNull::from(context.as_ref().get_ref()).as_ptr(), address);
        assert_eq!(context.as_ref().get_ref().value, 99);

        let reused = request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                panic!("existing context must be reused")
            })
            .unwrap();
        assert_eq!(NonNull::from(reused.as_ref().get_ref()).as_ptr(), address);
        assert_eq!(reused.as_ref().get_ref().value, 99);
        address
    };

    assert_eq!(slots[0], address.cast());
    assert_eq!(PINNED_CONTEXT_CONSTRUCTIONS.load(Ordering::Relaxed), 1);
    drop(owner);
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    assert!(PINNED_CONTEXT_DROP_SAW_INVALIDATED_SLOT.load(Ordering::Relaxed));
}

#[cfg(feature = "test-link")]
#[test]
fn native_slot_reset_cancels_old_context_before_replacement() {
    let _globals = RequestGlobals::new(1, 1);
    reset_pinned_context_state();
    let owner = TestPool::new();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.ctx = slots.as_mut_ptr();

    let old = {
        let mut request = request_from(&mut raw);
        let context = request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
        NonNull::from(context.as_ref().get_ref()).as_ptr()
    };

    slots[0] = ptr::null_mut();
    let status = unsafe { request_callback_status(&raw mut raw, |_request| Status::NGX_OK) };
    assert_eq!(status, NGX_OK as _);
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);

    let new = {
        let mut request = request_from(&mut raw);
        let context = request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
        NonNull::from(context.as_ref().get_ref()).as_ptr()
    };

    assert_ne!(new, old);
    assert_eq!(slots[0], new.cast());
    drop(owner);
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 2);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 2);
}

#[cfg(feature = "test-link")]
#[test]
fn stale_context_cancellation_keeps_the_pool_live_until_context_drop() {
    struct HeldContext {
        request: NonNull<ngx_http_request_t>,
        hold: Option<RequestHold>,
    }

    impl Drop for HeldContext {
        fn drop(&mut self) {
            assert!(!unsafe { self.request.as_ref() }.pool.is_null());
            PINNED_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct HeldContextModule;

    unsafe impl HttpModule for HeldContextModule {
        fn module() -> ModuleDescriptor {
            PinnedContextModule::module()
        }
    }

    unsafe impl HttpModuleRequestContext for HeldContextModule {
        type RequestContext = HeldContext;

        fn cancel(context: Pin<&mut HeldContext>) {
            let context = context.get_mut();
            let request = context.request;
            RequestHold::cancel(&mut context.hold);
            assert!(!unsafe { request.as_ref() }.pool.is_null());
        }

        fn cleanup(context: Pin<&mut HeldContext>) {
            unsafe { RequestHold::disarm_for_cleanup(&mut context.get_mut().hold) };
        }
    }

    let mut fixture = TerminalRequestFixture::new();
    reset_pinned_context_state();
    let mut slots = [ptr::null_mut(); 1];
    fixture.request.ctx = slots.as_mut_ptr();
    let mut hold = None;
    fixture.hold(&mut hold);
    let raw = NonNull::from(&mut *fixture.request);
    let context = {
        let mut request = request_from(&mut fixture.request);
        let context = request
            .get_or_insert_pinned_module_context_with::<HeldContextModule>(|| HeldContext {
                request: raw,
                hold,
            })
            .unwrap();
        NonNull::from(context.as_ref().get_ref())
    };
    fixture.request.set_count(1);
    unsafe { *fixture.request.ctx = ptr::null_mut() };

    let result = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| unsafe {
        RequestRefMut::is_current_module_context::<HeldContextModule>(raw.as_ptr(), context)
    }));
    if fixture.request.pool.is_null() {
        fixture.disarm_nginx_pools();
    }
    assert_eq!(result.unwrap(), Ok(false));
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    assert!(fixture.request.pool.is_null());
}

#[cfg(feature = "test-link")]
#[test]
fn failed_request_context_constructor_leaves_the_slot_unpublished_and_retries() {
    let _globals = RequestGlobals::new(1, 1);
    reset_pinned_context_state();
    let owner = TestPool::new();
    let cleanup = unsafe { (*owner.raw).cleanup };
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.ctx = slots.as_mut_ptr();

    {
        let mut request = request_from(&mut raw);
        assert!(matches!(
            request.try_get_or_insert_pinned_module_context_with::<PinnedContextModule, _>(|| {
                Err::<PinnedContext, _>(ConstructorError::Rejected)
            }),
            Err(RequestContextCreateError::Construction(ConstructorError::Rejected))
        ));
    }
    assert!(slots[0].is_null());
    assert_eq!(unsafe { (*owner.raw).cleanup }, cleanup);

    {
        let mut request = request_from(&mut raw);
        let context = request
            .try_get_or_insert_pinned_module_context_with::<PinnedContextModule, _>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                Ok::<PinnedContext, ConstructorError>(pinned_context(slots.as_mut_ptr()))
            })
            .unwrap();
        assert_eq!(context.as_ref().get_ref().value, 41);
    }
    assert!(!slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CONSTRUCTIONS.load(Ordering::Relaxed), 1);

    drop(owner);
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn failed_request_context_cleanup_registration_keeps_the_slot_empty_and_retries() {
    let _globals = RequestGlobals::new(1, 1);
    reset_pinned_context_state();
    let owner = TestPool::new();
    let cleanup = unsafe { (*owner.raw).cleanup };
    unsafe { (*owner.raw).max = 0 };
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.ctx = slots.as_mut_ptr();

    for successes in 0..=3 {
        unsafe { ngx_rs_test_fail_allocations_after(successes) };
        let result = {
            let mut request = request_from(&mut raw);
            request
                .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                    PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                    pinned_context(slots.as_mut_ptr())
                })
                .map(|_| ())
        };
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert_eq!(result, Err(RequestContextError::Allocation));
        assert!(slots[0].is_null());
        assert_eq!(unsafe { (*owner.raw).cleanup }, cleanup);
    }
    assert_eq!(PINNED_CONTEXT_CONSTRUCTIONS.load(Ordering::Relaxed), 0);

    {
        let mut request = request_from(&mut raw);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                PINNED_CONTEXT_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
    }
    assert!(!slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CONSTRUCTIONS.load(Ordering::Relaxed), 1);

    drop(owner);
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn request_pool_cleanup_cancels_pinned_timer_and_posted_event_before_drop() {
    let _globals = RequestGlobals::new(1, 1);
    reset_event_context_state();
    let owner = TestPool::new();
    let log = static_log_ref();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.ctx = slots.as_mut_ptr();

    {
        let mut request = request_from(&mut raw);
        let mut context = request
            .get_or_insert_pinned_module_context_with::<EventContextModule>(|| EventContext {
                timer: Timer::new(log, (), timer_context_callback as TimerContextCallback),
                posted: PostedEvent::new(log, (), posted_context_callback as PostedContextCallback),
            })
            .unwrap();
        let mut timer = unsafe { context.as_mut().map_unchecked_mut(|context| &mut context.timer) };
        unsafe { timer.as_mut().arm(5) }.unwrap();
        let mut posted =
            unsafe { context.as_mut().map_unchecked_mut(|context| &mut context.posted) };
        assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Next) }, Ok(true));
    }

    drop(owner);
    assert!(slots[0].is_null());
    assert_eq!(EVENT_CONTEXT_DROPS.load(Ordering::Relaxed), 1);

    let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
    unsafe {
        ngx_current_msec = 5;
        ngx_event_expire_timers();
        ngx_event_move_posted_next(&raw mut cycle);
        ngx_event_process_posted(&raw mut cycle, &raw mut ngx_posted_events);
    }
    assert_eq!(TIMER_CONTEXT_CALLBACKS.load(Ordering::Relaxed), 0);
    assert_eq!(POSTED_CONTEXT_CALLBACKS.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "test-link")]
#[test]
fn removing_a_pinned_request_context_cleans_up_exactly_once() {
    let _globals = RequestGlobals::new(1, 1);
    reset_pinned_context_state();
    let owner = TestPool::new();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.ctx = slots.as_mut_ptr();

    {
        let mut request = request_from(&mut raw);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
        assert_eq!(request.remove_module_context::<PinnedContextModule>(), Ok(true));
        assert!(slots[0].is_null());
        assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
        assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
        assert!(PINNED_CONTEXT_DROP_SAW_INVALIDATED_SLOT.load(Ordering::Relaxed));
        assert_eq!(request.remove_module_context::<PinnedContextModule>(), Ok(false));
    }

    drop(owner);
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn failed_request_context_cleanup_unlink_restores_its_slot() {
    let _globals = RequestGlobals::new(1, 1);
    reset_pinned_context_state();
    let owner = TestPool::new();
    let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_request();
    raw.pool = owner.raw;
    raw.ctx = slots.as_mut_ptr();

    {
        let mut request = request_from(&mut raw);
        request
            .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                pinned_context(slots.as_mut_ptr())
            })
            .unwrap();
    }

    let context = slots[0];
    let cleanup = unsafe { (*owner.raw).cleanup };
    assert!(!cleanup.is_null());
    unsafe {
        (*owner.raw).cleanup = (*cleanup).next;
        (*cleanup).next = ptr::null_mut();
    }

    {
        let mut request = request_from(&mut raw);
        assert_eq!(
            request.remove_module_context::<PinnedContextModule>(),
            Err(RequestContextError::MissingCleanup)
        );
    }
    assert_eq!(slots[0], context);
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 0);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 0);

    unsafe {
        (*cleanup).next = (*owner.raw).cleanup;
        (*owner.raw).cleanup = cleanup;
    }
    {
        let mut request = request_from(&mut raw);
        assert_eq!(request.remove_module_context::<PinnedContextModule>(), Ok(true));
    }
    assert!(slots[0].is_null());
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);

    drop(owner);
    assert_eq!(PINNED_CONTEXT_CLEANUPS.load(Ordering::Relaxed), 1);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[test]
fn status_is_none_when_unset_or_invalid() {
    let mut raw = zeroed_request();

    assert_eq!(request_from(&mut raw).status(), None);

    raw.headers_out.status = 600;
    assert_eq!(request_from(&mut raw).status(), None);
}

#[test]
fn status_returns_a_valid_response_status() {
    let mut raw = zeroed_request();
    raw.headers_out.status = 204;

    assert_eq!(request_from(&mut raw).status(), Some(HTTPStatus::NO_CONTENT));
}

#[test]
fn method_parses_supported_tokens() {
    let methods = [
        ("GET", Method::GET),
        ("HEAD", Method::HEAD),
        ("POST", Method::POST),
        ("PUT", Method::PUT),
        ("DELETE", Method::DELETE),
        ("MKCOL", Method::MKCOL),
        ("COPY", Method::COPY),
        ("MOVE", Method::MOVE),
        ("OPTIONS", Method::OPTIONS),
        ("PROPFIND", Method::PROPFIND),
        ("PROPPATCH", Method::PROPPATCH),
        ("LOCK", Method::LOCK),
        ("UNLOCK", Method::UNLOCK),
        ("PATCH", Method::PATCH),
        ("TRACE", Method::TRACE),
        ("CONNECT", Method::CONNECT),
    ];

    for (token, expected) in methods {
        assert_eq!(Method::try_from(token).unwrap(), expected);
    }
}

#[test]
fn method_rejects_unknown_or_lowercase_tokens() {
    assert!(Method::try_from("UNKNOWN").is_err());
    assert!(Method::try_from("get").is_err());
}
