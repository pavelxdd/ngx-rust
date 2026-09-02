use alloc::boxed::Box;
use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::HttpGlobals;
use crate::collections::NgxArray;
use crate::core::Status;
use crate::ffi::{
    NGX_HTTP_MODULE, NGX_LOG_EMERG, ngx_array_t, ngx_conf_t, ngx_create_pool, ngx_destroy_pool,
    ngx_http_conf_ctx_t, ngx_http_core_main_conf_t, ngx_http_handler_pt, ngx_http_request_t,
    ngx_int_t, ngx_log_t, ngx_pool_t, ngx_uint_t,
};
use crate::http::{
    HTTPStatus, HttpPhase, HttpRequestHandler, RequestRefMut, phase_handler_postconfiguration,
};

const PHASE_COUNT: usize = HttpPhase::Log as usize + 1;
const PHASE_HANDLER_CAPACITY: usize = 8;

struct LogCapture {
    level: ngx_uint_t,
    len: usize,
    bytes: [u8; 2048],
}

impl Default for LogCapture {
    fn default() -> Self {
        Self { level: 0, len: 0, bytes: [0; 2048] }
    }
}

unsafe extern "C" fn capture_log(
    log: *mut ngx_log_t,
    level: ngx_uint_t,
    bytes: *mut u8,
    len: usize,
) {
    let Some(log) = (unsafe { log.as_mut() }) else {
        return;
    };
    let Some(capture) = (unsafe { log.wdata.cast::<LogCapture>().as_mut() }) else {
        return;
    };
    if bytes.is_null() {
        return;
    }

    let len = len.min(capture.bytes.len());
    unsafe {
        ptr::copy_nonoverlapping(bytes, capture.bytes.as_mut_ptr(), len);
    }
    capture.level = level;
    capture.len = len;
}

fn phase_handler_array(
    elts: *mut c_void,
    nalloc: ngx_uint_t,
    pool: *mut ngx_pool_t,
) -> ngx_array_t {
    ngx_array_t { elts, nelts: 0, size: mem::size_of::<ngx_http_handler_pt>(), nalloc, pool }
}

struct PhaseFixture {
    _globals: HttpGlobals,
    pool: *mut ngx_pool_t,
    _log: Box<ngx_log_t>,
    capture: Box<LogCapture>,
    _handler_storage: Box<[[ngx_http_handler_pt; PHASE_HANDLER_CAPACITY]; PHASE_COUNT]>,
    main: Box<ngx_http_core_main_conf_t>,
    main_slots: Box<[*mut c_void; 1]>,
    _context: Box<ngx_http_conf_ctx_t>,
    cf: Box<ngx_conf_t>,
}

impl PhaseFixture {
    fn new() -> Self {
        let globals = HttpGlobals::new(1, 1);
        let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
        let capture = Box::<LogCapture>::default();
        let pool = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!pool.is_null());

        let mut handler_storage = Box::new([[None; PHASE_HANDLER_CAPACITY]; PHASE_COUNT]);
        let mut main = Box::new(unsafe { mem::zeroed::<ngx_http_core_main_conf_t>() });
        for (phase, storage) in main.phases.iter_mut().zip(handler_storage.iter_mut()) {
            phase.handlers =
                phase_handler_array(storage.as_mut_ptr().cast(), PHASE_HANDLER_CAPACITY as _, pool);
        }

        let mut main_slots = Box::new([(&raw mut *main).cast()]);
        let mut context = Box::new(ngx_http_conf_ctx_t {
            main_conf: main_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
            loc_conf: ptr::null_mut(),
        });
        let mut cf = Box::new(unsafe { mem::zeroed::<ngx_conf_t>() });
        cf.module_type = NGX_HTTP_MODULE as _;
        cf.ctx = (&raw mut *context).cast();
        cf.pool = pool;
        cf.log = &raw mut *log;

        Self {
            _globals: globals,
            pool,
            _log: log,
            capture,
            _handler_storage: handler_storage,
            main,
            main_slots,
            _context: context,
            cf,
        }
    }

    fn register<H: HttpRequestHandler>(&mut self) -> ngx_int_t {
        unsafe { phase_handler_postconfiguration::<H>(&raw mut *self.cf) }
    }

    fn phase_handlers(&mut self, phase: HttpPhase) -> &mut ngx_array_t {
        &mut self.main.phases[phase as usize].handlers
    }

    fn registered_handler(&self, phase: HttpPhase, index: usize) -> ngx_http_handler_pt {
        let handlers = unsafe {
            NgxArray::<ngx_http_handler_pt>::from_ngx_array(
                &self.main.phases[phase as usize].handlers,
            )
        };
        handlers.and_then(|handlers| handlers.get(index).copied()).flatten()
    }

    fn capture_errors(&mut self) {
        self._log.log_level = NGX_LOG_EMERG as _;
        self._log.writer = Some(capture_log);
        self._log.wdata = (&raw mut *self.capture).cast();
    }
}

impl Drop for PhaseFixture {
    fn drop(&mut self) {
        unsafe {
            ngx_destroy_pool(self.pool);
        }
    }
}

fn callback_request() -> ngx_http_request_t {
    let mut request = unsafe { mem::zeroed::<ngx_http_request_t>() };
    request.signature = NGX_HTTP_MODULE as _;
    request
}

fn assert_access_registration_error(fixture: &mut PhaseFixture) {
    let before = fixture.phase_handlers(HttpPhase::Access).nelts;
    assert_eq!(fixture.register::<AccessHandler>(), Status::NGX_ERROR.0);
    assert_eq!(fixture.phase_handlers(HttpPhase::Access).nelts, before);
}

struct PostReadHandler;

impl HttpRequestHandler for PostReadHandler {
    const PHASE: HttpPhase = HttpPhase::PostRead;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct ServerRewriteHandler;

impl HttpRequestHandler for ServerRewriteHandler {
    const PHASE: HttpPhase = HttpPhase::ServerRewrite;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct RewriteHandler;

impl HttpRequestHandler for RewriteHandler {
    const PHASE: HttpPhase = HttpPhase::Rewrite;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct PreaccessHandler;

impl HttpRequestHandler for PreaccessHandler {
    const PHASE: HttpPhase = HttpPhase::Preaccess;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct AccessHandler;

impl HttpRequestHandler for AccessHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct NamedAccessHandler;

impl HttpRequestHandler for NamedAccessHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }

    fn name() -> &'static str {
        "named HTTP phase"
    }
}

struct PreContentHandler;

impl HttpRequestHandler for PreContentHandler {
    const PHASE: HttpPhase = HttpPhase::PreContent;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct ContentHandler;

impl HttpRequestHandler for ContentHandler {
    const PHASE: HttpPhase = HttpPhase::Content;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct LogHandler;

impl HttpRequestHandler for LogHandler {
    const PHASE: HttpPhase = HttpPhase::Log;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

static NEXT_HANDLER_ORDER: AtomicUsize = AtomicUsize::new(0);
static FIRST_HANDLER_ORDER: AtomicUsize = AtomicUsize::new(0);
static SECOND_HANDLER_ORDER: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);

struct FirstAccessHandler;

impl HttpRequestHandler for FirstAccessHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        FIRST_HANDLER_ORDER
            .store(NEXT_HANDLER_ORDER.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
        Status::NGX_DECLINED
    }
}

struct SecondAccessHandler;

impl HttpRequestHandler for SecondAccessHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        SECOND_HANDLER_ORDER
            .store(NEXT_HANDLER_ORDER.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
        Status::NGX_DECLINED
    }
}

struct RawStatusHandler;

impl HttpRequestHandler for RawStatusHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = isize;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_AGAIN.0
    }
}

struct StatusHandler;

impl HttpRequestHandler for StatusHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct HttpStatusHandler;

impl HttpRequestHandler for HttpStatusHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = HTTPStatus;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        HTTPStatus::NO_CONTENT
    }
}

struct OptionalStatusHandler;

impl HttpRequestHandler for OptionalStatusHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Option<Status>;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        None
    }
}

struct ResultStatusHandler;

impl HttpRequestHandler for ResultStatusHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Result<Status, HTTPStatus>;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        Err(HTTPStatus::BAD_REQUEST)
    }
}

struct CountingHandler;

impl HttpRequestHandler for CountingHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Status;

    fn handler(_request: &mut RequestRefMut<'_>) -> Self::Output {
        CALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        Status::NGX_DECLINED
    }
}

#[test]
fn phase_postconfiguration_rejects_null_and_misaligned_parser_contexts() {
    assert_eq!(
        unsafe { phase_handler_postconfiguration::<AccessHandler>(ptr::null_mut()) },
        Status::NGX_ERROR.0
    );

    let misaligned = ptr::without_provenance_mut::<ngx_conf_t>(1);
    assert_eq!(
        unsafe { phase_handler_postconfiguration::<AccessHandler>(misaligned) },
        Status::NGX_ERROR.0
    );
}

#[test]
fn phase_registration_does_not_require_the_late_module_type_discriminator() {
    let mut fixture = PhaseFixture::new();
    fixture.cf.module_type = 0;

    assert_eq!(fixture.register::<AccessHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.phase_handlers(HttpPhase::Access).nelts, 1);
}

#[test]
fn phase_registration_rejects_missing_configuration_and_invalid_core_module_identity() {
    {
        let mut fixture = PhaseFixture::new();
        fixture.main_slots[0] = ptr::null_mut();
        assert_access_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        fixture._globals.set_http_core_module(0, 0, 0);
        assert_access_registration_error(&mut fixture);
        fixture._globals.set_http_core_module(NGX_HTTP_MODULE as _, ngx_uint_t::MAX, 0);
        assert_access_registration_error(&mut fixture);
        fixture._globals.set_http_core_module(NGX_HTTP_MODULE as _, 1, 0);
        assert_access_registration_error(&mut fixture);
        fixture._globals.set_http_core_module(NGX_HTTP_MODULE as _, 0, 1);
        assert_access_registration_error(&mut fixture);
    }
}

#[test]
fn phase_registration_rejects_malformed_phase_storage_without_appending() {
    {
        let mut fixture = PhaseFixture::new();
        *fixture.phase_handlers(HttpPhase::Access) = unsafe { mem::zeroed() };
        assert_access_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(HttpPhase::Access).elts = ptr::null_mut();
        assert_access_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        let elts = fixture.phase_handlers(HttpPhase::Access).elts;
        fixture.phase_handlers(HttpPhase::Access).elts = unsafe { elts.cast::<u8>().add(1).cast() };
        assert_access_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(HttpPhase::Access).size = mem::size_of::<ngx_http_handler_pt>() + 1;
        assert_access_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(HttpPhase::Access).nelts = (PHASE_HANDLER_CAPACITY + 1) as _;
        assert_access_registration_error(&mut fixture);
    }
}

#[test]
fn phase_registration_reports_push_failure_without_appending() {
    let mut fixture = PhaseFixture::new();
    fixture.phase_handlers(HttpPhase::Access).pool = ptr::null_mut();

    assert_access_registration_error(&mut fixture);
}

#[test]
fn phase_registration_logs_the_handler_name_at_emerg() {
    let mut fixture = PhaseFixture::new();
    fixture.capture_errors();
    fixture.phase_handlers(HttpPhase::Access).pool = ptr::null_mut();

    assert_eq!(fixture.register::<NamedAccessHandler>(), Status::NGX_ERROR.0);
    assert_eq!(fixture.capture.level, NGX_LOG_EMERG as _);
    assert!(
        fixture.capture.bytes[..fixture.capture.len]
            .windows(b"failed to register named HTTP phase handler".len())
            .any(|window| window == b"failed to register named HTTP phase handler")
    );
}

#[test]
fn phase_registration_appends_every_public_http_phase() {
    let mut fixture = PhaseFixture::new();

    assert_eq!(fixture.register::<PostReadHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<ServerRewriteHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<RewriteHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<PreaccessHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<AccessHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<PreContentHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<ContentHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<LogHandler>(), Status::NGX_OK.0);

    for phase in [
        HttpPhase::PostRead,
        HttpPhase::ServerRewrite,
        HttpPhase::Rewrite,
        HttpPhase::Preaccess,
        HttpPhase::Access,
        HttpPhase::PreContent,
        HttpPhase::Content,
        HttpPhase::Log,
    ] {
        assert_eq!(fixture.phase_handlers(phase).nelts, 1);
    }
}

#[test]
fn phase_registration_keeps_nginx_reverse_dispatch_order() {
    NEXT_HANDLER_ORDER.store(0, Ordering::Relaxed);
    FIRST_HANDLER_ORDER.store(0, Ordering::Relaxed);
    SECOND_HANDLER_ORDER.store(0, Ordering::Relaxed);
    let mut fixture = PhaseFixture::new();

    assert_eq!(fixture.register::<FirstAccessHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<SecondAccessHandler>(), Status::NGX_OK.0);

    let handlers = unsafe {
        NgxArray::<ngx_http_handler_pt>::from_ngx_array(fixture.phase_handlers(HttpPhase::Access))
    };
    assert_eq!(handlers.map(|handlers| handlers.len()), Some(2));
    let Some(handlers) = handlers else {
        return;
    };
    let mut request = callback_request();
    for handler in handlers.iter().rev().flatten() {
        assert_eq!(unsafe { (*handler)(&raw mut request) }, Status::NGX_DECLINED.0);
    }

    assert_eq!(SECOND_HANDLER_ORDER.load(Ordering::Relaxed), 1);
    assert_eq!(FIRST_HANDLER_ORDER.load(Ordering::Relaxed), 2);
}

#[test]
fn phase_handlers_convert_statuses_and_create_fresh_request_borrows() {
    CALLBACK_COUNT.store(0, Ordering::Relaxed);
    let mut fixture = PhaseFixture::new();

    assert_eq!(fixture.register::<RawStatusHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<StatusHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<HttpStatusHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<OptionalStatusHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<ResultStatusHandler>(), Status::NGX_OK.0);
    assert_eq!(fixture.register::<CountingHandler>(), Status::NGX_OK.0);

    let mut request = callback_request();
    for (index, expected) in [
        (0, Status::NGX_AGAIN.0),
        (1, Status::NGX_DECLINED.0),
        (2, HTTPStatus::NO_CONTENT.into()),
        (3, Status::NGX_ERROR.0),
        (4, HTTPStatus::BAD_REQUEST.into()),
    ] {
        let Some(handler) = fixture.registered_handler(HttpPhase::Access, index) else {
            panic!("registered phase handler is missing");
        };
        assert_eq!(unsafe { handler(&raw mut request) }, expected);
    }

    let Some(handler) = fixture.registered_handler(HttpPhase::Access, 5) else {
        panic!("registered phase handler is missing");
    };
    assert_eq!(unsafe { handler(ptr::null_mut()) }, Status::NGX_ERROR.0);
    assert_eq!(unsafe { handler(ptr::without_provenance_mut(1)) }, Status::NGX_ERROR.0);
    assert_eq!(unsafe { handler(&raw mut request) }, Status::NGX_DECLINED.0);
    assert_eq!(unsafe { handler(&raw mut request) }, Status::NGX_DECLINED.0);
    assert_eq!(CALLBACK_COUNT.load(Ordering::Relaxed), 2);
}
