extern crate alloc;

use alloc::boxed::Box;
use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::StreamGlobals;
use crate::collections::NgxArray;
use crate::core::Status;
use crate::ffi::{
    NGX_LOG_EMERG, NGX_STREAM_MODULE, ngx_array_t, ngx_conf_t, ngx_create_pool, ngx_destroy_pool,
    ngx_log_t, ngx_pool_t, ngx_stream_conf_ctx_t, ngx_stream_core_main_conf_t,
    ngx_stream_handler_pt, ngx_stream_session_t, ngx_uint_t,
};
use crate::stream::{
    Session, StreamPhase, StreamSessionHandler, add_phase_handler, try_add_phase_handler,
};

const PHASE_COUNT: usize = StreamPhase::Log as usize + 1;
const PHASE_HANDLER_CAPACITY: usize = 4;

struct LogCapture {
    len: usize,
}

unsafe extern "C" fn capture_log(
    log: *mut ngx_log_t,
    _level: ngx_uint_t,
    _bytes: *mut u8,
    len: usize,
) {
    let Some(log) = (unsafe { log.as_mut() }) else {
        return;
    };
    let Some(capture) = (unsafe { log.wdata.cast::<LogCapture>().as_mut() }) else {
        return;
    };

    capture.len = len;
}

fn phase_handler_array(
    elts: *mut c_void,
    nalloc: ngx_uint_t,
    pool: *mut ngx_pool_t,
) -> ngx_array_t {
    ngx_array_t { elts, nelts: 0, size: mem::size_of::<ngx_stream_handler_pt>(), nalloc, pool }
}

struct PhaseFixture {
    _globals: StreamGlobals,
    pool: *mut ngx_pool_t,
    _log: Box<ngx_log_t>,
    capture: Box<LogCapture>,
    _handler_storage: Box<[[ngx_stream_handler_pt; PHASE_HANDLER_CAPACITY]; PHASE_COUNT]>,
    main: Box<ngx_stream_core_main_conf_t>,
    main_slots: Box<[*mut c_void; 1]>,
    _context: Box<ngx_stream_conf_ctx_t>,
    cf: Box<ngx_conf_t>,
}

impl PhaseFixture {
    fn new() -> Self {
        let globals = StreamGlobals::new(1, 1);
        let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
        let capture = Box::new(LogCapture { len: 0 });
        let pool = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!pool.is_null());

        let mut handler_storage = Box::new([[None; PHASE_HANDLER_CAPACITY]; PHASE_COUNT]);
        let mut main = Box::new(unsafe { mem::zeroed::<ngx_stream_core_main_conf_t>() });
        for (phase, storage) in main.phases.iter_mut().zip(handler_storage.iter_mut()) {
            phase.handlers =
                phase_handler_array(storage.as_mut_ptr().cast(), PHASE_HANDLER_CAPACITY as _, pool);
        }

        let mut main_slots = Box::new([(&raw mut *main).cast()]);
        let mut context = Box::new(ngx_stream_conf_ctx_t {
            main_conf: main_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
        });
        let mut cf = Box::new(unsafe { mem::zeroed::<ngx_conf_t>() });
        cf.module_type = NGX_STREAM_MODULE as _;
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

    fn phase_handlers(&mut self, phase: StreamPhase) -> &mut ngx_array_t {
        &mut self.main.phases[phase as usize].handlers
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

struct PrereadHandler;

impl StreamSessionHandler for PrereadHandler {
    const PHASE: StreamPhase = StreamPhase::Preread;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

fn assert_preread_registration_error(fixture: &mut PhaseFixture) {
    let before = fixture.phase_handlers(StreamPhase::Preread).nelts;
    assert!(add_phase_handler::<PrereadHandler>(&mut fixture.cf).is_err());
    assert_eq!(fixture.phase_handlers(StreamPhase::Preread).nelts, before);
}

struct PostAcceptHandler;

impl StreamSessionHandler for PostAcceptHandler {
    const PHASE: StreamPhase = StreamPhase::PostAccept;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct PreaccessHandler;

impl StreamSessionHandler for PreaccessHandler {
    const PHASE: StreamPhase = StreamPhase::Preaccess;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct AccessHandler;

impl StreamSessionHandler for AccessHandler {
    const PHASE: StreamPhase = StreamPhase::Access;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct SslHandler;

impl StreamSessionHandler for SslHandler {
    const PHASE: StreamPhase = StreamPhase::Ssl;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

struct LogHandler;

impl StreamSessionHandler for LogHandler {
    const PHASE: StreamPhase = StreamPhase::Log;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

static NEXT_HANDLER_ORDER: AtomicUsize = AtomicUsize::new(0);
static FIRST_HANDLER_ORDER: AtomicUsize = AtomicUsize::new(0);
static SECOND_HANDLER_ORDER: AtomicUsize = AtomicUsize::new(0);

struct FirstPrereadHandler;

impl StreamSessionHandler for FirstPrereadHandler {
    const PHASE: StreamPhase = StreamPhase::Preread;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        FIRST_HANDLER_ORDER
            .store(NEXT_HANDLER_ORDER.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
        Status::NGX_DECLINED
    }
}

struct SecondPrereadHandler;

impl StreamSessionHandler for SecondPrereadHandler {
    const PHASE: StreamPhase = StreamPhase::Preread;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        SECOND_HANDLER_ORDER
            .store(NEXT_HANDLER_ORDER.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
        Status::NGX_DECLINED
    }
}

#[test]
fn phase_registration_rejects_malformed_phase_storage_without_panicking() {
    {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(StreamPhase::Preread).size = 0;
        assert_preread_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(StreamPhase::Preread).elts = ptr::null_mut();
        assert_preread_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        let elts = fixture.phase_handlers(StreamPhase::Preread).elts;
        fixture.phase_handlers(StreamPhase::Preread).elts =
            unsafe { elts.cast::<u8>().add(1).cast() };
        assert_preread_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(StreamPhase::Preread).size =
            mem::size_of::<ngx_stream_handler_pt>() + 1;
        assert_preread_registration_error(&mut fixture);
    }

    {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(StreamPhase::Preread).nelts = (PHASE_HANDLER_CAPACITY + 1) as _;
        assert_preread_registration_error(&mut fixture);
    }
}

#[test]
fn phase_registration_rejects_missing_core_main_configuration() {
    let mut fixture = PhaseFixture::new();
    fixture.main_slots[0] = ptr::null_mut();

    assert_preread_registration_error(&mut fixture);
}

#[test]
fn phase_registration_rejects_a_non_stream_configuration() {
    let mut fixture = PhaseFixture::new();
    fixture.cf.module_type = 0;

    assert_preread_registration_error(&mut fixture);
}

#[test]
fn phase_registration_reports_push_failure_without_appending() {
    let mut fixture = PhaseFixture::new();
    fixture.phase_handlers(StreamPhase::Preread).pool = ptr::null_mut();

    assert_preread_registration_error(&mut fixture);
}

#[test]
fn try_phase_registration_returns_error_without_logging() {
    let mut fixture = PhaseFixture::new();
    fixture.capture_errors();
    fixture.phase_handlers(StreamPhase::Preread).pool = ptr::null_mut();

    assert!(try_add_phase_handler::<PrereadHandler>(&mut fixture.cf).is_err());
    assert_eq!(fixture.capture.len, 0);
}

#[test]
fn phase_registration_appends_every_public_stream_phase() {
    let mut fixture = PhaseFixture::new();

    assert!(add_phase_handler::<PostAcceptHandler>(&mut fixture.cf).is_ok());
    assert!(add_phase_handler::<PreaccessHandler>(&mut fixture.cf).is_ok());
    assert!(add_phase_handler::<AccessHandler>(&mut fixture.cf).is_ok());
    assert!(add_phase_handler::<SslHandler>(&mut fixture.cf).is_ok());
    assert!(add_phase_handler::<PrereadHandler>(&mut fixture.cf).is_ok());
    assert!(add_phase_handler::<LogHandler>(&mut fixture.cf).is_ok());

    assert_eq!(fixture.phase_handlers(StreamPhase::PostAccept).nelts, 1);
    assert_eq!(fixture.phase_handlers(StreamPhase::Preaccess).nelts, 1);
    assert_eq!(fixture.phase_handlers(StreamPhase::Access).nelts, 1);
    assert_eq!(fixture.phase_handlers(StreamPhase::Ssl).nelts, 1);
    assert_eq!(fixture.phase_handlers(StreamPhase::Preread).nelts, 1);
    assert_eq!(fixture.phase_handlers(StreamPhase::Log).nelts, 1);
}

#[test]
fn phase_registration_keeps_nginx_reverse_dispatch_order() {
    NEXT_HANDLER_ORDER.store(0, Ordering::Relaxed);
    FIRST_HANDLER_ORDER.store(0, Ordering::Relaxed);
    SECOND_HANDLER_ORDER.store(0, Ordering::Relaxed);
    let mut fixture = PhaseFixture::new();

    assert!(add_phase_handler::<FirstPrereadHandler>(&mut fixture.cf).is_ok());
    assert!(add_phase_handler::<SecondPrereadHandler>(&mut fixture.cf).is_ok());

    let handlers = unsafe {
        NgxArray::<ngx_stream_handler_pt>::from_ngx_array(
            fixture.phase_handlers(StreamPhase::Preread),
        )
    };
    assert_eq!(handlers.as_ref().map(|handlers| handlers.len()), Some(2));
    let Some(handlers) = handlers else {
        return;
    };
    let mut session = unsafe { mem::zeroed::<ngx_stream_session_t>() };
    for handler in handlers.iter().rev().flatten() {
        assert_eq!(unsafe { (*handler)(&raw mut session) }, Status::NGX_DECLINED.0);
    }

    assert_eq!(SECOND_HANDLER_ORDER.load(Ordering::Relaxed), 1);
    assert_eq!(FIRST_HANDLER_ORDER.load(Ordering::Relaxed), 2);
}
