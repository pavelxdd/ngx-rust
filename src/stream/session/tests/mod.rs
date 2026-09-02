extern crate alloc;
#[cfg(feature = "test-link")]
extern crate std;

use alloc::boxed::Box;
#[cfg(feature = "test-link")]
use core::ffi::c_void;
#[cfg(feature = "test-link")]
use core::marker::PhantomPinned;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "test-link")]
use std::sync::MutexGuard;

use super::{
    IntoHandlerStatus, Session, SessionContextError, SessionError, StreamModuleSessionContext,
    StreamSessionHandler, raw_handler,
};
use crate::core::{ConnectionError, ModuleDescriptor, Status};
#[cfg(feature = "test-link")]
use crate::event::{Timer, TimerCallback};
use crate::ffi::{NGX_ERROR, ngx_module_t, ngx_stream_session_t};
#[cfg(feature = "test-link")]
use crate::ffi::{
    NGX_STREAM_MODULE, ngx_connection_t, ngx_create_pool, ngx_current_msec, ngx_destroy_pool,
    ngx_event_expire_timers, ngx_event_timer_init, ngx_log_t, ngx_pool_t, ngx_uint_t,
};
#[cfg(feature = "test-link")]
use crate::log::LogRef;
use crate::stream::{
    StreamConfigError, StreamModule, StreamModuleMainConf, StreamModuleServerConf, StreamPhase,
};

struct TestContextModule;

unsafe impl StreamModule for TestContextModule {
    fn module() -> ModuleDescriptor {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_STREAM_MODULE as _;
        module.index = 0;
        module.ctx_index = 0;
        ModuleDescriptor::from_test(module)
    }
}

unsafe impl StreamModuleMainConf for TestContextModule {
    type MainConf = u32;
}

unsafe impl StreamModuleServerConf for TestContextModule {
    type ServerConf = u32;
}

fn zeroed_session() -> ngx_stream_session_t {
    unsafe { MaybeUninit::zeroed().assume_init() }
}

fn misaligned_session_ptr(storage: &mut [u8]) -> *mut ngx_stream_session_t {
    let alignment = core::mem::align_of::<ngx_stream_session_t>();
    let offset = storage.as_mut_ptr().align_offset(alignment);
    assert!(offset < storage.len());
    unsafe { storage.as_mut_ptr().add(offset + 1).cast() }
}

#[cfg(feature = "test-link")]
struct StreamGlobals {
    _guard: MutexGuard<'static, ()>,
    max_module: ngx_uint_t,
    stream_max_module: ngx_uint_t,
}

#[cfg(feature = "test-link")]
impl StreamGlobals {
    fn new() -> Self {
        let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let max_module = unsafe { nginx_sys::ngx_max_module };
        let stream_max_module = unsafe { nginx_sys::ngx_stream_max_module };

        unsafe {
            nginx_sys::ngx_max_module = 1;
            nginx_sys::ngx_stream_max_module = 1;
        }

        Self { _guard: guard, max_module, stream_max_module }
    }
}

#[cfg(feature = "test-link")]
impl Drop for StreamGlobals {
    fn drop(&mut self) {
        unsafe {
            nginx_sys::ngx_max_module = self.max_module;
            nginx_sys::ngx_stream_max_module = self.stream_max_module;
        }
    }
}

struct TestHandler;

impl StreamSessionHandler for TestHandler {
    const PHASE: StreamPhase = StreamPhase::Preread;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        Status::NGX_DECLINED
    }
}

static RAW_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

struct RawHandler;

impl StreamSessionHandler for RawHandler {
    const PHASE: StreamPhase = StreamPhase::Preread;
    type Output = Status;

    fn handler(_session: &mut Session<'_>) -> Self::Output {
        RAW_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
        Status::NGX_DECLINED
    }
}

#[cfg(feature = "test-link")]
static CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
unsafe extern "C" {
    fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
    fn ngx_rs_test_reset_allocation_failures();
}

#[cfg(feature = "test-link")]
struct TestContext(u32);

#[cfg(feature = "test-link")]
impl Drop for TestContext {
    fn drop(&mut self) {
        CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
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
}

#[cfg(feature = "test-link")]
impl Drop for TestPool {
    fn drop(&mut self) {
        unsafe { ngx_destroy_pool(self.raw) };
    }
}

#[cfg(feature = "test-link")]
struct PoolContextModule;

#[cfg(feature = "test-link")]
unsafe impl StreamModule for PoolContextModule {
    fn module() -> ModuleDescriptor {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_STREAM_MODULE as _;
        module.index = 0;
        module.ctx_index = 0;
        ModuleDescriptor::from_test(module)
    }
}

#[cfg(feature = "test-link")]
unsafe impl StreamModuleSessionContext for PoolContextModule {
    type SessionContext = TestContext;
}

#[cfg(feature = "test-link")]
struct OutOfBoundsContextModule;

#[cfg(feature = "test-link")]
unsafe impl StreamModule for OutOfBoundsContextModule {
    fn module() -> ModuleDescriptor {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_STREAM_MODULE as _;
        module.index = 1;
        module.ctx_index = 0;
        ModuleDescriptor::from_test(module)
    }
}

#[cfg(feature = "test-link")]
unsafe impl StreamModuleSessionContext for OutOfBoundsContextModule {
    type SessionContext = TestContext;
}

#[cfg(feature = "test-link")]
static PINNED_CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
struct PinnedContext {
    value: u32,
    _pin: PhantomPinned,
}

#[cfg(feature = "test-link")]
impl Drop for PinnedContext {
    fn drop(&mut self) {
        PINNED_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
struct PinnedContextModule;

#[cfg(feature = "test-link")]
unsafe impl StreamModule for PinnedContextModule {
    fn module() -> ModuleDescriptor {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_STREAM_MODULE as _;
        module.index = 0;
        module.ctx_index = 0;
        ModuleDescriptor::from_test(module)
    }
}

#[cfg(feature = "test-link")]
unsafe impl StreamModuleSessionContext for PinnedContextModule {
    type SessionContext = PinnedContext;
}

#[cfg(feature = "test-link")]
static TIMER_CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
static TIMER_CONTEXT_CALLBACKS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
type TimerContextCallback = for<'callback> fn(TimerCallback<'callback, ()>);

#[cfg(feature = "test-link")]
fn timer_context_callback(_timer: TimerCallback<'_, ()>) {
    TIMER_CONTEXT_CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(feature = "test-link")]
struct TimerContextDrop;

#[cfg(feature = "test-link")]
impl Drop for TimerContextDrop {
    fn drop(&mut self) {
        TIMER_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
struct TimerContext {
    timer: Timer<'static, (), TimerContextCallback>,
    _drop: TimerContextDrop,
}

#[cfg(feature = "test-link")]
fn static_log_ref() -> LogRef<'static> {
    let log = Box::leak(Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() }));
    unsafe { LogRef::from_raw(log) }.expect("test logger")
}

#[cfg(feature = "test-link")]
struct TimerContextModule;

#[cfg(feature = "test-link")]
unsafe impl StreamModule for TimerContextModule {
    fn module() -> ModuleDescriptor {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_STREAM_MODULE as _;
        module.index = 0;
        module.ctx_index = 0;
        ModuleDescriptor::from_test(module)
    }
}

#[cfg(feature = "test-link")]
unsafe impl StreamModuleSessionContext for TimerContextModule {
    type SessionContext = TimerContext;
}

mod adapter;
mod context;
