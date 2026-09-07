use core::cell::RefCell;
use core::future::Future;
use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::ptr::NonNull;

use crate::async_::{AttachedTask, spawn};
use crate::event::{PostedEvent, PostedEventCallback, PostedQueue};
use crate::ffi::{NGX_DONE, NGX_ERROR, ngx_http_posted_request_t, ngx_int_t};
use crate::http::{
    HttpModuleRequestContext, HttpPhase, HttpRequestHandler, IntoHandlerStatus, RequestHold,
    RequestRefMut, add_phase_handler,
};
use crate::log::LogRef;
use crate::{ngx_log_debug_http, ngx_log_error};

/// An asynchronous HTTP phase handler.
///
/// [`start`](Self::start) runs while nginx owns the request. Its returned future is required to be
/// `'static`, so it cannot keep request references across a suspension point. When the future
/// completes, nginx invokes [`finish`](Self::finish) with a new exclusive request borrow.
pub trait AsyncHttpRequestHandler: Sized + 'static {
    /// The phase in which the handler is invoked.
    const PHASE: HttpPhase;
    /// The HTTP module whose request-context slot owns the pending task.
    type Module: HttpModuleRequestContext<RequestContext = AsyncHandlerContext<Self>>;
    /// The value produced without holding a request reference.
    ///
    /// It is moved out of pinned request state before [`finish`](Self::finish), so it must be
    /// [`Unpin`].
    type Output: 'static + Unpin;
    /// The final phase-handler result.
    type Result: IntoHandlerStatus;

    /// Starts the asynchronous work.
    fn start(request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static;

    /// Applies the completed output to the request on the nginx event loop.
    fn finish(request: &mut RequestRefMut<'_>, output: Self::Output) -> Self::Result;

    /// Handler name used in log messages.
    fn name() -> &'static str {
        core::any::type_name::<Self>()
    }
}

/// Failure returned while registering an asynchronous HTTP phase handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsyncHandlerRegistrationError {
    /// The content phase finalizes every non-declined handler result and cannot suspend safely.
    ContentPhase,
    /// The log phase runs during request teardown and cannot resume asynchronously.
    LogPhase,
    /// Nginx could not allocate the phase-handler registration entry.
    Allocation,
}

type AsyncContinuationCallback<H> =
    for<'callback> fn(PostedEventCallback<'callback, RefCell<AsyncContinuationState<H>>>);
type AsyncContinuation<H> =
    PostedEvent<'static, RefCell<AsyncContinuationState<H>>, AsyncContinuationCallback<H>>;

struct AsyncContinuationState<H>
where
    H: AsyncHttpRequestHandler,
{
    task: Option<AttachedTask<()>>,
    output: Option<H::Output>,
    hold: Option<RequestHold>,
    posted_request: NonNull<ngx_http_posted_request_t>,
    context: Option<NonNull<AsyncHandlerContext<H>>>,
    active: bool,
    phase_posted: bool,
}

impl<H> AsyncContinuationState<H>
where
    H: AsyncHttpRequestHandler,
{
    fn new(posted_request: NonNull<ngx_http_posted_request_t>) -> Self {
        Self {
            task: None,
            output: None,
            hold: None,
            posted_request,
            context: None,
            active: true,
            phase_posted: false,
        }
    }
}

/// Request-owned state for an [`AsyncHttpRequestHandler`].
///
/// Associate this type with the handler's module through [`HttpModuleRequestContext`]. Dropping
/// the module context cancels pending work before nginx releases the request pool.
pub struct AsyncHandlerContext<H>
where
    H: AsyncHttpRequestHandler,
{
    continuation: NonNull<AsyncContinuation<H>>,
    _pin: PhantomPinned,
}

impl<H> AsyncHandlerContext<H>
where
    H: AsyncHttpRequestHandler,
{
    fn new(continuation: NonNull<AsyncContinuation<H>>) -> Self {
        Self { continuation, _pin: PhantomPinned }
    }
}

impl<H> Drop for AsyncHandlerContext<H>
where
    H: AsyncHttpRequestHandler,
{
    fn drop(&mut self) {
        let continuation = unsafe { self.continuation.as_mut() };
        {
            let mut state = continuation.state().borrow_mut();
            state.active = false;
            state.task.take();
            state.output.take();
        }
        unsafe { Pin::new_unchecked(&mut *continuation) }.shutdown();
        RequestHold::cancel(&mut continuation.state().borrow_mut().hold);
    }
}

struct AsyncPhaseHandler<H>(PhantomData<fn() -> H>);

impl<H> HttpRequestHandler for AsyncPhaseHandler<H>
where
    H: AsyncHttpRequestHandler,
{
    const PHASE: HttpPhase = H::PHASE;
    type Output = ngx_int_t;

    fn handler(request: &mut RequestRefMut<'_>) -> Self::Output {
        let has_context = match request.module_context::<H::Module>() {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => return NGX_ERROR as ngx_int_t,
        };
        if has_context {
            let output = {
                let Ok(Some(context)) = request.pinned_module_context_mut::<H::Module>() else {
                    return NGX_ERROR as ngx_int_t;
                };
                let continuation = context.as_ref().get_ref().continuation;
                let mut state = unsafe { continuation.as_ref() }.state().borrow_mut();
                if !state.phase_posted {
                    ngx_log_debug_http!(request, "async handler {} pending", H::name());
                    return async_phase_pending_status();
                }
                let Some(output) = state.output.take() else {
                    ngx_log_debug_http!(request, "async handler {} pending", H::name());
                    return async_phase_pending_status();
                };
                state.active = false;
                state.task.take();
                output
            };

            ngx_log_debug_http!(request, "async handler {} complete", H::name());
            if !matches!(request.remove_module_context::<H::Module>(), Ok(true)) {
                if let Ok(Some(log)) = request.log() {
                    ngx_log_error!(
                        crate::ffi::NGX_LOG_ERR,
                        log,
                        "async handler {} context removal failed",
                        H::name()
                    );
                }
                return NGX_ERROR as ngx_int_t;
            }
            return H::finish(request, output).into_handler_status(&request.view());
        }

        let log = match request.log() {
            Ok(Some(log)) => log,
            Ok(None) | Err(_) => return NGX_ERROR as ngx_int_t,
        };
        let (pool_raw, continuation) = {
            let pool = match request.pool() {
                Ok(pool) => pool,
                Err(_) => return NGX_ERROR as ngx_int_t,
            };
            let pool_raw = pool.as_ptr();
            // SAFETY: the continuation is owned and cancelled by this request pool, which also
            // owns the connection logger.
            let log = unsafe { LogRef::from_raw(log.as_ptr()) }.expect("request logger");
            let Some(posted_request) = NonNull::new(pool.calloc_type()) else {
                ngx_log_error!(
                    crate::ffi::NGX_LOG_ERR,
                    log,
                    "async handler {} posted request allocation failed",
                    H::name()
                );
                return NGX_ERROR as ngx_int_t;
            };
            let continuation = match unsafe {
                AsyncContinuation::allocate_in_pool(
                    &pool,
                    log,
                    RefCell::new(AsyncContinuationState::new(posted_request)),
                    async_phase_continuation::<H> as AsyncContinuationCallback<H>,
                )
            } {
                Ok(continuation) => continuation.into_non_null(),
                Err(_) => {
                    ngx_log_error!(
                        crate::ffi::NGX_LOG_ERR,
                        log,
                        "async handler {} continuation allocation failed",
                        H::name()
                    );
                    return NGX_ERROR as ngx_int_t;
                }
            };
            (pool_raw, continuation)
        };
        let context = match request.get_or_insert_pinned_module_context_with::<H::Module>(|| {
            AsyncHandlerContext::new(continuation)
        }) {
            Ok(context) => NonNull::from(context.as_ref().get_ref()),
            Err(_) => {
                let pool = unsafe { crate::core::Pool::from_raw(pool_raw) }
                    .expect("request pool remained valid while its context was created");
                let _ = unsafe { pool.remove_cleanup(continuation) };
                ngx_log_error!(
                    crate::ffi::NGX_LOG_ERR,
                    log,
                    "async handler {} context allocation failed",
                    H::name()
                );
                return NGX_ERROR as ngx_int_t;
            }
        };
        unsafe { continuation.as_ref() }.state().borrow_mut().context = Some(context);
        // H::start may publish callbacks in this pool, so install their cancellation owner first.
        let future = H::start(request);
        let started = match spawn(handler_future(future, continuation)) {
            Ok(task) => {
                let mut state = unsafe { continuation.as_ref() }.state().borrow_mut();
                state.task = Some(task.into_attached());
                // SAFETY: AsyncHandlerContext is pinned in this request pool and its cleanup
                // disarms the hold before nginx destroys the request.
                unsafe { request.hold(&mut state.hold) }.is_ok()
            }
            Err(_) => false,
        };
        if !started {
            if !matches!(request.remove_module_context::<H::Module>(), Ok(true)) {
                ngx_log_error!(
                    crate::ffi::NGX_LOG_ERR,
                    log,
                    "async handler {} context removal after startup failed",
                    H::name()
                );
            }
            return NGX_ERROR as ngx_int_t;
        }

        async_phase_pending_status()
    }

    fn name() -> &'static str {
        H::name()
    }
}

fn validate_async_phase(phase: HttpPhase) -> Result<(), AsyncHandlerRegistrationError> {
    match phase {
        HttpPhase::Content => Err(AsyncHandlerRegistrationError::ContentPhase),
        HttpPhase::Log => Err(AsyncHandlerRegistrationError::LogPhase),
        _ => Ok(()),
    }
}

fn async_phase_pending_status() -> ngx_int_t {
    NGX_DONE as _
}

async fn handler_future<H>(
    future: impl Future<Output = H::Output> + 'static,
    mut continuation: NonNull<AsyncContinuation<H>>,
) where
    H: AsyncHttpRequestHandler,
{
    let output = future.await;

    let continuation = unsafe { continuation.as_mut() };
    {
        let mut state = continuation.state().borrow_mut();
        if !state.active {
            return;
        }
        debug_assert!(state.output.is_none());
        state.output = Some(output);
    }
    // Scheduler tasks run on the initialized nginx worker event-loop thread.
    let _ = unsafe { Pin::new_unchecked(continuation).post(PostedQueue::Next) };
}

fn async_phase_continuation<H>(event: PostedEventCallback<'_, RefCell<AsyncContinuationState<H>>>)
where
    H: AsyncHttpRequestHandler,
{
    let (request, expected_context) = {
        let state = event.state().borrow();
        if !state.active || state.phase_posted || state.output.is_none() {
            return;
        }
        let Some(request) = RequestHold::request_ptr(&state.hold) else {
            return;
        };
        let Some(context) = state.context else {
            return;
        };
        (request, context)
    };

    let current = unsafe {
        RequestRefMut::is_current_module_context::<H::Module>(request.as_ptr(), expected_context)
    }
    .unwrap_or(false);
    if !current {
        return;
    }

    let mut state = event.state().borrow_mut();
    if !state.active || state.phase_posted || state.output.is_none() {
        return;
    }
    let resumed = {
        let state = &mut *state;
        RequestHold::resume_phase(&mut state.hold, unsafe { state.posted_request.as_mut() }).is_ok()
    };
    if resumed {
        state.phase_posted = true;
    }
}

/// Registers an asynchronous HTTP phase handler.
///
/// Call this function from the module's postconfiguration callback. The owning module must retain
/// a [`crate::async_::WorkerSchedulerLease`] from its process-start hook until its process-exit
/// hook.
pub fn add_async_phase_handler<H>(
    parser: &mut crate::http::HttpConfigurationParser<'_>,
) -> Result<(), AsyncHandlerRegistrationError>
where
    H: AsyncHttpRequestHandler,
{
    validate_async_phase(H::PHASE)?;
    add_phase_handler::<AsyncPhaseHandler<H>>(parser)
        .map_err(|_| AsyncHandlerRegistrationError::Allocation)
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use core::cell::{Cell, RefCell};
    use core::ffi::c_void;
    use core::future::Future;
    use core::marker::PhantomData;
    use core::mem::{self, MaybeUninit};
    use core::panic::AssertUnwindSafe;
    use core::pin::Pin;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::panic::catch_unwind;
    use std::sync::{Mutex, MutexGuard, Once};
    use std::thread;

    use super::*;
    use crate::core::ModuleDescriptor;
    #[cfg(nginx1_25_4)]
    use crate::core::Status;
    #[cfg(nginx1_25_4)]
    use crate::ffi::ngx_http_finalize_request;
    use crate::ffi::{
        NGX_DECLINED, NGX_DONE, NGX_ERROR, NGX_HTTP_MODULE, NGX_OK, NGX_USE_CLEAR_EVENT,
        ngx_array_t, ngx_conf_t, ngx_connection_t, ngx_create_pool, ngx_cycle, ngx_cycle_t,
        ngx_delete_posted_event, ngx_destroy_pool, ngx_event_actions, ngx_event_actions_t,
        ngx_event_flags, ngx_event_move_posted_next, ngx_event_process_posted, ngx_event_t,
        ngx_http_conf_ctx_t, ngx_http_core_loc_conf_t, ngx_http_core_main_conf_t,
        ngx_http_core_srv_conf_t, ngx_http_handler_pt, ngx_http_log_ctx_t,
        ngx_http_phase_handler_t, ngx_http_request_t, ngx_http_run_posted_requests, ngx_int_t,
        ngx_log_t, ngx_module_t, ngx_pool_t, ngx_posted_events, ngx_posted_next_events,
        ngx_queue_init, ngx_uint_t,
    };
    #[cfg(nginx1_25_4)]
    use crate::http::subrequest::{SubRequestBuilder, SubRequestError};
    use crate::http::{HttpModule, HttpModuleRequestContext};

    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    static mut TEST_MODULE: MaybeUninit<ngx_module_t> = MaybeUninit::uninit();
    static TEST_MODULE_INIT: Once = Once::new();
    static POSTED_REQUEST: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_posted_request(request: *mut ngx_http_request_t) {
        POSTED_REQUEST.store(request as usize, Ordering::Relaxed);
    }

    fn test_module() -> ModuleDescriptor {
        TEST_MODULE_INIT.call_once(|| unsafe {
            (&raw mut TEST_MODULE).cast::<ngx_module_t>().write(ngx_module_t {
                type_: NGX_HTTP_MODULE as _,
                index: 0,
                ctx_index: 0,
                ..ngx_module_t::default()
            });
        });
        unsafe { ModuleDescriptor::from_raw((&raw mut TEST_MODULE).cast::<ngx_module_t>()) }
            .unwrap()
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|error| error.into_inner())
    }

    unsafe extern "C" fn test_add_event(
        event: *mut ngx_event_t,
        _event_type: ngx_int_t,
        _flags: ngx_uint_t,
    ) -> ngx_int_t {
        unsafe { (*event).set_active(1) };
        NGX_OK as _
    }

    unsafe extern "C" fn test_delete_event(
        event: *mut ngx_event_t,
        _event_type: ngx_int_t,
        _flags: ngx_uint_t,
    ) -> ngx_int_t {
        unsafe { (*event).set_active(0) };
        NGX_OK as _
    }

    fn reset_event_globals() {
        unsafe {
            ngx_queue_init(&raw mut ngx_posted_events);
            ngx_queue_init(&raw mut ngx_posted_next_events);
        }
    }

    struct ReadyModule;

    unsafe impl HttpModule for ReadyModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl HttpModuleRequestContext for ReadyModule {
        type RequestContext = AsyncHandlerContext<ReadyHandler>;
    }

    static READY_STARTS: AtomicUsize = AtomicUsize::new(0);
    static READY_FINISHES: AtomicUsize = AtomicUsize::new(0);
    static READY_OUTPUT: AtomicUsize = AtomicUsize::new(0);
    static READY_FINISHED_WITHOUT_CONTEXT: AtomicBool = AtomicBool::new(false);

    fn reset_ready_state() {
        READY_STARTS.store(0, Ordering::Relaxed);
        READY_FINISHES.store(0, Ordering::Relaxed);
        READY_OUTPUT.store(0, Ordering::Relaxed);
        READY_FINISHED_WITHOUT_CONTEXT.store(false, Ordering::Relaxed);
    }

    struct ReadyHandler;

    impl AsyncHttpRequestHandler for ReadyHandler {
        const PHASE: HttpPhase = HttpPhase::Access;
        type Module = ReadyModule;
        type Output = usize;
        type Result = ngx_int_t;

        fn start(_request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static {
            READY_STARTS.fetch_add(1, Ordering::Relaxed);
            core::future::ready(41)
        }

        fn finish(request: &mut RequestRefMut<'_>, output: Self::Output) -> Self::Result {
            READY_OUTPUT.store(output, Ordering::Relaxed);
            READY_FINISHES.fetch_add(1, Ordering::Relaxed);
            READY_FINISHED_WITHOUT_CONTEXT.store(
                request.module_context::<ReadyModule>().unwrap().is_none(),
                Ordering::Relaxed,
            );
            NGX_OK as _
        }
    }

    struct DeclinedModule;

    unsafe impl HttpModule for DeclinedModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl HttpModuleRequestContext for DeclinedModule {
        type RequestContext = AsyncHandlerContext<DeclinedHandler>;
    }

    struct DeclinedHandler;

    impl AsyncHttpRequestHandler for DeclinedHandler {
        const PHASE: HttpPhase = HttpPhase::Access;
        type Module = DeclinedModule;
        type Output = ();
        type Result = ngx_int_t;

        fn start(_request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static {
            core::future::ready(())
        }

        fn finish(_request: &mut RequestRefMut<'_>, _output: Self::Output) -> Self::Result {
            NGX_DECLINED as _
        }
    }

    struct ErrorModule;

    unsafe impl HttpModule for ErrorModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl HttpModuleRequestContext for ErrorModule {
        type RequestContext = AsyncHandlerContext<ErrorHandler>;
    }

    struct ErrorHandler;

    impl AsyncHttpRequestHandler for ErrorHandler {
        const PHASE: HttpPhase = HttpPhase::Access;
        type Module = ErrorModule;
        type Output = ();
        type Result = ngx_int_t;

        fn start(_request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static {
            core::future::ready(())
        }

        fn finish(_request: &mut RequestRefMut<'_>, _output: Self::Output) -> Self::Result {
            NGX_ERROR as _
        }
    }

    struct PendingModule;

    unsafe impl HttpModule for PendingModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl HttpModuleRequestContext for PendingModule {
        type RequestContext = AsyncHandlerContext<PendingHandler>;
    }

    struct LocalState {
        ready: Cell<bool>,
        polls: Cell<usize>,
        drops: Cell<usize>,
        waker: RefCell<Option<Waker>>,
    }

    impl LocalState {
        fn new() -> Self {
            Self {
                ready: Cell::new(false),
                polls: Cell::new(0),
                drops: Cell::new(0),
                waker: RefCell::new(None),
            }
        }
    }

    struct LocalFuture {
        state: Rc<LocalState>,
    }

    impl Future for LocalFuture {
        type Output = usize;

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.state.polls.set(this.state.polls.get() + 1);
            if this.state.ready.get() {
                Poll::Ready(7)
            } else {
                *this.state.waker.borrow_mut() = Some(context.waker().clone());
                Poll::Pending
            }
        }
    }

    impl Drop for LocalFuture {
        fn drop(&mut self) {
            self.state.drops.set(self.state.drops.get() + 1);
        }
    }

    std::thread_local! {
        static LOCAL_STATE: RefCell<Option<Rc<LocalState>>> = const { RefCell::new(None) };
    }

    fn install_local_state() -> Rc<LocalState> {
        let state = Rc::new(LocalState::new());
        LOCAL_STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none());
            *slot = Some(Rc::clone(&state));
        });
        state
    }

    fn take_local_state() -> Rc<LocalState> {
        LOCAL_STATE.with(|slot| slot.borrow_mut().take().expect("local state was not installed"))
    }

    static PENDING_FINISHES: AtomicUsize = AtomicUsize::new(0);

    struct PendingHandler;

    impl AsyncHttpRequestHandler for PendingHandler {
        const PHASE: HttpPhase = HttpPhase::Access;
        type Module = PendingModule;
        type Output = usize;
        type Result = ngx_int_t;

        fn start(_request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static {
            LocalFuture { state: take_local_state() }
        }

        fn finish(_request: &mut RequestRefMut<'_>, _output: Self::Output) -> Self::Result {
            PENDING_FINISHES.fetch_add(1, Ordering::Relaxed);
            NGX_OK as _
        }
    }

    #[cfg(nginx1_25_4)]
    struct AsyncSubrequestModule;

    #[cfg(nginx1_25_4)]
    unsafe impl HttpModule for AsyncSubrequestModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    #[cfg(nginx1_25_4)]
    unsafe impl HttpModuleRequestContext for AsyncSubrequestModule {
        type RequestContext = AsyncHandlerContext<AsyncSubrequestHandler>;
    }

    #[cfg(nginx1_25_4)]
    struct AsyncSubrequestState {
        subrequest: Cell<*mut ngx_http_request_t>,
        callbacks: Cell<usize>,
        completion_drops: Cell<usize>,
        task_drops: Cell<usize>,
    }

    #[cfg(nginx1_25_4)]
    impl AsyncSubrequestState {
        fn new() -> Self {
            Self {
                subrequest: Cell::new(ptr::null_mut()),
                callbacks: Cell::new(0),
                completion_drops: Cell::new(0),
                task_drops: Cell::new(0),
            }
        }
    }

    #[cfg(nginx1_25_4)]
    struct CompletionCapture(Rc<AsyncSubrequestState>);

    #[cfg(nginx1_25_4)]
    impl Drop for CompletionCapture {
        fn drop(&mut self) {
            self.0.completion_drops.set(self.0.completion_drops.get() + 1);
        }
    }

    #[cfg(nginx1_25_4)]
    struct TaskCapture(Rc<AsyncSubrequestState>);

    #[cfg(nginx1_25_4)]
    impl Drop for TaskCapture {
        fn drop(&mut self) {
            self.0.task_drops.set(self.0.task_drops.get() + 1);
        }
    }

    #[cfg(nginx1_25_4)]
    std::thread_local! {
        static ASYNC_SUBREQUEST_STATE: RefCell<Option<Rc<AsyncSubrequestState>>> = const { RefCell::new(None) };
    }

    #[cfg(nginx1_25_4)]
    fn install_async_subrequest_state() -> Rc<AsyncSubrequestState> {
        let state = Rc::new(AsyncSubrequestState::new());
        ASYNC_SUBREQUEST_STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none());
            *slot = Some(Rc::clone(&state));
        });
        state
    }

    #[cfg(nginx1_25_4)]
    static ASYNC_SUBREQUEST_SAW_CONTEXT: AtomicBool = AtomicBool::new(false);
    #[cfg(nginx1_25_4)]
    static ASYNC_SUBREQUEST_FINISHES: AtomicUsize = AtomicUsize::new(0);

    #[cfg(nginx1_25_4)]
    struct AsyncSubrequestHandler;

    #[cfg(nginx1_25_4)]
    impl AsyncHttpRequestHandler for AsyncSubrequestHandler {
        const PHASE: HttpPhase = HttpPhase::Access;
        type Module = AsyncSubrequestModule;
        type Output = Result<(), SubRequestError>;
        type Result = ngx_int_t;

        fn start(request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static {
            ASYNC_SUBREQUEST_SAW_CONTEXT.store(
                request.module_context::<AsyncSubrequestModule>().unwrap().is_some(),
                Ordering::Relaxed,
            );
            let state = ASYNC_SUBREQUEST_STATE
                .with(|slot| slot.borrow_mut().take())
                .expect("async subrequest state was not installed");
            let completion = CompletionCapture(Rc::clone(&state));
            let callback_state = Rc::clone(&state);
            let (future, subrequest) = SubRequestBuilder::new(request, "/delayed")
                .unwrap()
                .keep_body()
                .init_headers_in(0)
                .waited()
                .background()
                .build_async(move |_, _| {
                    callback_state.callbacks.set(callback_state.callbacks.get() + 1);
                    drop(completion);
                    ((), Status::NGX_OK)
                })
                .unwrap();
            state.subrequest.set(unsafe { subrequest.as_ptr() });

            async move {
                let _task = TaskCapture(Rc::clone(&state));
                future.await
            }
        }

        fn finish(_request: &mut RequestRefMut<'_>, _output: Self::Output) -> Self::Result {
            ASYNC_SUBREQUEST_FINISHES.fetch_add(1, Ordering::Relaxed);
            NGX_OK as _
        }
    }

    struct ForeignModule;

    unsafe impl HttpModule for ForeignModule {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl HttpModuleRequestContext for ForeignModule {
        type RequestContext = AsyncHandlerContext<ForeignHandler>;
    }

    struct ForeignState {
        ready: AtomicBool,
        polls: AtomicUsize,
        drops: AtomicUsize,
        waker: Mutex<Option<Waker>>,
    }

    impl ForeignState {
        fn new() -> Self {
            Self {
                ready: AtomicBool::new(false),
                polls: AtomicUsize::new(0),
                drops: AtomicUsize::new(0),
                waker: Mutex::new(None),
            }
        }

        fn wake(&self) {
            let waker = lock(&self.waker).take().expect("foreign future was not polled");
            waker.wake();
        }
    }

    struct ForeignFuture {
        state: Arc<ForeignState>,
    }

    impl Future for ForeignFuture {
        type Output = usize;

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.state.polls.fetch_add(1, Ordering::Relaxed);
            if this.state.ready.load(Ordering::Relaxed) {
                Poll::Ready(13)
            } else {
                *lock(&this.state.waker) = Some(context.waker().clone());
                Poll::Pending
            }
        }
    }

    impl Drop for ForeignFuture {
        fn drop(&mut self) {
            self.state.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    static FOREIGN_STATE: Mutex<Option<Arc<ForeignState>>> = Mutex::new(None);
    static FOREIGN_FINISHES: AtomicUsize = AtomicUsize::new(0);

    fn install_foreign_state() -> Arc<ForeignState> {
        let state = Arc::new(ForeignState::new());
        let mut slot = lock(&FOREIGN_STATE);
        assert!(slot.is_none());
        *slot = Some(Arc::clone(&state));
        state
    }

    struct ForeignHandler;

    impl AsyncHttpRequestHandler for ForeignHandler {
        const PHASE: HttpPhase = HttpPhase::Access;
        type Module = ForeignModule;
        type Output = usize;
        type Result = ngx_int_t;

        fn start(_request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static {
            ForeignFuture {
                state: lock(&FOREIGN_STATE).take().expect("foreign state was not installed"),
            }
        }

        fn finish(_request: &mut RequestRefMut<'_>, _output: Self::Output) -> Self::Result {
            FOREIGN_FINISHES.fetch_add(1, Ordering::Relaxed);
            NGX_OK as _
        }
    }

    struct RegistrationModule<H>(PhantomData<fn() -> H>);

    unsafe impl<H> HttpModule for RegistrationModule<H>
    where
        H: AsyncHttpRequestHandler,
    {
        fn module() -> ModuleDescriptor {
            test_module()
        }
    }

    unsafe impl<H> HttpModuleRequestContext for RegistrationModule<H>
    where
        H: AsyncHttpRequestHandler,
    {
        type RequestContext = AsyncHandlerContext<H>;
    }

    macro_rules! registration_handler {
        ($name:ident, $phase:expr) => {
            struct $name;

            impl AsyncHttpRequestHandler for $name {
                const PHASE: HttpPhase = $phase;
                type Module = RegistrationModule<Self>;
                type Output = ();
                type Result = ngx_int_t;

                fn start(
                    _request: &mut RequestRefMut<'_>,
                ) -> impl Future<Output = Self::Output> + 'static {
                    core::future::ready(())
                }

                fn finish(_request: &mut RequestRefMut<'_>, _output: Self::Output) -> Self::Result {
                    NGX_OK as _
                }
            }
        };
    }

    registration_handler!(PostReadRegistration, HttpPhase::PostRead);
    registration_handler!(ServerRewriteRegistration, HttpPhase::ServerRewrite);
    registration_handler!(RewriteRegistration, HttpPhase::Rewrite);
    registration_handler!(PreaccessRegistration, HttpPhase::Preaccess);
    registration_handler!(AccessRegistration, HttpPhase::Access);
    registration_handler!(PreContentRegistration, HttpPhase::PreContent);
    registration_handler!(ContentRegistration, HttpPhase::Content);
    registration_handler!(LogRegistration, HttpPhase::Log);

    struct GlobalState {
        max_module: ngx_uint_t,
        http_max_module: ngx_uint_t,
        core_module_type: ngx_uint_t,
        core_module_index: ngx_uint_t,
        core_module_context_index: ngx_uint_t,
        cycle: *mut ngx_cycle_t,
        event_actions: ngx_event_actions_t,
        event_flags: ngx_uint_t,
    }

    struct TestGlobals {
        _nginx: MutexGuard<'static, ()>,
        _scheduler: MutexGuard<'static, ()>,
        previous: GlobalState,
    }

    impl TestGlobals {
        fn new() -> Self {
            let nginx = lock(&crate::TEST_NGINX_GLOBALS);
            let scheduler = lock(&crate::async_::SCHEDULER_TESTS);
            let previous = unsafe {
                let core = &raw const nginx_sys::ngx_http_core_module;
                GlobalState {
                    max_module: nginx_sys::ngx_max_module,
                    http_max_module: nginx_sys::ngx_http_max_module,
                    core_module_type: (*core).type_,
                    core_module_index: (*core).index,
                    core_module_context_index: (*core).ctx_index,
                    cycle: ngx_cycle,
                    event_actions: ngx_event_actions,
                    event_flags: ngx_event_flags,
                }
            };
            unsafe {
                nginx_sys::ngx_max_module = 1;
                nginx_sys::ngx_http_max_module = 1;
                let core = &raw mut nginx_sys::ngx_http_core_module;
                (*core).type_ = NGX_HTTP_MODULE as _;
                (*core).index = 0;
                (*core).ctx_index = 0;
            }
            reset_event_globals();
            Self { _nginx: nginx, _scheduler: scheduler, previous }
        }
    }

    impl Drop for TestGlobals {
        fn drop(&mut self) {
            reset_event_globals();
            unsafe {
                nginx_sys::ngx_max_module = self.previous.max_module;
                nginx_sys::ngx_http_max_module = self.previous.http_max_module;
                let core = &raw mut nginx_sys::ngx_http_core_module;
                (*core).type_ = self.previous.core_module_type;
                (*core).index = self.previous.core_module_index;
                (*core).ctx_index = self.previous.core_module_context_index;
                ngx_cycle = self.previous.cycle;
                ngx_event_actions = self.previous.event_actions;
                ngx_event_flags = self.previous.event_flags;
            }
        }
    }

    struct TestPool {
        raw: *mut ngx_pool_t,
        log: Box<ngx_log_t>,
    }

    impl TestPool {
        fn new() -> Self {
            let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
            let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!raw.is_null());
            Self { raw, log }
        }
    }

    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }

    struct TestCycle {
        cycle: ngx_cycle_t,
        connection: ngx_connection_t,
        read: ngx_event_t,
        write: ngx_event_t,
        log: ngx_log_t,
    }

    impl TestCycle {
        fn new() -> Box<Self> {
            let mut cycle = Box::new(unsafe { MaybeUninit::<Self>::zeroed().assume_init() });
            cycle.cycle.log = &raw mut cycle.log;
            cycle.cycle.connection_n = 1;
            cycle.cycle.free_connection_n = 1;
            cycle.cycle.free_connections = &raw mut cycle.connection;
            cycle.connection.read = &raw mut cycle.read;
            cycle.connection.write = &raw mut cycle.write;
            cycle
        }

        fn raw(&mut self) -> *mut ngx_cycle_t {
            &raw mut self.cycle
        }
    }

    struct TestWorker {
        _globals: TestGlobals,
        cycle: Box<TestCycle>,
        lease: Option<crate::async_::WorkerSchedulerLease>,
    }

    impl TestWorker {
        fn new() -> Self {
            let globals = TestGlobals::new();
            let mut cycle = TestCycle::new();
            unsafe {
                ngx_cycle = cycle.raw();
                ngx_event_actions = mem::zeroed();
                ngx_event_actions.add = Some(test_add_event);
                ngx_event_actions.del = Some(test_delete_event);
                ngx_event_flags = NGX_USE_CLEAR_EVENT as _;
            }
            Self { _globals: globals, cycle, lease: None }
        }

        fn init(&mut self) {
            let log = unsafe { LogRef::from_raw(&raw mut self.cycle.log) }.expect("test logger");
            self.lease = Some(unsafe { crate::async_::acquire_worker(log) }.unwrap());
        }

        fn process_posted(&mut self) {
            unsafe {
                ngx_event_move_posted_next(self.cycle.raw());
                ngx_event_process_posted(self.cycle.raw(), &raw mut ngx_posted_events);
            }
        }

        fn deliver_notification(&mut self) {
            let handler = self.cycle.read.handler.expect("notification handler");
            unsafe { handler(&raw mut self.cycle.read) };
        }
    }

    impl Drop for TestWorker {
        fn drop(&mut self) {
            if let Some(mut lease) = self.lease.take() {
                let _ = lease.release();
            }
        }
    }

    unsafe extern "C" fn stop_phase_engine(
        _request: *mut ngx_http_request_t,
        _phase: *mut ngx_http_phase_handler_t,
    ) -> ngx_int_t {
        NGX_OK as _
    }

    #[cfg(nginx1_25_4)]
    unsafe extern "C" fn blocked_write_handler(_request: *mut ngx_http_request_t) {}

    struct TestRequest {
        _pool: TestPool,
        _contexts: Box<[*mut c_void; 1]>,
        write_event: Box<ngx_event_t>,
        _connection: Box<ngx_connection_t>,
        _core_loc: Box<ngx_http_core_loc_conf_t>,
        #[cfg_attr(not(nginx1_25_4), allow(dead_code))]
        loc_conf: Box<[*mut c_void; 1]>,
        request: Box<ngx_http_request_t>,
    }

    impl TestRequest {
        fn new() -> Self {
            let pool = TestPool::new();
            let mut contexts = Box::new([ptr::null_mut()]);
            let mut write_event =
                Box::new(unsafe { MaybeUninit::<ngx_event_t>::zeroed().assume_init() });
            let mut connection =
                Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
            connection.write = &raw mut *write_event;
            connection.log = (&raw const *pool.log).cast_mut();
            let mut core_loc = Box::new(unsafe {
                MaybeUninit::<ngx_http_core_loc_conf_t>::zeroed().assume_init()
            });
            let mut loc_conf = Box::new([(&raw mut *core_loc).cast::<c_void>()]);
            let mut request =
                Box::new(unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() });
            request.signature = NGX_HTTP_MODULE as _;
            request.main = &raw mut *request;
            request.pool = pool.raw;
            request.connection = &raw mut *connection;
            request.ctx = contexts.as_mut_ptr();
            request.loc_conf = loc_conf.as_mut_ptr();
            request.set_count(1);
            connection.data = (&raw mut *request).cast();

            Self {
                _pool: pool,
                _contexts: contexts,
                write_event,
                _connection: connection,
                _core_loc: core_loc,
                loc_conf,
                request,
            }
        }

        fn borrow(&mut self) -> RequestRefMut<'_> {
            unsafe { RequestRefMut::from_raw(&raw mut *self.request).unwrap() }
        }

        fn write_is_posted(&self) -> usize {
            self.write_event.posted() as _
        }

        fn main_count(&self) -> u32 {
            self.request.count()
        }
    }

    impl Drop for TestRequest {
        fn drop(&mut self) {
            if self.write_event.posted() != 0 {
                unsafe { ngx_delete_posted_event(&raw mut *self.write_event) };
            }
        }
    }

    fn continuation_for<H>(request: &mut RequestRefMut<'_>) -> NonNull<AsyncContinuation<H>>
    where
        H: AsyncHttpRequestHandler,
    {
        request
            .pinned_module_context_mut::<H::Module>()
            .unwrap()
            .expect("async context was not installed")
            .as_ref()
            .get_ref()
            .continuation
    }

    fn start_handler<H>(request: &mut TestRequest)
    where
        H: AsyncHttpRequestHandler,
    {
        let mut request = request.borrow();
        assert_eq!(AsyncPhaseHandler::<H>::handler(&mut request), NGX_DONE as _);
    }

    fn complete_handler<H>(
        worker: &mut TestWorker,
        request: &mut TestRequest,
    ) -> NonNull<AsyncContinuation<H>>
    where
        H: AsyncHttpRequestHandler,
    {
        start_handler::<H>(request);
        worker.process_posted();
        worker.process_posted();
        let continuation = {
            let mut request = request.borrow();
            continuation_for::<H>(&mut request)
        };
        assert_eq!(request.write_is_posted(), 1);
        continuation
    }

    fn remove_handler_context<H>(request: &mut TestRequest)
    where
        H: AsyncHttpRequestHandler,
    {
        let mut request = request.borrow();
        assert_eq!(request.remove_module_context::<H::Module>(), Ok(true));
    }

    const PHASE_COUNT: usize = HttpPhase::Log as usize + 1;
    const PHASE_HANDLER_CAPACITY: usize = 1;

    fn phase_handler_array(
        elts: *mut c_void,
        nalloc: ngx_uint_t,
        pool: *mut ngx_pool_t,
    ) -> ngx_array_t {
        ngx_array_t { elts, nelts: 0, size: mem::size_of::<ngx_http_handler_pt>(), nalloc, pool }
    }

    struct PhaseFixture {
        _globals: TestGlobals,
        pool: *mut ngx_pool_t,
        _log: Box<ngx_log_t>,
        _handler_storage: Box<[[ngx_http_handler_pt; PHASE_HANDLER_CAPACITY]; PHASE_COUNT]>,
        main: Box<ngx_http_core_main_conf_t>,
        _main_slots: Box<[*mut c_void; 1]>,
        _context: Box<ngx_http_conf_ctx_t>,
        cf: Box<ngx_conf_t>,
    }

    impl PhaseFixture {
        fn new() -> Self {
            let globals = TestGlobals::new();
            let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
            let pool = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!pool.is_null());
            let mut handler_storage = Box::new([[None; PHASE_HANDLER_CAPACITY]; PHASE_COUNT]);
            let mut main = Box::new(unsafe {
                MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init()
            });
            for (phase, storage) in main.phases.iter_mut().zip(handler_storage.iter_mut()) {
                phase.handlers = phase_handler_array(
                    storage.as_mut_ptr().cast(),
                    PHASE_HANDLER_CAPACITY as _,
                    pool,
                );
            }
            let mut main_slots = Box::new([(&raw mut *main).cast()]);
            let mut context = Box::new(ngx_http_conf_ctx_t {
                main_conf: main_slots.as_mut_ptr(),
                srv_conf: ptr::null_mut(),
                loc_conf: ptr::null_mut(),
            });
            let mut cf = Box::new(unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() });
            cf.module_type = NGX_HTTP_MODULE as _;
            cf.ctx = (&raw mut *context).cast();
            cf.pool = pool;
            cf.log = &raw mut *log;

            Self {
                _globals: globals,
                pool,
                _log: log,
                _handler_storage: handler_storage,
                main,
                _main_slots: main_slots,
                _context: context,
                cf,
            }
        }

        fn configuration(&mut self) -> crate::http::HttpConfigurationParser<'_> {
            crate::http::HttpConfigurationParser::from_test_callback(&mut self.cf)
        }

        fn phase_handlers(&mut self, phase: HttpPhase) -> &mut ngx_array_t {
            &mut self.main.phases[phase as usize].handlers
        }
    }

    impl Drop for PhaseFixture {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.pool) };
        }
    }

    #[test]
    fn spawn_failure_removes_the_new_request_context() {
        let _globals = TestGlobals::new();
        let mut request = TestRequest::new();
        let mut request_ref = request.borrow();

        assert_eq!(AsyncPhaseHandler::<ReadyHandler>::handler(&mut request_ref), NGX_ERROR as _);
        assert!(request_ref.module_context::<ReadyModule>().unwrap().is_none());
    }

    #[test]
    fn registers_each_supported_async_phase() {
        let mut fixture = PhaseFixture::new();

        assert_eq!(
            add_async_phase_handler::<PostReadRegistration>(&mut fixture.configuration()),
            Ok(())
        );
        assert_eq!(
            add_async_phase_handler::<ServerRewriteRegistration>(&mut fixture.configuration()),
            Ok(())
        );
        assert_eq!(
            add_async_phase_handler::<RewriteRegistration>(&mut fixture.configuration()),
            Ok(())
        );
        assert_eq!(
            add_async_phase_handler::<PreaccessRegistration>(&mut fixture.configuration()),
            Ok(())
        );
        assert_eq!(
            add_async_phase_handler::<AccessRegistration>(&mut fixture.configuration()),
            Ok(())
        );
        assert_eq!(
            add_async_phase_handler::<PreContentRegistration>(&mut fixture.configuration()),
            Ok(())
        );

        for phase in [
            HttpPhase::PostRead,
            HttpPhase::ServerRewrite,
            HttpPhase::Rewrite,
            HttpPhase::Preaccess,
            HttpPhase::Access,
            HttpPhase::PreContent,
        ] {
            assert_eq!(fixture.phase_handlers(phase).nelts, 1);
        }
    }

    #[test]
    fn content_registration_returns_a_typed_error_without_panicking() {
        let mut fixture = PhaseFixture::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            add_async_phase_handler::<ContentRegistration>(&mut fixture.configuration())
        }));

        assert_eq!(result.unwrap(), Err(AsyncHandlerRegistrationError::ContentPhase));
        assert_eq!(fixture.phase_handlers(HttpPhase::Content).nelts, 0);
    }

    #[test]
    fn log_registration_returns_a_typed_error_without_panicking() {
        let mut fixture = PhaseFixture::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            add_async_phase_handler::<LogRegistration>(&mut fixture.configuration())
        }));

        assert_eq!(result.unwrap(), Err(AsyncHandlerRegistrationError::LogPhase));
        assert_eq!(fixture.phase_handlers(HttpPhase::Log).nelts, 0);
    }

    #[test]
    fn registration_allocation_failure_returns_a_typed_error() {
        let mut fixture = PhaseFixture::new();
        fixture.phase_handlers(HttpPhase::Access).nalloc = 0;

        assert_eq!(
            add_async_phase_handler::<AccessRegistration>(&mut fixture.configuration()),
            Err(AsyncHandlerRegistrationError::Allocation)
        );
        assert_eq!(fixture.phase_handlers(HttpPhase::Access).nelts, 0);
    }

    #[test]
    fn phase_reentry_stays_suspended_until_the_async_output_is_available() {
        let mut worker = TestWorker::new();
        worker.init();

        let mut server_rewrite = TestRequest::new();
        {
            let mut request = server_rewrite.borrow();
            assert_eq!(
                AsyncPhaseHandler::<ServerRewriteRegistration>::handler(&mut request),
                NGX_DONE as _
            );
            assert_eq!(
                AsyncPhaseHandler::<ServerRewriteRegistration>::handler(&mut request),
                NGX_DONE as _
            );
        }
        remove_handler_context::<ServerRewriteRegistration>(&mut server_rewrite);
        worker.process_posted();

        let mut rewrite = TestRequest::new();
        {
            let mut request = rewrite.borrow();
            assert_eq!(
                AsyncPhaseHandler::<RewriteRegistration>::handler(&mut request),
                NGX_DONE as _
            );
            assert_eq!(
                AsyncPhaseHandler::<RewriteRegistration>::handler(&mut request),
                NGX_DONE as _
            );
        }
        remove_handler_context::<RewriteRegistration>(&mut rewrite);
        worker.process_posted();
    }

    #[test]
    fn ready_output_waits_for_continuation_dispatch_before_finish() {
        let mut worker = TestWorker::new();
        worker.init();
        reset_ready_state();
        let mut request = TestRequest::new();

        start_handler::<ReadyHandler>(&mut request);
        worker.process_posted();
        let continuation = {
            let mut request_ref = request.borrow();
            continuation_for::<ReadyHandler>(&mut request_ref)
        };
        {
            let state = unsafe { continuation.as_ref() }.state().borrow();
            assert!(state.active);
            assert!(state.output.is_some());
            assert!(state.hold.is_some());
            assert!(!state.phase_posted);
        }
        assert!(unsafe { continuation.as_ref() }.is_posted());
        assert_eq!(request.write_is_posted(), 0);
        assert_eq!(request.main_count(), 2);

        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<ReadyHandler>::handler(&mut request_ref), NGX_DONE as _);
            assert!(request_ref.module_context::<ReadyModule>().unwrap().is_some());
        }
        assert_eq!(READY_FINISHES.load(Ordering::Relaxed), 0);
        {
            let state = unsafe { continuation.as_ref() }.state().borrow();
            assert!(state.output.is_some());
            assert!(state.hold.is_some());
            assert!(!state.phase_posted);
        }
        assert_eq!(request.main_count(), 2);

        worker.process_posted();
        assert_eq!(request.write_is_posted(), 1);
        assert_eq!(request.main_count(), 1);
        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<ReadyHandler>::handler(&mut request_ref), NGX_OK as _);
        }
        assert_eq!(READY_FINISHES.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn completion_schedules_the_request_write_event_once() {
        let mut worker = TestWorker::new();
        worker.init();
        reset_ready_state();
        let mut request = TestRequest::new();

        start_handler::<ReadyHandler>(&mut request);
        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<ReadyHandler>::handler(&mut request_ref), NGX_DONE as _);
        }
        assert_eq!(READY_STARTS.load(Ordering::Relaxed), 1);
        assert_eq!(request.main_count(), 2);

        worker.process_posted();
        let continuation = {
            let mut request_ref = request.borrow();
            continuation_for::<ReadyHandler>(&mut request_ref)
        };
        assert!(unsafe { continuation.as_ref() }.is_posted());
        assert_eq!(request.write_is_posted(), 0);

        worker.process_posted();
        assert_eq!(request.write_is_posted(), 1);
        assert_eq!(request.main_count(), 1);
        assert!(request.request.posted_requests.is_null());
        assert!(unsafe { continuation.as_ref() }.state().borrow().phase_posted);

        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<ReadyHandler>::handler(&mut request_ref), NGX_OK as _);
            assert!(request_ref.module_context::<ReadyModule>().unwrap().is_none());
        }
        assert_eq!(READY_FINISHES.load(Ordering::Relaxed), 1);
        assert_eq!(READY_OUTPUT.load(Ordering::Relaxed), 41);
        assert!(READY_FINISHED_WITHOUT_CONTEXT.load(Ordering::Relaxed));
        assert!(unsafe { continuation.as_ref() }.is_shutdown());
        let state = unsafe { continuation.as_ref() }.state().borrow();
        assert!(!state.active);
        assert!(state.output.is_none());
        assert!(state.hold.is_none());
    }

    #[test]
    fn completion_posts_a_noncurrent_request_before_waking_its_connection() {
        let mut worker = TestWorker::new();
        worker.init();
        reset_ready_state();
        POSTED_REQUEST.store(0, Ordering::Relaxed);
        let mut request = TestRequest::new();
        let mut log_context =
            Box::new(unsafe { MaybeUninit::<ngx_http_log_ctx_t>::zeroed().assume_init() });
        request._pool.log.data = (&raw mut *log_context).cast();

        let mut main =
            Box::new(unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() });
        main.signature = NGX_HTTP_MODULE as _;
        main.main = &raw mut *main;
        main.pool = request._pool.raw;
        main.connection = &raw mut *request._connection;
        main.set_count(1);
        request.request.main = &raw mut *main;
        request.request.parent = &raw mut *main;
        request._connection.data = (&raw mut *main).cast();
        log_context.connection = &raw mut *request._connection;

        start_handler::<ReadyHandler>(&mut request);
        worker.process_posted();
        let continuation = {
            let mut request_ref = request.borrow();
            continuation_for::<ReadyHandler>(&mut request_ref)
        };
        {
            let state = unsafe { continuation.as_ref() }.state().borrow();
            assert!(state.output.is_some());
            assert!(state.hold.is_some());
            assert!(!state.phase_posted);
        }
        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<ReadyHandler>::handler(&mut request_ref), NGX_DONE as _);
            assert!(request_ref.module_context::<ReadyModule>().unwrap().is_some());
        }
        assert_eq!(READY_FINISHES.load(Ordering::Relaxed), 0);
        assert_eq!(main.count(), 2);

        unsafe {
            (*request._pool.raw).d.last = (*request._pool.raw).d.end;
            (*request._pool.raw).max = 0;
            ngx_rs_test_fail_allocations_after(0);
        }
        worker.process_posted();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert!(!main.posted_requests.is_null());
        assert_eq!(unsafe { (*main.posted_requests).request }, &raw mut *request.request);
        let posted_request =
            unsafe { continuation.as_ref() }.state().borrow().posted_request.as_ptr();
        assert_eq!(main.posted_requests, posted_request);
        assert_eq!(request.write_is_posted(), 1);

        request.request.write_event_handler = Some(record_posted_request);
        unsafe { ngx_http_run_posted_requests(&raw mut *request._connection) };

        assert_eq!(POSTED_REQUEST.load(Ordering::Relaxed), (&raw mut *request.request) as usize);
        assert!(main.posted_requests.is_null());
        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<ReadyHandler>::handler(&mut request_ref), NGX_OK as _);
        }
        assert_eq!(READY_FINISHES.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn failed_completion_resume_retains_its_owner_for_retry() {
        let mut worker = TestWorker::new();
        worker.init();
        reset_ready_state();
        let mut request = TestRequest::new();
        request.request.phase_handler = -1;

        start_handler::<ReadyHandler>(&mut request);
        worker.process_posted();
        worker.process_posted();
        let mut continuation = {
            let mut request_ref = request.borrow();
            continuation_for::<ReadyHandler>(&mut request_ref)
        };
        {
            let state = unsafe { continuation.as_ref() }.state().borrow();
            assert!(state.active);
            assert!(state.output.is_some());
            assert!(state.hold.is_some());
            assert!(!state.phase_posted);
        }
        assert_eq!(request.main_count(), 2);

        request.request.phase_handler = 0;
        unsafe {
            Pin::new_unchecked(continuation.as_mut()).post(PostedQueue::Next).unwrap();
        }
        worker.process_posted();

        let state = unsafe { continuation.as_ref() }.state().borrow();
        assert!(state.phase_posted);
        assert!(state.hold.is_none());
        assert_eq!(request.main_count(), 1);
    }

    #[test]
    fn delayed_local_wake_posts_once_and_finishes_with_a_fresh_request_borrow() {
        let mut worker = TestWorker::new();
        worker.init();
        PENDING_FINISHES.store(0, Ordering::Relaxed);
        let state = install_local_state();
        let mut request = TestRequest::new();

        start_handler::<PendingHandler>(&mut request);
        worker.process_posted();
        assert_eq!(state.polls.get(), 1);
        assert!(state.waker.borrow().is_some());

        state.ready.set(true);
        let waker = state.waker.borrow_mut().take().unwrap();
        waker.wake_by_ref();
        waker.wake_by_ref();
        worker.process_posted();
        worker.process_posted();

        assert_eq!(request.write_is_posted(), 1);
        assert_eq!(request.main_count(), 1);
        assert_eq!(state.drops.get(), 1);
        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<PendingHandler>::handler(&mut request_ref), NGX_OK as _);
            assert!(request_ref.module_context::<PendingModule>().unwrap().is_none());
        }
        assert_eq!(PENDING_FINISHES.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn delayed_foreign_wake_notifies_the_worker_and_resumes_the_phase() {
        let mut worker = TestWorker::new();
        worker.init();
        FOREIGN_FINISHES.store(0, Ordering::Relaxed);
        let state = install_foreign_state();
        let mut request = TestRequest::new();

        start_handler::<ForeignHandler>(&mut request);
        worker.process_posted();
        assert_eq!(state.polls.load(Ordering::Relaxed), 1);

        let foreign = Arc::clone(&state);
        thread::spawn(move || {
            foreign.ready.store(true, Ordering::Relaxed);
            foreign.wake();
        })
        .join()
        .unwrap();

        worker.deliver_notification();
        worker.process_posted();
        assert_eq!(request.write_is_posted(), 1);
        assert_eq!(request.main_count(), 1);
        assert_eq!(state.drops.load(Ordering::Relaxed), 1);
        {
            let mut request_ref = request.borrow();
            assert_eq!(AsyncPhaseHandler::<ForeignHandler>::handler(&mut request_ref), NGX_OK as _);
        }
        assert_eq!(FOREIGN_FINISHES.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn finish_propagates_declined_and_error_statuses() {
        let mut worker = TestWorker::new();
        worker.init();

        let mut declined = TestRequest::new();
        complete_handler::<DeclinedHandler>(&mut worker, &mut declined);
        {
            let mut request_ref = declined.borrow();
            assert_eq!(
                AsyncPhaseHandler::<DeclinedHandler>::handler(&mut request_ref),
                NGX_DECLINED as _
            );
        }
        assert_ne!(declined.write_event.posted(), 0);
        unsafe { ngx_delete_posted_event(&raw mut *declined.write_event) };

        let mut error = TestRequest::new();
        complete_handler::<ErrorHandler>(&mut worker, &mut error);
        let mut request_ref = error.borrow();
        assert_eq!(AsyncPhaseHandler::<ErrorHandler>::handler(&mut request_ref), NGX_ERROR as _);
    }

    #[test]
    fn internal_redirect_cancels_pending_generation_before_replacement() {
        let mut worker = TestWorker::new();
        worker.init();
        PENDING_FINISHES.store(0, Ordering::Relaxed);
        let old = install_local_state();
        let mut request = TestRequest::new();

        start_handler::<PendingHandler>(&mut request);
        worker.process_posted();
        assert_eq!(old.polls.get(), 1);
        let old_waker = old.waker.borrow_mut().take().unwrap();
        assert_eq!(request.main_count(), 2);

        let mut phase_handlers =
            Box::new([unsafe { MaybeUninit::<ngx_http_phase_handler_t>::zeroed().assume_init() }]);
        phase_handlers[0].checker = Some(stop_phase_engine);
        let mut main_conf =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init() });
        main_conf.phase_engine.handlers = phase_handlers.as_mut_ptr();
        main_conf.phase_engine.server_rewrite_index = 0;
        let mut core_loc =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_loc_conf_t>::zeroed().assume_init() });
        let mut loc_conf = Box::new([(&raw mut *core_loc).cast::<c_void>()]);
        let mut main_conf_slots = Box::new([(&raw mut *main_conf).cast::<c_void>()]);
        let mut http_context = Box::new(ngx_http_conf_ctx_t {
            main_conf: main_conf_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
            loc_conf: loc_conf.as_mut_ptr(),
        });
        let mut server =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_srv_conf_t>::zeroed().assume_init() });
        server.ctx = &raw mut *http_context;
        let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
        http_context.srv_conf = server_slots.as_mut_ptr();
        request.request.main_conf = main_conf_slots.as_mut_ptr();
        request.request.srv_conf = server_slots.as_mut_ptr();
        request.request.loc_conf = loc_conf.as_mut_ptr();
        request.request.set_uri_changes(2);

        {
            let mut request_ref = request.borrow();
            assert_eq!(
                request_ref.internal_redirect("/replacement"),
                Ok(crate::core::Status::NGX_DONE)
            );
            request_ref.finalize(crate::core::Status::NGX_DONE).unwrap();
        }
        assert_ne!(request.request.internal(), 0);
        assert_eq!(old.drops.get(), 1);
        assert_eq!(request.main_count(), 1);
        assert!(request._contexts[0].is_null());

        let replacement = install_local_state();
        start_handler::<PendingHandler>(&mut request);
        assert_eq!(request.main_count(), 2);

        old_waker.wake();
        worker.process_posted();
        assert_eq!(PENDING_FINISHES.load(Ordering::Relaxed), 0);
        assert_eq!(request.write_is_posted(), 0);

        worker.process_posted();
        assert_eq!(replacement.polls.get(), 1);
        remove_handler_context::<PendingHandler>(&mut request);
        assert_eq!(replacement.drops.get(), 1);
        assert_eq!(request.main_count(), 1);
    }

    #[cfg(nginx1_25_4)]
    #[test]
    fn native_termination_cancels_pending_main_before_late_wake() {
        let mut worker = TestWorker::new();
        worker.init();
        PENDING_FINISHES.store(0, Ordering::Relaxed);
        let state = install_local_state();
        let mut request = TestRequest::new();

        start_handler::<PendingHandler>(&mut request);
        worker.process_posted();
        assert_eq!(state.polls.get(), 1);
        let waker = state.waker.borrow_mut().take().unwrap();
        assert_eq!(request.main_count(), 2);
        request.request.set_blocked(1);
        request.request.write_event_handler = Some(blocked_write_handler);

        unsafe { ngx_http_finalize_request(&raw mut *request.request, NGX_ERROR as _) };

        assert_ne!(request.request.terminated(), 0);
        assert!(request._contexts[0].is_null());
        assert_eq!(request.main_count(), 1);
        waker.wake();
        worker.process_posted();
        assert_eq!(state.drops.get(), 1);
        assert_eq!(PENDING_FINISHES.load(Ordering::Relaxed), 0);
        assert_eq!(request.write_is_posted(), 0);
        assert_eq!(request.main_count(), 1);

        let finalizer = request.request.write_event_handler.expect("native request finalizer");
        request.request.set_blocked(0);
        unsafe { finalizer(&raw mut *request.request) };
        assert!(!request.request.posted_requests.is_null());
        assert_eq!(request.main_count(), 1);
        request.request.posted_requests = ptr::null_mut();
        request.request.write_event_handler = None;
        drop(request);
        assert_eq!(state.drops.get(), 1);
    }

    #[cfg(nginx1_25_4)]
    #[test]
    fn native_termination_cancels_done_noncurrent_subrequest_before_late_wake() {
        let mut worker = TestWorker::new();
        worker.init();
        PENDING_FINISHES.store(0, Ordering::Relaxed);
        let state = install_local_state();
        let mut main = TestRequest::new();
        let mut contexts = Box::new([ptr::null_mut()]);
        let mut subrequest =
            Box::new(unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() });
        subrequest.signature = NGX_HTTP_MODULE as _;
        subrequest.main = &raw mut *main.request;
        subrequest.parent = &raw mut *main.request;
        subrequest.pool = main._pool.raw;
        subrequest.connection = &raw mut *main._connection;
        subrequest.ctx = contexts.as_mut_ptr();
        subrequest.loc_conf = main.loc_conf.as_mut_ptr();
        subrequest.set_done(1);

        {
            let mut request = unsafe { RequestRefMut::from_raw(&raw mut *subrequest).unwrap() };
            assert_eq!(AsyncPhaseHandler::<PendingHandler>::handler(&mut request), NGX_DONE as _);
        }
        worker.process_posted();
        assert_eq!(state.polls.get(), 1);
        let waker = state.waker.borrow_mut().take().unwrap();
        assert_eq!(main.main_count(), 2);
        main.request.set_blocked(1);
        main.request.write_event_handler = Some(blocked_write_handler);

        unsafe { ngx_http_finalize_request(&raw mut *subrequest, NGX_ERROR as _) };

        assert_ne!(main.request.terminated(), 0);
        assert_ne!(subrequest.done(), 0);
        assert!(contexts[0].is_null());
        assert_eq!(main.main_count(), 1);
        waker.wake();
        worker.process_posted();
        assert_eq!(state.drops.get(), 1);
        assert_eq!(PENDING_FINISHES.load(Ordering::Relaxed), 0);
        assert_eq!(main.write_is_posted(), 0);
        assert_eq!(main.main_count(), 1);

        let finalizer = main.request.write_event_handler.expect("native request finalizer");
        main.request.set_blocked(0);
        unsafe { finalizer(&raw mut *main.request) };
        assert!(!main.request.posted_requests.is_null());
        assert_eq!(main.main_count(), 1);
        main.request.posted_requests = ptr::null_mut();
        main.request.write_event_handler = None;
        drop(main);
        assert_eq!(state.drops.get(), 1);
    }

    #[cfg(nginx1_25_4)]
    #[test]
    fn native_termination_cancels_waited_subrequest_before_late_completion() {
        let mut worker = TestWorker::new();
        worker.init();
        ASYNC_SUBREQUEST_SAW_CONTEXT.store(false, Ordering::Relaxed);
        ASYNC_SUBREQUEST_FINISHES.store(0, Ordering::Relaxed);
        let state = install_async_subrequest_state();
        let mut request = TestRequest::new();
        let mut main_conf =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init() });
        let mut main_conf_slots = Box::new([(&raw mut *main_conf).cast::<c_void>()]);
        let mut http_context = Box::new(ngx_http_conf_ctx_t {
            main_conf: main_conf_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
            loc_conf: request.loc_conf.as_mut_ptr(),
        });
        let mut server =
            Box::new(unsafe { MaybeUninit::<ngx_http_core_srv_conf_t>::zeroed().assume_init() });
        server.ctx = &raw mut *http_context;
        let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
        http_context.srv_conf = server_slots.as_mut_ptr();
        request.request.main_conf = main_conf_slots.as_mut_ptr();
        request.request.srv_conf = server_slots.as_mut_ptr();
        request.request.set_subrequests(2);

        start_handler::<AsyncSubrequestHandler>(&mut request);
        assert!(ASYNC_SUBREQUEST_SAW_CONTEXT.load(Ordering::Relaxed));
        assert_eq!(request.main_count(), 3);
        worker.process_posted();
        assert_eq!(state.task_drops.get(), 0);
        assert_eq!(state.completion_drops.get(), 0);

        request.request.set_blocked(1);
        request.request.write_event_handler = Some(blocked_write_handler);
        unsafe { ngx_http_finalize_request(&raw mut *request.request, NGX_ERROR as _) };

        assert_ne!(request.request.terminated(), 0);
        assert!(request._contexts[0].is_null());
        assert_eq!(request.main_count(), 2);
        assert_eq!(state.task_drops.get(), 1);
        assert_eq!(state.callbacks.get(), 0);
        assert_eq!(state.completion_drops.get(), 0);

        let subrequest = state.subrequest.get();
        assert!(!subrequest.is_null());
        request._connection.set_error(0);
        unsafe { ngx_http_finalize_request(subrequest, NGX_OK as _) };
        assert_ne!(unsafe { (*subrequest).done() }, 0);
        assert_eq!(request.main_count(), 1);
        assert_eq!(state.callbacks.get(), 0);
        assert_eq!(state.completion_drops.get(), 1);

        worker.process_posted();
        worker.process_posted();
        assert_eq!(ASYNC_SUBREQUEST_FINISHES.load(Ordering::Relaxed), 0);
        assert_eq!(request.write_is_posted(), 0);
        assert_eq!(state.task_drops.get(), 1);
        assert_eq!(state.completion_drops.get(), 1);

        request.request.set_blocked(0);
        request.request.posted_requests = ptr::null_mut();
        request.request.write_event_handler = None;
        drop(request);
        assert_eq!(state.task_drops.get(), 1);
        assert_eq!(state.completion_drops.get(), 1);
    }

    #[test]
    fn request_cleanup_before_the_first_task_poll_cancels_the_task() {
        let mut worker = TestWorker::new();
        worker.init();
        let state = install_local_state();
        let mut request = TestRequest::new();

        start_handler::<PendingHandler>(&mut request);
        assert_eq!(request.main_count(), 2);
        remove_handler_context::<PendingHandler>(&mut request);
        assert_eq!(request.main_count(), 1);
        worker.process_posted();

        assert_eq!(state.polls.get(), 0);
        assert_eq!(state.drops.get(), 1);
        assert_eq!(request.write_is_posted(), 0);
        let request_ref = request.borrow();
        assert!(request_ref.module_context::<PendingModule>().unwrap().is_none());
    }

    #[test]
    fn request_cleanup_while_pending_cancels_the_task_and_ignores_its_wake() {
        let mut worker = TestWorker::new();
        worker.init();
        PENDING_FINISHES.store(0, Ordering::Relaxed);
        let state = install_local_state();
        let mut request = TestRequest::new();

        start_handler::<PendingHandler>(&mut request);
        worker.process_posted();
        assert_eq!(state.polls.get(), 1);
        let waker = state.waker.borrow_mut().take().unwrap();
        remove_handler_context::<PendingHandler>(&mut request);
        waker.wake();
        worker.process_posted();

        assert_eq!(state.drops.get(), 1);
        assert_eq!(PENDING_FINISHES.load(Ordering::Relaxed), 0);
        assert_eq!(request.write_is_posted(), 0);
    }

    #[test]
    fn request_cleanup_after_output_cancels_the_posted_continuation() {
        let mut worker = TestWorker::new();
        worker.init();
        let mut request = TestRequest::new();

        start_handler::<ReadyHandler>(&mut request);
        worker.process_posted();
        let continuation = {
            let mut request_ref = request.borrow();
            continuation_for::<ReadyHandler>(&mut request_ref)
        };
        assert!(unsafe { continuation.as_ref() }.is_posted());
        {
            let state = unsafe { continuation.as_ref() }.state().borrow();
            assert!(state.active);
            assert!(state.output.is_some());
            assert!(state.hold.is_some());
            assert!(!state.phase_posted);
        }
        assert_eq!(request.main_count(), 2);

        remove_handler_context::<ReadyHandler>(&mut request);
        assert!(unsafe { continuation.as_ref() }.is_shutdown());
        {
            let state = unsafe { continuation.as_ref() }.state().borrow();
            assert!(!state.active);
            assert!(state.output.is_none());
            assert!(state.hold.is_none());
            assert!(!state.phase_posted);
        }
        assert_eq!(request.main_count(), 1);
        worker.process_posted();

        assert_eq!(request.write_is_posted(), 0);
    }

    #[test]
    fn request_cleanup_after_phase_post_cancels_the_continuation_state() {
        let mut worker = TestWorker::new();
        worker.init();
        let mut request = TestRequest::new();

        let continuation = complete_handler::<ReadyHandler>(&mut worker, &mut request);
        assert!(unsafe { continuation.as_ref() }.state().borrow().phase_posted);
        assert_eq!(request.write_is_posted(), 1);
        remove_handler_context::<ReadyHandler>(&mut request);

        assert!(unsafe { continuation.as_ref() }.is_shutdown());
        let state = unsafe { continuation.as_ref() }.state().borrow();
        assert!(!state.active);
        assert!(state.task.is_none());
        assert!(state.output.is_none());
        assert!(state.hold.is_none());
    }

    #[test]
    fn request_context_mismatch_retains_completion_for_retry() {
        let mut worker = TestWorker::new();
        worker.init();
        let mut request = TestRequest::new();

        start_handler::<ReadyHandler>(&mut request);
        worker.process_posted();
        let mut continuation = {
            let mut request_ref = request.borrow();
            continuation_for::<ReadyHandler>(&mut request_ref)
        };
        let mut foreign =
            Box::new(unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() });
        foreign.signature = NGX_HTTP_MODULE as _;
        foreign.main = &raw mut *foreign;
        foreign.set_count(1);
        request.request.main = &raw mut *foreign;

        worker.process_posted();

        assert_eq!(request.write_is_posted(), 0);
        {
            let state = unsafe { continuation.as_ref() }.state().borrow();
            assert!(state.active);
            assert!(state.output.is_some());
            assert!(state.hold.is_some());
            assert!(!state.phase_posted);
        }
        assert_eq!(request.request.count(), 2);

        request.request.main = &raw mut *request.request;
        unsafe {
            Pin::new_unchecked(continuation.as_mut()).post(PostedQueue::Next).unwrap();
        }
        worker.process_posted();

        let state = unsafe { continuation.as_ref() }.state().borrow();
        assert!(state.phase_posted);
        assert!(state.hold.is_none());
        assert_eq!(request.main_count(), 1);
        drop(state);
        remove_handler_context::<ReadyHandler>(&mut request);
    }
}
