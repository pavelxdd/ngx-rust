use core::future::Future;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::allocator::AllocError;
use crate::async_::{AttachedTask, spawn};
use crate::ffi::{NGX_AGAIN, NGX_ERROR, ngx_event_t, ngx_int_t, ngx_post_event, ngx_posted_events};
use crate::http::{
    HttpModuleRequestContext, HttpPhase, HttpRequestHandler, IntoHandlerStatus, RequestRefMut,
    add_phase_handler,
};
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

/// Request-owned state for an [`AsyncHttpRequestHandler`].
///
/// Associate this type with the handler's module through [`HttpModuleRequestContext`]. Dropping
/// the module context cancels pending work before nginx releases the request pool.
pub struct AsyncHandlerContext<H>
where
    H: AsyncHttpRequestHandler,
{
    task: Option<AttachedTask<()>>,
    output: Option<H::Output>,
    handler: PhantomData<fn() -> H>,
}

impl<H> AsyncHandlerContext<H>
where
    H: AsyncHttpRequestHandler,
{
    fn new() -> Self {
        Self { task: None, output: None, handler: PhantomData }
    }
}

struct AsyncPhaseHandler<H>(PhantomData<fn() -> H>);

impl<H> HttpRequestHandler for AsyncPhaseHandler<H>
where
    H: AsyncHttpRequestHandler,
{
    const PHASE: HttpPhase = async_phase(H::PHASE);
    type Output = ngx_int_t;

    fn handler(request: &mut RequestRefMut<'_>) -> Self::Output {
        let has_context = match request.module_context::<H::Module>() {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => return NGX_ERROR as ngx_int_t,
        };
        if has_context {
            let output = {
                let Ok(Some(mut context)) = request.pinned_module_context_mut::<H::Module>() else {
                    return NGX_ERROR as ngx_int_t;
                };
                let context = context.as_mut().get_mut();
                let Some(output) = context.output.take() else {
                    ngx_log_debug_http!(request, "async handler {} pending", H::name());
                    return NGX_AGAIN as ngx_int_t;
                };
                context.task.take();
                output
            };

            ngx_log_debug_http!(request, "async handler {} complete", H::name());
            if !matches!(request.remove_module_context::<H::Module>(), Ok(true)) {
                if let Ok(Some(log)) = request.log() {
                    ngx_log_error!(
                        crate::ffi::NGX_LOG_ERR,
                        log.as_ptr(),
                        "async handler {} context removal failed",
                        H::name()
                    );
                }
                return NGX_ERROR as ngx_int_t;
            }
            return H::finish(request, output).into_handler_status(&request.view());
        }

        let future = H::start(request);
        let write_event = match request.connection_mut() {
            Ok(mut connection) => match connection.write_event() {
                Ok(event) => event.as_ptr(),
                Err(_) => return NGX_ERROR as ngx_int_t,
            },
            Err(_) => return NGX_ERROR as ngx_int_t,
        };
        let spawn_failed = {
            let mut context = match request
                .get_or_insert_pinned_module_context_with::<H::Module>(AsyncHandlerContext::new)
            {
                Ok(context) => context,
                Err(_) => {
                    if let Ok(Some(log)) = request.log() {
                        ngx_log_error!(
                            crate::ffi::NGX_LOG_ERR,
                            log.as_ptr(),
                            "async handler {} context allocation failed",
                            H::name()
                        );
                    }
                    return NGX_ERROR as ngx_int_t;
                }
            };
            let context_ptr = {
                let context = context.as_mut().get_mut();
                NonNull::from(&mut *context)
            };

            match spawn(handler_future(future, context_ptr, write_event)) {
                Ok(task) => {
                    context.as_mut().get_mut().task = Some(task.into_attached());
                    false
                }
                Err(_) => true,
            }
        };
        if spawn_failed {
            if !matches!(request.remove_module_context::<H::Module>(), Ok(true)) {
                if let Ok(Some(log)) = request.log() {
                    ngx_log_error!(
                        crate::ffi::NGX_LOG_ERR,
                        log.as_ptr(),
                        "async handler {} context removal after scheduler startup failed",
                        H::name()
                    );
                }
            }
            return NGX_ERROR as ngx_int_t;
        }

        NGX_AGAIN as ngx_int_t
    }

    fn name() -> &'static str {
        H::name()
    }
}

const fn async_phase(phase: HttpPhase) -> HttpPhase {
    assert!(!matches!(phase, HttpPhase::Content), "content phase is not supported");
    phase
}

async fn handler_future<H>(
    future: impl Future<Output = H::Output> + 'static,
    context: NonNull<AsyncHandlerContext<H>>,
    write_event: *mut ngx_event_t,
) where
    H: AsyncHttpRequestHandler,
{
    let output = future.await;

    // The request context owns this task. nginx runs phase handlers, task polls, and pool
    // cleanup sequentially on the worker event loop. If cleanup wins, dropping LocalTask requests
    // cancellation before the context storage is released, and the scheduler cancels it before
    // any later runnable can poll this future.
    unsafe {
        debug_assert!((*context.as_ptr()).output.is_none());
        (*context.as_ptr()).output = Some(output);
        ngx_post_event(write_event, &raw mut ngx_posted_events);
    }
}

/// Registers an asynchronous HTTP phase handler.
///
/// Call this function from the module's postconfiguration callback. The owning module must call
/// [`crate::async_::init_worker`] from its process-start hook and
/// [`crate::async_::shutdown_worker`] from its process-exit hook.
pub fn add_async_phase_handler<H>(cf: &mut crate::ffi::ngx_conf_t) -> Result<(), AllocError>
where
    H: AsyncHttpRequestHandler,
{
    add_phase_handler::<AsyncPhaseHandler<H>>(cf)
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use core::ffi::c_void;
    use core::future::Future;
    use core::mem::MaybeUninit;
    use core::ptr;
    use std::sync::{MutexGuard, Once};

    use super::*;
    use crate::ffi::{
        NGX_ERROR, NGX_HTTP_MODULE, NGX_OK, ngx_connection_t, ngx_create_pool, ngx_destroy_pool,
        ngx_event_t, ngx_http_request_t, ngx_log_t, ngx_module_t, ngx_pool_t, ngx_uint_t,
    };
    use crate::http::{HttpModule, HttpModuleRequestContext};

    static mut TEST_MODULE: MaybeUninit<ngx_module_t> = MaybeUninit::uninit();
    static TEST_MODULE_INIT: Once = Once::new();

    fn test_module() -> &'static ngx_module_t {
        TEST_MODULE_INIT.call_once(|| unsafe {
            (&raw mut TEST_MODULE).cast::<ngx_module_t>().write(ngx_module_t {
                type_: NGX_HTTP_MODULE as _,
                index: 0,
                ctx_index: 0,
                ..ngx_module_t::default()
            });
        });
        unsafe { &*(&raw const TEST_MODULE).cast::<ngx_module_t>() }
    }

    struct TestModule;

    unsafe impl HttpModule for TestModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl HttpModuleRequestContext for TestModule {
        type RequestContext = AsyncHandlerContext<TestHandler>;
    }

    struct TestHandler;

    impl AsyncHttpRequestHandler for TestHandler {
        const PHASE: HttpPhase = HttpPhase::Access;
        type Module = TestModule;
        type Output = ();
        type Result = ngx_int_t;

        fn start(_request: &mut RequestRefMut<'_>) -> impl Future<Output = Self::Output> + 'static {
            core::future::ready(())
        }

        fn finish(_request: &mut RequestRefMut<'_>, _output: Self::Output) -> Self::Result {
            NGX_OK as _
        }
    }

    struct TestGlobals {
        _guard: MutexGuard<'static, ()>,
        max_module: ngx_uint_t,
        http_max_module: ngx_uint_t,
    }

    impl TestGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let (max_module, http_max_module) =
                unsafe { (nginx_sys::ngx_max_module, nginx_sys::ngx_http_max_module) };
            unsafe {
                nginx_sys::ngx_max_module = 1;
                nginx_sys::ngx_http_max_module = 1;
            }
            Self { _guard: guard, max_module, http_max_module }
        }
    }

    impl Drop for TestGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_max_module = self.max_module;
                nginx_sys::ngx_http_max_module = self.http_max_module;
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

    #[test]
    fn spawn_failure_removes_the_new_request_context() {
        let _globals = TestGlobals::new();
        assert_eq!(crate::async_::shutdown_worker(), Ok(false));
        let pool = TestPool::new();
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut write_event = unsafe { MaybeUninit::<ngx_event_t>::zeroed().assume_init() };
        let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
        connection.write = &raw mut write_event;
        connection.log = (&raw const *pool.log).cast_mut();
        let mut raw = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        raw.signature = NGX_HTTP_MODULE as _;
        raw.main = &raw mut raw;
        raw.pool = pool.raw;
        raw.connection = &raw mut connection;
        raw.ctx = contexts.as_mut_ptr();
        let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };

        assert_eq!(AsyncPhaseHandler::<TestHandler>::handler(&mut request), NGX_ERROR as _);
        assert!(request.module_context::<TestModule>().unwrap().is_none());
    }
}
