use core::future::Future;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::allocator::AllocError;
use crate::async_::{Task, spawn};
use crate::ffi::{NGX_AGAIN, NGX_ERROR, ngx_event_t, ngx_int_t, ngx_post_event, ngx_posted_events};
use crate::http::{
    HttpModuleRequestContext, HttpPhase, HttpRequestHandler, IntoHandlerStatus, Request,
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
    type Output: 'static;
    /// The final phase-handler result.
    type Result: IntoHandlerStatus;

    /// Starts the asynchronous work.
    fn start(request: &mut Request) -> impl Future<Output = Self::Output> + 'static;

    /// Applies the completed output to the request on the nginx event loop.
    fn finish(request: &mut Request, output: Self::Output) -> Self::Result;

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
    task: Option<Task<()>>,
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

    fn handler(request: &mut Request) -> Self::Output {
        if request.module_context::<H::Module>().is_some() {
            let output = {
                let context = request.module_context_mut::<H::Module>().expect("context exists");
                let Some(output) = context.output.take() else {
                    ngx_log_debug_http!(request, "async handler {} pending", H::name());
                    return NGX_AGAIN as ngx_int_t;
                };
                context.task.take();
                output
            };

            ngx_log_debug_http!(request, "async handler {} complete", H::name());
            if request.remove_module_context::<H::Module>().is_none() {
                ngx_log_error!(
                    crate::ffi::NGX_LOG_ERR,
                    request.log(),
                    "async handler {} context removal failed",
                    H::name()
                );
                return NGX_ERROR as ngx_int_t;
            }
            return H::finish(request, output).into_handler_status(request);
        }

        let future = H::start(request);
        let write_event = unsafe { (*request.connection()).write };
        let context = match request
            .get_or_insert_module_context_with::<H::Module>(AsyncHandlerContext::new)
        {
            Ok(context) => context,
            Err(_) => {
                ngx_log_error!(
                    crate::ffi::NGX_LOG_ERR,
                    request.log(),
                    "async handler {} context allocation failed",
                    H::name()
                );
                return NGX_ERROR as ngx_int_t;
            }
        };
        let context_ptr = NonNull::from(&mut *context);
        context.task = Some(spawn(handler_future(future, context_ptr, write_event)));

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
    // cleanup sequentially on the worker event loop. If cleanup wins, dropping Task cancels
    // this future before the context storage is released.
    unsafe {
        debug_assert!((*context.as_ptr()).output.is_none());
        (*context.as_ptr()).output = Some(output);
        ngx_post_event(write_event, &raw mut ngx_posted_events);
    }
}

/// Registers an asynchronous HTTP phase handler.
///
/// Call this function from the module's postconfiguration callback.
pub fn add_async_phase_handler<H>(cf: &mut crate::ffi::ngx_conf_t) -> Result<(), AllocError>
where
    H: AsyncHttpRequestHandler,
{
    add_phase_handler::<AsyncPhaseHandler<H>>(cf)
}
