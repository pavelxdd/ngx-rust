use core::ffi::c_void;
use core::fmt;
use core::mem;
use core::ptr;

#[cfg(feature = "async")]
use alloc::rc::Rc;
#[cfg(feature = "async")]
use core::cell::RefCell;
#[cfg(feature = "async")]
use core::future::Future;
#[cfg(feature = "async")]
use core::pin::Pin;
#[cfg(feature = "async")]
use core::task::{Context, Poll, Waker};

use nginx_sys::{
    NGX_HTTP_SUBREQUEST_BACKGROUND, NGX_HTTP_SUBREQUEST_CLONE, NGX_HTTP_SUBREQUEST_IN_MEMORY,
    NGX_HTTP_SUBREQUEST_WAITED, ngx_http_post_subrequest_t, ngx_http_request_body_t,
    ngx_http_request_t, ngx_int_t, ngx_list_init, ngx_list_t, ngx_str_t, ngx_table_elt_t,
    ngx_uint_t,
};

use crate::allocator::AllocError;
use crate::http::{IntoHandlerStatus, Request};
use crate::ngx_log_debug_http;

/// Default post-subrequest handler type.
pub type DefaultSubRequestHandler = fn(&mut Request, ngx_int_t) -> ngx_int_t;

/// Error returned while creating or awaiting a subrequest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubRequestError {
    /// The request pool could not allocate required state.
    Alloc,
    /// Nginx rejected the subrequest with the contained status.
    Create(ngx_int_t),
    /// Nginx released the parent request before the subrequest completed.
    #[cfg(feature = "async")]
    Canceled,
}

impl From<AllocError> for SubRequestError {
    fn from(_: AllocError) -> Self {
        Self::Alloc
    }
}

impl fmt::Display for SubRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alloc => f.write_str("subrequest allocation failed"),
            Self::Create(status) => write!(f, "subrequest creation failed with status {status}"),
            #[cfg(feature = "async")]
            Self::Canceled => f.write_str("subrequest canceled"),
        }
    }
}

impl core::error::Error for SubRequestError {}

/// Builder for an nginx HTTP subrequest.
///
/// The URI, arguments, and completion handler are owned by the request pool. By default, the
/// subrequest gets an empty input-header list and a separate empty request body.
pub struct SubRequestBuilder<'r, H = DefaultSubRequestHandler> {
    request: &'r mut Request,
    uri: ngx_str_t,
    args: Option<ngx_str_t>,
    flags: ngx_uint_t,
    keep_body: bool,
    headers_in_capacity: ngx_uint_t,
    handler: Option<H>,
}

impl<'r> SubRequestBuilder<'r> {
    /// Create a builder for `uri`.
    pub fn new(request: &'r mut Request, uri: &str) -> Result<Self, SubRequestError> {
        let uri = unsafe { ngx_str_t::from_bytes(request.pool().as_ptr(), uri.as_bytes()) }
            .ok_or(SubRequestError::Alloc)?;

        Ok(Self {
            request,
            uri,
            args: None,
            flags: 0,
            keep_body: false,
            headers_in_capacity: 4,
            handler: None,
        })
    }
}

impl<'r, H> SubRequestBuilder<'r, H> {
    /// Set the subrequest query string.
    pub fn args(mut self, args: &str) -> Result<Self, SubRequestError> {
        self.args = Some(
            unsafe { ngx_str_t::from_bytes(self.request.pool().as_ptr(), args.as_bytes()) }
                .ok_or(SubRequestError::Alloc)?,
        );
        Ok(self)
    }

    /// Run `handler` after nginx finalizes the subrequest.
    pub fn handler<HT, O>(self, handler: HT) -> SubRequestBuilder<'r, HT>
    where
        HT: FnOnce(&mut Request, ngx_int_t) -> O + 'static,
        O: IntoHandlerStatus,
    {
        SubRequestBuilder {
            request: self.request,
            uri: self.uri,
            args: self.args,
            flags: self.flags,
            keep_body: self.keep_body,
            headers_in_capacity: self.headers_in_capacity,
            handler: Some(handler),
        }
    }

    /// Buffer the subrequest response in memory.
    pub fn in_memory(mut self) -> Self {
        self.flags |= NGX_HTTP_SUBREQUEST_IN_MEMORY as ngx_uint_t;
        self
    }

    /// Mark the subrequest as waited by its parent.
    pub fn waited(mut self) -> Self {
        self.flags |= NGX_HTTP_SUBREQUEST_WAITED as ngx_uint_t;
        self
    }

    /// Clone the parent request location and phase state.
    pub fn cloned(mut self) -> Self {
        self.flags |= NGX_HTTP_SUBREQUEST_CLONE as ngx_uint_t;
        self
    }

    /// Run the subrequest without blocking other requests.
    pub fn background(mut self) -> Self {
        self.flags |= NGX_HTTP_SUBREQUEST_BACKGROUND as ngx_uint_t;
        self
    }

    /// Keep the parent's request body instead of installing an empty body.
    pub fn keep_body(mut self) -> Self {
        self.keep_body = true;
        self
    }

    /// Set the initial input-header capacity.
    ///
    /// A capacity of zero preserves the parent's shallow-copied headers.
    pub fn init_headers_in(mut self, capacity: ngx_uint_t) -> Self {
        self.headers_in_capacity = capacity;
        self
    }

    /// Create and schedule the subrequest.
    ///
    /// The returned request can be modified until the current nginx handler returns.
    pub fn build<O>(mut self) -> Result<&'r mut Request, SubRequestError>
    where
        H: FnOnce(&mut Request, ngx_int_t) -> O + 'static,
        O: IntoHandlerStatus,
    {
        let pool = self.request.pool();
        let request_body = if self.keep_body {
            ptr::null_mut()
        } else {
            let body: *mut ngx_http_request_body_t =
                pool.calloc(mem::size_of::<ngx_http_request_body_t>()).cast();
            if body.is_null() {
                return Err(SubRequestError::Alloc);
            }
            body
        };

        let headers_in = if self.headers_in_capacity == 0 {
            None
        } else {
            if self.headers_in_capacity.checked_mul(mem::size_of::<ngx_table_elt_t>()).is_none() {
                return Err(SubRequestError::Alloc);
            }
            let mut headers = unsafe { mem::zeroed::<ngx_list_t>() };
            let status = unsafe {
                ngx_list_init(
                    &raw mut headers,
                    pool.as_ptr(),
                    self.headers_in_capacity,
                    mem::size_of::<ngx_table_elt_t>(),
                )
            };
            crate::core::Status(status).into_result().map_err(|_| SubRequestError::Alloc)?;
            Some(headers)
        };

        let post = if let Some(handler) = self.handler.take() {
            let handler = unsafe { pool.allocate_with_cleanup(|| Some(handler))? };
            let post: *mut ngx_http_post_subrequest_t =
                pool.alloc(mem::size_of::<ngx_http_post_subrequest_t>()).cast();
            if post.is_null() {
                return Err(SubRequestError::Alloc);
            }
            unsafe {
                post.write(ngx_http_post_subrequest_t {
                    handler: Some(run_handler::<H, O>),
                    data: handler.as_ptr().cast(),
                });
            }
            post
        } else {
            ptr::null_mut()
        };

        let args = self.args.as_mut().map_or(ptr::null_mut(), ptr::from_mut);
        let request: *mut ngx_http_request_t = self.request.into();
        let mut subrequest = ptr::null_mut();
        let status = unsafe {
            nginx_sys::ngx_http_subrequest(
                request,
                &raw mut self.uri,
                args,
                &raw mut subrequest,
                post,
                self.flags,
            )
        };
        crate::core::Status(status).into_result().map_err(|_| SubRequestError::Create(status))?;

        let subrequest: &'r mut Request = unsafe { Request::from_ngx_http_request(subrequest) };
        if !self.keep_body {
            subrequest.as_mut().request_body = request_body;
        }
        if let Some(headers) = headers_in {
            subrequest.reset_headers_in(headers);
        }
        Ok(subrequest)
    }
}

#[cfg(feature = "async")]
impl<'r> SubRequestBuilder<'r> {
    /// Create a subrequest and return a future for its owned completion value.
    ///
    /// The completion handler runs with temporary access to the subrequest. Its first return value
    /// is moved into the future, while the second is returned to nginx as the post-subrequest
    /// handler status. The returned request can be modified until the current nginx handler
    /// returns.
    pub fn build_async<T, H, O>(
        self,
        handler: H,
    ) -> Result<(SubRequestFuture<T>, &'r mut Request), SubRequestError>
    where
        T: 'static,
        H: FnOnce(&mut Request, ngx_int_t) -> (T, O) + 'static,
        O: IntoHandlerStatus,
    {
        let state = Rc::new(RefCell::new(AsyncSubRequestState::new()));
        let future = SubRequestFuture { state: Rc::clone(&state) };
        let guard = AsyncSubRequestGuard { state, active: true };
        let subrequest = self
            .handler(move |request, status| {
                let (output, handler_status) = handler(request, status);
                guard.finish(output);
                handler_status
            })
            .build()?;

        Ok((future, subrequest))
    }
}

/// Future returned by [`SubRequestBuilder::build_async`].
#[cfg(feature = "async")]
pub struct SubRequestFuture<T> {
    state: Rc<RefCell<AsyncSubRequestState<T>>>,
}

#[cfg(feature = "async")]
impl<T> Future for SubRequestFuture<T> {
    type Output = Result<T, SubRequestError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.get_mut().state.borrow_mut();
        assert!(!state.consumed, "subrequest future polled after completion");

        if let Some(output) = state.output.take() {
            state.consumed = true;
            return Poll::Ready(output);
        }

        if let Some(waker) = state.waker.as_mut() {
            waker.clone_from(context.waker());
        } else {
            state.waker = Some(context.waker().clone());
        }
        Poll::Pending
    }
}

#[cfg(feature = "async")]
struct AsyncSubRequestState<T> {
    output: Option<Result<T, SubRequestError>>,
    waker: Option<Waker>,
    consumed: bool,
}

#[cfg(feature = "async")]
impl<T> AsyncSubRequestState<T> {
    fn new() -> Self {
        Self { output: None, waker: None, consumed: false }
    }

    fn complete(&mut self, output: Result<T, SubRequestError>) -> Option<Waker> {
        if self.consumed || self.output.is_some() {
            return None;
        }
        self.output = Some(output);
        self.waker.take()
    }
}

#[cfg(feature = "async")]
struct AsyncSubRequestGuard<T> {
    state: Rc<RefCell<AsyncSubRequestState<T>>>,
    active: bool,
}

#[cfg(feature = "async")]
impl<T> AsyncSubRequestGuard<T> {
    fn finish(mut self, output: T) {
        self.active = false;
        let waker = self.state.borrow_mut().complete(Ok(output));
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[cfg(feature = "async")]
impl<T> Drop for AsyncSubRequestGuard<T> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        let waker = self.state.borrow_mut().complete(Err(SubRequestError::Canceled));
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

unsafe extern "C" fn run_handler<H, O>(
    request: *mut ngx_http_request_t,
    data: *mut c_void,
    status: ngx_int_t,
) -> ngx_int_t
where
    H: FnOnce(&mut Request, ngx_int_t) -> O + 'static,
    O: IntoHandlerStatus,
{
    let request = unsafe { Request::from_ngx_http_request(request) };
    ngx_log_debug_http!(request, "subrequest handler called with status {status}");

    let handler = unsafe { &mut *data.cast::<Option<H>>() }.take();
    handler.map_or(status, |handler| handler(request, status).into_handler_status(request))
}

#[cfg(all(test, feature = "async"))]
mod tests {
    use super::*;

    #[test]
    fn dropping_completion_guard_cancels_future() {
        let state = Rc::new(RefCell::new(AsyncSubRequestState::<()>::new()));
        let mut future = SubRequestFuture { state: Rc::clone(&state) };
        let guard = AsyncSubRequestGuard { state, active: true };

        drop(guard);

        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            Pin::new(&mut future).poll(&mut context),
            Poll::Ready(Err(SubRequestError::Canceled))
        );
    }
}
