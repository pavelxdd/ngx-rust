use core::ffi::c_void;
use core::fmt;
use core::mem;
use core::ptr::{self, NonNull};

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
use crate::http::{IntoHandlerStatus, RequestError, RequestRefMut, request_callback_status};
use crate::ngx_log_debug_http;

/// Default post-subrequest handler type.
pub type DefaultSubRequestHandler = fn(&mut RequestRefMut<'_>, ngx_int_t) -> ngx_int_t;

/// Error returned while creating or awaiting a subrequest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubRequestError {
    /// The request pool could not allocate required state.
    Alloc,
    /// Nginx rejected the subrequest with the contained status.
    Create(ngx_int_t),
    /// The parent or produced request failed validation.
    Request(RequestError),
    /// Nginx released the parent request before the subrequest completed.
    #[cfg(feature = "async")]
    Canceled,
}

impl From<AllocError> for SubRequestError {
    fn from(_: AllocError) -> Self {
        Self::Alloc
    }
}

impl From<RequestError> for SubRequestError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl fmt::Display for SubRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alloc => f.write_str("subrequest allocation failed"),
            Self::Create(status) => write!(f, "subrequest creation failed with status {status}"),
            Self::Request(error) => write!(f, "invalid request: {error:?}"),
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
pub struct SubRequestBuilder<'request, 'callback, H = DefaultSubRequestHandler> {
    request: &'request mut RequestRefMut<'callback>,
    uri: ngx_str_t,
    args: Option<ngx_str_t>,
    flags: ngx_uint_t,
    keep_body: bool,
    headers_in_capacity: ngx_uint_t,
    handler: Option<H>,
}

impl<'request, 'callback> SubRequestBuilder<'request, 'callback> {
    /// Create a builder for `uri`.
    pub fn new(
        request: &'request mut RequestRefMut<'callback>,
        uri: &str,
    ) -> Result<Self, SubRequestError> {
        let uri = unsafe { ngx_str_t::from_bytes(request.pool()?.as_ptr(), uri.as_bytes()) }
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

impl<'request, 'callback, H> SubRequestBuilder<'request, 'callback, H> {
    /// Set the subrequest query string.
    pub fn args(mut self, args: &str) -> Result<Self, SubRequestError> {
        self.args = Some(
            unsafe { ngx_str_t::from_bytes(self.request.pool()?.as_ptr(), args.as_bytes()) }
                .ok_or(SubRequestError::Alloc)?,
        );
        Ok(self)
    }

    /// Run `handler` after nginx finalizes the subrequest.
    pub fn handler<HT, O>(self, handler: HT) -> SubRequestBuilder<'request, 'callback, HT>
    where
        HT: for<'scope> FnOnce(&mut RequestRefMut<'scope>, ngx_int_t) -> O + 'static,
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
    /// A capacity of zero preserves the parent's shallow-copied headers for read-only access.
    pub fn init_headers_in(mut self, capacity: ngx_uint_t) -> Self {
        self.headers_in_capacity = capacity;
        self
    }

    /// Create and schedule the subrequest.
    ///
    /// The returned request can be modified until the current nginx handler returns.
    pub fn build<O>(mut self) -> Result<RequestRefMut<'request>, SubRequestError>
    where
        H: for<'scope> FnOnce(&mut RequestRefMut<'scope>, ngx_int_t) -> O + 'static,
        O: IntoHandlerStatus,
    {
        let pool = self.request.pool()?;
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

        let mut handler = self
            .handler
            .take()
            .map(|handler| pool.allocate_with_cleanup(|| Some(handler)))
            .transpose()?;
        let post = if let Some(handler_value) = handler.as_ref() {
            let handler_data = handler_value.as_non_null().as_ptr().cast();
            let post: *mut ngx_http_post_subrequest_t =
                pool.alloc(mem::size_of::<ngx_http_post_subrequest_t>()).cast();
            if post.is_null() {
                if let Some(handler) = handler.take() {
                    let removed = handler.remove();
                    debug_assert!(removed);
                }
                return Err(SubRequestError::Alloc);
            }
            unsafe {
                post.write(ngx_http_post_subrequest_t {
                    handler: Some(run_handler::<H, O>),
                    data: handler_data,
                });
            }
            post
        } else {
            ptr::null_mut()
        };

        let args = self.args.as_mut().map_or(ptr::null_mut(), ptr::from_mut);
        let request = unsafe { self.request.as_ptr() };
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
        if crate::core::Status(status).into_result().is_err() {
            if let Some(handler) = handler.take() {
                let removed = handler.remove();
                debug_assert!(removed);
            }
            return Err(SubRequestError::Create(status));
        }
        if let Some(handler) = handler {
            let _ = handler.into_non_null();
        }

        let mut subrequest = unsafe { RequestRefMut::from_raw(subrequest) }?;
        if !self.keep_body {
            unsafe { (*subrequest.as_ptr()).request_body = request_body };
        }
        if let Some(headers) = headers_in {
            subrequest.reset_headers_in(headers);
        } else {
            // Native shallow copy leaves a one-part list's tail pointing at the parent's inline part.
            subrequest.repair_headers_in_last();
        }
        Ok(subrequest)
    }
}

#[cfg(feature = "async")]
impl<'request> SubRequestBuilder<'request, '_> {
    /// Create a subrequest and return a future for its owned completion value.
    ///
    /// The completion handler runs with temporary access to the subrequest. Its first return value
    /// is moved into the future, while the second is returned to nginx as the post-subrequest
    /// handler status. The returned request can be modified until the current nginx handler
    /// returns.
    pub fn build_async<T, H, O>(
        self,
        handler: H,
    ) -> Result<(SubRequestFuture<T>, RequestRefMut<'request>), SubRequestError>
    where
        T: 'static,
        H: for<'scope> FnOnce(&mut RequestRefMut<'scope>, ngx_int_t) -> (T, O) + 'static,
        O: IntoHandlerStatus,
    {
        let state = Rc::new(RefCell::new(AsyncSubRequestState::new()));
        let future = SubRequestFuture { state: Rc::clone(&state) };
        let guard = AsyncSubRequestGuard { state, active: true };
        let subrequest = self
            .handler(move |request, status| {
                if !guard.accepts_completion() {
                    return nginx_sys::NGX_OK as ngx_int_t;
                }
                let (output, handler_status) = handler(request, status);
                let handler_status = handler_status.into_handler_status(&request.view());
                guard.finish(output);
                handler_status
            })
            .build()?;

        Ok((future, subrequest))
    }
}

/// Future returned by [`SubRequestBuilder::build_async`].
///
/// Dropping the future cancels delivery and suppresses its completion handler if nginx invokes the
/// native post-subrequest callback later.
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
impl<T> Drop for SubRequestFuture<T> {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        if state.consumed {
            return;
        }
        state.canceled = true;
        state.output.take();
        state.waker.take();
    }
}

#[cfg(feature = "async")]
struct AsyncSubRequestState<T> {
    output: Option<Result<T, SubRequestError>>,
    waker: Option<Waker>,
    consumed: bool,
    canceled: bool,
}

#[cfg(feature = "async")]
impl<T> AsyncSubRequestState<T> {
    fn new() -> Self {
        Self { output: None, waker: None, consumed: false, canceled: false }
    }

    fn complete(&mut self, output: Result<T, SubRequestError>) -> Option<Waker> {
        if self.canceled || self.consumed || self.output.is_some() {
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
    fn accepts_completion(&self) -> bool {
        !self.state.borrow().canceled
    }

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
    H: for<'scope> FnOnce(&mut RequestRefMut<'scope>, ngx_int_t) -> O + 'static,
    O: IntoHandlerStatus,
{
    let Some(mut handler) = NonNull::new(data.cast::<Option<H>>()) else {
        return nginx_sys::NGX_ERROR as _;
    };
    if !handler.as_ptr().is_aligned() {
        return nginx_sys::NGX_ERROR as _;
    }

    let handler = unsafe { handler.as_mut() }.take();
    let callback = |request: &mut RequestRefMut<'_>| {
        ngx_log_debug_http!(request, "subrequest handler called with status {status}");
        handler
            .map_or(status, |handler| handler(request, status).into_handler_status(&request.view()))
    };
    unsafe { request_callback_status(request, callback) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    use alloc::boxed::Box;
    #[cfg(feature = "test-link")]
    use alloc::rc::Rc;
    #[cfg(feature = "test-link")]
    use core::cell::Cell;
    #[cfg(feature = "test-link")]
    use nginx_sys::{
        NGX_HTTP_MODULE, ngx_connection_t, ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_uint_t,
    };
    #[cfg(all(feature = "test-link", nginx1_29_8))]
    use nginx_sys::{
        ngx_http_conf_ctx_t, ngx_http_core_loc_conf_t, ngx_http_core_main_conf_t,
        ngx_http_core_srv_conf_t,
    };
    #[cfg(all(feature = "test-link", nginx1_29_8))]
    use std::sync::MutexGuard;

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    struct TestGlobals {
        _guard: MutexGuard<'static, ()>,
        http_max_module: ngx_uint_t,
        core_context_index: ngx_uint_t,
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    impl TestGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let (http_max_module, core_context_index) = unsafe {
                let core = &raw const nginx_sys::ngx_http_core_module;
                (nginx_sys::ngx_http_max_module, (*core).ctx_index)
            };
            unsafe {
                nginx_sys::ngx_http_max_module = 1;
                let core = &raw mut nginx_sys::ngx_http_core_module;
                (*core).ctx_index = 0;
            }
            Self { _guard: guard, http_max_module, core_context_index }
        }
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    impl Drop for TestGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_http_max_module = self.http_max_module;
                let core = &raw mut nginx_sys::ngx_http_core_module;
                (*core).ctx_index = self.core_context_index;
            }
        }
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    struct NativeSubRequestFixture {
        _globals: TestGlobals,
        pool: *mut nginx_sys::ngx_pool_t,
        _log: Box<ngx_log_t>,
        _connection: Box<ngx_connection_t>,
        _core_loc: Box<ngx_http_core_loc_conf_t>,
        _loc_conf: Box<[*mut c_void; 1]>,
        _main_conf: Box<ngx_http_core_main_conf_t>,
        _main_conf_slots: Box<[*mut c_void; 1]>,
        _http_context: Box<ngx_http_conf_ctx_t>,
        _server: Box<ngx_http_core_srv_conf_t>,
        _server_slots: Box<[*mut c_void; 1]>,
        request: Box<ngx_http_request_t>,
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    impl NativeSubRequestFixture {
        fn new() -> Self {
            let globals = TestGlobals::new();
            let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
            let pool = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!pool.is_null());
            let mut connection = Box::new(unsafe { mem::zeroed::<ngx_connection_t>() });
            connection.log = &raw mut *log;
            connection.fd = -1;
            let mut core_loc = Box::new(unsafe { mem::zeroed::<ngx_http_core_loc_conf_t>() });
            let mut loc_conf = Box::new([(&raw mut *core_loc).cast::<c_void>()]);
            let mut main_conf = Box::new(unsafe { mem::zeroed::<ngx_http_core_main_conf_t>() });
            let mut main_conf_slots = Box::new([(&raw mut *main_conf).cast::<c_void>()]);
            let mut http_context = Box::new(ngx_http_conf_ctx_t {
                main_conf: main_conf_slots.as_mut_ptr(),
                srv_conf: ptr::null_mut(),
                loc_conf: loc_conf.as_mut_ptr(),
            });
            let mut server = Box::new(unsafe { mem::zeroed::<ngx_http_core_srv_conf_t>() });
            server.ctx = &raw mut *http_context;
            let mut server_slots = Box::new([(&raw mut *server).cast::<c_void>()]);
            http_context.srv_conf = server_slots.as_mut_ptr();
            let mut request = Box::new(unsafe { mem::zeroed::<ngx_http_request_t>() });
            request.signature = NGX_HTTP_MODULE as _;
            request.main = &raw mut *request;
            request.parent = &raw mut *request;
            request.pool = pool;
            request.connection = &raw mut *connection;
            request.main_conf = main_conf_slots.as_mut_ptr();
            request.srv_conf = server_slots.as_mut_ptr();
            request.loc_conf = loc_conf.as_mut_ptr();
            request.set_count(1);
            request.set_subrequests(2);
            connection.data = (&raw mut *request).cast();

            Self {
                _globals: globals,
                pool,
                _log: log,
                _connection: connection,
                _core_loc: core_loc,
                _loc_conf: loc_conf,
                _main_conf: main_conf,
                _main_conf_slots: main_conf_slots,
                _http_context: http_context,
                _server: server,
                _server_slots: server_slots,
                request,
            }
        }

        fn borrow(&mut self) -> RequestRefMut<'_> {
            unsafe { RequestRefMut::from_raw(&raw mut *self.request).unwrap() }
        }
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    impl Drop for NativeSubRequestFixture {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.pool) };
        }
    }

    #[cfg(feature = "test-link")]
    struct DropCounter(Rc<Cell<usize>>);

    #[cfg(feature = "test-link")]
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn rejected_creation_drops_handler_before_parent_pool_cleanup() {
        let mut log = unsafe { mem::zeroed::<ngx_log_t>() };
        let pool = unsafe { ngx_create_pool(4096, &raw mut log) };
        assert!(!pool.is_null());
        let mut connection = unsafe { mem::zeroed::<ngx_connection_t>() };
        connection.log = &raw mut log;
        let mut raw = unsafe { mem::zeroed::<ngx_http_request_t>() };
        raw.signature = NGX_HTTP_MODULE as _;
        raw.main = &raw mut raw;
        raw.pool = pool;
        raw.connection = &raw mut connection;
        raw.set_count(1);
        raw.set_subrequests(0);

        let drops = Rc::new(Cell::new(0));
        {
            let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };
            let captured = DropCounter(Rc::clone(&drops));
            let result = SubRequestBuilder::new(&mut request, "/child")
                .unwrap()
                .handler(move |_, _| {
                    drop(captured);
                    crate::core::Status::NGX_OK
                })
                .build();

            assert!(
                matches!(result, Err(SubRequestError::Create(status)) if status == nginx_sys::NGX_ERROR as _)
            );
            assert_eq!(drops.get(), 1);
        }
        unsafe { ngx_destroy_pool(pool) };
        assert_eq!(drops.get(), 1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn post_handler_allocation_failure_drops_transferred_handler_once() {
        let mut log = unsafe { mem::zeroed::<ngx_log_t>() };
        let pool = unsafe { ngx_create_pool(4096, &raw mut log) };
        assert!(!pool.is_null());
        let mut connection = unsafe { mem::zeroed::<ngx_connection_t>() };
        connection.log = &raw mut log;
        let mut raw = unsafe { mem::zeroed::<ngx_http_request_t>() };
        raw.signature = NGX_HTTP_MODULE as _;
        raw.main = &raw mut raw;
        raw.pool = pool;
        raw.connection = &raw mut connection;
        raw.set_count(1);
        raw.set_subrequests(1);

        let drops = Rc::new(Cell::new(0));
        let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };
        let builder =
            SubRequestBuilder::new(&mut request, "/child").unwrap().keep_body().init_headers_in(0);
        let captured = DropCounter(Rc::clone(&drops));
        let handler = move |_: &mut RequestRefMut<'_>, _| {
            drop(captured);
            crate::core::Status::NGX_OK
        };
        fn option_size<T>(_: &T) -> usize {
            mem::size_of::<Option<T>>()
        }

        let align = mem::align_of::<usize>();
        let aligned = |size: usize| (size + align - 1) & !(align - 1);
        let required = aligned(mem::size_of::<nginx_sys::ngx_pool_cleanup_t>())
            + aligned(option_size(&handler));
        unsafe {
            assert!(((*pool).d.end as usize - (*pool).d.last as usize) >= required);
            (*pool).d.last = (*pool).d.end.sub(required);
            ngx_rs_test_fail_allocations_after(0);
        }
        let result = builder.handler(handler).build();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert!(matches!(result, Err(SubRequestError::Alloc)));
        assert_eq!(drops.get(), 1);
        unsafe { ngx_destroy_pool(pool) };
        assert_eq!(drops.get(), 1);
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    #[test]
    fn inherited_headers_are_readable_for_one_and_multiple_parts() {
        for capacity in [2, 1] {
            let mut fixture = NativeSubRequestFixture::new();
            {
                let mut request = fixture.borrow();
                let mut headers = unsafe { request.headers_in_builder(capacity) }.unwrap();
                headers.add(b"Host", b"parent.test").unwrap();
                headers.add(b"X-Second", b"two").unwrap();
                headers.commit();
            }
            let parent = &raw mut *fixture.request;
            let original = unsafe {
                (
                    (*parent).headers_in.headers.part.elts,
                    (*parent).headers_in.headers.part.nelts,
                    (*parent).headers_in.headers.part.next,
                    (*parent).headers_in.headers.last,
                    (*parent).headers_in.count,
                    (*parent).headers_in.host,
                )
            };
            assert_eq!(original.2.is_null(), capacity == 2);

            let mut request = fixture.borrow();
            let child = SubRequestBuilder::new(&mut request, "/child")
                .unwrap()
                .keep_body()
                .init_headers_in(0)
                .background()
                .build()
                .unwrap();
            let child_raw = unsafe { child.as_ptr() };
            assert_eq!(unsafe { (*child_raw).headers_in.count }, original.4);
            assert_eq!(unsafe { (*child_raw).headers_in.host }, original.5);
            if capacity == 2 {
                assert_eq!(unsafe { (*child_raw).headers_in.headers.last }, unsafe {
                    &raw mut (*child_raw).headers_in.headers.part
                });
            } else {
                assert_eq!(unsafe { (*child_raw).headers_in.headers.last }, original.3);
            }
            {
                let headers = child.headers_in().unwrap();
                let mut headers = headers.iter();
                let host = headers.next().unwrap();
                assert_eq!(host.key(), b"Host");
                assert_eq!(host.value(), b"parent.test");
                let second = headers.next().unwrap();
                assert_eq!(second.key(), b"X-Second");
                assert_eq!(second.value(), b"two");
                assert!(headers.next().is_none());
            }
            child.finalize(crate::core::Status::NGX_OK).unwrap();

            assert_eq!(fixture.request.count(), 1);
            assert_eq!(
                (
                    fixture.request.headers_in.headers.part.elts,
                    fixture.request.headers_in.headers.part.nelts,
                    fixture.request.headers_in.headers.part.next,
                    fixture.request.headers_in.headers.last,
                    fixture.request.headers_in.count,
                    fixture.request.headers_in.host,
                ),
                original
            );
        }
    }

    #[cfg(all(feature = "test-link", nginx1_29_8))]
    #[test]
    fn inherited_header_creation_failures_do_not_change_the_parent() {
        let mut reached_success = false;

        for successes in 0..8 {
            let mut fixture = NativeSubRequestFixture::new();
            {
                let mut request = fixture.borrow();
                let mut headers = unsafe { request.headers_in_builder(1) }.unwrap();
                headers.add(b"Host", b"parent.test").unwrap();
                headers.add(b"X-Second", b"two").unwrap();
                headers.commit();
            }
            let original = (
                fixture.request.headers_in.headers.part.elts,
                fixture.request.headers_in.headers.part.nelts,
                fixture.request.headers_in.headers.part.next,
                fixture.request.headers_in.headers.last,
                fixture.request.headers_in.count,
                fixture.request.headers_in.host,
            );
            let original_native_owners = (
                fixture.request.posted_requests,
                fixture.request.postponed,
                fixture._connection.data,
            );
            let pool = fixture.pool;
            let mut request = fixture.borrow();
            let builder = SubRequestBuilder::new(&mut request, "/child").unwrap();
            unsafe {
                (*pool).d.last = (*pool).d.end;
                (*pool).max = 0;
                ngx_rs_test_fail_allocations_after(successes);
            }
            let result = builder.keep_body().init_headers_in(0).background().build();
            unsafe { ngx_rs_test_reset_allocation_failures() };

            match result {
                Ok(child) => {
                    assert_eq!(child.headers_in().unwrap().len(), 2);
                    child.finalize(crate::core::Status::NGX_OK).unwrap();
                    reached_success = true;
                }
                Err(error) => {
                    assert!(matches!(
                        error,
                        SubRequestError::Create(status)
                            if status == nginx_sys::NGX_ERROR as ngx_int_t
                    ));
                    assert_eq!(
                        (
                            fixture.request.posted_requests,
                            fixture.request.postponed,
                            fixture._connection.data,
                        ),
                        original_native_owners
                    );
                }
            }
            assert_eq!(fixture.request.count(), 1);
            assert_eq!(
                (
                    fixture.request.headers_in.headers.part.elts,
                    fixture.request.headers_in.headers.part.nelts,
                    fixture.request.headers_in.headers.part.next,
                    fixture.request.headers_in.headers.last,
                    fixture.request.headers_in.count,
                    fixture.request.headers_in.host,
                ),
                original
            );
            if reached_success {
                break;
            }
        }

        assert!(reached_success);
    }

    #[cfg(feature = "async")]
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
