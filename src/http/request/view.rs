use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use core::slice;

use crate::core::*;
use crate::ffi::*;
use crate::http::status::*;
use crate::http::{
    HttpConfigError, HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf,
    UpstreamStateError, UpstreamStates, conf,
};
use crate::log::LogRef;

use super::headers::HeaderListError;

/// Failure returned while creating or using a checked HTTP request view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    /// The request pointer is null.
    NullRequest,
    /// The request pointer does not satisfy `ngx_http_request_t` alignment.
    MisalignedRequest,
    /// The pointed value is not an initialized HTTP request.
    InvalidRequestSignature,
    /// The request does not identify a main request.
    MissingMain,
    /// The main request pointer does not satisfy `ngx_http_request_t` alignment.
    MisalignedMain,
    /// The main request does not have a valid HTTP request signature.
    InvalidMainSignature,
    /// The main request is not the root of this request's parent chain.
    ForeignMain,
    /// The request has no pool.
    MissingPool,
    /// The native main-request reference count cannot retain another lifecycle owner.
    ReferenceCountOverflow,
    /// The request pool pointer does not satisfy `ngx_pool_t` alignment.
    MisalignedPool,
    /// An output chain belongs to a different nginx pool.
    ForeignPool,
    /// The client connection is invalid.
    Connection(ConnectionError),
    /// A native request string has a nonzero length but no data pointer.
    MissingStringData,
    /// A native request timestamp cannot be represented as an unsigned value.
    NegativeStartTime,
    /// A native request counter cannot be represented as an unsigned value.
    NegativeCounter,
    /// A response content length cannot be represented by nginx's `off_t`.
    ContentLengthTooLarge,
    /// Content-Length and Transfer-Encoding are owned by nginx's output framing filters.
    ManagedOutputFraming,
    /// The output-header list is not safe to update.
    InvalidHeaderList(HeaderListError),
    /// Nginx could not allocate request-pool storage.
    Allocation,
}

impl From<ConnectionError> for RequestError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

pub(super) fn checked_request_ptr(
    request: *mut ngx_http_request_t,
) -> Result<NonNull<ngx_http_request_t>, RequestError> {
    let request = NonNull::new(request).ok_or(RequestError::NullRequest)?;
    if !request.as_ptr().is_aligned() {
        return Err(RequestError::MisalignedRequest);
    }
    if unsafe { request.as_ref().signature } != NGX_HTTP_MODULE {
        return Err(RequestError::InvalidRequestSignature);
    }

    Ok(request)
}

pub(super) unsafe fn checked_ngx_str<'a>(value: ngx_str_t) -> Result<&'a NgxStr, RequestError> {
    if value.len == 0 {
        return Ok(NgxStr::from_bytes(&[]));
    }

    let data = NonNull::new(value.data).ok_or(RequestError::MissingStringData)?;
    let bytes = unsafe { slice::from_raw_parts(data.as_ptr(), value.len) };
    Ok(NgxStr::from_bytes(bytes))
}

const MAX_SUBREQUEST_PARENT_EDGES: usize = NGX_HTTP_MAX_SUBREQUESTS as usize + 1;
/// Highest main-request count a Rust hold may publish; nginx reserves the remaining 1,000.
pub(super) const MAX_REQUEST_COUNT_AFTER_HOLD: u32 = u16::MAX as u32 - 1000;

/// Shared callback-scoped access to an nginx HTTP request.
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRef;
///
/// unsafe fn escape(raw: *const ngx_http_request_t) -> RequestRef<'static> {
///     unsafe { RequestRef::with_raw(raw, |request| request) }.unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRef;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *const ngx_http_request_t) {
///     let _ = unsafe { RequestRef::with_raw(raw, |request| require_send(request)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRef;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// unsafe fn reject(raw: *const ngx_http_request_t) {
///     let _ = unsafe { RequestRef::with_raw(raw, |request| require_sync(&request)) };
/// }
/// ```
#[derive(Clone, Copy)]
pub struct RequestRef<'callback> {
    pub(super) raw: NonNull<ngx_http_request_t>,
    pub(super) _callback: PhantomData<&'callback ngx_http_request_t>,
    pub(super) _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> RequestRef<'callback> {
    /// Creates a checked shared request view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `request` must point to a live initialized nginx request for `'callback`. Neither its
    /// request pool nor its client connection pool may be reset before that pool is destroyed.
    /// Nginx must not mutate the request while this shared view exists, and the view must remain on
    /// its owning event-loop thread.
    pub unsafe fn from_raw(request: *const ngx_http_request_t) -> Result<Self, RequestError> {
        let raw = checked_request_ptr(request.cast_mut())?;
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with a request view that cannot escape the nginx callback through a safe
    /// value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    pub unsafe fn with_raw<R>(
        request: *const ngx_http_request_t,
        f: impl for<'scope> FnOnce(RequestRef<'scope>) -> R,
    ) -> Result<R, RequestError> {
        let request = unsafe { Self::from_raw(request) }?;
        Ok(f(request))
    }

    /// Returns the native request pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the target nginx API's aliasing and callback-lifetime requirements.
    pub unsafe fn as_ptr(&self) -> *const ngx_http_request_t {
        self.raw.as_ptr()
    }

    /// Shared main configuration for module `M`.
    pub fn main_conf<M>(&self) -> Result<Option<&M::MainConf>, HttpConfigError>
    where
        M: HttpModuleMainConf,
    {
        Ok(conf::request_main_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Shared server configuration for module `M`.
    pub fn server_conf<M>(&self) -> Result<Option<&M::ServerConf>, HttpConfigError>
    where
        M: HttpModuleServerConf,
    {
        Ok(conf::request_server_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Shared location configuration for module `M`.
    pub fn location_conf<M>(&self) -> Result<Option<&M::LocationConf>, HttpConfigError>
    where
        M: HttpModuleLocationConf,
    {
        Ok(conf::request_location_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    pub(super) fn main_raw(&self) -> Result<NonNull<ngx_http_request_t>, RequestError> {
        let main =
            NonNull::new(unsafe { self.raw.as_ref().main }).ok_or(RequestError::MissingMain)?;
        if !main.as_ptr().is_aligned() {
            return Err(RequestError::MisalignedMain);
        }
        if unsafe { main.as_ref().signature } != NGX_HTTP_MODULE {
            return Err(RequestError::InvalidMainSignature);
        }
        if !ptr::eq(unsafe { main.as_ref().main }, main.as_ptr()) {
            return Err(RequestError::ForeignMain);
        }
        if ptr::eq(main.as_ptr(), self.raw.as_ptr()) {
            return Ok(main);
        }

        let mut request = self.raw;
        for _ in 0..MAX_SUBREQUEST_PARENT_EDGES {
            let parent = NonNull::new(unsafe { request.as_ref().parent })
                .ok_or(RequestError::ForeignMain)?;
            if !parent.as_ptr().is_aligned()
                || unsafe { parent.as_ref().signature } != NGX_HTTP_MODULE
                || !ptr::eq(unsafe { parent.as_ref().main }, main.as_ptr())
            {
                return Err(RequestError::ForeignMain);
            }
            if ptr::eq(parent.as_ptr(), request.as_ptr()) {
                return Err(RequestError::ForeignMain);
            }
            if ptr::eq(parent.as_ptr(), main.as_ptr()) {
                return Ok(main);
            }
            request = parent;
        }

        Err(RequestError::ForeignMain)
    }

    /// Returns whether this is the main request.
    pub fn is_main(&self) -> Result<bool, RequestError> {
        Ok(ptr::eq(self.main_raw()?.as_ptr(), self.raw.as_ptr()))
    }

    /// Whether nginx marked this request as internal.
    pub fn is_internal(&self) -> bool {
        unsafe { ngx_rs_http_request_is_internal(self.raw.as_ptr()) != 0 }
    }

    /// Number of additional nested subrequests nginx permits from this request.
    pub fn subrequests_available(&self) -> u32 {
        unsafe { self.raw.as_ref().subrequests() }
    }

    /// Shared access to the root main request.
    pub fn main(&self) -> Result<RequestRef<'_>, RequestError> {
        Ok(RequestRef {
            raw: self.main_raw()?,
            _callback: PhantomData,
            _not_thread_safe: PhantomData,
        })
    }

    /// Request pool.
    pub fn pool(&self) -> Result<Pool<'_>, RequestError> {
        let pool = unsafe { self.raw.as_ref().pool };
        if pool.is_null() {
            return Err(RequestError::MissingPool);
        }
        unsafe { Pool::from_raw(pool) }.ok_or(RequestError::MisalignedPool)
    }

    /// Client connection associated with this request.
    pub fn connection(&self) -> Result<ConnectionRef<'_>, RequestError> {
        unsafe { ConnectionRef::from_raw(self.raw.as_ref().connection) }.map_err(Into::into)
    }

    /// Logger associated with the client connection, when nginx configured one.
    ///
    /// ```compile_fail
    /// use ngx::ffi::ngx_http_request_t;
    /// use ngx::http::RequestRef;
    /// use ngx::log::LogRef;
    ///
    /// unsafe fn escape(raw: *const ngx_http_request_t) -> LogRef<'static> {
    ///     unsafe { RequestRef::with_raw(raw, |request| request.log().unwrap().unwrap()) }.unwrap()
    /// }
    /// ```
    pub fn log(&self) -> Result<Option<LogRef<'callback>>, RequestError> {
        let connection =
            unsafe { ConnectionRef::<'callback>::from_raw(self.raw.as_ref().connection) }
                .map_err(RequestError::from)?;
        connection.log().map_err(Into::into)
    }

    /// Seconds since the Unix epoch when nginx created the request.
    pub fn start_sec(&self) -> Result<u64, RequestError> {
        u64::try_from(unsafe { self.raw.as_ref().start_sec })
            .map_err(|_| RequestError::NegativeStartTime)
    }

    /// Millisecond component of the request creation time.
    pub fn start_msec(&self) -> u64 {
        unsafe { self.raw.as_ref().start_msec as u64 }
    }

    /// Bytes received for the request line, headers, and body parsed so far.
    pub fn request_length(&self) -> Result<u64, RequestError> {
        u64::try_from(unsafe { self.raw.as_ref().request_length })
            .map_err(|_| RequestError::NegativeCounter)
    }

    /// Current value of the client connection's sent-byte counter.
    pub fn bytes_sent(&self) -> Result<u64, RequestError> {
        self.connection()?.bytes_sent().map_err(Into::into)
    }

    /// HTTP response status set by nginx.
    ///
    /// Returns `None` while the status is unset or outside the valid HTTP range.
    pub fn status(&self) -> Option<HTTPStatus> {
        HTTPStatus::try_from(unsafe { self.raw.as_ref().headers_out.status }).ok()
    }

    /// Path part of the request URI.
    pub fn path(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().uri) }
    }

    /// Full request URI including query arguments.
    pub fn unparsed_uri(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().unparsed_uri) }
    }

    /// Whether nginx marked the response as header-only.
    pub fn header_only(&self) -> bool {
        unsafe { ngx_rs_http_request_header_only(self.raw.as_ptr()) != 0 }
    }

    /// Whether nginx may reuse the client connection after this response.
    pub fn keepalive(&self) -> bool {
        unsafe { ngx_rs_http_request_keepalive(self.raw.as_ptr()) != 0 }
    }

    /// Whether nginx expects output trailers for this response.
    pub fn expect_trailers(&self) -> bool {
        unsafe { ngx_rs_http_request_expect_trailers(self.raw.as_ptr()) != 0 }
    }

    /// Returns checked upstream connection attempts recorded for this request.
    pub fn upstream_states(&self) -> Result<Option<UpstreamStates<'_>>, UpstreamStateError> {
        unsafe { UpstreamStates::from_raw(self.raw.as_ref().upstream_states) }
    }

    /// Returns the active upstream pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the upstream object's aliasing and request-lifetime requirements.
    pub unsafe fn upstream(&self) -> Option<NonNull<ngx_http_upstream_t>> {
        NonNull::new(unsafe { self.raw.as_ref().upstream })
    }
}

impl fmt::Debug for RequestRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestRef").field("raw", &self.raw).finish()
    }
}

/// Exclusive callback-scoped access to an nginx HTTP request.
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRefMut;
///
/// unsafe fn escape(raw: *mut ngx_http_request_t) -> RequestRefMut<'static> {
///     unsafe { RequestRefMut::with_raw(raw, |request| request) }.unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRefMut;
///
/// fn aliases(mut request: RequestRefMut<'_>) {
///     let main = request.main_mut().unwrap();
///     let _another = request.main_mut().unwrap();
///     drop(main);
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRefMut;
///
/// fn retain_in_future(raw: *mut ngx_http_request_t) {
///     let _future = unsafe {
///         RequestRefMut::with_raw(raw, |request| async move {
///             let _request = request;
///         })
///     };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRefMut;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *mut ngx_http_request_t) {
///     let _ = unsafe { RequestRefMut::with_raw(raw, |request| require_send(request)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_request_t;
/// use ngx::http::RequestRefMut;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// unsafe fn reject(raw: *mut ngx_http_request_t) {
///     let _ = unsafe { RequestRefMut::with_raw(raw, |request| require_sync(&request)) };
/// }
/// ```
///
/// Raw nginx complex-value descriptors contain unchecked script pointers and are not accepted by
/// the safe request API.
///
/// ```compile_fail
/// use ngx::ffi::ngx_http_complex_value_t;
/// use ngx::http::RequestRefMut;
///
/// fn reject_raw_complex_value(
///     request: &mut RequestRefMut<'_>,
///     value: &ngx_http_complex_value_t,
/// ) {
///     let _ = request.get_complex_value(value);
/// }
/// ```
pub struct RequestRefMut<'callback> {
    pub(super) raw: NonNull<ngx_http_request_t>,
    pub(super) _callback: PhantomData<&'callback mut ngx_http_request_t>,
    pub(super) _not_thread_safe: PhantomData<*mut ()>,
}

/// Exclusive access to a main request's module context without terminal request authority.
pub struct MainRequestRefMut<'callback> {
    pub(super) request: RequestRefMut<'callback>,
}

impl<'callback> RequestRefMut<'callback> {
    /// Creates a checked exclusive request view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `request` must point to a live initialized nginx request for `'callback`. Neither its
    /// request pool nor its client connection pool may be reset before that pool is destroyed.
    /// Nginx must make the request exclusively available for that lifetime, and the view must
    /// remain on its owning event-loop thread.
    pub unsafe fn from_raw(request: *mut ngx_http_request_t) -> Result<Self, RequestError> {
        let raw = checked_request_ptr(request)?;
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with a request view that cannot escape the nginx callback through a safe
    /// value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    pub unsafe fn with_raw<R>(
        request: *mut ngx_http_request_t,
        f: impl for<'scope> FnOnce(RequestRefMut<'scope>) -> R,
    ) -> Result<R, RequestError> {
        let request = unsafe { Self::from_raw(request) }?;
        Ok(f(request))
    }

    /// Returns a shared reborrow of this request.
    pub fn view(&self) -> RequestRef<'_> {
        RequestRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
    }

    /// Shared main configuration for module `M`.
    pub fn main_conf<M>(&self) -> Result<Option<&'callback M::MainConf>, HttpConfigError>
    where
        M: HttpModuleMainConf,
    {
        Ok(conf::request_main_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Shared server configuration for module `M`.
    pub fn server_conf<M>(&self) -> Result<Option<&'callback M::ServerConf>, HttpConfigError>
    where
        M: HttpModuleServerConf,
    {
        Ok(conf::request_server_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Shared location configuration for module `M`.
    ///
    /// ```compile_fail
    /// # use ngx::http::{HttpModuleLocationConf, RequestRefMut};
    /// # fn mutable<M: HttpModuleLocationConf>(request: &mut RequestRefMut<'_>) {
    /// let _ = request.location_conf_mut::<M>();
    /// # }
    /// ```
    pub fn location_conf<M>(&self) -> Result<Option<&'callback M::LocationConf>, HttpConfigError>
    where
        M: HttpModuleLocationConf,
    {
        Ok(conf::request_location_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Returns whether this is the main request.
    pub fn is_main(&self) -> Result<bool, RequestError> {
        self.view().is_main()
    }

    /// Whether nginx marked this request as internal.
    pub fn is_internal(&self) -> bool {
        self.view().is_internal()
    }

    /// Number of additional nested subrequests nginx permits from this request.
    pub fn subrequests_available(&self) -> u32 {
        self.view().subrequests_available()
    }

    /// Shared access to the root main request.
    pub fn main(&self) -> Result<RequestRef<'_>, RequestError> {
        let raw =
            RequestRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
                .main_raw()?;
        Ok(RequestRef { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Request pool.
    ///
    /// ```compile_fail
    /// use ngx::http::{HTTPStatus, RequestRefMut};
    ///
    /// fn finalize_then_allocate(request: RequestRefMut<'_>) {
    ///     let pool = request.pool().unwrap();
    ///     request.finalize(HTTPStatus::BAD_REQUEST).unwrap();
    ///     pool.allocate_with_cleanup(|| ()).unwrap();
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::http::RequestRefMut;
    ///
    /// fn resume_then_allocate(request: RequestRefMut<'_>) {
    ///     let pool = request.pool().unwrap();
    ///     request.resume_preaccess().unwrap();
    ///     pool.allocate_with_cleanup(|| ()).unwrap();
    /// }
    /// ```
    pub fn pool(&self) -> Result<Pool<'_>, RequestError> {
        let pool = unsafe { self.raw.as_ref().pool };
        if pool.is_null() {
            return Err(RequestError::MissingPool);
        }
        unsafe { Pool::from_raw(pool) }.ok_or(RequestError::MisalignedPool)
    }

    /// Client connection associated with this request.
    pub fn connection(&self) -> Result<ConnectionRef<'_>, RequestError> {
        unsafe { ConnectionRef::from_raw(self.raw.as_ref().connection) }.map_err(Into::into)
    }

    /// Logger associated with the client connection, when nginx configured one.
    pub fn log(&self) -> Result<Option<LogRef<'callback>>, RequestError> {
        let connection =
            unsafe { ConnectionRef::<'callback>::from_raw(self.raw.as_ref().connection) }
                .map_err(RequestError::from)?;
        connection.log().map_err(Into::into)
    }

    /// Seconds since the Unix epoch when nginx created the request.
    pub fn start_sec(&self) -> Result<u64, RequestError> {
        self.view().start_sec()
    }

    /// Millisecond component of the request creation time.
    pub fn start_msec(&self) -> u64 {
        self.view().start_msec()
    }

    /// Bytes received for the request line, headers, and body parsed so far.
    pub fn request_length(&self) -> Result<u64, RequestError> {
        self.view().request_length()
    }

    /// Current value of the client connection's sent-byte counter.
    pub fn bytes_sent(&self) -> Result<u64, RequestError> {
        self.view().bytes_sent()
    }

    /// HTTP response status set by nginx.
    pub fn status(&self) -> Option<HTTPStatus> {
        self.view().status()
    }

    /// Path part of the request URI.
    pub fn path(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().uri) }
    }

    /// Full request URI including query arguments.
    pub fn unparsed_uri(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().unparsed_uri) }
    }

    /// Whether nginx marked the response as header-only.
    pub fn header_only(&self) -> bool {
        self.view().header_only()
    }

    /// Whether nginx may reuse the client connection after this response.
    pub fn keepalive(&self) -> bool {
        self.view().keepalive()
    }

    /// Whether nginx expects output trailers for this response.
    pub fn expect_trailers(&self) -> bool {
        self.view().expect_trailers()
    }

    /// Returns checked upstream connection attempts recorded for this request.
    pub fn upstream_states(&self) -> Result<Option<UpstreamStates<'_>>, UpstreamStateError> {
        unsafe { UpstreamStates::from_raw(self.raw.as_ref().upstream_states) }
    }

    /// Returns the active upstream pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the upstream object's aliasing and request-lifetime requirements.
    pub unsafe fn upstream(&self) -> Option<NonNull<ngx_http_upstream_t>> {
        unsafe { self.view().upstream() }
    }

    /// Returns the native request pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the target nginx API's aliasing and callback-lifetime requirements.
    pub unsafe fn as_ptr(&self) -> *mut ngx_http_request_t {
        self.raw.as_ptr()
    }

    /// Exclusive reborrow of the root main request without terminal request authority.
    ///
    /// ```compile_fail
    /// use ngx::http::{HTTPStatus, RequestRefMut};
    ///
    /// fn finalize_through_reborrow(request: &mut RequestRefMut<'_>) {
    ///     request.main_mut().unwrap().finalize(HTTPStatus::BAD_REQUEST).unwrap();
    /// }
    /// ```
    pub fn main_mut(&mut self) -> Result<MainRequestRefMut<'_>, RequestError> {
        let raw =
            RequestRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
                .main_raw()?;
        Ok(MainRequestRefMut {
            request: RequestRefMut { raw, _callback: PhantomData, _not_thread_safe: PhantomData },
        })
    }

    /// Consumes this view and returns exclusive access to the root main request.
    pub fn into_main(self) -> Result<Self, RequestError> {
        let raw =
            RequestRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
                .main_raw()?;
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Exclusive access to the client connection associated with this request.
    pub fn connection_mut(&mut self) -> Result<ConnectionRefMut<'_>, RequestError> {
        unsafe { ConnectionRefMut::from_raw(self.raw.as_ref().connection) }.map_err(Into::into)
    }

    /// Sets the HTTP response status.
    pub fn set_status(&mut self, status: HTTPStatus) {
        unsafe { self.raw.as_mut().headers_out.status = status.into() };
    }

    /// Sets whether nginx may reuse the client connection after this response.
    pub fn set_keepalive(&mut self, keepalive: bool) {
        unsafe { ngx_rs_http_request_set_keepalive(self.raw.as_ptr(), keepalive.into()) };
    }

    /// Sets whether nginx must suppress the response body.
    pub fn set_header_only(&mut self, header_only: bool) {
        unsafe { ngx_rs_http_request_set_header_only(self.raw.as_ptr(), header_only.into()) };
    }

    /// Sets whether nginx expects output trailers for this response.
    pub fn set_expect_trailers(&mut self, expect_trailers: bool) {
        unsafe {
            ngx_rs_http_request_set_expect_trailers(self.raw.as_ptr(), expect_trailers.into())
        };
    }

    /// Marks whether nginx has sent the response headers.
    pub fn set_header_sent(&mut self, header_sent: bool) {
        unsafe { ngx_rs_http_request_set_header_sent(self.raw.as_ptr(), header_sent.into()) };
    }

    /// Sends the output header.
    pub fn send_header(&mut self) -> Result<Status, RequestError> {
        self.validate_terminal_operation()?;
        Ok(Status(unsafe { ngx_http_send_header(self.raw.as_ptr()) }))
    }

    /// Transfers a request-pool-owned response chain to nginx's current output filter.
    pub fn output_filter(&mut self, body: PoolChain<'_>) -> Result<Status, RequestError> {
        self.validate_terminal_operation()?;
        let pool = self.pool()?;
        if !body.belongs_to(&pool) {
            return Err(RequestError::ForeignPool);
        }
        Ok(Status(unsafe { ngx_http_output_filter(self.raw.as_ptr(), body.into_raw()) }))
    }
}

impl fmt::Debug for RequestRefMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.view().fmt(f)
    }
}
