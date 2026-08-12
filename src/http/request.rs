use core::convert::Infallible;
use core::error;
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::slice;
use core::str::FromStr;

#[cfg(feature = "std")]
use core::panic::AssertUnwindSafe;
#[cfg(feature = "std")]
use std::panic::catch_unwind;

use crate::collections::{NgxList, list::NgxListIter};
use crate::core::*;
#[cfg(feature = "async")]
use crate::event::PostedQueue;
use crate::ffi::*;
use crate::http::status::*;
use crate::http::{
    HttpConfigError, HttpFilter, HttpFilterError, HttpFilterSlot, HttpModuleLocationConf,
    HttpModuleRequestContext, HttpPhase, NgxHttpCoreModule, UpstreamStateError, UpstreamStates,
    conf,
};

/// Define a static request handler.
///
/// Handlers are expected to take a single [`RequestRefMut`] argument and return a [`Status`].
#[macro_export]
macro_rules! http_request_handler {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
        ) -> $crate::ffi::ngx_int_t {
            let handler: for<'scope> fn(&mut $crate::http::RequestRefMut<'scope>) -> _ = $handler;
            unsafe { $crate::http::request_callback_status(r, |request| handler(request)) }
        }
    };
}

/// Define a static post subrequest handler.
///
/// Handlers are expected to take a single [`RequestRefMut`] argument and return a [`Status`].
#[macro_export]
macro_rules! http_subrequest_handler {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            data: *mut ::core::ffi::c_void,
            rc: $crate::ffi::ngx_int_t,
        ) -> $crate::ffi::ngx_int_t {
            let handler: for<'scope> fn(
                &mut $crate::http::RequestRefMut<'scope>,
                *mut ::core::ffi::c_void,
                $crate::ffi::ngx_int_t,
            ) -> _ = $handler;
            unsafe {
                $crate::http::request_callback_status(r, |request| handler(request, data, rc))
            }
        }
    };
}

/// Define a static variable setter.
///
/// The set handler allows setting the property referenced by the variable.
/// The set handler expects a [`RequestRefMut`], [`mut ngx_variable_value_t`], and a [`usize`].
/// Variables: <https://nginx.org/en/docs/dev/development_guide.html#http_variables>
#[macro_export]
macro_rules! http_variable_set {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            v: *mut $crate::ffi::ngx_variable_value_t,
            data: usize,
        ) {
            let handler: for<'scope> fn(
                &mut $crate::http::RequestRefMut<'scope>,
                *mut $crate::ffi::ngx_variable_value_t,
                usize,
            ) -> _ = $handler;
            let _ = unsafe {
                $crate::http::request_callback_status(r, |request| {
                    handler(request, v, data);
                    $crate::core::Status::NGX_OK
                })
            };
        }
    };
}

/// Define a static variable evaluator.
///
/// The get handler is responsible for evaluating a variable in the context of a specific request.
/// Variable evaluators accept a [`RequestRefMut`] input argument and two output
/// arguments: [`ngx_variable_value_t`] and [`usize`].
/// Variables: <https://nginx.org/en/docs/dev/development_guide.html#http_variables>
#[macro_export]
macro_rules! http_variable_get {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            v: *mut $crate::ffi::ngx_variable_value_t,
            data: usize,
        ) -> $crate::ffi::ngx_int_t {
            let handler: for<'scope> fn(
                &mut $crate::http::RequestRefMut<'scope>,
                *mut $crate::ffi::ngx_variable_value_t,
                usize,
            ) -> _ = $handler;
            unsafe { $crate::http::request_callback_status(r, |request| handler(request, v, data)) }
        }
    };
}

/// Trait for converting handler return types into `ngx_int_t`.
/// Any desired error handling / logging logic can be implemented
/// in the `into_handler_status` method.
///
/// There are predefined implementations for `ngx_int_t`, [`Status`], [`HTTPStatus`],
/// [`Option`] with a value type implementing [`IntoHandlerStatus`], and [`Result`] with value and
/// error types implementing [`IntoHandlerStatus`].
pub trait IntoHandlerStatus
where
    Self: Sized,
{
    /// Convert the handler return type into an `ngx_int_t`.
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t;
}

impl<T> IntoHandlerStatus for Option<T>
where
    T: IntoHandlerStatus,
{
    #[inline]
    fn into_handler_status(self, r: &RequestRef<'_>) -> ngx_int_t {
        self.map(|val| val.into_handler_status(r)).unwrap_or(NGX_ERROR as _)
    }
}

impl<T, E> IntoHandlerStatus for Result<T, E>
where
    T: IntoHandlerStatus,
    E: IntoHandlerStatus,
{
    #[inline]
    fn into_handler_status(self, r: &RequestRef<'_>) -> ngx_int_t {
        match self {
            Ok(value) => value.into_handler_status(r),
            Err(error) => error.into_handler_status(r),
        }
    }
}

impl IntoHandlerStatus for ngx_int_t {
    #[inline]
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t {
        self
    }
}

impl IntoHandlerStatus for Status {
    #[inline]
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t {
        self.0
    }
}

impl IntoHandlerStatus for HTTPStatus {
    #[inline]
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t {
        self.0 as _
    }
}

/// Trait for static request handler.
pub trait HttpRequestHandler {
    /// The phase in which the handler is invoked.
    const PHASE: HttpPhase;
    /// The return type of the handler.
    type Output: IntoHandlerStatus;
    /// The handler function.
    fn handler(request: &mut RequestRefMut<'_>) -> Self::Output;
    /// Handler name for logging purposes.
    /// [`core::any::type_name`] is used by default.
    fn name() -> &'static str {
        core::any::type_name::<Self>()
    }
}

/// The C-compatible handler wrapper function.
///
/// # Safety
///
/// The caller has provided a valid non-null pointer to an [`ngx_http_request_t`].
pub(crate) unsafe extern "C" fn raw_handler<H>(r: *mut ngx_http_request_t) -> ngx_int_t
where
    H: HttpRequestHandler,
{
    unsafe { request_callback_status(r, |request| H::handler(request)) }
}

unsafe extern "C" fn raw_client_body_handler<H>(request: *mut ngx_http_request_t)
where
    H: HttpClientBodyHandler,
{
    let _ = unsafe {
        request_callback_status(request, |request| {
            if H::is_active(request.view()) {
                H::body_read(request);
            }
            Status::NGX_OK
        })
    };
}

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
    /// The request pool pointer does not satisfy `ngx_pool_t` alignment.
    MisalignedPool,
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
    /// Nginx could not allocate request-pool storage.
    Allocation,
}

impl From<ConnectionError> for RequestError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

/// Failure returned while accessing a module request-context slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestContextError {
    /// The module descriptor does not identify a usable HTTP context slot.
    Configuration(HttpConfigError),
    /// Nginx has not installed the request context-slot array.
    MissingSlots,
    /// The request context-slot array does not satisfy pointer alignment.
    MisalignedSlots,
    /// A non-null module context does not satisfy its Rust type's alignment.
    MisalignedContext,
    /// The request pool cannot be used for a context operation.
    Request(RequestError),
    /// Nginx could not allocate the context and its cleanup entry.
    Allocation,
    /// The context cleanup was missing when removal was requested.
    MissingCleanup,
}

impl From<HttpConfigError> for RequestContextError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<RequestError> for RequestContextError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Failure returned while constructing a request module context.
#[derive(Debug, Eq, PartialEq)]
pub enum RequestContextCreateError<E> {
    /// Request or module context state prevented construction.
    Context(RequestContextError),
    /// The caller's context constructor rejected construction.
    Construction(E),
}

impl<E> From<RequestContextError> for RequestContextCreateError<E> {
    fn from(error: RequestContextError) -> Self {
        Self::Context(error)
    }
}

impl<E> From<RequestError> for RequestContextCreateError<E> {
    fn from(error: RequestError) -> Self {
        Self::Context(error.into())
    }
}

impl<E> From<PoolCleanupError<E>> for RequestContextCreateError<E> {
    fn from(error: PoolCleanupError<E>) -> Self {
        match error {
            PoolCleanupError::Allocation => Self::Context(RequestContextError::Allocation),
            PoolCleanupError::Construction(error) => Self::Construction(error),
        }
    }
}

/// Failure while acquiring or consuming a delayed HTTP request hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestHoldError {
    /// The request could not be used for the operation.
    Request(RequestError),
    /// The context already owns a hold for this request.
    AlreadyHeld,
    /// The context does not own a hold.
    Missing,
    /// The hold belongs to another request.
    ForeignRequest,
    /// The main request no longer has a live reference count.
    InactiveMain,
    /// The 16-bit nginx main-request count cannot be incremented.
    CountOverflow,
}

impl From<RequestError> for RequestHoldError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Failure while using a terminal request continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestContinuationError {
    /// The request could not be used for the operation.
    Request(RequestError),
    /// Calling the saved filter failed.
    Filter(HttpFilterError),
    /// Phase resumption could not prepare a valid nginx request state.
    Phase(RequestPhaseResumeError),
    /// The delayed request hold could not create its terminal continuation.
    Hold(RequestHoldError),
    /// The continuation has already completed or been cancelled.
    Consumed,
    /// The saved header filter has already been called for this continuation.
    HeaderAlreadyContinued,
    /// The saved body filter has already been called for this continuation.
    BodyAlreadyContinued,
}

impl From<RequestError> for RequestContinuationError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<HttpFilterError> for RequestContinuationError {
    fn from(error: HttpFilterError) -> Self {
        Self::Filter(error)
    }
}

impl From<RequestPhaseResumeError> for RequestContinuationError {
    fn from(error: RequestPhaseResumeError) -> Self {
        Self::Phase(error)
    }
}

impl From<RequestHoldError> for RequestContinuationError {
    fn from(error: RequestHoldError) -> Self {
        Self::Hold(error)
    }
}

/// Failure while resuming HTTP phase processing after an asynchronous callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPhaseResumeError {
    /// The request could not be used for the operation.
    Request(RequestError),
    /// The current phase handler index is invalid.
    NegativePhaseHandler,
    /// Advancing the phase handler would overflow nginx's index type.
    PhaseHandlerOverflow,
}

impl From<RequestError> for RequestPhaseResumeError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// One explicit reference retained by a delayed HTTP request context.
///
/// Store this in the pinned request context that owns the delayed operation. Dropping it does not
/// call nginx; cleanup must cancel it explicitly when no terminal continuation can run.
#[must_use = "a request hold must be consumed or cancelled explicitly"]
pub struct RequestHold {
    request: NonNull<ngx_http_request_t>,
    main: NonNull<ngx_http_request_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

/// Exclusive terminal owner for a request hold removed from its context.
///
/// The hold is removed before the owner performs a terminal nginx operation, so reentry cannot
/// resume or finalize the request a second time. This owner takes the callback-scoped request
/// borrow, and terminal operations consume it before nginx may invalidate the request. Dropping
/// this value never invokes nginx.
#[must_use = "a request continuation must complete or cancel its terminal operation explicitly"]
pub struct RequestContinuation<'callback> {
    request: RequestRefMut<'callback>,
    _hold: RequestHold,
    consumed: bool,
    header_continued: bool,
    body_continued: bool,
}

/// Failure returned while validating an nginx HTTP header list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderListError {
    /// The nginx list layout, part bounds, or part chain is invalid.
    InvalidList,
    /// A header key has a nonzero length but no data pointer.
    MissingKeyData,
    /// A header value has a nonzero length but no data pointer.
    MissingValueData,
    /// A header key is too long to create a Rust slice.
    KeyTooLong,
    /// A header value is too long to create a Rust slice.
    ValueTooLong,
}

/// Failure returned while preparing a replacement nginx HTTP header set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderBuildError {
    /// The request could not provide a usable pool.
    Request(RequestError),
    /// The requested initial list capacity is zero or cannot describe a list allocation.
    InvalidCapacity,
    /// Nginx could not allocate request-pool storage.
    Allocation,
    /// The input header count cannot be represented by nginx.
    CountOverflow,
}

impl From<RequestError> for HeaderBuildError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Failure returned while accessing a checked nginx request body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBodyError {
    /// The request-body pointer does not satisfy `ngx_http_request_body_t` alignment.
    MisalignedBody,
    /// The request-body chain is malformed.
    Chain(ChainError),
}

impl From<ChainError> for RequestBodyError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

/// Failure while copying a checked HTTP chain into a request-pool temporary file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestTempFileError {
    /// The request could not provide a usable pool or logger.
    Request(RequestError),
    /// The HTTP core module configuration could not be resolved.
    Configuration(HttpConfigError),
    /// Nginx did not install a core location configuration for this request.
    MissingCoreLocationConfiguration,
    /// The core location configuration has no client-body temporary path.
    MissingTempPath,
    /// The configured temporary path pointer is not aligned for `ngx_path_t`.
    MisalignedTempPath,
    /// The request connection has no logger for the temporary file.
    MissingLog,
    /// An input or output chain is malformed or could not allocate a link.
    Chain(ChainError),
    /// A buffer is malformed or could not allocate request-pool storage.
    Buffer(BufferError),
    /// Nginx could not allocate the request-pool temporary-file state or output descriptor.
    Allocation,
    /// The temporary-file offset is negative.
    NegativeOffset,
    /// The input length cannot be represented by nginx's file offset type.
    LengthOverflow,
    /// Appending the input length would overflow the temporary-file offset.
    OffsetOverflow,
    /// Nginx failed to open or write the temporary file.
    Write,
    /// Nginx did not write the complete requested range.
    ShortWrite {
        /// Number of bytes requested from nginx.
        expected: usize,
        /// Number of bytes reported as written by nginx.
        written: usize,
    },
}

impl From<RequestError> for RequestTempFileError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<HttpConfigError> for RequestTempFileError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<ChainError> for RequestTempFileError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<BufferError> for RequestTempFileError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

/// Request-pool owner for a lazily created nginx temporary file.
///
/// The temporary file uses the HTTP core `client_body_temp_path`, is removed by nginx pool
/// cleanup, and creates its file descriptor only when a nonempty memory buffer is appended.
/// File-backed input is copied into the returned request-pool chain without a second disk write.
///
/// ```compile_fail
/// use ngx::http::{RequestRefMut, RequestTempFile};
///
/// fn escape(request: &RequestRefMut<'_>) -> RequestTempFile<'static> {
///     request.temp_file().unwrap()
/// }
/// ```
pub struct RequestTempFile<'callback> {
    pool: Pool<'callback>,
    path: NonNull<ngx_path_t>,
    log: NonNull<ngx_log_t>,
    temp_file: Option<NonNull<ngx_temp_file_t>>,
    _not_thread_safe: PhantomData<*mut ()>,
}

/// Checked aggregate size of an nginx request body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBodySize {
    bytes: usize,
    saturated: bool,
}

impl RequestBodySize {
    /// Returns the aggregate size, or [`usize::MAX`] after arithmetic saturation.
    pub fn bytes(self) -> usize {
        self.bytes
    }

    /// Returns whether the aggregate size exceeded [`usize::MAX`].
    pub fn is_saturated(self) -> bool {
        self.saturated
    }
}

/// Callback-scoped checked view over an nginx request body.
///
/// ```compile_fail
/// use ngx::http::{RequestBodyRef, RequestRefMut};
///
/// fn escape(request: &RequestRefMut<'_>) -> RequestBodyRef<'static> {
///     request.request_body().unwrap().unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use core::future::Future;
/// use ngx::http::RequestRefMut;
///
/// fn suspend(request: &RequestRefMut<'_>) -> impl Future<Output = ()> + 'static {
///     let body = request.request_body().unwrap().unwrap();
///     async move {
///         core::future::ready(()).await;
///         let _ = body.size();
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBodyRef<'callback> {
    raw: NonNull<ngx_http_request_body_t>,
    _callback: PhantomData<&'callback ngx_http_request_body_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl RequestBodyRef<'_> {
    fn from_raw(body: *mut ngx_http_request_body_t) -> Result<Option<Self>, RequestBodyError> {
        let Some(raw) = NonNull::new(body) else {
            return Ok(None);
        };
        if !body.is_aligned() {
            return Err(RequestBodyError::MisalignedBody);
        }

        Ok(Some(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData }))
    }

    /// Returns the checked nullable nginx chain stored by this request body.
    pub fn chain(&self) -> Result<ChainRef<'_>, RequestBodyError> {
        unsafe { ChainRef::from_raw(self.raw.as_ref().bufs) }.map_err(Into::into)
    }

    /// Returns the aggregate nginx-visible body size without overflowing `usize`.
    ///
    /// Validation continues after saturation so a malformed later link still returns an error.
    pub fn size(&self) -> Result<RequestBodySize, RequestBodyError> {
        let mut bytes: usize = 0;
        let mut saturated = false;

        for buffer in self.chain()?.iter() {
            let buffer = buffer?;
            let length = buffer.len().map_err(ChainError::from)?;
            if let Some(total) = bytes.checked_add(length) {
                bytes = total;
            } else {
                bytes = usize::MAX;
                saturated = true;
            }
        }

        Ok(RequestBodySize { bytes, saturated })
    }
}

/// Result returned when starting nginx client-body processing.
#[derive(Debug, Eq, PartialEq)]
pub enum ClientBodyReadStatus {
    /// Nginx completed the operation synchronously.
    Ok,
    /// Nginx needs more body input.
    Again,
    /// Nginx completed or continued through an alternate native path.
    Done,
    /// Nginx returned an HTTP special response without invoking the callback.
    Special(HTTPStatus),
    /// Nginx returned another status.
    Error(Status),
}

impl ClientBodyReadStatus {
    fn from_raw(status: ngx_int_t) -> Self {
        if status == NGX_OK as ngx_int_t {
            return Self::Ok;
        }
        if status == NGX_AGAIN as ngx_int_t {
            return Self::Again;
        }
        if status == NGX_DONE as ngx_int_t {
            return Self::Done;
        }
        if status >= NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
            if let Ok(status) = usize::try_from(status) {
                if let Ok(status) = HTTPStatus::try_from(status) {
                    return Self::Special(status);
                }
            }
        }

        Self::Error(Status(status))
    }

    /// Returns the exact native nginx status code.
    pub fn raw(&self) -> ngx_int_t {
        match self {
            Self::Ok => NGX_OK as ngx_int_t,
            Self::Again => NGX_AGAIN as ngx_int_t,
            Self::Done => NGX_DONE as ngx_int_t,
            Self::Special(status) => status.0 as ngx_int_t,
            Self::Error(status) => status.0,
        }
    }
}

/// Static callback invoked when nginx completes a client-body read.
///
/// The owner of request cancellation keeps its active state in its pinned request context and
/// overrides [`is_active`](Self::is_active) to reject late native callbacks.
pub trait HttpClientBodyHandler {
    /// Returns whether the request owner still accepts a client-body callback.
    fn is_active(_request: RequestRef<'_>) -> bool {
        true
    }

    /// Handles one callback-scoped client-body completion.
    fn body_read(request: &mut RequestRefMut<'_>);
}

/// Failure returned while preparing a replacement request body and its framing headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBodyBuildError {
    /// The request could not provide a usable pool.
    Request(RequestError),
    /// Existing input headers are invalid.
    HeaderList(HeaderListError),
    /// A replacement input-header candidate could not be prepared.
    HeaderBuild(HeaderBuildError),
    /// A pool-owned body buffer could not be prepared.
    Buffer(BufferError),
    /// A pool-owned body chain could not be prepared.
    Chain(ChainError),
    /// The aggregate body size overflowed `usize`.
    LengthOverflow,
    /// The aggregate body size cannot be represented by nginx's `off_t`.
    ContentLengthTooLarge,
    /// Nginx could not allocate the request-body structure.
    Allocation,
}

impl From<RequestError> for RequestBodyBuildError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<HeaderListError> for RequestBodyBuildError {
    fn from(error: HeaderListError) -> Self {
        Self::HeaderList(error)
    }
}

impl From<HeaderBuildError> for RequestBodyBuildError {
    fn from(error: HeaderBuildError) -> Self {
        Self::HeaderBuild(error)
    }
}

impl From<BufferError> for RequestBodyBuildError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

impl From<ChainError> for RequestBodyBuildError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

/// One checked byte-oriented nginx HTTP header entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpHeaderRef<'header> {
    key: &'header [u8],
    value: &'header [u8],
    lowercase_key: Option<&'header [u8]>,
    hash: ngx_uint_t,
}

impl HttpHeaderRef<'_> {
    /// Returns the raw header-name bytes.
    pub fn key(&self) -> &[u8] {
        self.key
    }

    /// Returns the raw header-value bytes.
    pub fn value(&self) -> &[u8] {
        self.value
    }

    /// Returns nginx's lowercase header-name bytes when they are available.
    pub fn lowercase_key(&self) -> Option<&[u8]> {
        self.lowercase_key
    }

    /// Returns nginx's header hash.
    pub fn hash(&self) -> ngx_uint_t {
        self.hash
    }

    /// Returns whether nginx has not disabled this header.
    pub fn is_enabled(&self) -> bool {
        self.hash != 0
    }
}

/// Checked byte-oriented view over an nginx HTTP header list.
#[derive(Debug)]
pub struct HttpHeaderList<'header> {
    headers: &'header NgxList<ngx_table_elt_t>,
}

impl HttpHeaderList<'_> {
    /// Returns the total number of entries across all nginx list parts.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns whether the list contains no entries.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Iterates over checked byte-oriented header entries in list order.
    pub fn iter(&self) -> HttpHeaderIter<'_> {
        HttpHeaderIter(self.headers.iter())
    }
}

/// Iterator over [`HttpHeaderList`] entries.
pub struct HttpHeaderIter<'header>(NgxListIter<'header, ngx_table_elt_t>);

impl<'header> Iterator for HttpHeaderIter<'header> {
    type Item = HttpHeaderRef<'header>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|header| unsafe { http_header_from_raw(header) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for HttpHeaderIter<'_> {}

/// Request-pool builder for atomically replacing HTTP input headers.
pub struct HttpHeadersInBuilder<'request, 'callback> {
    request: &'request mut RequestRefMut<'callback>,
    pool: *mut ngx_pool_t,
    headers: ngx_http_headers_in_t,
}

impl<'request, 'callback> HttpHeadersInBuilder<'request, 'callback> {
    fn new(
        request: &'request mut RequestRefMut<'callback>,
        capacity: usize,
    ) -> Result<Self, HeaderBuildError> {
        let pool = request.pool()?.as_ptr();
        let mut headers: ngx_http_headers_in_t = unsafe { core::mem::zeroed() };
        headers.headers = create_header_list(pool, capacity)?;
        headers.content_length_n = -1;
        headers.keep_alive_n = -1;

        Ok(Self { request, pool, headers })
    }

    /// Adds a copied raw input header to the candidate list.
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> Result<(), HeaderBuildError> {
        let count = self.headers.count.checked_add(1).ok_or(HeaderBuildError::CountOverflow)?;
        let header = append_pool_header(&mut self.headers.headers, self.pool, key, value)?;
        self.headers.count = count;
        unsafe { bind_headers_in(&mut self.headers, header.as_ptr()) };
        Ok(())
    }

    /// Starts constructing a request-pool body candidate for this replacement-header set.
    pub fn request_body_candidate(
        &self,
    ) -> Result<RequestBodyCandidate<'callback>, RequestBodyBuildError> {
        let pool = unsafe { Pool::from_raw(self.pool) }.ok_or(RequestError::MisalignedPool)?;
        Ok(RequestBodyCandidate::new(pool))
    }

    /// Publishes the replacement headers, body, and authoritative body framing together.
    pub fn commit_with_body(
        self,
        body: RequestBodyCandidate<'callback>,
    ) -> Result<(), RequestBodyBuildError> {
        let Self { request, pool, mut headers } = self;
        if pool != body.pool.as_ptr() {
            return Err(RequestBodyBuildError::Buffer(BufferError::ForeignPool));
        }

        replace_request_body_framing(&mut headers, pool, body.length)?;
        let body = body.into_raw()?;
        publish_request_body(request, headers, body.as_ptr());
        Ok(())
    }

    /// Publishes the replacement headers with a null body and a zero Content-Length.
    pub fn commit_without_body(self) -> Result<(), RequestBodyBuildError> {
        let Self { request, pool, mut headers } = self;
        replace_request_body_framing(&mut headers, pool, 0)?;
        publish_request_body(request, headers, ptr::null_mut());
        Ok(())
    }

    /// Publishes the complete input-header candidate to the request.
    pub fn commit(self) {
        let request = unsafe { self.request.raw.as_mut() };
        request.headers_in = self.headers;
        repair_header_list_last(&mut request.headers_in.headers);
    }
}

/// Request-pool builder for atomically replacing HTTP output headers.
pub struct HttpHeadersOutBuilder<'request, 'callback> {
    request: &'request mut RequestRefMut<'callback>,
    pool: *mut ngx_pool_t,
    headers: ngx_http_headers_out_t,
}

impl<'request, 'callback> HttpHeadersOutBuilder<'request, 'callback> {
    fn new(
        request: &'request mut RequestRefMut<'callback>,
        capacity: usize,
    ) -> Result<Self, HeaderBuildError> {
        let pool = request.pool()?.as_ptr();
        let mut headers = unsafe { request.raw.as_ref().headers_out };
        headers.headers = create_header_list(pool, capacity)?;
        clear_headers_out_slots(&mut headers);

        Ok(Self { request, pool, headers })
    }

    /// Adds a copied raw output header to the candidate list.
    ///
    /// `Content-Type` is represented by nginx's dedicated output field rather than a list entry.
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> Result<(), HeaderBuildError> {
        if key.eq_ignore_ascii_case(b"Content-Type") {
            return self.set_content_type(value);
        }

        let header = append_pool_header(&mut self.headers.headers, self.pool, key, value)?;
        unsafe { bind_headers_out(&mut self.headers, header.as_ptr()) };
        Ok(())
    }

    /// Sets the copied nginx output Content-Type field.
    pub fn set_content_type(&mut self, value: &[u8]) -> Result<(), HeaderBuildError> {
        let value = copy_pool_bytes(self.pool, value)?;
        self.headers.content_type_len = value.len;
        self.headers.content_type = value;
        self.headers.charset = ngx_str_t::empty();
        self.headers.content_type_lowcase = ptr::null_mut();
        self.headers.content_type_hash = 0;
        Ok(())
    }

    /// Publishes the complete output-header candidate to the request.
    pub fn commit(self) {
        let request = unsafe { self.request.raw.as_mut() };
        request.headers_out = self.headers;
        repair_header_list_last(&mut request.headers_out.headers);
        repair_header_list_last(&mut request.headers_out.trailers);
    }
}

/// Request-pool candidate for a non-null HTTP request body.
pub struct RequestBodyCandidate<'callback> {
    pool: Pool<'callback>,
    chain: PoolChain<'callback>,
    length: usize,
}

impl<'callback> RequestBodyCandidate<'callback> {
    fn new(pool: Pool<'callback>) -> Self {
        let chain = pool.chain();
        Self { pool, chain, length: 0 }
    }

    /// Copies memory bytes into the request-pool body candidate.
    pub fn append_copy(&mut self, bytes: &[u8]) -> Result<(), RequestBodyBuildError> {
        if bytes.is_empty() {
            return Ok(());
        }

        let buffer = self.pool.copy_buffer(bytes, BufferFlags::default())?;
        self.append(buffer)
    }

    /// Appends one request-pool-owned buffer to the body candidate.
    pub fn append(&mut self, buffer: PoolBuffer<'callback>) -> Result<(), RequestBodyBuildError> {
        let length = buffer.view().len()?;
        let total = self.length.checked_add(length).ok_or(RequestBodyBuildError::LengthOverflow)?;
        self.chain.append(buffer)?;
        self.length = total;
        Ok(())
    }

    /// Appends a zero-size control buffer to the request-pool body candidate.
    pub fn append_control(&mut self, flags: BufferFlags) -> Result<(), RequestBodyBuildError> {
        let buffer = self.pool.control_buffer(flags)?;
        self.append(buffer)
    }

    fn into_raw(self) -> Result<NonNull<ngx_http_request_body_t>, RequestBodyBuildError> {
        let Self { pool, chain, length: _ } = self;
        let body = NonNull::new(pool.calloc_type::<ngx_http_request_body_t>())
            .ok_or(RequestBodyBuildError::Allocation)?;
        let mut candidate: ngx_http_request_body_t = unsafe { core::mem::zeroed() };
        candidate.bufs = chain.into_raw();
        unsafe { body.as_ptr().write(candidate) };
        Ok(body)
    }
}

/// Request-pool builder for atomically replacing an HTTP request body and its framing.
pub struct RequestBodyBuilder<'request, 'callback> {
    request: &'request mut RequestRefMut<'callback>,
    body: RequestBodyCandidate<'callback>,
}

impl<'request, 'callback> RequestBodyBuilder<'request, 'callback> {
    fn new(request: &'request mut RequestRefMut<'callback>) -> Result<Self, RequestBodyBuildError> {
        let raw_pool = request.pool()?.as_ptr();
        // The checked request view owns the callback lifetime that keeps its pool alive.
        let pool = unsafe { Pool::from_raw(raw_pool) }.ok_or(RequestError::MisalignedPool)?;

        Ok(Self { request, body: RequestBodyCandidate::new(pool) })
    }

    /// Copies memory bytes into the request-pool body candidate.
    pub fn append_copy(&mut self, bytes: &[u8]) -> Result<(), RequestBodyBuildError> {
        self.body.append_copy(bytes)
    }

    /// Appends one request-pool-owned buffer to the body candidate.
    pub fn append(&mut self, buffer: PoolBuffer<'callback>) -> Result<(), RequestBodyBuildError> {
        self.body.append(buffer)
    }

    /// Appends a zero-size control buffer to the body candidate.
    pub fn append_control(&mut self, flags: BufferFlags) -> Result<(), RequestBodyBuildError> {
        self.body.append_control(flags)
    }

    /// Publishes the complete non-null request-body candidate and matching framing headers.
    pub fn commit(self) -> Result<(), RequestBodyBuildError> {
        let Self { request, body } = self;
        let headers = request_body_headers_candidate(request, body.pool.as_ptr(), body.length)?;
        let body = body.into_raw()?;
        publish_request_body(request, headers, body.as_ptr());
        Ok(())
    }
}

static REQUEST_TEMP_FILE_WARNING: &[u8] = b"an HTTP body is buffered to a temporary file\0";

impl<'callback> RequestTempFile<'callback> {
    fn new(request: &RequestRefMut<'callback>) -> Result<Self, RequestTempFileError> {
        let raw_pool = request.pool()?.as_ptr();
        let pool = unsafe { Pool::from_raw(raw_pool) }.ok_or(RequestError::MisalignedPool)?;
        let location = NgxHttpCoreModule::location_conf(request)?
            .ok_or(RequestTempFileError::MissingCoreLocationConfiguration)?;
        let path = NonNull::new(location.client_body_temp_path)
            .ok_or(RequestTempFileError::MissingTempPath)?;
        if !path.as_ptr().is_aligned() {
            return Err(RequestTempFileError::MisalignedTempPath);
        }
        let log = request.log()?.ok_or(RequestTempFileError::MissingLog)?;

        Ok(Self { pool, path, log, temp_file: None, _not_thread_safe: PhantomData })
    }

    /// Copies one checked nginx chain into request-pool owned output.
    ///
    /// Nonempty memory buffers are appended to this temporary file. File-backed buffers receive
    /// request-pool file descriptors over their original ranges, and zero-size control buffers
    /// retain their control flags without opening a temporary file.
    ///
    /// ```compile_fail
    /// use ngx::core::{ChainRef, PoolChain};
    /// use ngx::http::RequestRefMut;
    ///
    /// fn escape<'scope>(
    ///     request: &RequestRefMut<'scope>,
    ///     chain: ChainRef<'scope>,
    /// ) -> PoolChain<'static> {
    ///     request.temp_file().unwrap().append(chain).unwrap()
    /// }
    /// ```
    pub fn append(
        &mut self,
        input: ChainRef<'callback>,
    ) -> Result<PoolChain<'callback>, RequestTempFileError> {
        for buffer in input.iter() {
            buffer?.kind()?;
        }

        let mut output = self.pool.chain();
        for buffer in input.iter() {
            let buffer = buffer?;
            let flags = buffer.flags();

            match buffer.kind()? {
                BufferView::Memory(bytes) => {
                    let (temp_file, start, end) =
                        self.append_memory(buffer.as_ptr(), bytes.len())?;
                    self.append_temp_file_buffer(&mut output, temp_file, start, end, flags)?;
                }
                BufferView::File(file) => {
                    let buffer = self.pool.file_buffer_slice(buffer, 0..file.len(), flags)?;
                    output.append(buffer)?;
                }
                BufferView::Control(_) => {
                    let buffer = self.pool.control_buffer(flags)?;
                    output.append(buffer)?;
                }
            }
        }

        Ok(output)
    }

    fn append_memory(
        &mut self,
        buffer: *const ngx_buf_t,
        length: usize,
    ) -> Result<(NonNull<ngx_temp_file_t>, off_t, off_t), RequestTempFileError> {
        let mut temp_file = self.temp_file()?;
        let (start, end) = temp_file_range(unsafe { temp_file.as_ref().offset }, length)?;
        let mut link: ngx_chain_t = unsafe { core::mem::zeroed() };
        link.buf = buffer.cast_mut();

        let written = unsafe { ngx_write_chain_to_temp_file(temp_file.as_ptr(), &raw mut link) };
        let actual_end = unsafe { temp_file.as_ref().file.offset };
        if actual_end < start {
            return Err(RequestTempFileError::Write);
        }
        unsafe { temp_file.as_mut().offset = actual_end };
        check_temp_file_write(length, written)?;
        if actual_end != end {
            return Err(RequestTempFileError::Write);
        }

        Ok((temp_file, start, end))
    }

    fn append_temp_file_buffer(
        &self,
        output: &mut PoolChain<'callback>,
        temp_file: NonNull<ngx_temp_file_t>,
        start: off_t,
        end: off_t,
        flags: BufferFlags,
    ) -> Result<(), RequestTempFileError> {
        let file = NonNull::new(self.pool.calloc_type::<ngx_file_t>())
            .ok_or(RequestTempFileError::Allocation)?;
        unsafe { file.as_ptr().write(temp_file.as_ref().file) };

        let mut buffer = NonNull::new(self.pool.calloc_type::<ngx_buf_t>())
            .ok_or(RequestTempFileError::Allocation)?;
        unsafe {
            let buffer = buffer.as_mut();
            buffer.file = file.as_ptr();
            buffer.file_pos = start;
            buffer.file_last = end;
            buffer.set_in_file(1);
            buffer.set_flush(u32::from(flags.flush));
            buffer.set_sync(u32::from(flags.sync));
            buffer.set_last_buf(u32::from(flags.last_buf));
            buffer.set_last_in_chain(u32::from(flags.last_in_chain));
        }

        let buffer = unsafe { BufferRef::from_raw(buffer.as_ptr()) }?;
        output.append_borrowed(buffer)?;
        Ok(())
    }

    fn temp_file(&mut self) -> Result<NonNull<ngx_temp_file_t>, RequestTempFileError> {
        if let Some(temp_file) = self.temp_file {
            return Ok(temp_file);
        }

        let mut temp_file = NonNull::new(self.pool.calloc_type::<ngx_temp_file_t>())
            .ok_or(RequestTempFileError::Allocation)?;
        unsafe {
            let temp_file_ref = temp_file.as_mut();
            temp_file_ref.file.fd = NGX_INVALID_FILE as _;
            temp_file_ref.file.log = self.log.as_ptr();
            temp_file_ref.path = self.path.as_ptr();
            temp_file_ref.pool = self.pool.as_ptr();
            temp_file_ref.warn = REQUEST_TEMP_FILE_WARNING.as_ptr().cast_mut();
            temp_file_ref.access = 0o600;
            temp_file_ref.set_log_level(NGX_LOG_WARN as _);
            temp_file_ref.set_clean(1);
        }
        self.temp_file = Some(temp_file);
        Ok(temp_file)
    }
}

fn temp_file_range(offset: off_t, length: usize) -> Result<(off_t, off_t), RequestTempFileError> {
    if offset < 0 {
        return Err(RequestTempFileError::NegativeOffset);
    }

    let length = off_t::try_from(length).map_err(|_| RequestTempFileError::LengthOverflow)?;
    let end = offset.checked_add(length).ok_or(RequestTempFileError::OffsetOverflow)?;
    Ok((offset, end))
}

fn check_temp_file_write(expected: usize, written: isize) -> Result<(), RequestTempFileError> {
    if written < 0 {
        return Err(RequestTempFileError::Write);
    }

    let written = usize::try_from(written).map_err(|_| RequestTempFileError::Write)?;
    if written != expected {
        return Err(RequestTempFileError::ShortWrite { expected, written });
    }

    Ok(())
}

fn checked_header_list(headers: &ngx_list_t) -> Result<HttpHeaderList<'_>, HeaderListError> {
    let headers = unsafe { NgxList::<ngx_table_elt_t>::from_ngx_list(headers) }
        .ok_or(HeaderListError::InvalidList)?;
    for header in headers.iter() {
        checked_header_bytes(
            header.key,
            HeaderListError::MissingKeyData,
            HeaderListError::KeyTooLong,
        )?;
        checked_header_bytes(
            header.value,
            HeaderListError::MissingValueData,
            HeaderListError::ValueTooLong,
        )?;
    }

    Ok(HttpHeaderList { headers })
}

fn checked_header_bytes<'header>(
    value: ngx_str_t,
    missing: HeaderListError,
    too_long: HeaderListError,
) -> Result<&'header [u8], HeaderListError> {
    if value.len == 0 {
        return Ok(&[]);
    }
    if value.len > isize::MAX as usize {
        return Err(too_long);
    }

    let data = NonNull::new(value.data).ok_or(missing)?;
    Ok(unsafe { slice::from_raw_parts(data.as_ptr(), value.len) })
}

unsafe fn http_header_from_raw(header: &ngx_table_elt_t) -> HttpHeaderRef<'_> {
    let key = unsafe { header_bytes_unchecked(header.key) };
    let value = unsafe { header_bytes_unchecked(header.value) };
    let lowercase_key = NonNull::new(header.lowcase_key)
        .map(|key| unsafe { slice::from_raw_parts(key.as_ptr(), header.key.len) });

    HttpHeaderRef { key, value, lowercase_key, hash: header.hash }
}

unsafe fn header_bytes_unchecked<'header>(value: ngx_str_t) -> &'header [u8] {
    if value.len == 0 {
        return &[];
    }

    unsafe { slice::from_raw_parts(value.data, value.len) }
}

fn create_header_list(
    pool: *mut ngx_pool_t,
    capacity: usize,
) -> Result<ngx_list_t, HeaderBuildError> {
    if capacity == 0
        || capacity
            .checked_mul(core::mem::size_of::<ngx_table_elt_t>())
            .is_none_or(|size| size > isize::MAX as usize)
    {
        return Err(HeaderBuildError::InvalidCapacity);
    }

    let mut headers: ngx_list_t = unsafe { core::mem::zeroed() };
    if unsafe {
        ngx_list_init(&raw mut headers, pool, capacity, core::mem::size_of::<ngx_table_elt_t>())
    } != NGX_OK as ngx_int_t
    {
        return Err(HeaderBuildError::Allocation);
    }

    Ok(headers)
}

fn copy_pool_bytes(pool: *mut ngx_pool_t, bytes: &[u8]) -> Result<ngx_str_t, HeaderBuildError> {
    if bytes.is_empty() {
        return Ok(ngx_str_t::empty());
    }

    let data = NonNull::new(unsafe { ngx_pnalloc(pool, bytes.len()).cast::<u_char>() })
        .ok_or(HeaderBuildError::Allocation)?;
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), data.as_ptr(), bytes.len()) };
    Ok(ngx_str_t { len: bytes.len(), data: data.as_ptr() })
}

fn append_pool_header(
    headers: &mut ngx_list_t,
    pool: *mut ngx_pool_t,
    key: &[u8],
    value: &[u8],
) -> Result<NonNull<ngx_table_elt_t>, HeaderBuildError> {
    let key = copy_pool_bytes(pool, key)?;
    let value = copy_pool_bytes(pool, value)?;
    let lowcase_key = if key.len == 0 {
        ptr::null_mut()
    } else {
        NonNull::new(unsafe { ngx_pnalloc(pool, key.len).cast::<u_char>() })
            .ok_or(HeaderBuildError::Allocation)?
            .as_ptr()
    };
    let hash = if lowcase_key.is_null() {
        0
    } else {
        unsafe { ngx_hash_strlow(lowcase_key, key.data, key.len) }
    };
    repair_header_list_last(headers);
    let header = NonNull::new(unsafe { ngx_list_push(headers).cast::<ngx_table_elt_t>() })
        .ok_or(HeaderBuildError::Allocation)?;

    unsafe {
        header.as_ptr().write(ngx_table_elt_t {
            hash,
            key,
            value,
            lowcase_key,
            next: ptr::null_mut(),
        });
    }
    Ok(header)
}

fn repair_header_list_last(headers: &mut ngx_list_t) {
    let mut last = &raw mut headers.part;
    while !unsafe { (*last).next }.is_null() {
        last = unsafe { (*last).next };
    }
    headers.last = last;
}

unsafe fn append_header_slot(slot: &mut *mut ngx_table_elt_t, header: *mut ngx_table_elt_t) {
    let mut tail = slot;
    while !(*tail).is_null() {
        tail = unsafe { &mut (**tail).next };
    }
    unsafe {
        *tail = header;
        (*header).next = ptr::null_mut();
    }
}

unsafe fn bind_headers_in(headers: &mut ngx_http_headers_in_t, header: *mut ngx_table_elt_t) {
    if unsafe { (*header).hash } == 0 {
        return;
    }
    let key = unsafe { header_bytes_unchecked((*header).key) };

    if key.eq_ignore_ascii_case(b"Host") {
        if headers.host.is_null() {
            headers.server = unsafe { (*header).value };
        }
        unsafe { append_header_slot(&mut headers.host, header) };
    } else if key.eq_ignore_ascii_case(b"Content-Length") {
        unsafe { append_header_slot(&mut headers.content_length, header) };
    } else if key.eq_ignore_ascii_case(b"Content-Type") {
        unsafe { append_header_slot(&mut headers.content_type, header) };
    } else if key.eq_ignore_ascii_case(b"User-Agent") {
        unsafe { append_header_slot(&mut headers.user_agent, header) };
    } else if key.eq_ignore_ascii_case(b"Referer") {
        unsafe { append_header_slot(&mut headers.referer, header) };
    } else if key.eq_ignore_ascii_case(b"Authorization") {
        unsafe { append_header_slot(&mut headers.authorization, header) };
    } else if key.eq_ignore_ascii_case(b"Proxy-Authorization") {
        unsafe { append_header_slot(&mut headers.proxy_authorization, header) };
    } else if key.eq_ignore_ascii_case(b"Cookie") {
        unsafe { append_header_slot(&mut headers.cookie, header) };
    } else if key.eq_ignore_ascii_case(b"Expect") {
        unsafe { append_header_slot(&mut headers.expect, header) };
    } else if key.eq_ignore_ascii_case(b"Range") {
        unsafe { append_header_slot(&mut headers.range, header) };
    } else if key.eq_ignore_ascii_case(b"If-Modified-Since") {
        unsafe { append_header_slot(&mut headers.if_modified_since, header) };
    } else if key.eq_ignore_ascii_case(b"If-Unmodified-Since") {
        unsafe { append_header_slot(&mut headers.if_unmodified_since, header) };
    } else if key.eq_ignore_ascii_case(b"If-Match") {
        unsafe { append_header_slot(&mut headers.if_match, header) };
    } else if key.eq_ignore_ascii_case(b"If-None-Match") {
        unsafe { append_header_slot(&mut headers.if_none_match, header) };
    } else if key.eq_ignore_ascii_case(b"If-Range") {
        unsafe { append_header_slot(&mut headers.if_range, header) };
    } else if key.eq_ignore_ascii_case(b"Content-Range") {
        unsafe { append_header_slot(&mut headers.content_range, header) };
    }
}

unsafe fn bind_headers_out(headers: &mut ngx_http_headers_out_t, header: *mut ngx_table_elt_t) {
    if unsafe { (*header).hash } == 0 {
        return;
    }
    let key = unsafe { header_bytes_unchecked((*header).key) };

    if key.eq_ignore_ascii_case(b"Server") {
        unsafe { append_header_slot(&mut headers.server, header) };
    } else if key.eq_ignore_ascii_case(b"Date") {
        unsafe { append_header_slot(&mut headers.date, header) };
    } else if key.eq_ignore_ascii_case(b"Content-Length") {
        unsafe { append_header_slot(&mut headers.content_length, header) };
    } else if key.eq_ignore_ascii_case(b"Content-Encoding") {
        unsafe { append_header_slot(&mut headers.content_encoding, header) };
    } else if key.eq_ignore_ascii_case(b"Location") {
        unsafe { append_header_slot(&mut headers.location, header) };
    } else if key.eq_ignore_ascii_case(b"Refresh") {
        unsafe { append_header_slot(&mut headers.refresh, header) };
    } else if key.eq_ignore_ascii_case(b"Last-Modified") {
        unsafe { append_header_slot(&mut headers.last_modified, header) };
    } else if key.eq_ignore_ascii_case(b"Content-Range") {
        unsafe { append_header_slot(&mut headers.content_range, header) };
    } else if key.eq_ignore_ascii_case(b"Accept-Ranges") {
        unsafe { append_header_slot(&mut headers.accept_ranges, header) };
    } else if key.eq_ignore_ascii_case(b"WWW-Authenticate") {
        unsafe { append_header_slot(&mut headers.www_authenticate, header) };
    } else if key.eq_ignore_ascii_case(b"Proxy-Authenticate") {
        unsafe { append_header_slot(&mut headers.proxy_authenticate, header) };
    } else if key.eq_ignore_ascii_case(b"Expires") {
        unsafe { append_header_slot(&mut headers.expires, header) };
    } else if key.eq_ignore_ascii_case(b"ETag") {
        unsafe { append_header_slot(&mut headers.etag, header) };
    } else if key.eq_ignore_ascii_case(b"Cache-Control") {
        unsafe { append_header_slot(&mut headers.cache_control, header) };
    } else if key.eq_ignore_ascii_case(b"Link") {
        unsafe { append_header_slot(&mut headers.link, header) };
    }
}

fn clear_headers_out_slots(headers: &mut ngx_http_headers_out_t) {
    headers.server = ptr::null_mut();
    headers.date = ptr::null_mut();
    headers.content_length = ptr::null_mut();
    headers.content_encoding = ptr::null_mut();
    headers.location = ptr::null_mut();
    headers.refresh = ptr::null_mut();
    headers.last_modified = ptr::null_mut();
    headers.content_range = ptr::null_mut();
    headers.accept_ranges = ptr::null_mut();
    headers.www_authenticate = ptr::null_mut();
    headers.proxy_authenticate = ptr::null_mut();
    headers.expires = ptr::null_mut();
    headers.etag = ptr::null_mut();
    headers.cache_control = ptr::null_mut();
    headers.link = ptr::null_mut();
    headers.content_type_len = 0;
    headers.content_type = ngx_str_t::empty();
    headers.charset = ngx_str_t::empty();
    headers.content_type_lowcase = ptr::null_mut();
    headers.content_type_hash = 0;
}

fn clear_headers_out_metadata(headers: &mut ngx_http_headers_out_t) {
    headers.status = 0;
    headers.status_line = ngx_str_t::empty();
    clear_headers_out_slots(headers);
    headers.override_charset = ptr::null_mut();
    headers.content_length_n = -1;
    headers.content_offset = 0;
    headers.date_time = 0;
    headers.last_modified_time = -1;

    headers.trailers.part.nelts = 0;
    headers.trailers.part.next = ptr::null_mut();
    headers.trailers.last = &raw mut headers.trailers.part;
}

fn request_body_headers_candidate(
    request: &RequestRefMut<'_>,
    pool: *mut ngx_pool_t,
    length: usize,
) -> Result<ngx_http_headers_in_t, RequestBodyBuildError> {
    let headers = request.headers_in()?;
    let capacity = headers.len().checked_add(1).ok_or(HeaderBuildError::CountOverflow)?;
    let mut candidate = unsafe { request.raw.as_ref().headers_in };
    candidate.headers = create_header_list(pool, capacity)?;
    candidate.count = 0;
    candidate.content_length = ptr::null_mut();
    candidate.transfer_encoding = ptr::null_mut();

    for header in headers.iter() {
        let count = candidate.count.checked_add(1).ok_or(HeaderBuildError::CountOverflow)?;
        let copied =
            append_pool_header(&mut candidate.headers, pool, header.key(), header.value())?;
        unsafe { (*copied.as_ptr()).hash = header.hash() };
        candidate.count = count;
    }

    replace_request_body_framing(&mut candidate, pool, length)?;
    Ok(candidate)
}

fn replace_request_body_framing(
    headers: &mut ngx_http_headers_in_t,
    pool: *mut ngx_pool_t,
    length: usize,
) -> Result<(), RequestBodyBuildError> {
    let content_length =
        off_t::try_from(length).map_err(|_| RequestBodyBuildError::ContentLengthTooLarge)?;
    repair_header_list_last(&mut headers.headers);
    let list = unsafe { NgxList::<ngx_table_elt_t>::from_ngx_list_mut(&mut headers.headers) }
        .ok_or(HeaderListError::InvalidList)?;
    for header in list.iter_mut() {
        let key = unsafe { header_bytes_unchecked(header.key) };
        if key.eq_ignore_ascii_case(b"Content-Length")
            || key.eq_ignore_ascii_case(b"Transfer-Encoding")
        {
            header.hash = 0;
        }
    }

    headers.content_length = ptr::null_mut();
    headers.transfer_encoding = ptr::null_mut();
    let mut decimal = [0_u8; core::mem::size_of::<usize>() * 3];
    let value = decimal_bytes(length, &mut decimal);
    let count = headers.count.checked_add(1).ok_or(HeaderBuildError::CountOverflow)?;
    let content_length_header =
        append_pool_header(&mut headers.headers, pool, b"Content-Length", value)?;
    headers.count = count;
    unsafe { bind_headers_in(headers, content_length_header.as_ptr()) };
    headers.content_length_n = content_length;
    headers.transfer_encoding = ptr::null_mut();
    headers.set_chunked(0);
    Ok(())
}

fn publish_request_body(
    request: &mut RequestRefMut<'_>,
    headers: ngx_http_headers_in_t,
    body: *mut ngx_http_request_body_t,
) {
    let request = unsafe { request.raw.as_mut() };
    request.headers_in = headers;
    request.request_body = body;
    repair_header_list_last(&mut request.headers_in.headers);
}

fn decimal_bytes(mut value: usize, buffer: &mut [u8]) -> &[u8] {
    let mut index = buffer.len();
    loop {
        index -= 1;
        buffer[index] = (value % 10) as u8 + b'0';
        value /= 10;
        if value == 0 {
            return &buffer[index..];
        }
    }
}

#[repr(C)]
struct RequestContextOwner<T> {
    context: T,
    slot: NonNull<*mut c_void>,
    cleanup: fn(Pin<&mut T>),
}

impl<T> RequestContextOwner<T> {
    fn context_ptr(owner: NonNull<Self>) -> NonNull<T> {
        unsafe { NonNull::from(&mut (*owner.as_ptr()).context) }
    }
}

impl<T> Drop for RequestContextOwner<T> {
    fn drop(&mut self) {
        let context = ptr::addr_of_mut!(self.context).cast::<c_void>();
        unsafe {
            if ptr::eq(*self.slot.as_ptr(), context) {
                *self.slot.as_ptr() = ptr::null_mut();
            }
            (self.cleanup)(Pin::new_unchecked(&mut self.context));
        }
    }
}

fn checked_request_ptr(
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

unsafe fn checked_ngx_str<'a>(value: ngx_str_t) -> Result<&'a NgxStr, RequestError> {
    if value.len == 0 {
        return Ok(NgxStr::from_bytes(&[]));
    }

    let data = NonNull::new(value.data).ok_or(RequestError::MissingStringData)?;
    let bytes = unsafe { slice::from_raw_parts(data.as_ptr(), value.len) };
    Ok(NgxStr::from_bytes(bytes))
}

const MAX_SUBREQUEST_DEPTH: usize = 50;

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
    raw: NonNull<ngx_http_request_t>,
    _callback: PhantomData<&'callback ngx_http_request_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl RequestRef<'_> {
    /// Creates a checked shared request view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `request` must point to a live initialized nginx request for `'callback`. Nginx must not
    /// mutate it while this shared view exists, and the view must remain on its owning event-loop
    /// thread.
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

    fn main_raw(&self) -> Result<NonNull<ngx_http_request_t>, RequestError> {
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
        for _ in 0..MAX_SUBREQUEST_DEPTH {
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
        unsafe { self.raw.as_ref().internal() != 0 }
    }

    /// Number of additional nested subrequests nginx permits from this request.
    pub fn subrequests_available(&self) -> u32 {
        unsafe { self.raw.as_ref().subrequests().saturating_sub(1) }
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
    pub fn log(&self) -> Result<Option<NonNull<ngx_log_t>>, RequestError> {
        self.connection()?.log().map_err(Into::into)
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

    /// Request method verb.
    pub fn method(&self) -> Method {
        Method::from_ngx(unsafe { self.raw.as_ref().method })
    }

    /// Path part of the request URI.
    pub fn path(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().uri) }
    }

    /// Full request URI including query arguments.
    pub fn unparsed_uri(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().unparsed_uri) }
    }

    fn module_context_slot(
        &self,
        module: &ngx_module_t,
    ) -> Result<NonNull<*mut c_void>, RequestContextError> {
        let index = conf::request_context_index(module)?;
        let slots = NonNull::new(unsafe { self.raw.as_ref().ctx })
            .ok_or(RequestContextError::MissingSlots)?;
        if !slots.as_ptr().is_aligned() {
            return Err(RequestContextError::MisalignedSlots);
        }

        Ok(unsafe { NonNull::new_unchecked(slots.as_ptr().add(index)) })
    }

    fn context_from_slot<T>(
        slot: NonNull<*mut c_void>,
    ) -> Result<Option<NonNull<T>>, RequestContextError> {
        let Some(context) = NonNull::new(unsafe { (*slot.as_ptr()).cast::<T>() }) else {
            return Ok(None);
        };
        if !context.as_ptr().is_aligned() {
            return Err(RequestContextError::MisalignedContext);
        }

        Ok(Some(context))
    }

    /// Shared context associated with module `M` for this request.
    pub fn module_context<M>(&self) -> Result<Option<&M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let slot = self.module_context_slot(M::module())?;
        Ok(Self::context_from_slot::<M::RequestContext>(slot)?
            .map(|context| unsafe { context.as_ref() }))
    }

    /// Client HTTP User-Agent, when nginx parsed one.
    pub fn user_agent(&self) -> Result<Option<&NgxStr>, RequestError> {
        let header = unsafe { self.raw.as_ref().headers_in.user_agent };
        if header.is_null() {
            return Ok(None);
        }

        unsafe { checked_ngx_str((*header).value) }.map(Some)
    }

    /// Whether nginx marked the response as header-only.
    pub fn header_only(&self) -> bool {
        unsafe { self.raw.as_ref().header_only() != 0 }
    }

    /// Returns a checked byte-oriented view over input headers.
    pub fn headers_in(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(unsafe { &self.raw.as_ref().headers_in.headers })
    }

    /// Returns a checked callback-scoped view over the current request body, when nginx has one.
    pub fn request_body(&self) -> Result<Option<RequestBodyRef<'_>>, RequestBodyError> {
        RequestBodyRef::from_raw(unsafe { self.raw.as_ref().request_body })
    }

    /// Returns checked upstream connection attempts recorded for this request.
    pub fn upstream_states(&self) -> Result<Option<UpstreamStates<'_>>, UpstreamStateError> {
        unsafe { UpstreamStates::from_raw(self.raw.as_ref().upstream_states) }
    }

    /// Returns a checked byte-oriented view over output headers.
    pub fn headers_out(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(unsafe { &self.raw.as_ref().headers_out.headers })
    }

    /// Returns the active upstream pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the upstream object's aliasing and request-lifetime requirements.
    pub unsafe fn upstream(&self) -> Option<NonNull<ngx_http_upstream_t>> {
        NonNull::new(unsafe { self.raw.as_ref().upstream })
    }

    /// Iterates over input headers.
    ///
    /// Header structural validation and byte-oriented APIs are provided separately.
    pub fn headers_in_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.raw.as_ref().headers_in.headers) }
    }

    /// Iterates over output headers.
    ///
    /// Header structural validation and byte-oriented APIs are provided separately.
    pub fn headers_out_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.raw.as_ref().headers_out.headers) }
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
pub struct RequestRefMut<'callback> {
    raw: NonNull<ngx_http_request_t>,
    _callback: PhantomData<&'callback mut ngx_http_request_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> RequestRefMut<'callback> {
    /// Creates a checked exclusive request view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `request` must point to a live initialized nginx request for `'callback`. Nginx must make
    /// it exclusively available for that lifetime, and the view must remain on its owning
    /// event-loop thread.
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

    /// Retains the main request while a context delays its terminal HTTP operation.
    ///
    /// `hold` must be the one slot in the pinned request context that owns this delayed path.
    /// Call this only after nginx reports that work will continue asynchronously; synchronous
    /// completion leaves `hold` empty. The hold is installed only after the main request count
    /// can be incremented.
    pub fn hold(&mut self, hold: &mut Option<RequestHold>) -> Result<(), RequestHoldError> {
        if hold.is_some() {
            return Err(RequestHoldError::AlreadyHeld);
        }

        let mut main = self.view().main_raw()?;
        let count = unsafe { main.as_ref().count() };
        if count == 0 {
            return Err(RequestHoldError::InactiveMain);
        }
        if count == u16::MAX as _ {
            return Err(RequestHoldError::CountOverflow);
        }

        unsafe { main.as_mut().set_count(count + 1) };
        *hold = Some(RequestHold { request: self.raw, main, _not_thread_safe: PhantomData });
        Ok(())
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
    pub fn pool(&self) -> Result<Pool<'callback>, RequestError> {
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
    pub fn log(&self) -> Result<Option<NonNull<ngx_log_t>>, RequestError> {
        self.view().log()
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

    /// Request method verb.
    pub fn method(&self) -> Method {
        self.view().method()
    }

    /// Path part of the request URI.
    pub fn path(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().uri) }
    }

    /// Full request URI including query arguments.
    pub fn unparsed_uri(&self) -> Result<&NgxStr, RequestError> {
        unsafe { checked_ngx_str(self.raw.as_ref().unparsed_uri) }
    }

    /// Shared context associated with module `M` for this request.
    pub fn module_context<M>(&self) -> Result<Option<&M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let slot =
            RequestRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
                .module_context_slot(M::module())?;
        Ok(RequestRef::context_from_slot::<M::RequestContext>(slot)?
            .map(|context| unsafe { context.as_ref() }))
    }

    /// Exclusive access to an explicitly movable context associated with module `M`.
    pub fn module_context_mut<M>(
        &mut self,
    ) -> Result<Option<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
        M::RequestContext: Unpin,
    {
        let slot = self.view().module_context_slot(M::module())?;
        Ok(RequestRef::context_from_slot::<M::RequestContext>(slot)?
            .map(|mut context| unsafe { context.as_mut() }))
    }

    /// Returns pinned exclusive access to a context associated with module `M`.
    pub fn pinned_module_context_mut<M>(
        &mut self,
    ) -> Result<Option<Pin<&mut M::RequestContext>>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let slot = self.view().module_context_slot(M::module())?;
        Ok(RequestRef::context_from_slot::<M::RequestContext>(slot)?
            .map(|mut context| unsafe { Pin::new_unchecked(context.as_mut()) }))
    }

    /// Returns an explicitly movable module context, inserting a pool-owned value when absent.
    pub fn get_or_insert_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<&mut M::RequestContext, RequestContextError>
    where
        M: HttpModuleRequestContext,
        M::RequestContext: Unpin,
    {
        self.get_or_insert_pinned_module_context_with::<M>(constructor).map(Pin::into_inner)
    }

    /// Returns a pinned module context, inserting a pool-owned value when absent.
    ///
    /// The request context slot is published only after the context and its pool cleanup are
    /// initialized. Pool cleanup clears the slot, calls [`HttpModuleRequestContext::cleanup`],
    /// and then drops the value.
    ///
    /// ```compile_fail
    /// use core::marker::PhantomPinned;
    /// use core::pin::Pin;
    /// use ngx::ffi::ngx_module_t;
    /// use ngx::http::{HttpModule, HttpModuleRequestContext, RequestRefMut};
    ///
    /// struct Module;
    /// unsafe impl HttpModule for Module {
    ///     fn module() -> &'static ngx_module_t {
    ///         unreachable!()
    ///     }
    /// }
    /// struct Context(PhantomPinned);
    /// unsafe impl HttpModuleRequestContext for Module {
    ///     type RequestContext = Context;
    /// }
    /// fn cannot_move(request: &mut RequestRefMut<'_>) {
    ///     let context = request
    ///         .get_or_insert_pinned_module_context_with::<Module>(|| Context(PhantomPinned))
    ///         .unwrap();
    ///     let _ = Pin::into_inner(context);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::ffi::ngx_module_t;
    /// use ngx::http::{HttpModule, HttpModuleRequestContext, RequestRef, RequestRefMut};
    ///
    /// struct Module;
    /// unsafe impl HttpModule for Module {
    ///     fn module() -> &'static ngx_module_t {
    ///         unreachable!()
    ///     }
    /// }
    /// struct Context<'request> {
    ///     request: RequestRef<'request>,
    /// }
    /// unsafe impl HttpModuleRequestContext for Module {
    ///     type RequestContext = Context<'static>;
    /// }
    /// fn cannot_retain_request<'request>(request: &mut RequestRefMut<'request>) {
    ///     let _ = request.get_or_insert_pinned_module_context_with::<Module>(|| Context {
    ///         request: request.view(),
    ///     });
    /// }
    /// ```
    pub fn get_or_insert_pinned_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<Pin<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        match self
            .try_get_or_insert_pinned_module_context_with::<M, Infallible>(|| Ok(constructor()))
        {
            Ok(context) => Ok(context),
            Err(RequestContextCreateError::Context(error)) => Err(error),
            Err(RequestContextCreateError::Construction(error)) => match error {},
        }
    }

    /// Returns a pinned module context, using a fallible constructor when it is absent.
    pub fn try_get_or_insert_pinned_module_context_with<M, E>(
        &mut self,
        constructor: impl FnOnce() -> Result<M::RequestContext, E>,
    ) -> Result<Pin<&mut M::RequestContext>, RequestContextCreateError<E>>
    where
        M: HttpModuleRequestContext,
    {
        let slot = self.view().module_context_slot(M::module())?;
        if let Some(mut context) = RequestRef::context_from_slot::<M::RequestContext>(slot)? {
            return Ok(unsafe { Pin::new_unchecked(context.as_mut()) });
        }

        let owner = self
            .pool()?
            .try_allocate_with_cleanup(|| {
                constructor().map(|context| RequestContextOwner {
                    context,
                    slot,
                    cleanup: M::cleanup,
                })
            })?
            .into_non_null();
        let mut context = RequestContextOwner::context_ptr(owner);
        unsafe { *slot.as_ptr() = context.as_ptr().cast() };
        Ok(unsafe { Pin::new_unchecked(context.as_mut()) })
    }

    /// Drops and removes the module context when present.
    ///
    /// Returns `Ok(false)` when the slot is empty. A missing cleanup restores the original slot
    /// and returns [`RequestContextError::MissingCleanup`].
    pub fn remove_module_context<M>(&mut self) -> Result<bool, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let pool = self.pool()?;
        let slot = self.view().module_context_slot(M::module())?;
        let Some(context) = RequestRef::context_from_slot::<M::RequestContext>(slot)? else {
            return Ok(false);
        };

        unsafe { *slot.as_ptr() = ptr::null_mut() };
        if unsafe { pool.remove_cleanup(context.cast::<RequestContextOwner<M::RequestContext>>()) }
        {
            Ok(true)
        } else {
            unsafe { *slot.as_ptr() = context.as_ptr().cast() };
            Err(RequestContextError::MissingCleanup)
        }
    }

    /// Client HTTP User-Agent, when nginx parsed one.
    pub fn user_agent(&self) -> Result<Option<&NgxStr>, RequestError> {
        let header = unsafe { self.raw.as_ref().headers_in.user_agent };
        if header.is_null() {
            return Ok(None);
        }

        unsafe { checked_ngx_str((*header).value) }.map(Some)
    }

    /// Whether nginx marked the response as header-only.
    pub fn header_only(&self) -> bool {
        self.view().header_only()
    }

    /// Returns a checked byte-oriented view over input headers.
    pub fn headers_in(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(unsafe { &self.raw.as_ref().headers_in.headers })
    }

    /// Returns a checked byte-oriented view over output headers.
    pub fn headers_out(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(unsafe { &self.raw.as_ref().headers_out.headers })
    }

    /// Starts constructing a complete replacement input-header list in the request pool.
    pub fn headers_in_builder(
        &mut self,
        capacity: usize,
    ) -> Result<HttpHeadersInBuilder<'_, 'callback>, HeaderBuildError> {
        HttpHeadersInBuilder::new(self, capacity)
    }

    /// Returns a checked callback-scoped view over the current request body, when nginx has one.
    pub fn request_body(&self) -> Result<Option<RequestBodyRef<'_>>, RequestBodyError> {
        RequestBodyRef::from_raw(unsafe { self.raw.as_ref().request_body })
    }

    /// Returns checked upstream connection attempts recorded for this request.
    pub fn upstream_states(&self) -> Result<Option<UpstreamStates<'_>>, UpstreamStateError> {
        unsafe { UpstreamStates::from_raw(self.raw.as_ref().upstream_states) }
    }

    /// Creates a request-pool owner for the configured HTTP temporary-file path.
    ///
    /// The owner allocates its native state and opens its file only when a nonempty memory buffer
    /// is appended through [`RequestTempFile::append`].
    pub fn temp_file(&self) -> Result<RequestTempFile<'callback>, RequestTempFileError> {
        RequestTempFile::new(self)
    }

    /// Starts constructing a complete request-pool body and framing-header replacement.
    pub fn request_body_builder(
        &mut self,
    ) -> Result<RequestBodyBuilder<'_, 'callback>, RequestBodyBuildError> {
        RequestBodyBuilder::new(self)
    }

    /// Clears the current body pointer and publishes a zero Content-Length without transfer coding.
    pub fn clear_request_body(&mut self) -> Result<(), RequestBodyBuildError> {
        let pool = self.pool()?.as_ptr();
        let headers = request_body_headers_candidate(self, pool, 0)?;
        let request = unsafe { self.raw.as_mut() };
        request.headers_in = headers;
        request.request_body = ptr::null_mut();
        repair_header_list_last(&mut request.headers_in.headers);
        Ok(())
    }

    /// Starts nginx client-body processing with one static callback type.
    ///
    /// An immediate special response is returned without invoking `H`. The callback's owner keeps
    /// cancellation state in its pinned request context through [`HttpClientBodyHandler::is_active`].
    pub fn read_client_body<H: HttpClientBodyHandler>(&mut self) -> ClientBodyReadStatus {
        ClientBodyReadStatus::from_raw(unsafe {
            ngx_http_read_client_request_body(self.raw.as_ptr(), Some(raw_client_body_handler::<H>))
        })
    }

    /// Starts constructing a complete replacement output-header list in the request pool.
    pub fn headers_out_builder(
        &mut self,
        capacity: usize,
    ) -> Result<HttpHeadersOutBuilder<'_, 'callback>, HeaderBuildError> {
        HttpHeadersOutBuilder::new(self, capacity)
    }

    /// Starts constructing a complete output-header candidate with fresh response metadata.
    ///
    /// Unlike [`headers_out_builder`](Self::headers_out_builder), this clears the status,
    /// trailers, and scalar output metadata inherited from the current response.
    pub fn clean_headers_out_builder(
        &mut self,
        capacity: usize,
    ) -> Result<HttpHeadersOutBuilder<'_, 'callback>, HeaderBuildError> {
        let mut builder = HttpHeadersOutBuilder::new(self, capacity)?;
        clear_headers_out_metadata(&mut builder.headers);
        Ok(builder)
    }

    /// Returns the active upstream pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the upstream object's aliasing and request-lifetime requirements.
    pub unsafe fn upstream(&self) -> Option<NonNull<ngx_http_upstream_t>> {
        unsafe { self.view().upstream() }
    }

    /// Iterates over input headers.
    pub fn headers_in_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.raw.as_ref().headers_in.headers) }
    }

    /// Iterates over output headers.
    pub fn headers_out_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.raw.as_ref().headers_out.headers) }
    }

    /// Returns the native request pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the target nginx API's aliasing and callback-lifetime requirements.
    pub unsafe fn as_ptr(&self) -> *mut ngx_http_request_t {
        self.raw.as_ptr()
    }

    /// Exclusive reborrow of the root main request.
    pub fn main_mut(&mut self) -> Result<RequestRefMut<'_>, RequestError> {
        let raw =
            RequestRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
                .main_raw()?;
        Ok(RequestRefMut { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
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

    /// Gets the value of a complex value.
    pub fn get_complex_value(
        &mut self,
        value: &ngx_http_complex_value_t,
    ) -> Result<Option<&NgxStr>, RequestError> {
        let mut output = ngx_str_t::default();
        let status = unsafe {
            ngx_http_complex_value(
                self.raw.as_ptr(),
                ptr::from_ref(value).cast_mut(),
                &raw mut output,
            )
        };
        if Status(status).into_result().is_err() {
            return Ok(None);
        }

        unsafe { checked_ngx_str(output) }.map(Some)
    }

    /// Discards the request body.
    pub fn discard_request_body(&mut self) -> Status {
        Status(unsafe { ngx_http_discard_request_body(self.raw.as_ptr()) })
    }

    /// Adds an input header allocated from the request pool.
    pub fn add_header_in(&mut self, key: &str, value: &str) -> Result<(), RequestError> {
        let pool = self.pool()?.as_ptr();
        let table = unsafe { ngx_list_push(&raw mut self.raw.as_mut().headers_in.headers).cast() };
        unsafe { add_to_ngx_table(table, pool, key, value) }.ok_or(RequestError::Allocation)
    }

    pub(crate) fn reset_headers_in(&mut self, headers: ngx_list_t) {
        let request = unsafe { self.raw.as_mut() };
        request.headers_in = unsafe { core::mem::zeroed() };
        request.headers_in.headers = headers;
        request.headers_in.headers.last = &raw mut request.headers_in.headers.part;
        request.headers_in.content_length_n = -1;
        request.headers_in.keep_alive_n = -1;
    }

    /// Adds an output header allocated from the request pool.
    pub fn add_header_out(&mut self, key: &str, value: &str) -> Result<(), RequestError> {
        let pool = self.pool()?.as_ptr();
        let table = unsafe { ngx_list_push(&raw mut self.raw.as_mut().headers_out.headers).cast() };
        unsafe { add_to_ngx_table(table, pool, key, value) }.ok_or(RequestError::Allocation)
    }

    /// Sets the response Content-Length.
    pub fn set_content_length_n(&mut self, length: usize) -> Result<(), RequestError> {
        let length = off_t::try_from(length).map_err(|_| RequestError::ContentLengthTooLarge)?;
        unsafe { self.raw.as_mut().headers_out.content_length_n = length };
        Ok(())
    }

    /// Sends the output header.
    pub fn send_header(&mut self) -> Result<Status, RequestError> {
        self.validate_terminal_operation()?;
        Ok(Status(unsafe { ngx_http_send_header(self.raw.as_ptr()) }))
    }

    /// Sends a checked response chain through nginx's current output filter.
    pub fn output_filter(&mut self, body: ChainRef<'_>) -> Result<Status, RequestError> {
        self.validate_terminal_operation()?;
        Ok(Status(unsafe { ngx_http_output_filter(self.raw.as_ptr(), body.as_ptr()) }))
    }

    /// Finalizes this request with an explicit nginx status.
    ///
    /// This consumes the request because nginx can invalidate it synchronously.
    ///
    /// ```compile_fail
    /// use ngx::http::{HTTPStatus, RequestRefMut};
    ///
    /// fn finalize_then_use(request: RequestRefMut<'_>) {
    ///     let _ = request.finalize(HTTPStatus::BAD_REQUEST);
    ///     let _ = request.is_main();
    /// }
    /// ```
    pub fn finalize(self, status: impl Into<Status>) -> Result<(), RequestError> {
        self.validate_terminal_operation()?;
        let status = status.into();
        unsafe { ngx_http_finalize_request(self.raw.as_ptr(), status.0) };
        Ok(())
    }

    /// Advances a PREACCESS handler after its asynchronous callback completes.
    ///
    /// This consumes the request because running phases can finalize it synchronously.
    pub fn resume_preaccess(mut self) -> Result<(), RequestPhaseResumeError> {
        self.prepare_preaccess_resume()?;
        unsafe { ngx_http_core_run_phases(self.raw.as_ptr()) };
        Ok(())
    }

    /// Performs an internal redirect to a location.
    pub fn internal_redirect(&mut self, location: &str) -> Result<Status, RequestError> {
        if location.is_empty() {
            return Ok(Status::NGX_ERROR);
        }
        let Some(mut uri) = (unsafe { ngx_str_t::from_str(self.pool()?.as_ptr(), location) })
        else {
            return Err(RequestError::Allocation);
        };

        let status = if location.starts_with('@') {
            unsafe { ngx_http_named_location(self.raw.as_ptr(), &raw mut uri) }
        } else {
            unsafe { ngx_http_internal_redirect(self.raw.as_ptr(), &raw mut uri, ptr::null_mut()) }
        };
        Ok(Status(status))
    }

    fn validate_terminal_operation(&self) -> Result<(), RequestError> {
        self.view().main_raw()?;
        self.connection()?;
        Ok(())
    }

    fn prepare_preaccess_resume(&mut self) -> Result<(), RequestPhaseResumeError> {
        self.validate_terminal_operation()?;
        let phase_handler = unsafe { self.raw.as_ref().phase_handler };
        if phase_handler < 0 {
            return Err(RequestPhaseResumeError::NegativePhaseHandler);
        }
        let phase_handler =
            phase_handler.checked_add(1).ok_or(RequestPhaseResumeError::PhaseHandlerOverflow)?;

        let request = unsafe { self.raw.as_mut() };
        request.write_event_handler = Some(ngx_http_core_run_phases);
        request.phase_handler = phase_handler;
        Ok(())
    }
}

impl RequestHold {
    /// Removes this hold from its context and grants the only terminal continuation.
    ///
    /// This consumes the callback-scoped request borrow so a terminal operation cannot leave a
    /// safe request view after nginx may free the request.
    pub fn take<'callback>(
        hold: &mut Option<Self>,
        request: RequestRefMut<'callback>,
    ) -> Result<RequestContinuation<'callback>, RequestHoldError> {
        let current = hold.as_ref().ok_or(RequestHoldError::Missing)?;
        let main = request.view().main_raw()?;
        if current.request != request.raw || current.main != main {
            return Err(RequestHoldError::ForeignRequest);
        }
        if unsafe { main.as_ref().count() } <= 1 {
            return Err(RequestHoldError::InactiveMain);
        }

        let hold = hold.take().ok_or(RequestHoldError::Missing)?;
        Ok(RequestContinuation {
            request,
            _hold: hold,
            consumed: false,
            header_continued: false,
            body_continued: false,
        })
    }

    /// Clears a context-owned hold after request cleanup made terminal continuation impossible.
    ///
    /// This only removes module-local ownership; it never finalizes or resumes nginx.
    pub fn cancel(hold: &mut Option<Self>) -> bool {
        hold.take().is_some()
    }

    #[cfg(feature = "async")]
    pub(crate) fn resume_phase(hold: &mut Option<Self>) -> Result<(), RequestContinuationError> {
        let request = hold.as_ref().ok_or(RequestHoldError::Missing)?.request;
        let request = unsafe { RequestRefMut::from_raw(request.as_ptr()) }?;
        Self::take(hold, request)?.resume_phase()
    }
}

impl RequestContinuation<'_> {
    fn ensure_active(&self) -> Result<(), RequestContinuationError> {
        if self.consumed {
            return Err(RequestContinuationError::Consumed);
        }

        Ok(())
    }

    fn ensure_releasable_hold(&self) -> Result<(), RequestHoldError> {
        if unsafe { self._hold.main.as_ref().count() } <= 1 {
            return Err(RequestHoldError::InactiveMain);
        }

        Ok(())
    }

    fn release_hold(hold: &mut RequestHold) {
        let mut main = hold.main;
        let count = unsafe { main.as_ref().count() };
        debug_assert!(count > 1);
        unsafe { main.as_mut().set_count(count - 1) };
    }

    /// Cancels this terminal owner after request cleanup made continuation impossible.
    ///
    /// Cancellation never invokes nginx and makes later terminal operations fail.
    pub fn cancel(&mut self) -> Result<(), RequestContinuationError> {
        if self.consumed {
            return Err(RequestContinuationError::Consumed);
        }

        self.consumed = true;
        Ok(())
    }

    /// Sends this response header while the continuation remains active.
    pub fn send_header(&mut self) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        self.request.send_header().map_err(Into::into)
    }

    /// Sends this checked response chain while the continuation remains active.
    pub fn output_filter(
        &mut self,
        chain: ChainRef<'_>,
    ) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        self.request.output_filter(chain).map_err(Into::into)
    }

    /// Calls the saved header filter once for this delayed terminal path.
    ///
    /// This keeps the continuation active so the caller can pass the terminal status to
    /// [`finalize`](Self::finalize) after the complete filter sequence.
    pub fn call_next_header<M: HttpFilter>(
        &mut self,
        filters: &HttpFilterSlot<M>,
    ) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        if self.header_continued {
            return Err(RequestContinuationError::HeaderAlreadyContinued);
        }

        self.request.validate_terminal_operation()?;
        let status = filters.call_next_header(&mut self.request)?;
        self.header_continued = true;
        Ok(Status(status))
    }

    /// Calls the saved body filter once for this delayed terminal path.
    ///
    /// This keeps the continuation active so the caller can pass the terminal status to
    /// [`finalize`](Self::finalize) after the complete filter sequence.
    pub fn call_next_body<M: HttpFilter>(
        &mut self,
        filters: &HttpFilterSlot<M>,
        chain: ChainRef<'_>,
    ) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        if self.body_continued {
            return Err(RequestContinuationError::BodyAlreadyContinued);
        }

        self.request.validate_terminal_operation()?;
        let status = filters.call_next_body(&mut self.request, chain)?;
        self.body_continued = true;
        Ok(Status(status))
    }

    /// Finalizes the request and consumes this terminal continuation before entering nginx.
    ///
    /// ```compile_fail
    /// use ngx::http::{HTTPStatus, RequestContinuation};
    ///
    /// fn finalize_then_cancel(continuation: RequestContinuation<'_>) {
    ///     let _ = continuation.finalize(HTTPStatus::BAD_REQUEST);
    ///     let _ = continuation.cancel();
    /// }
    /// ```
    pub fn finalize(mut self, status: impl Into<Status>) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.ensure_releasable_hold()?;
        self.request.validate_terminal_operation()?;
        Self::release_hold(&mut self._hold);
        self.consumed = true;
        let status = status.into();
        unsafe { ngx_http_finalize_request(self.request.raw.as_ptr(), status.0) };
        Ok(())
    }

    /// Resumes PREACCESS processing and consumes this terminal continuation before entering nginx.
    pub fn resume_preaccess(mut self) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.ensure_releasable_hold()?;
        self.request.prepare_preaccess_resume()?;
        Self::release_hold(&mut self._hold);
        self.consumed = true;
        unsafe { ngx_http_core_run_phases(self.request.raw.as_ptr()) };
        Ok(())
    }

    #[cfg(feature = "async")]
    fn resume_phase(mut self) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.ensure_releasable_hold()?;
        {
            let (request, hold) = (&mut self.request, &mut self._hold);
            request.validate_terminal_operation()?;
            let original_handler = unsafe { request.raw.as_ref().write_event_handler };
            unsafe { request.raw.as_mut().write_event_handler = Some(ngx_http_core_run_phases) };
            let request_raw = request.raw.as_ptr();
            let request_is_current = unsafe {
                let connection = request.raw.as_ref().connection;
                (*connection).data == request_raw.cast()
            };
            let posted: Result<(), RequestError> = (|| {
                let mut connection = request.connection_mut()?;
                let mut event = connection.write_event()?;
                if !request_is_current
                    && unsafe { ngx_http_post_request(request_raw, ptr::null_mut()) } != NGX_OK as _
                {
                    return Err(RequestError::Allocation);
                }

                Self::release_hold(hold);
                event.post(PostedQueue::Next);
                Ok(())
            })();
            if let Err(error) = posted {
                unsafe { request.raw.as_mut().write_event_handler = original_handler };
                return Err(error.into());
            }
        }
        self.consumed = true;
        Ok(())
    }
}

impl fmt::Debug for RequestRefMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.view().fmt(f)
    }
}

/// Runs one HTTP callback with a checked exclusive request view and converts its result to an
/// nginx status. Panics from Rust callbacks never unwind through nginx's C ABI.
#[doc(hidden)]
pub unsafe fn request_callback_status<R>(
    request: *mut ngx_http_request_t,
    callback: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
) -> ngx_int_t
where
    R: IntoHandlerStatus,
{
    #[cfg(feature = "std")]
    {
        match catch_unwind(AssertUnwindSafe(|| unsafe {
            RequestRefMut::with_raw(request, |mut request| {
                let result = callback(&mut request);
                result.into_handler_status(&request.view())
            })
        })) {
            Ok(Ok(status)) => status,
            Ok(Err(_)) | Err(_) => NGX_ERROR as _,
        }
    }

    #[cfg(not(feature = "std"))]
    {
        unsafe {
            RequestRefMut::with_raw(request, |mut request| {
                let result = callback(&mut request);
                result.into_handler_status(&request.view())
            })
        }
        .unwrap_or(NGX_ERROR as _)
    }
}

impl conf::sealed::MainConfSource for RequestRef<'_> {}
impl conf::sealed::ServerConfSource for RequestRef<'_> {}
impl conf::sealed::LocationConfSource for RequestRef<'_> {}

impl crate::http::HttpModuleMainConfExt for RequestRef<'_> {
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleMainConfExt>::http_main_conf(
                self.raw.as_ref(),
                module,
            )
        }
    }
}

impl crate::http::HttpModuleServerConfExt for RequestRef<'_> {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleServerConfExt>::http_server_conf(
                self.raw.as_ref(),
                module,
            )
        }
    }
}

impl crate::http::HttpModuleLocationConfExt for RequestRef<'_> {
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleLocationConfExt>::http_location_conf(
                self.raw.as_ref(),
                module,
            )
        }
    }
}

impl conf::sealed::MainConfSource for RequestRefMut<'_> {}
impl conf::sealed::MainConfSourceMut for RequestRefMut<'_> {}
impl conf::sealed::ServerConfSource for RequestRefMut<'_> {}
impl conf::sealed::ServerConfSourceMut for RequestRefMut<'_> {}
impl conf::sealed::LocationConfSource for RequestRefMut<'_> {}
impl conf::sealed::LocationConfSourceMut for RequestRefMut<'_> {}

impl crate::http::HttpModuleMainConfExt for RequestRefMut<'_> {
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleMainConfExt>::http_main_conf(
                self.raw.as_ref(),
                module,
            )
        }
    }
}

impl crate::http::HttpModuleMainConfMutExt for RequestRefMut<'_> {
    unsafe fn http_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleMainConfMutExt>::http_main_conf_mut(
                self.raw.as_mut(),
                module,
            )
        }
    }
}

impl crate::http::HttpModuleServerConfExt for RequestRefMut<'_> {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleServerConfExt>::http_server_conf(
                self.raw.as_ref(),
                module,
            )
        }
    }
}

impl crate::http::HttpModuleServerConfMutExt for RequestRefMut<'_> {
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleServerConfMutExt>::http_server_conf_mut(
                self.raw.as_mut(),
                module,
            )
        }
    }
}

impl crate::http::HttpModuleLocationConfExt for RequestRefMut<'_> {
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleLocationConfExt>::http_location_conf(
                self.raw.as_ref(),
                module,
            )
        }
    }
}

impl crate::http::HttpModuleLocationConfMutExt for RequestRefMut<'_> {
    unsafe fn http_location_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        unsafe {
            <ngx_http_request_t as crate::http::HttpModuleLocationConfMutExt>::http_location_conf_mut(
                self.raw.as_mut(),
                module,
            )
        }
    }
}

/// Iterator for [`ngx_list_t`] types.
///
/// Implementes the core::iter::Iterator trait.
pub struct NgxListIterator<'a>(NgxListIter<'a, ngx_table_elt_t>);

/// Creates new HTTP header iterator
///
/// # Safety
///
/// The list parts must be valid and contain initialized [`ngx_table_elt_t`] values whose key and
/// value strings remain valid for the returned borrow.
pub unsafe fn list_iterator(list: &ngx_list_t) -> NgxListIterator<'_> {
    let list = unsafe { NgxList::from_ngx_list(list) }.expect("HTTP header list type");
    NgxListIterator(list.iter())
}

// iterator for ngx_list_t
impl<'a> Iterator for NgxListIterator<'a> {
    type Item = (&'a NgxStr, &'a NgxStr);

    fn next(&mut self) -> Option<Self::Item> {
        let header = self.0.next()?;
        unsafe { Some((NgxStr::from_ngx_str(header.key), NgxStr::from_ngx_str(header.value))) }
    }
}

/// A possible error value when converting `Method`
pub struct InvalidMethod {
    _priv: (),
}

/// Request method verb
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Method(MethodInner);

impl Method {
    /// UNKNOWN
    pub const UNKNOWN: Method = Method(MethodInner::Unknown);

    /// GET
    pub const GET: Method = Method(MethodInner::Get);

    /// HEAD
    pub const HEAD: Method = Method(MethodInner::Head);

    /// POST
    pub const POST: Method = Method(MethodInner::Post);

    /// PUT
    pub const PUT: Method = Method(MethodInner::Put);

    /// DELETE
    pub const DELETE: Method = Method(MethodInner::Delete);

    /// MKCOL
    pub const MKCOL: Method = Method(MethodInner::Mkcol);

    /// COPY
    pub const COPY: Method = Method(MethodInner::Copy);

    /// MOVE
    pub const MOVE: Method = Method(MethodInner::Move);

    /// OPTIONS
    pub const OPTIONS: Method = Method(MethodInner::Options);

    /// PROPFIND
    pub const PROPFIND: Method = Method(MethodInner::Propfind);

    /// PROPPATCH
    pub const PROPPATCH: Method = Method(MethodInner::Proppatch);

    /// LOCK
    pub const LOCK: Method = Method(MethodInner::Lock);

    /// UNLOCK
    pub const UNLOCK: Method = Method(MethodInner::Unlock);

    /// PATCH
    pub const PATCH: Method = Method(MethodInner::Patch);

    /// TRACE
    pub const TRACE: Method = Method(MethodInner::Trace);

    /// CONNECT
    pub const CONNECT: Method = Method(MethodInner::Connect);

    /// Convert a Method to a &str.
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            MethodInner::Unknown => "UNKNOWN",
            MethodInner::Get => "GET",
            MethodInner::Head => "HEAD",
            MethodInner::Post => "POST",
            MethodInner::Put => "PUT",
            MethodInner::Delete => "DELETE",
            MethodInner::Mkcol => "MKCOL",
            MethodInner::Copy => "COPY",
            MethodInner::Move => "MOVE",
            MethodInner::Options => "OPTIONS",
            MethodInner::Propfind => "PROPFIND",
            MethodInner::Proppatch => "PROPPATCH",
            MethodInner::Lock => "LOCK",
            MethodInner::Unlock => "UNLOCK",
            MethodInner::Patch => "PATCH",
            MethodInner::Trace => "TRACE",
            MethodInner::Connect => "CONNECT",
        }
    }

    fn from_bytes(t: &[u8]) -> Result<Method, InvalidMethod> {
        match t {
            b"GET" => Ok(Self::GET),
            b"HEAD" => Ok(Self::HEAD),
            b"POST" => Ok(Self::POST),
            b"PUT" => Ok(Self::PUT),
            b"DELETE" => Ok(Self::DELETE),
            b"MKCOL" => Ok(Self::MKCOL),
            b"COPY" => Ok(Self::COPY),
            b"MOVE" => Ok(Self::MOVE),
            b"OPTIONS" => Ok(Self::OPTIONS),
            b"PROPFIND" => Ok(Self::PROPFIND),
            b"PROPPATCH" => Ok(Self::PROPPATCH),
            b"LOCK" => Ok(Self::LOCK),
            b"UNLOCK" => Ok(Self::UNLOCK),
            b"PATCH" => Ok(Self::PATCH),
            b"TRACE" => Ok(Self::TRACE),
            b"CONNECT" => Ok(Self::CONNECT),
            _ => Err(InvalidMethod::new()),
        }
    }

    fn from_ngx(t: ngx_uint_t) -> Method {
        let t = t as _;
        match t {
            crate::ffi::NGX_HTTP_GET => Method(MethodInner::Get),
            crate::ffi::NGX_HTTP_HEAD => Method(MethodInner::Head),
            crate::ffi::NGX_HTTP_POST => Method(MethodInner::Post),
            crate::ffi::NGX_HTTP_PUT => Method(MethodInner::Put),
            crate::ffi::NGX_HTTP_DELETE => Method(MethodInner::Delete),
            crate::ffi::NGX_HTTP_MKCOL => Method(MethodInner::Mkcol),
            crate::ffi::NGX_HTTP_COPY => Method(MethodInner::Copy),
            crate::ffi::NGX_HTTP_MOVE => Method(MethodInner::Move),
            crate::ffi::NGX_HTTP_OPTIONS => Method(MethodInner::Options),
            crate::ffi::NGX_HTTP_PROPFIND => Method(MethodInner::Propfind),
            crate::ffi::NGX_HTTP_PROPPATCH => Method(MethodInner::Proppatch),
            crate::ffi::NGX_HTTP_LOCK => Method(MethodInner::Lock),
            crate::ffi::NGX_HTTP_UNLOCK => Method(MethodInner::Unlock),
            crate::ffi::NGX_HTTP_PATCH => Method(MethodInner::Patch),
            crate::ffi::NGX_HTTP_TRACE => Method(MethodInner::Trace),
            #[cfg(nginx1_21_1)]
            crate::ffi::NGX_HTTP_CONNECT => Method(MethodInner::Connect),
            _ => Method(MethodInner::Unknown),
        }
    }
}

impl AsRef<str> for Method {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'a> PartialEq<&'a Method> for Method {
    #[inline]
    fn eq(&self, other: &&'a Method) -> bool {
        self == *other
    }
}

impl PartialEq<Method> for &Method {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        *self == other
    }
}

impl PartialEq<str> for Method {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<Method> for str {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        self == other.as_ref()
    }
}

impl<'a> PartialEq<&'a str> for Method {
    #[inline]
    fn eq(&self, other: &&'a str) -> bool {
        self.as_ref() == *other
    }
}

impl PartialEq<Method> for &str {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        *self == other.as_ref()
    }
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl fmt::Display for Method {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.as_ref())
    }
}

impl<'a> From<&'a Method> for Method {
    #[inline]
    fn from(t: &'a Method) -> Self {
        t.clone()
    }
}

impl<'a> TryFrom<&'a [u8]> for Method {
    type Error = InvalidMethod;

    #[inline]
    fn try_from(t: &'a [u8]) -> Result<Self, Self::Error> {
        Method::from_bytes(t)
    }
}

impl<'a> TryFrom<&'a str> for Method {
    type Error = InvalidMethod;

    #[inline]
    fn try_from(t: &'a str) -> Result<Self, Self::Error> {
        TryFrom::try_from(t.as_bytes())
    }
}

impl FromStr for Method {
    type Err = InvalidMethod;

    #[inline]
    fn from_str(t: &str) -> Result<Self, Self::Err> {
        TryFrom::try_from(t)
    }
}

impl InvalidMethod {
    fn new() -> InvalidMethod {
        InvalidMethod { _priv: () }
    }
}

impl fmt::Debug for InvalidMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("InvalidMethod")
            // skip _priv noise
            .finish()
    }
}

impl fmt::Display for InvalidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid HTTP method")
    }
}

impl error::Error for InvalidMethod {}

#[derive(Clone, PartialEq, Eq, Hash)]
enum MethodInner {
    Unknown,
    Get,
    Head,
    Post,
    Put,
    Delete,
    Mkcol,
    Copy,
    Move,
    Options,
    Propfind,
    Proppatch,
    Lock,
    Unlock,
    Patch,
    Trace,
    Connect,
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{boxed::Box, vec, vec::Vec};
    #[cfg(all(feature = "test-link", unix))]
    use core::ffi::c_int;
    #[cfg(all(feature = "test-link", unix))]
    use core::mem::ManuallyDrop;
    use core::mem::MaybeUninit;
    #[cfg(feature = "test-link")]
    use core::pin::Pin;
    #[cfg(feature = "test-link")]
    use core::ptr;
    #[cfg(feature = "test-link")]
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    #[cfg(feature = "test-link")]
    use core::{ffi::c_void, marker::PhantomPinned};
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
    #[cfg(feature = "test-link")]
    use crate::event::{PostedEvent, PostedEventCallback, PostedQueue, Timer, TimerCallback};
    use crate::http::{HttpModule, HttpModuleRequestContext};

    #[cfg(feature = "test-link")]
    use crate::ffi::{
        ngx_create_pool, ngx_current_msec, ngx_cycle_t, ngx_destroy_pool, ngx_event_expire_timers,
        ngx_event_move_posted_next, ngx_event_process_posted, ngx_event_timer_init, ngx_log_t,
        ngx_pool_t, ngx_posted_events, ngx_posted_next_events, ngx_queue_init, ngx_uint_t,
    };

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    #[cfg(all(feature = "test-link", unix))]
    unsafe extern "C" {
        fn fcntl(fd: ngx_fd_t, command: c_int) -> c_int;
    }

    #[cfg(all(feature = "test-link", unix))]
    const F_GETFD: c_int = 1;

    struct TestContextModule;

    unsafe impl HttpModule for TestContextModule {
        fn module() -> &'static ngx_module_t {
            Box::leak(Box::new(ngx_module_t {
                type_: NGX_HTTP_MODULE as _,
                index: 0,
                ctx_index: 0,
                ..ngx_module_t::default()
            }))
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
        fn module() -> &'static ngx_module_t {
            Box::leak(Box::new(ngx_module_t {
                type_: NGX_HTTP_MODULE as _,
                index: 0,
                ctx_index: 0,
                ..ngx_module_t::default()
            }))
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
        timer: Timer<(), TimerContextCallback>,
        posted: PostedEvent<(), PostedContextCallback>,
    }

    #[cfg(feature = "test-link")]
    impl Drop for EventContext {
        fn drop(&mut self) {
            EVENT_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct EventContextModule;

    #[cfg(feature = "test-link")]
    unsafe impl HttpModule for EventContextModule {
        fn module() -> &'static ngx_module_t {
            Box::leak(Box::new(ngx_module_t {
                type_: NGX_HTTP_MODULE as _,
                index: 0,
                ctx_index: 0,
                ..ngx_module_t::default()
            }))
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

    http_request_handler!(callback_status_handler, |_: &mut RequestRefMut<'_>| {
        Status::NGX_AGAIN
    });
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
            ) = unsafe {
                let module = &raw const nginx_sys::ngx_http_core_module;
                (
                    nginx_sys::ngx_max_module,
                    nginx_sys::ngx_http_max_module,
                    (*module).type_,
                    (*module).index,
                    (*module).ctx_index,
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
    }

    #[cfg(feature = "test-link")]
    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
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
            let mut path: Box<ngx_path_t> =
                Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
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
            self.path.name =
                ngx_str_t { len: self.path_name.len(), data: self.path_name.as_mut_ptr() };
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
    ) -> (BufferRef<'pool>, NonNull<ngx_file_t>) {
        let mut file = NonNull::new(pool.calloc_type::<ngx_file_t>()).unwrap();
        let mut buffer = NonNull::new(pool.calloc_type::<ngx_buf_t>()).unwrap();
        unsafe {
            file.as_mut().fd = fd;
            let buffer = buffer.as_mut();
            buffer.file = file.as_ptr();
            buffer.file_pos = start;
            buffer.file_last = end;
            buffer.set_in_file(1);
            buffer.set_flush(u32::from(flags.flush));
            buffer.set_sync(u32::from(flags.sync));
            buffer.set_last_buf(u32::from(flags.last_buf));
            buffer.set_last_in_chain(u32::from(flags.last_in_chain));
        }
        (unsafe { BufferRef::from_raw(buffer.as_ptr()) }.unwrap(), file)
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
    fn request_views_validate_pool_connection_and_logger_pointers() {
        let mut missing_pool = zeroed_request();
        assert!(matches!(request_from(&mut missing_pool).pool(), Err(RequestError::MissingPool)));

        let mut misaligned_pool = zeroed_request();
        misaligned_pool.pool = core::ptr::without_provenance_mut(1);
        assert!(matches!(
            request_from(&mut misaligned_pool).pool(),
            Err(RequestError::MisalignedPool)
        ));

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

    #[cfg(feature = "std")]
    #[test]
    fn callback_boundary_catches_panics() {
        let mut raw = zeroed_request();
        initialize_request(&mut raw);

        assert_eq!(
            unsafe {
                request_callback_status(&raw mut raw, |_| -> Status { panic!("callback panic") })
            },
            NGX_ERROR as _
        );
    }

    #[test]
    fn header_iterator_returns_keys_and_values() {
        let mut headers: [ngx_table_elt_t; 2] = unsafe { MaybeUninit::zeroed().assume_init() };
        headers[0].key = crate::ngx_string!("X-First");
        headers[0].value = crate::ngx_string!("one");
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
    fn checked_header_views_keep_raw_bytes_parts_and_disabled_entries() {
        let input_key = [b'X', b'-', 0xff];
        let input_value = [0, 0xff];
        let input_lowcase = [b'x', b'-', 0xff];
        let mut input_headers: [ngx_table_elt_t; 1] =
            unsafe { MaybeUninit::zeroed().assume_init() };
        input_headers[0].hash = 17;
        input_headers[0].key =
            ngx_str_t { len: input_key.len(), data: input_key.as_ptr().cast_mut() };
        input_headers[0].value =
            ngx_str_t { len: input_value.len(), data: input_value.as_ptr().cast_mut() };
        input_headers[0].lowcase_key = input_lowcase.as_ptr().cast_mut();

        let mut empty_headers: [ngx_table_elt_t; 1] =
            unsafe { MaybeUninit::zeroed().assume_init() };
        let disabled_key = *b"X-Disabled";
        let disabled_value = [0xff, b'!'];
        let disabled_lowcase = *b"x-disabled";
        let mut disabled_headers: [ngx_table_elt_t; 1] =
            unsafe { MaybeUninit::zeroed().assume_init() };
        disabled_headers[0].hash = 0;
        disabled_headers[0].key =
            ngx_str_t { len: disabled_key.len(), data: disabled_key.as_ptr().cast_mut() };
        disabled_headers[0].value =
            ngx_str_t { len: disabled_value.len(), data: disabled_value.as_ptr().cast_mut() };
        disabled_headers[0].lowcase_key = disabled_lowcase.as_ptr().cast_mut();

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
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].key(), input_key);
        assert_eq!(headers[0].value(), input_value);
        assert_eq!(headers[0].lowercase_key(), Some(input_lowcase.as_slice()));
        assert_eq!(headers[0].hash(), 17);
        assert!(headers[0].is_enabled());
        assert_eq!(headers[1].key(), disabled_key);
        assert_eq!(headers[1].value(), disabled_value);
        assert_eq!(headers[1].lowercase_key(), Some(disabled_lowcase.as_slice()));
        assert!(!headers[1].is_enabled());

        let output_key = [b'Y', 0xfe];
        let output_value = [0xff, b'!'];
        let output_lowcase = [b'y', 0xfe];
        let mut output_headers: [ngx_table_elt_t; 1] =
            unsafe { MaybeUninit::zeroed().assume_init() };
        output_headers[0].hash = 23;
        output_headers[0].key =
            ngx_str_t { len: output_key.len(), data: output_key.as_ptr().cast_mut() };
        output_headers[0].value =
            ngx_str_t { len: output_value.len(), data: output_value.as_ptr().cast_mut() };
        output_headers[0].lowcase_key = output_lowcase.as_ptr().cast_mut();
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
        assert_eq!(header.lowercase_key(), Some(output_lowcase.as_slice()));
        assert_eq!(header.hash(), 23);
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
        assert!(matches!(
            request_from(&mut raw).headers_in(),
            Err(HeaderListError::MissingKeyData)
        ));

        let key = *b"X";
        let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
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
        assert!(matches!(
            request_from(&mut raw).headers_in(),
            Err(HeaderListError::MissingValueData)
        ));

        let mut header: ngx_table_elt_t = unsafe { MaybeUninit::zeroed().assume_init() };
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
            let mut headers = request.headers_in_builder(1).unwrap();
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
            unsafe { checked_ngx_str((*raw.headers_in.proxy_authorization).value) }
                .unwrap()
                .as_bytes(),
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
            unsafe { checked_ngx_str((*raw.headers_in.if_modified_since).value) }
                .unwrap()
                .as_bytes(),
            b"Wed, 21 Oct 2015 07:28:00 GMT"
        );
        assert_eq!(
            unsafe { checked_ngx_str((*raw.headers_in.if_unmodified_since).value) }
                .unwrap()
                .as_bytes(),
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
            (b"Content-Length".as_slice(), b"91".as_slice()),
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
        assert_eq!(
            unsafe { checked_ngx_str((*raw.headers_out.content_length).value) }.unwrap().as_bytes(),
            b"91"
        );
        assert_eq!(
            unsafe { checked_ngx_str((*raw.headers_out.content_encoding).value) }
                .unwrap()
                .as_bytes(),
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
            unsafe { checked_ngx_str((*raw.headers_out.www_authenticate).value) }
                .unwrap()
                .as_bytes(),
            b"Basic"
        );
        assert_eq!(
            unsafe { checked_ngx_str((*raw.headers_out.proxy_authenticate).value) }
                .unwrap()
                .as_bytes(),
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
                .filter(|header| header.key().eq_ignore_ascii_case(b"Content-Type"))
                .count(),
            0
        );
        assert_eq!(headers.iter().filter(|header| header.key() == b"X-Duplicate").count(), 2);
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

        {
            let mut headers = request.clean_headers_out_builder(1).unwrap();
            headers.add(b"Content-Type", b"text/plain").unwrap();
            headers.commit();
        }

        assert!(!body.into_raw().is_null());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn request_body_builder_copies_bytes_and_replaces_framing() {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;

        {
            let mut request = request_from(&mut raw);
            let mut headers = request.headers_in_builder(1).unwrap();
            headers.add(b"Host", b"example.test").unwrap();
            headers.add(b"Content-Length", b"99").unwrap();
            headers.add(b"Transfer-Encoding", b"chunked").unwrap();
            headers.commit();
        }

        raw.headers_in.content_length_n = 99;
        raw.headers_in.set_chunked(1);
        let mut previous_body: ngx_http_request_body_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
        let mut previous_temp_file: ngx_temp_file_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
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
        let mut content_length_count = 0;
        let mut disabled_content_length_count = 0;
        let mut disabled_transfer_encoding_count = 0;
        for header in headers.iter() {
            if header.is_enabled() && header.key().eq_ignore_ascii_case(b"Content-Length") {
                content_length_count += 1;
                assert_eq!(header.value(), b"3");
            }
            if !header.is_enabled() && header.key().eq_ignore_ascii_case(b"Content-Length") {
                disabled_content_length_count += 1;
            }
            if !header.is_enabled() && header.key().eq_ignore_ascii_case(b"Transfer-Encoding") {
                disabled_transfer_encoding_count += 1;
            }
        }
        assert_eq!(content_length_count, 1);
        assert_eq!(disabled_content_length_count, 1);
        assert_eq!(disabled_transfer_encoding_count, 1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn input_header_builder_publishes_replacement_body_and_framing_together() {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        let mut previous_body: ngx_http_request_body_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
        let mut previous_temp_file: ngx_temp_file_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
        previous_body.temp_file = &raw mut previous_temp_file;
        raw.request_body = &raw mut previous_body;

        {
            let mut request = request_from(&mut raw);
            let mut headers = request.headers_in_builder(1).unwrap();
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
                (b"Content-Length".to_vec(), b"99".to_vec(), false),
                (b"Transfer-Encoding".to_vec(), b"chunked".to_vec(), false),
                (b"Content-Length".to_vec(), b"11".to_vec(), true),
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
    fn input_header_builder_clears_body_and_replaces_framing_together() {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        let mut previous_temp_file: ngx_temp_file_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
        let mut previous_buffer: ngx_buf_t = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut previous_chain: ngx_chain_t = unsafe { MaybeUninit::zeroed().assume_init() };
        previous_chain.buf = &raw mut previous_buffer;
        let mut previous_body: ngx_http_request_body_t =
            unsafe { MaybeUninit::zeroed().assume_init() };
        previous_body.temp_file = &raw mut previous_temp_file;
        previous_body.bufs = &raw mut previous_chain;
        raw.request_body = &raw mut previous_body;

        {
            let mut request = request_from(&mut raw);
            let mut headers = request.headers_in_builder(1).unwrap();
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
                (b"Content-Length".to_vec(), b"99".to_vec(), false),
                (b"Transfer-Encoding".to_vec(), b"chunked".to_vec(), false),
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
            let headers = request.headers_in_builder(1).unwrap();
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
                let mut headers = request.headers_in_builder(1).unwrap();
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
                let mut headers = request.headers_in_builder(1)?;
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
    fn temp_file_writer_lazily_writes_memory_with_clean_pool_cleanup() {
        let deleted_path;
        #[cfg(unix)]
        let fd;
        {
            let mut fixture = TempFileFixture::new();
            {
                let flags =
                    BufferFlags { flush: true, last_in_chain: true, ..BufferFlags::default() };
                let request = request_from(&mut fixture.request);
                let pool = request.pool().unwrap();
                let mut input = pool.chain();
                input.append(pool.copy_buffer(b"body", flags).unwrap()).unwrap();
                let mut writer = request.temp_file().unwrap();

                assert!(writer.temp_file.is_none());

                let output = writer.append(chain_ref(input)).unwrap();
                let temp = writer.temp_file.unwrap();
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
                assert_ne!(output_file.file_ptr(), native_file);
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
        assert!(writer.temp_file.is_none());
        let empty_output = empty_output.iter().next().unwrap().unwrap();
        assert_eq!(empty_output.flags(), zero_flags);
        assert!(matches!(empty_output.kind(), Ok(BufferView::Control(_))));

        let first_output = writer.append(chain_ref(first_input)).unwrap();
        let second_output = writer.append(chain_ref(second_input)).unwrap();
        let temp = writer.temp_file.unwrap();
        let native = unsafe { temp.as_ref() };
        assert_eq!(native.offset, 6);
        assert_eq!(
            first_output.iter().next().unwrap().unwrap().file().unwrap().unwrap().start(),
            0
        );
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
        input.append_borrowed(file).unwrap();
        input.append(pool.control_buffer(control_flags).unwrap()).unwrap();
        input.append(pool.copy_buffer(b"right", last_flags).unwrap()).unwrap();
        let mut writer = request.temp_file().unwrap();

        let output = writer.append(chain_ref(input)).unwrap();
        let temp = writer.temp_file.unwrap();
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
        assert_ne!(file_view.file_ptr(), source_file.as_ptr());

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
        input.append_borrowed(file).unwrap();
        let mut writer = request.temp_file().unwrap();

        let output = writer.append(chain_ref(input)).unwrap();
        assert!(writer.temp_file.is_none());
        let output = output.iter().next().unwrap().unwrap();
        assert_eq!(output.flags(), flags);
        let file = output.file().unwrap().unwrap();
        assert_eq!((file.start(), file.end()), (11, 16));
        assert_eq!(unsafe { (*file.file_ptr()).fd }, unsafe { source_file.as_ref().fd });
        assert_ne!(file.file_ptr(), source_file.as_ptr());
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
        input.append_borrowed(invalid).unwrap();
        let mut writer = request.temp_file().unwrap();

        assert!(matches!(
            writer.append(chain_ref(input)),
            Err(RequestTempFileError::Buffer(BufferError::InvalidFileRange))
        ));
        assert!(writer.temp_file.is_none());
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
                unsafe { writer.temp_file.unwrap().as_ref().file.fd },
                NGX_INVALID_FILE as _
            );
        }

        {
            let mut fixture = TempFileFixture::new();
            let request = request_from(&mut fixture.request);
            let pool = request.pool().unwrap();
            let mut first_input = pool.chain();
            first_input
                .append(pool.copy_buffer(b"first", BufferFlags::default()).unwrap())
                .unwrap();
            let mut second_input = pool.chain();
            second_input
                .append(pool.copy_buffer(b"second", BufferFlags::default()).unwrap())
                .unwrap();
            let mut writer = request.temp_file().unwrap();
            writer.append(chain_ref(first_input)).unwrap();
            let mut temp = writer.temp_file.unwrap();
            let offset = unsafe { temp.as_ref().offset };
            let advanced_offset = offset + 2;
            unsafe {
                temp.as_mut().file.offset = advanced_offset;
                temp.as_mut().file.fd = NGX_INVALID_FILE as ngx_fd_t - 1;
            }

            assert!(matches!(
                writer.append(chain_ref(second_input)),
                Err(RequestTempFileError::Write)
            ));
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
            first_input
                .append(pool.copy_buffer(b"first", BufferFlags::default()).unwrap())
                .unwrap();
            let mut second_input = pool.chain();
            second_input
                .append(pool.copy_buffer(b"second", BufferFlags::default()).unwrap())
                .unwrap();
            let mut writer = request.temp_file().unwrap();

            unsafe {
                (*fixture.pool.raw).max = 0;
                ngx_rs_test_fail_allocations_after(successes);
            }
            let failed = writer.append(chain_ref(first_input));
            unsafe { ngx_rs_test_reset_allocation_failures() };

            let Some(temp) = writer.temp_file else {
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
        let mut invalid_file_link =
            ngx_chain_t { buf: &raw mut invalid_file, next: ptr::null_mut() };
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
        assert_eq!(
            ClientBodyReadStatus::from_raw(NGX_AGAIN as ngx_int_t),
            ClientBodyReadStatus::Again
        );
        assert_eq!(
            ClientBodyReadStatus::from_raw(NGX_DONE as ngx_int_t),
            ClientBodyReadStatus::Done
        );
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
        let mut main = zeroed_request();
        initialize_request(&mut main);
        main.set_count(1);

        let mut raw = zeroed_request();
        raw.main = &raw mut main;
        raw.parent = &raw mut main;
        let mut hold = None;

        let mut request = request_from(&mut raw);
        assert!(hold.is_none());
        assert_eq!(main.count(), 1);
        request.hold(&mut hold).unwrap();
        assert_eq!(main.count(), 2);
        assert_eq!(request.hold(&mut hold), Err(RequestHoldError::AlreadyHeld));

        let continuation = RequestHold::take(&mut hold, request).unwrap();
        assert!(hold.is_none());
        drop(continuation);

        let request = request_from(&mut raw);
        assert!(matches!(RequestHold::take(&mut hold, request), Err(RequestHoldError::Missing)));
        assert_eq!(main.count(), 2);
    }

    #[test]
    fn request_hold_rejects_inactive_and_full_main_counts() {
        let mut main = zeroed_request();
        initialize_request(&mut main);

        let mut raw = zeroed_request();
        raw.main = &raw mut main;
        raw.parent = &raw mut main;
        let mut hold = None;
        let mut request = request_from(&mut raw);

        assert_eq!(request.hold(&mut hold), Err(RequestHoldError::InactiveMain));
        assert!(hold.is_none());

        main.set_count(u16::MAX.into());
        assert_eq!(request.hold(&mut hold), Err(RequestHoldError::CountOverflow));
        assert!(hold.is_none());
        assert_eq!(main.count(), u16::MAX.into());
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
        first.hold(&mut hold).unwrap();
        let second = request_from(&mut second);
        assert!(matches!(
            RequestHold::take(&mut hold, second),
            Err(RequestHoldError::ForeignRequest)
        ));
        assert!(hold.is_some());
        assert_eq!(main.count(), 2);
    }

    #[test]
    fn request_hold_cannot_continue_an_invalidated_main_count() {
        let mut main = zeroed_request();
        initialize_request(&mut main);
        main.set_count(1);

        let mut raw = zeroed_request();
        raw.main = &raw mut main;
        raw.parent = &raw mut main;
        let mut hold = None;
        {
            let mut request = request_from(&mut raw);
            request.hold(&mut hold).unwrap();
        }
        main.set_count(1);

        let request = request_from(&mut raw);
        assert!(matches!(
            RequestHold::take(&mut hold, request),
            Err(RequestHoldError::InactiveMain)
        ));
        assert!(hold.is_some());

        main.set_count(0);
        let request = request_from(&mut raw);
        assert!(matches!(
            RequestHold::take(&mut hold, request),
            Err(RequestHoldError::InactiveMain)
        ));
        assert!(hold.is_some());
    }

    #[test]
    fn request_continuation_cancellation_prevents_reentry() {
        let mut main = zeroed_request();
        initialize_request(&mut main);
        main.set_count(1);

        let mut raw = zeroed_request();
        raw.main = &raw mut main;
        raw.parent = &raw mut main;
        let mut hold = None;

        let mut request = request_from(&mut raw);
        request.hold(&mut hold).unwrap();
        let mut continuation = RequestHold::take(&mut hold, request).unwrap();

        assert_eq!(continuation.cancel(), Ok(()));
        assert_eq!(continuation.cancel(), Err(RequestContinuationError::Consumed));
        assert_eq!(main.count(), 2);
    }

    #[test]
    fn request_hold_cleanup_cancels_once_without_finalizing() {
        let mut main = zeroed_request();
        initialize_request(&mut main);
        main.set_count(1);

        let mut raw = zeroed_request();
        raw.main = &raw mut main;
        raw.parent = &raw mut main;
        let mut hold = None;
        let mut request = request_from(&mut raw);
        request.hold(&mut hold).unwrap();

        assert!(RequestHold::cancel(&mut hold));
        assert!(!RequestHold::cancel(&mut hold));
        assert_eq!(main.count(), 2);
    }

    #[test]
    fn cancelled_continuation_rejects_nonterminal_and_terminal_operations() {
        let mut main = zeroed_request();
        initialize_request(&mut main);
        main.set_count(1);

        let mut raw = zeroed_request();
        raw.main = &raw mut main;
        raw.parent = &raw mut main;
        let mut hold = None;

        let mut request = request_from(&mut raw);
        request.hold(&mut hold).unwrap();
        let mut continuation = RequestHold::take(&mut hold, request).unwrap();
        continuation.cancel().unwrap();
        let chain = unsafe { ChainRef::from_raw(core::ptr::null_mut()).unwrap() };

        assert_eq!(continuation.send_header(), Err(RequestContinuationError::Consumed));
        assert_eq!(continuation.output_filter(chain), Err(RequestContinuationError::Consumed));
        assert_eq!(
            continuation.finalize(HTTPStatus::BAD_REQUEST),
            Err(RequestContinuationError::Consumed)
        );
        assert_eq!(main.count(), 2);

        let mut resume_main = zeroed_request();
        initialize_request(&mut resume_main);
        resume_main.set_count(1);
        let mut resume_raw = zeroed_request();
        resume_raw.main = &raw mut resume_main;
        resume_raw.parent = &raw mut resume_main;
        let mut resume_hold = None;
        let mut request = request_from(&mut resume_raw);
        request.hold(&mut resume_hold).unwrap();
        let mut continuation = RequestHold::take(&mut resume_hold, request).unwrap();
        continuation.cancel().unwrap();

        assert_eq!(continuation.resume_preaccess(), Err(RequestContinuationError::Consumed));
    }

    #[test]
    fn terminal_operations_reject_requests_without_connections() {
        let mut raw = zeroed_request();
        let mut request = request_from(&mut raw);
        let chain = unsafe { ChainRef::from_raw(core::ptr::null_mut()).unwrap() };
        let expected = RequestError::Connection(ConnectionError::NullConnection);

        assert_eq!(request.send_header(), Err(expected));
        assert_eq!(request.output_filter(chain), Err(expected));

        let mut finalize_raw = zeroed_request();
        assert_eq!(
            request_from(&mut finalize_raw).finalize(HTTPStatus::BAD_REQUEST),
            Err(expected)
        );

        let mut resume_raw = zeroed_request();
        assert_eq!(
            request_from(&mut resume_raw).resume_preaccess(),
            Err(RequestPhaseResumeError::Request(expected))
        );
    }

    #[test]
    fn invalidated_continuations_reject_terminal_operations() {
        let mut main = zeroed_request();
        initialize_request(&mut main);
        main.set_count(1);

        let mut raw = zeroed_request();
        raw.main = &raw mut main;
        raw.parent = &raw mut main;
        let mut hold = None;
        let expected = RequestError::Connection(ConnectionError::NullConnection);
        let mut request = request_from(&mut raw);
        request.hold(&mut hold).unwrap();
        let continuation = RequestHold::take(&mut hold, request).unwrap();

        assert_eq!(
            continuation.finalize(HTTPStatus::BAD_REQUEST),
            Err(RequestContinuationError::Request(expected))
        );

        let mut resume_main = zeroed_request();
        initialize_request(&mut resume_main);
        resume_main.set_count(1);
        let mut resume_raw = zeroed_request();
        resume_raw.main = &raw mut resume_main;
        resume_raw.parent = &raw mut resume_main;
        let mut resume_hold = None;
        let mut request = request_from(&mut resume_raw);
        request.hold(&mut resume_hold).unwrap();
        let continuation = RequestHold::take(&mut resume_hold, request).unwrap();

        assert_eq!(
            continuation.resume_preaccess(),
            Err(RequestContinuationError::Phase(RequestPhaseResumeError::Request(expected)))
        );
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
    fn client_body_read_invokes_once_and_ignores_cancelled_or_invalid_callbacks() {
        let _globals = RequestGlobals::new(0, 0);
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        let mut body: ngx_http_request_body_t = unsafe { MaybeUninit::zeroed().assume_init() };
        raw.request_body = &raw mut body;

        BODY_CALLBACKS.store(0, Ordering::Relaxed);
        BODY_CALLBACK_ACTIVE.store(false, Ordering::Relaxed);
        assert_eq!(
            request_from(&mut raw).read_client_body::<BodyCallback>(),
            ClientBodyReadStatus::Ok
        );
        assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 0);

        BODY_CALLBACK_ACTIVE.store(true, Ordering::Relaxed);
        assert_eq!(
            request_from(&mut raw).read_client_body::<BodyCallback>(),
            ClientBodyReadStatus::Ok
        );
        assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 1);

        BODY_CALLBACK_ACTIVE.store(false, Ordering::Relaxed);
        unsafe { raw_client_body_handler::<BodyCallback>(&raw mut raw) };
        unsafe { raw_client_body_handler::<BodyCallback>(ptr::null_mut()) };
        let mut storage = [0_u8;
            core::mem::size_of::<ngx_http_request_t>()
                + core::mem::align_of::<ngx_http_request_t>()];
        unsafe { raw_client_body_handler::<BodyCallback>(storage.as_mut_ptr().add(1).cast()) };
        assert_eq!(BODY_CALLBACKS.load(Ordering::Relaxed), 1);
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
        unsafe {
            (*owner.raw).max = 0;
            ngx_rs_test_fail_allocations_after(0);
        }
        let status = request_from(&mut raw).read_client_body::<BodyCallback>();
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert_eq!(status, ClientBodyReadStatus::Special(HTTPStatus::INTERNAL_SERVER_ERROR));
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
            request.headers_in_builder(1).unwrap().commit();
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
    fn request_body_builder_copies_file_metadata_and_keeps_control_links() {
        let owner = TestPool::new();
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        {
            let mut request = request_from(&mut raw);
            request.headers_in_builder(1).unwrap().commit();
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
                assert!(!ptr::eq(view.file_ptr(), &raw mut file));
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
            request.headers_in_builder(1).unwrap().commit();
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
                let mut headers = request.headers_in_builder(1).unwrap();
                headers.add(b"Host", b"example.test").unwrap();
                headers.add(b"Content-Length", b"7").unwrap();
                headers.add(b"Transfer-Encoding", b"chunked").unwrap();
                headers.commit();
            }
            raw.headers_in.content_length_n = 7;
            raw.headers_in.set_chunked(1);
            let mut old_temp_file: ngx_temp_file_t = unsafe { MaybeUninit::zeroed().assume_init() };
            let mut old_body: ngx_http_request_body_t =
                unsafe { MaybeUninit::zeroed().assume_init() };
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
                let mut headers = request.headers_in_builder(1)?;
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
            let mut headers = request.headers_in_builder(1).unwrap();
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
            request.headers_in_builder(1).unwrap().commit();
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

        assert!(matches!(request.headers_in_builder(0), Err(HeaderBuildError::InvalidCapacity)));
        assert!(matches!(request.headers_out_builder(0), Err(HeaderBuildError::InvalidCapacity)));
        assert!(matches!(
            request.headers_in_builder(capacity),
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

    #[test]
    fn internal_redirect_flag_is_exposed() {
        let mut raw = zeroed_request();

        assert!(!request_from(&mut raw).is_internal());

        raw.set_internal(1);
        assert!(request_from(&mut raw).is_internal());
    }

    #[test]
    fn subrequests_available_reports_the_remaining_nested_budget() {
        let mut raw = zeroed_request();

        raw.set_subrequests(3);
        assert_eq!(request_from(&mut raw).subrequests_available(), 2);

        raw.set_subrequests(1);
        assert_eq!(request_from(&mut raw).subrequests_available(), 0);

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
        let mut raw_main = zeroed_request();
        initialize_request(&mut raw_main);
        let mut raw_subrequest = zeroed_request();
        initialize_request(&mut raw_subrequest);
        raw_subrequest.main = &raw mut raw_main;
        raw_subrequest.parent = &raw mut raw_main;

        let mut request = request_from(&mut raw_subrequest);
        let main = request.main_mut().unwrap();
        unsafe { (*main.as_ptr()).request_length = 4096 };

        assert_eq!(raw_main.request_length, 4096);
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

            let context =
                request.pinned_module_context_mut::<PinnedContextModule>().unwrap().unwrap();
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
                request.try_get_or_insert_pinned_module_context_with::<PinnedContextModule, _>(
                    || { Err::<PinnedContext, _>(ConstructorError::Rejected) }
                ),
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

        for successes in 0..=1 {
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
        let mut owner = TestPool::new();
        let log = owner.log();
        let mut slots: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_request();
        raw.pool = owner.raw;
        raw.ctx = slots.as_mut_ptr();

        {
            let mut request = request_from(&mut raw);
            let mut context = request
                .get_or_insert_pinned_module_context_with::<EventContextModule>(|| EventContext {
                    timer: Timer::new(log, (), timer_context_callback as TimerContextCallback),
                    posted: PostedEvent::new(
                        log,
                        (),
                        posted_context_callback as PostedContextCallback,
                    ),
                })
                .unwrap();
            let mut timer =
                unsafe { context.as_mut().map_unchecked_mut(|context| &mut context.timer) };
            timer.as_mut().arm(5).unwrap();
            let mut posted =
                unsafe { context.as_mut().map_unchecked_mut(|context| &mut context.posted) };
            assert_eq!(posted.as_mut().post(PostedQueue::Next), Ok(true));
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
}
