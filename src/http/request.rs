use core::error;
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use core::slice;
use core::str::FromStr;

#[cfg(feature = "std")]
use core::panic::AssertUnwindSafe;
#[cfg(feature = "std")]
use std::panic::catch_unwind;

use crate::collections::{NgxList, list::NgxListIter};
use crate::core::*;
use crate::ffi::*;
use crate::http::status::*;
use crate::http::{HttpConfigError, HttpModuleRequestContext, HttpPhase, conf};

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

impl RequestRefMut<'_> {
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

    /// Exclusive context associated with module `M` for this request.
    pub fn module_context_mut<M>(
        &mut self,
    ) -> Result<Option<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let slot = self.view().module_context_slot(M::module())?;
        Ok(RequestRef::context_from_slot::<M::RequestContext>(slot)?
            .map(|mut context| unsafe { context.as_mut() }))
    }

    /// Returns the module context, inserting a pool-owned value when absent.
    pub fn get_or_insert_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<&mut M::RequestContext, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let slot = self.view().module_context_slot(M::module())?;
        if let Some(mut context) = RequestRef::context_from_slot::<M::RequestContext>(slot)? {
            return Ok(unsafe { context.as_mut() });
        }

        let mut context = self
            .pool()?
            .allocate_with_cleanup(constructor)
            .map_err(|_| RequestContextError::Allocation)?
            .into_non_null();
        unsafe { *slot.as_ptr() = context.as_ptr().cast() };
        Ok(unsafe { context.as_mut() })
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
        if unsafe { pool.remove_cleanup(context) } {
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
    pub fn send_header(&mut self) -> Status {
        Status(unsafe { ngx_http_send_header(self.raw.as_ptr()) })
    }

    /// Sends a response body through nginx's current output filter.
    pub fn output_filter(&mut self, body: &mut ngx_chain_t) -> Status {
        Status(unsafe { ngx_http_output_filter(self.raw.as_ptr(), body) })
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

    use alloc::{boxed::Box, vec::Vec};
    use core::mem::MaybeUninit;
    #[cfg(feature = "test-link")]
    use std::sync::MutexGuard;

    use super::*;
    use crate::http::{HttpModule, HttpModuleRequestContext};

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
    }

    #[cfg(feature = "test-link")]
    impl RequestGlobals {
        fn new(module_slots: ngx_uint_t, http_slots: ngx_uint_t) -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let (max_module, http_max_module) =
                unsafe { (nginx_sys::ngx_max_module, nginx_sys::ngx_http_max_module) };
            unsafe {
                nginx_sys::ngx_max_module = module_slots;
                nginx_sys::ngx_http_max_module = http_slots;
            }
            Self { _guard: guard, max_module, http_max_module }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for RequestGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_max_module = self.max_module;
                nginx_sys::ngx_http_max_module = self.http_max_module;
            }
        }
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
