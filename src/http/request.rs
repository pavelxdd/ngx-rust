use core::error;
use core::ffi::c_void;
use core::fmt;
use core::ptr::NonNull;
use core::slice;
use core::str::FromStr;

use crate::allocator::AllocError;
use crate::core::*;
use crate::ffi::*;
use crate::http::status::*;
use crate::http::upstream::UpstreamState;
use crate::http::{HttpModuleRequestContext, HttpPhase};

/// Define a static request handler.
///
/// Handlers are expected to take a single [`Request`] argument and return a [`Status`].
#[macro_export]
macro_rules! http_request_handler {
    ( $name: ident, $handler: expr ) => {
        extern "C" fn $name(r: *mut $crate::ffi::ngx_http_request_t) -> $crate::ffi::ngx_int_t {
            let request = unsafe { $crate::http::Request::from_ngx_http_request(r) };
            let status: $crate::core::Status = $handler(request);
            status.0
        }
    };
}

/// Define a static post subrequest handler.
///
/// Handlers are expected to take a single [`Request`] argument and return a [`Status`].
#[macro_export]
macro_rules! http_subrequest_handler {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            data: *mut ::core::ffi::c_void,
            rc: $crate::ffi::ngx_int_t,
        ) -> $crate::ffi::ngx_int_t {
            $handler(r, data, rc)
        }
    };
}

/// Define a static variable setter.
///
/// The set handler allows setting the property referenced by the variable.
/// The set handler expects a [`Request`], [`mut ngx_variable_value_t`], and a [`usize`].
/// Variables: <https://nginx.org/en/docs/dev/development_guide.html#http_variables>
#[macro_export]
macro_rules! http_variable_set {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            v: *mut $crate::ffi::ngx_variable_value_t,
            data: usize,
        ) {
            let request = unsafe { $crate::http::Request::from_ngx_http_request(r) };
            $handler(request, v, data);
        }
    };
}

/// Define a static variable evaluator.
///
/// The get handler is responsible for evaluating a variable in the context of a specific request.
/// Variable evaluators accept a [`Request`] input argument and two output
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
            let request = unsafe { $crate::http::Request::from_ngx_http_request(r) };
            let status: $crate::core::Status = $handler(request, v, data);
            status.0
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
    fn into_handler_status(self, _r: &Request) -> ngx_int_t;
}

impl<T> IntoHandlerStatus for Option<T>
where
    T: IntoHandlerStatus,
{
    #[inline]
    fn into_handler_status(self, r: &Request) -> ngx_int_t {
        self.map(|val| val.into_handler_status(r)).unwrap_or(NGX_ERROR as _)
    }
}

impl<T, E> IntoHandlerStatus for Result<T, E>
where
    T: IntoHandlerStatus,
    E: IntoHandlerStatus,
{
    #[inline]
    fn into_handler_status(self, r: &Request) -> ngx_int_t {
        match self {
            Ok(value) => value.into_handler_status(r),
            Err(error) => error.into_handler_status(r),
        }
    }
}

impl IntoHandlerStatus for ngx_int_t {
    #[inline]
    fn into_handler_status(self, _r: &Request) -> ngx_int_t {
        self
    }
}

impl IntoHandlerStatus for Status {
    #[inline]
    fn into_handler_status(self, _r: &Request) -> ngx_int_t {
        self.0
    }
}

impl IntoHandlerStatus for HTTPStatus {
    #[inline]
    fn into_handler_status(self, _r: &Request) -> ngx_int_t {
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
    fn handler(request: &mut Request) -> Self::Output;
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
    let r = unsafe { Request::from_ngx_http_request(r) };
    H::handler(r).into_handler_status(r)
}

/// Wrapper struct for an [`ngx_http_request_t`] pointer, providing methods for working with HTTP
/// requests.
///
/// See <https://nginx.org/en/docs/dev/development_guide.html#http_request>
#[repr(transparent)]
pub struct Request(ngx_http_request_t);

impl<'a> From<&'a Request> for *const ngx_http_request_t {
    fn from(request: &'a Request) -> Self {
        &raw const request.0
    }
}

impl<'a> From<&'a mut Request> for *mut ngx_http_request_t {
    fn from(request: &'a mut Request) -> Self {
        &raw mut request.0
    }
}

impl AsRef<ngx_http_request_t> for Request {
    fn as_ref(&self) -> &ngx_http_request_t {
        &self.0
    }
}

impl AsMut<ngx_http_request_t> for Request {
    fn as_mut(&mut self) -> &mut ngx_http_request_t {
        &mut self.0
    }
}

impl Request {
    /// Create a [`Request`] from an [`ngx_http_request_t`].
    ///
    /// # Safety
    ///
    /// The caller has provided a valid non-null pointer to a valid `ngx_http_request_t`
    /// which shares the same representation as `Request`.
    pub unsafe fn from_ngx_http_request<'a>(r: *mut ngx_http_request_t) -> &'a mut Request {
        unsafe { &mut *r.cast::<Request>() }
    }

    /// Create a shared [`Request`] from an [`ngx_http_request_t`] pointer.
    ///
    /// # Safety
    ///
    /// The caller must provide a valid non-null request pointer and ensure that no mutable
    /// reference to the request is live for the returned lifetime.
    pub unsafe fn from_const_ngx_http_request<'a>(r: *const ngx_http_request_t) -> &'a Request {
        unsafe { &*r.cast::<Request>() }
    }

    /// Is this the main request (as opposed to a subrequest)?
    pub fn is_main(&self) -> bool {
        let main = self.0.main.cast();
        core::ptr::eq(self, main)
    }

    /// Main request associated with this request.
    pub fn main(&self) -> &Request {
        if self.is_main() {
            self
        } else {
            unsafe { Request::from_const_ngx_http_request(self.0.main) }
        }
    }

    /// Mutable main request associated with this request.
    ///
    /// Nginx processes a request and its subrequests sequentially, so the active request borrow
    /// has exclusive access to their shared main-request state.
    pub fn main_mut(&mut self) -> &mut Request {
        if self.is_main() { self } else { unsafe { Request::from_ngx_http_request(self.0.main) } }
    }

    /// Request pool.
    pub fn pool(&self) -> Pool {
        // SAFETY: This request is allocated from `pool`, thus must be a valid pool.
        unsafe { Pool::from_ngx_pool(self.0.pool) }
    }

    /// Returns the result as an `Option` if it exists, otherwise `None`.
    ///
    /// The option wraps an ngx_http_upstream_t instance, it will be none when the underlying NGINX
    /// request does not have a pointer to a [`ngx_http_upstream_t`] upstream structure.
    ///
    /// [`ngx_http_upstream_t`] is best described in
    /// <https://nginx.org/en/docs/dev/development_guide.html#http_load_balancing>
    pub fn upstream(&self) -> Option<*mut ngx_http_upstream_t> {
        if self.0.upstream.is_null() {
            return None;
        }
        Some(self.0.upstream)
    }

    /// Upstream attempts recorded for this request, in chronological order.
    ///
    /// The slice is empty before nginx creates an upstream or when the request is served without
    /// contacting one. Retries add one state for each attempted peer.
    pub fn upstream_states(&self) -> &[UpstreamState] {
        if self.0.upstream_states.is_null() {
            return &[];
        }

        let states = unsafe { &*self.0.upstream_states };
        if states.nelts == 0 {
            return &[];
        }

        // SAFETY: nginx creates this array with ngx_http_upstream_state_t elements in the request
        // pool. UpstreamState is a transparent wrapper and the request borrow bounds the slice.
        unsafe { slice::from_raw_parts(states.elts.cast(), states.nelts) }
    }

    /// Seconds since the Unix epoch when nginx created the request.
    pub fn start_sec(&self) -> time_t {
        self.0.start_sec
    }

    /// Millisecond component of the request creation time.
    pub fn start_msec(&self) -> ngx_msec_t {
        self.0.start_msec
    }

    /// Bytes received for the request line, headers, and body parsed so far.
    pub fn request_length(&self) -> off_t {
        self.0.request_length
    }

    /// Current value of the client connection's sent-byte counter.
    pub fn bytes_sent(&self) -> off_t {
        // SAFETY: nginx assigns a connection before creating a valid HTTP request.
        unsafe { (*self.0.connection).sent }
    }

    /// Pointer to a [`ngx_connection_t`] client connection object.
    ///
    /// [`ngx_connection_t`]: https://nginx.org/en/docs/dev/development_guide.html#connection
    pub fn connection(&self) -> *mut ngx_connection_t {
        self.0.connection
    }

    /// Pointer to a [`ngx_log_t`].
    ///
    /// [`ngx_log_t`]: https://nginx.org/en/docs/dev/development_guide.html#logging
    pub fn log(&self) -> *mut ngx_log_t {
        unsafe { (*self.connection()).log }
    }

    /// Get Module context pointer
    fn get_module_ctx_ptr(&self, module: &ngx_module_t) -> *mut c_void {
        unsafe { *self.0.ctx.add(module.ctx_index) }
    }

    /// Context associated with module `M` for this request.
    pub fn module_context<M>(&self) -> Option<&M::RequestContext>
    where
        M: HttpModuleRequestContext,
    {
        let context = self.get_module_ctx_ptr(M::module()).cast::<M::RequestContext>();
        unsafe { context.as_ref() }
    }

    /// Mutable context associated with module `M` for this request.
    pub fn module_context_mut<M>(&mut self) -> Option<&mut M::RequestContext>
    where
        M: HttpModuleRequestContext,
    {
        let context = self.get_module_ctx_ptr(M::module()).cast::<M::RequestContext>();
        unsafe { context.as_mut() }
    }

    /// Returns the module context, inserting a pool-owned value when absent.
    pub fn get_or_insert_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<&mut M::RequestContext, AllocError>
    where
        M: HttpModuleRequestContext,
    {
        let context = self.get_module_ctx_ptr(M::module()).cast::<M::RequestContext>();
        if let Some(mut context) = NonNull::new(context) {
            return Ok(unsafe { context.as_mut() });
        }

        let mut context = unsafe { self.pool().allocate_with_cleanup(constructor)? };
        self.set_module_ctx_ptr(context.as_ptr().cast(), M::module());
        Ok(unsafe { context.as_mut() })
    }

    /// Drops and removes the module context when present.
    pub fn remove_module_context<M>(&mut self) -> Option<()>
    where
        M: HttpModuleRequestContext,
    {
        let context =
            NonNull::new(self.get_module_ctx_ptr(M::module()).cast::<M::RequestContext>())?;
        self.set_module_ctx_ptr(core::ptr::null_mut(), M::module());

        let mut pool = self.pool();
        if unsafe { pool.remove(context.as_ptr()) }.is_some() {
            Some(())
        } else {
            self.set_module_ctx_ptr(context.as_ptr().cast(), M::module());
            None
        }
    }

    fn set_module_ctx_ptr(&mut self, value: *mut c_void, module: &ngx_module_t) {
        unsafe {
            *self.0.ctx.add(module.ctx_index) = value;
        };
    }

    /// Get the value of a [complex value].
    ///
    /// [complex value]: https://nginx.org/en/docs/dev/development_guide.html#http_complex_values
    pub fn get_complex_value(&self, cv: &ngx_http_complex_value_t) -> Option<&NgxStr> {
        let r = (self as *const Request as *mut Request).cast();
        let val = cv as *const ngx_http_complex_value_t as *mut ngx_http_complex_value_t;
        // SAFETY: `ngx_http_complex_value` does not mutate `r` or `val` and guarentees that
        // a valid Nginx string is stored in `value` if it successfully returns.
        unsafe {
            let mut value = ngx_str_t::default();
            if ngx_http_complex_value(r, val, &raw mut value) != NGX_OK as ngx_int_t {
                return None;
            }
            Some(NgxStr::from_ngx_str(value))
        }
    }

    /// Discard (read and ignore) the [request body].
    ///
    /// [request body]: https://nginx.org/en/docs/dev/development_guide.html#http_request_body
    pub fn discard_request_body(&mut self) -> Status {
        unsafe { Status(ngx_http_discard_request_body(&raw mut self.0)) }
    }

    /// Client HTTP [User-Agent].
    ///
    /// [User-Agent]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
    pub fn user_agent(&self) -> Option<&NgxStr> {
        if !self.0.headers_in.user_agent.is_null() {
            unsafe { Some(NgxStr::from_ngx_str((*self.0.headers_in.user_agent).value)) }
        } else {
            None
        }
    }

    /// Set HTTP status of response.
    pub fn set_status(&mut self, status: HTTPStatus) {
        self.0.headers_out.status = status.into();
    }

    /// Add header to the `headers_in` object.
    ///
    /// See <https://nginx.org/en/docs/dev/development_guide.html#http_request>
    pub fn add_header_in(&mut self, key: &str, value: &str) -> Option<()> {
        let table: *mut ngx_table_elt_t =
            unsafe { ngx_list_push(&raw mut self.0.headers_in.headers).cast() };
        unsafe { add_to_ngx_table(table, self.0.pool, key, value) }
    }

    /// Add header to the `headers_out` object.
    ///
    /// See <https://nginx.org/en/docs/dev/development_guide.html#http_request>
    pub fn add_header_out(&mut self, key: &str, value: &str) -> Option<()> {
        let table: *mut ngx_table_elt_t =
            unsafe { ngx_list_push(&raw mut self.0.headers_out.headers).cast() };
        unsafe { add_to_ngx_table(table, self.0.pool, key, value) }
    }

    /// Set response body [Content-Length].
    ///
    /// [Content-Length]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length
    pub fn set_content_length_n(&mut self, n: usize) {
        self.0.headers_out.content_length_n = n as off_t;
    }

    /// Send the output header.
    ///
    /// Do not call this function until all output headers are set.
    pub fn send_header(&mut self) -> Status {
        unsafe { Status(ngx_http_send_header(&raw mut self.0)) }
    }

    /// Flag indicating that the output does not require a body.
    ///
    /// For example, this flag is used by `HTTP HEAD` requests.
    pub fn header_only(&self) -> bool {
        self.0.header_only() != 0
    }

    /// request method
    pub fn method(&self) -> Method {
        Method::from_ngx(self.0.method)
    }

    /// path part of request only
    pub fn path(&self) -> &NgxStr {
        unsafe { NgxStr::from_ngx_str(self.0.uri) }
    }

    /// full uri - containing path and args
    pub fn unparsed_uri(&self) -> &NgxStr {
        unsafe { NgxStr::from_ngx_str(self.0.unparsed_uri) }
    }

    /// Send the [response body].
    ///
    /// This function can be called multiple times.
    /// Set the `last_buf` flag in the last body buffer.
    ///
    /// [response body]: https://nginx.org/en/docs/dev/development_guide.html#http_request_body
    pub fn output_filter(&mut self, body: &mut ngx_chain_t) -> Status {
        unsafe { Status(ngx_http_output_filter(&raw mut self.0, body)) }
    }

    /// Perform internal redirect to a location
    pub fn internal_redirect(&self, location: &str) -> Status {
        assert!(!location.is_empty(), "uri location is empty");
        let uri_ptr = unsafe { &mut ngx_str_t::from_str(self.0.pool, location) as *mut _ };

        // FIXME: check status of ngx_http_named_location or ngx_http_internal_redirect
        if location.starts_with('@') {
            unsafe {
                ngx_http_named_location((self as *const Request as *mut Request).cast(), uri_ptr);
            }
        } else {
            unsafe {
                ngx_http_internal_redirect(
                    (self as *const Request as *mut Request).cast(),
                    uri_ptr,
                    core::ptr::null_mut(),
                );
            }
        }
        Status::NGX_DONE
    }

    /// Send a subrequest
    pub fn subrequest(
        &self,
        uri: &str,
        module: &ngx_module_t,
        post_callback: unsafe extern "C" fn(
            *mut ngx_http_request_t,
            *mut c_void,
            ngx_int_t,
        ) -> ngx_int_t,
    ) -> Status {
        let uri_ptr = unsafe { &mut ngx_str_t::from_str(self.0.pool, uri) as *mut _ };
        // -------------
        // allocate memory and set values for ngx_http_post_subrequest_t
        let sub_ptr = self.pool().alloc(core::mem::size_of::<ngx_http_post_subrequest_t>());

        // assert!(sub_ptr.is_null());
        let post_subreq =
            sub_ptr as *const ngx_http_post_subrequest_t as *mut ngx_http_post_subrequest_t;
        unsafe {
            (*post_subreq).handler = Some(post_callback);
            // WARN: safety! ensure that ctx is already set
            (*post_subreq).data = self.get_module_ctx_ptr(module);
        }
        // -------------

        let mut psr: *mut ngx_http_request_t = core::ptr::null_mut();
        let r = unsafe {
            ngx_http_subrequest(
                (self as *const Request as *mut Request).cast(),
                uri_ptr,
                core::ptr::null_mut(),
                &raw mut psr,
                sub_ptr as *mut _,
                NGX_HTTP_SUBREQUEST_WAITED as _,
            )
        };

        // previously call of ngx_http_subrequest() would ensure that the pointer is not null
        // anymore
        let sr = unsafe { &mut *psr };

        /*
         * allocate fake request body to avoid attempts to read it and to make
         * sure real body file (if already read) won't be closed by upstream
         */
        sr.request_body =
            self.pool().alloc(core::mem::size_of::<ngx_http_request_body_t>()) as *mut _;

        if sr.request_body.is_null() {
            return Status::NGX_ERROR;
        }
        sr.set_header_only(1 as _);
        Status(r)
    }

    /// Iterate over headers_in
    /// each header item is (&str, &str) (borrowed)
    pub fn headers_in_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.0.headers_in.headers) }
    }

    /// Iterate over headers_out
    /// each header item is (&str, &str) (borrowed)
    pub fn headers_out_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.0.headers_out.headers) }
    }
}

impl crate::http::HttpModuleConfExt for Request {
    #[inline]
    unsafe fn http_main_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe {
            // SAFETY: main_conf[module.ctx_index] is either NULL or allocated with ngx_p(c)alloc
            // and explicitly initialized by the module
            NonNull::new((*self.0.main_conf.add(module.ctx_index)).cast())
        }
    }

    #[inline]
    unsafe fn http_server_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe {
            // SAFETY: srv_conf[module.ctx_index] is either NULL or allocated with ngx_p(c)alloc and
            // explicitly initialized by the module
            NonNull::new((*self.0.srv_conf.add(module.ctx_index)).cast())
        }
    }

    #[inline]
    unsafe fn http_location_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe {
            // SAFETY: loc_conf[module.ctx_index] is either NULL or allocated with ngx_p(c)alloc and
            // explicitly initialized by the module
            NonNull::new((*self.0.loc_conf.add(module.ctx_index)).cast())
        }
    }
}

// trait OnSubRequestDone {

// }

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request").field("request_", &self.0).finish()
    }
}

/// Iterator for [`ngx_list_t`] types.
///
/// Implementes the core::iter::Iterator trait.
pub struct NgxListIterator<'a> {
    part: Option<ListPart<'a>>,
    i: ngx_uint_t,
}
struct ListPart<'a> {
    raw: &'a ngx_list_part_t,
    arr: &'a [ngx_table_elt_t],
}
impl<'a> From<&'a ngx_list_part_t> for ListPart<'a> {
    fn from(raw: &'a ngx_list_part_t) -> Self {
        let arr = if raw.nelts != 0 {
            unsafe { slice::from_raw_parts(raw.elts.cast(), raw.nelts) }
        } else {
            &[]
        };
        Self { raw, arr }
    }
}

/// Creates new HTTP header iterator
///
/// # Safety
///
/// The caller has provided a valid [`ngx_str_t`] which can be dereferenced validly.
pub unsafe fn list_iterator(list: &ngx_list_t) -> NgxListIterator<'_> {
    NgxListIterator { part: Some((&list.part).into()), i: 0 }
}

// iterator for ngx_list_t
impl<'a> Iterator for NgxListIterator<'a> {
    // TODO: try to use struct instead of &str pair
    // something like pub struct Header(ngx_table_elt_t);
    // then header would have key and value

    type Item = (&'a NgxStr, &'a NgxStr);

    fn next(&mut self) -> Option<Self::Item> {
        let part = self.part.as_mut()?;
        if self.i >= part.arr.len() {
            if let Some(next_part_raw) = unsafe { part.raw.next.as_ref() } {
                // loop back
                *part = next_part_raw.into();
                self.i = 0;
            } else {
                self.part = None;
                return None;
            }
        }
        let header = &part.arr[self.i];
        self.i += 1;
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

    fn from_bytes(_t: &[u8]) -> Result<Method, InvalidMethod> {
        todo!()
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
    #[allow(dead_code)]
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

    use alloc::boxed::Box;
    use core::mem::MaybeUninit;

    use super::*;
    use crate::http::{HttpModule, HttpModuleRequestContext};

    struct TestContextModule;

    impl HttpModule for TestContextModule {
        fn module() -> &'static ngx_module_t {
            let mut module = ngx_module_t::default();
            module.ctx_index = 0;
            Box::leak(Box::new(module))
        }
    }

    unsafe impl HttpModuleRequestContext for TestContextModule {
        type RequestContext = u32;
    }

    fn zeroed_request() -> ngx_http_request_t {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }

    fn request_from(raw: &mut ngx_http_request_t) -> &mut Request {
        unsafe { Request::from_ngx_http_request(raw) }
    }

    #[test]
    fn upstream_states_is_empty_without_an_array() {
        let mut raw = zeroed_request();

        assert!(request_from(&mut raw).upstream_states().is_empty());
    }

    #[test]
    fn upstream_states_is_empty_without_elements() {
        let mut states: ngx_array_t = unsafe { MaybeUninit::zeroed().assume_init() };
        states.elts = (&raw mut states).cast();

        let mut raw = zeroed_request();
        raw.upstream_states = &raw mut states;

        assert!(request_from(&mut raw).upstream_states().is_empty());
    }

    #[test]
    fn upstream_states_preserves_attempt_order() {
        let mut values: [ngx_http_upstream_state_t; 2] =
            unsafe { MaybeUninit::zeroed().assume_init() };
        values[0].status = 502;
        values[0].response_time = 3;
        values[1].status = 200;
        values[1].response_time = 12;

        let mut states: ngx_array_t = unsafe { MaybeUninit::zeroed().assume_init() };
        states.elts = values.as_mut_ptr().cast();
        states.nelts = values.len();

        let mut raw = zeroed_request();
        raw.upstream_states = &raw mut states;

        let attempts = request_from(&mut raw).upstream_states();
        assert_eq!(attempts.len(), 2);
        assert_eq!((attempts[0].status(), attempts[0].response_time()), (502, 3));
        assert_eq!((attempts[1].status(), attempts[1].response_time()), (200, 12));
    }

    #[test]
    fn request_metrics_read_nginx_fields() {
        let mut raw = zeroed_request();
        raw.start_sec = 1_700_000_000;
        raw.start_msec = 250;
        raw.request_length = 4096;

        let request = request_from(&mut raw);
        assert_eq!(request.start_sec(), 1_700_000_000);
        assert_eq!(request.start_msec(), 250);
        assert_eq!(request.request_length(), 4096);
    }

    #[test]
    fn bytes_sent_reads_the_client_connection() {
        let mut connection: ngx_connection_t = unsafe { MaybeUninit::zeroed().assume_init() };
        connection.sent = 8192;

        let mut raw = zeroed_request();
        raw.connection = &raw mut connection;

        assert_eq!(request_from(&mut raw).bytes_sent(), 8192);
    }

    #[test]
    fn result_converts_the_selected_branch_into_handler_status() {
        let mut raw = zeroed_request();
        let request = request_from(&mut raw);
        let success: Result<Status, HTTPStatus> = Ok(Status::NGX_AGAIN);
        let error: Result<Status, HTTPStatus> = Err(HTTPStatus::BAD_REQUEST);

        assert_eq!(success.into_handler_status(request), Status::NGX_AGAIN.0);
        assert_eq!(error.into_handler_status(request), 400);
    }

    #[test]
    fn main_returns_the_same_main_request() {
        let mut raw = zeroed_request();
        raw.main = &raw mut raw;
        let request = request_from(&mut raw);

        assert!(core::ptr::eq(request.main(), request));
    }

    #[test]
    fn main_returns_the_parent_of_a_subrequest() {
        let mut raw_main = zeroed_request();
        raw_main.main = &raw mut raw_main;
        let mut raw_subrequest = zeroed_request();
        raw_subrequest.main = &raw mut raw_main;

        let main: *const ngx_http_request_t = request_from(&mut raw_subrequest).main().into();

        assert_eq!(main, &raw const raw_main);
    }

    #[test]
    fn main_mut_updates_the_parent_of_a_subrequest() {
        let mut raw_main = zeroed_request();
        raw_main.main = &raw mut raw_main;
        let mut raw_subrequest = zeroed_request();
        raw_subrequest.main = &raw mut raw_main;

        request_from(&mut raw_subrequest).main_mut().0.request_length = 4096;

        assert_eq!(raw_main.request_length, 4096);
    }

    #[test]
    fn module_context_reads_the_associated_context_type() {
        let mut context = 41u32;
        let mut contexts = [(&raw mut context).cast()];
        let mut raw = zeroed_request();
        raw.ctx = contexts.as_mut_ptr();

        assert_eq!(request_from(&mut raw).module_context::<TestContextModule>(), Some(&41));
    }

    #[test]
    fn module_context_mut_updates_the_associated_context_type() {
        let mut context = 41u32;
        let mut contexts = [(&raw mut context).cast()];
        let mut raw = zeroed_request();
        raw.ctx = contexts.as_mut_ptr();

        *request_from(&mut raw).module_context_mut::<TestContextModule>().unwrap() = 42;

        assert_eq!(context, 42);
    }
}
