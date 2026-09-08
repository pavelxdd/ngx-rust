use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::core::*;
use crate::ffi::*;
use crate::http::status::HTTPStatus;

use super::context::*;
use super::headers::*;
use super::request_callback_status;
use super::view::*;

pub(super) unsafe extern "C" fn raw_client_body_handler<H>(request: *mut ngx_http_request_t)
where
    H: HttpClientBodyHandler,
{
    let Ok(raw) = checked_request_ptr(request) else {
        return;
    };
    let Ok(_hold) = retain_request_for_context_cancellation(raw) else {
        return;
    };
    if cancel_stale_request_contexts(raw).is_err() {
        return;
    }
    match take_client_body_read(raw, raw_client_body_handler::<H>) {
        ClientBodyCallbackState::Current => {
            let _ = unsafe {
                request_callback_status(request, |request| {
                    if H::is_active(request.view()) {
                        H::body_read(request);
                    }
                    Status::NGX_OK
                })
            };
        }
        ClientBodyCallbackState::Stale => unsafe {
            ngx_http_finalize_request(request, NGX_ERROR as _);
        },
        ClientBodyCallbackState::Missing => {}
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

/// Checked aggregate size of an nginx request body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBodySize {
    pub(super) bytes: usize,
    pub(super) saturated: bool,
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
    pub(super) fn from_raw(
        body: *mut ngx_http_request_body_t,
    ) -> Result<Option<Self>, RequestBodyError> {
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

/// Start-side ownership returned by nginx client-body processing.
///
/// When nginx is called and returns a non-special status, it retains one main-request reference
/// while the body callback owns asynchronous processing. [`release`](Self::release) consumes this
/// token exactly once. A special response, a registration failure, or an already pending read has
/// no start-side reference to release.
#[must_use = "client-body start ownership must be released after handling its status"]
pub struct ClientBodyReadStart<'request> {
    pub(super) request: RequestRefMut<'request>,
    status: ClientBodyReadStatus,
    pub(super) release_required: bool,
}

impl ClientBodyReadStatus {
    pub(super) fn from_raw(status: ngx_int_t) -> Self {
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
/// The SDK rejects callbacks displaced by a safe request redirect before invoking this trait. The
/// owner may additionally keep cancellation state in its pinned request context and override
/// [`is_active`](Self::is_active). A callback must not panic; panics terminate the worker process.
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

/// Request-pool candidate for a non-null HTTP request body.
///
/// ```compile_fail
/// use ngx::http::{HTTPStatus, RequestRefMut};
///
/// fn finalize_then_append(mut request: RequestRefMut<'_>) {
///     let mut body = {
///         let headers = unsafe { request.headers_in_builder(1) }.unwrap();
///         headers.request_body_candidate().unwrap()
///     };
///     request.finalize(HTTPStatus::BAD_REQUEST).unwrap();
///     body.append_copy(b"late").unwrap();
/// }
/// ```
pub struct RequestBodyCandidate<'callback> {
    pub(super) pool: Pool<'callback>,
    chain: PoolChain<'callback>,
    pub(super) length: usize,
}

impl<'callback> RequestBodyCandidate<'callback> {
    pub(super) fn new(pool: Pool<'callback>) -> Self {
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

    pub(super) fn into_raw(
        self,
    ) -> Result<NonNull<ngx_http_request_body_t>, RequestBodyBuildError> {
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
    body: RequestBodyCandidate<'request>,
}

impl<'request, 'callback> RequestBodyBuilder<'request, 'callback> {
    pub(super) fn new(
        request: &'request mut RequestRefMut<'callback>,
    ) -> Result<Self, RequestBodyBuildError> {
        let raw_pool = request.pool()?.as_ptr();
        // SAFETY: this builder exclusively borrows the request for `'request`.
        let pool =
            unsafe { Pool::<'request>::from_raw(raw_pool) }.ok_or(RequestError::MisalignedPool)?;

        Ok(Self { request, body: RequestBodyCandidate::new(pool) })
    }

    /// Copies memory bytes into the request-pool body candidate.
    pub fn append_copy(&mut self, bytes: &[u8]) -> Result<(), RequestBodyBuildError> {
        self.body.append_copy(bytes)
    }

    /// Appends one request-pool-owned buffer to the body candidate.
    pub fn append(&mut self, buffer: PoolBuffer<'request>) -> Result<(), RequestBodyBuildError> {
        self.body.append(buffer)
    }

    /// Appends a zero-size control buffer to the body candidate.
    pub fn append_control(&mut self, flags: BufferFlags) -> Result<(), RequestBodyBuildError> {
        self.body.append_control(flags)
    }

    /// Publishes the complete non-null request-body candidate and matching framing headers.
    pub fn commit(self) -> Result<(), RequestBodyBuildError> {
        let Self { request, body } = self;
        let framing = request_body_framing_candidate(request, body.pool.as_ptr(), body.length)?;
        let body = body.into_raw()?;
        publish_request_body_framing(request, framing, body.as_ptr())
    }
}

pub(super) struct RequestBodyFramingCandidate {
    content_length: ngx_table_elt_t,
    content_length_n: off_t,
    #[cfg(nginx1_29_8)]
    count: ngx_uint_t,
}

pub(super) fn request_body_framing_candidate(
    request: &RequestRefMut<'_>,
    pool: *mut ngx_pool_t,
    length: usize,
) -> Result<RequestBodyFramingCandidate, RequestBodyBuildError> {
    request.headers_in()?;
    #[cfg(nginx1_29_8)]
    let headers = unsafe { &request.raw.as_ref().headers_in };
    #[cfg(nginx1_29_8)]
    let count = headers.count.checked_add(1).ok_or(HeaderBuildError::CountOverflow)?;
    let content_length_n =
        off_t::try_from(length).map_err(|_| RequestBodyBuildError::ContentLengthTooLarge)?;
    let mut decimal = [0_u8; core::mem::size_of::<usize>() * 3];
    let value = decimal_bytes(length, &mut decimal);
    let content_length = build_pool_header(pool, b"Content-Length", value)?;

    Ok(RequestBodyFramingCandidate {
        content_length,
        content_length_n,
        #[cfg(nginx1_29_8)]
        count,
    })
}

pub(super) fn publish_request_body_framing(
    request: &mut RequestRefMut<'_>,
    candidate: RequestBodyFramingCandidate,
    body: *mut ngx_http_request_body_t,
) -> Result<(), RequestBodyBuildError> {
    let request = unsafe { request.raw.as_mut() };
    let headers = &mut request.headers_in;
    disable_framing_headers(&mut headers.headers, HttpHeaderSource::Input)?;
    let content_length = append_header(&mut headers.headers, candidate.content_length)?;

    headers.content_length = content_length.as_ptr();
    headers.transfer_encoding = ptr::null_mut();
    headers.content_length_n = candidate.content_length_n;
    #[cfg(nginx1_29_8)]
    {
        headers.count = candidate.count;
    }
    headers.set_chunked(0);
    request.request_body = body;
    Ok(())
}

#[cfg(nginx1_29_8)]
pub(super) fn replace_request_body_framing(
    headers: &mut ngx_http_headers_in_t,
    pool: *mut ngx_pool_t,
    length: usize,
) -> Result<(), RequestBodyBuildError> {
    let content_length =
        off_t::try_from(length).map_err(|_| RequestBodyBuildError::ContentLengthTooLarge)?;
    disable_framing_headers(&mut headers.headers, HttpHeaderSource::Input)?;

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

#[cfg(nginx1_29_8)]
pub(super) fn publish_request_body(
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

impl ClientBodyReadStart<'_> {
    /// Returns the native status class without releasing start-side ownership.
    pub fn status(&self) -> &ClientBodyReadStatus {
        &self.status
    }

    /// Returns the request while start-side ownership keeps it live.
    pub fn request(&self) -> &RequestRefMut<'_> {
        &self.request
    }

    /// Releases start-side ownership after the caller has handled the native status.
    ///
    /// This may synchronously finalize the request and must be the caller's final request operation.
    pub fn release(self) {
        if self.release_required {
            unsafe { ngx_http_finalize_request(self.request.raw.as_ptr(), NGX_DONE as _) };
        }
    }
}

impl<'callback> RequestRef<'callback> {
    /// Returns a checked callback-scoped view over the current request body, when nginx has one.
    pub fn request_body(&self) -> Result<Option<RequestBodyRef<'_>>, RequestBodyError> {
        RequestBodyRef::from_raw(unsafe { self.raw.as_ref().request_body })
    }
}

impl<'callback> RequestRefMut<'callback> {
    /// Returns a checked callback-scoped view over the current request body, when nginx has one.
    pub fn request_body(&self) -> Result<Option<RequestBodyRef<'_>>, RequestBodyError> {
        RequestBodyRef::from_raw(unsafe { self.raw.as_ref().request_body })
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
        let framing = request_body_framing_candidate(self, pool, 0)?;
        publish_request_body_framing(self, framing, ptr::null_mut())
    }

    /// Starts nginx client-body processing with one static callback type.
    ///
    /// An immediate special response is returned without invoking `H`. A read already pending
    /// from this or an older request generation returns [`ClientBodyReadStatus::Again`] without
    /// calling nginx again. A late callback from an older generation terminates the request rather
    /// than dispatching `H` against replacement state. The returned token must be released after
    /// its status has been handled.
    pub fn read_client_body<'request, H: HttpClientBodyHandler>(
        &'request mut self,
    ) -> ClientBodyReadStart<'request> {
        let callback = raw_client_body_handler::<H>;
        let (status, release_required) = match register_client_body_read(self.raw, callback) {
            Ok(Some(id)) => {
                let status = ClientBodyReadStatus::from_raw(unsafe {
                    ngx_http_read_client_request_body(
                        self.raw.as_ptr(),
                        Some(raw_client_body_handler::<H>),
                    )
                });
                let release_required = !matches!(&status, ClientBodyReadStatus::Special(_));
                if matches!(
                    status,
                    ClientBodyReadStatus::Special(_) | ClientBodyReadStatus::Error(_)
                ) {
                    clear_client_body_read(self.raw, id, callback);
                }
                (status, release_required)
            }
            Ok(None) => (ClientBodyReadStatus::Again, false),
            Err(_) => (ClientBodyReadStatus::Error(Status::NGX_ERROR), false),
        };
        let request = unsafe { RequestRefMut::from_raw(self.raw.as_ptr()) }
            .expect("a client-body start reborrows its validated request");
        ClientBodyReadStart { request, status, release_required }
    }

    /// Discards the request body.
    pub fn discard_request_body(&mut self) -> Status {
        Status(unsafe { ngx_http_discard_request_body(self.raw.as_ptr()) })
    }
}

impl<'request, 'callback> HttpHeadersInBuilder<'request, 'callback> {
    /// Starts constructing a request-pool body candidate for this replacement-header set.
    pub fn request_body_candidate(
        &self,
    ) -> Result<RequestBodyCandidate<'request>, RequestBodyBuildError> {
        // SAFETY: this builder exclusively borrows the request for `'request`.
        let pool =
            unsafe { Pool::<'request>::from_raw(self.pool) }.ok_or(RequestError::MisalignedPool)?;
        Ok(RequestBodyCandidate::new(pool))
    }

    /// Publishes the replacement headers, body, and authoritative body framing together.
    pub fn commit_with_body(
        self,
        body: RequestBodyCandidate<'request>,
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
}
