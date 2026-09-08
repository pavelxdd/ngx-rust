use core::ptr::{self, NonNull};
use core::slice;

use crate::collections::{NgxList, list::NgxListRawIter};
use crate::core::*;
use crate::ffi::*;

use super::view::*;

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
    /// The existing output-trailer list is not safe to clone into a candidate.
    InvalidSource(HeaderListError),
    /// The requested initial list capacity is zero or cannot describe a list allocation.
    InvalidCapacity,
    /// Nginx could not allocate request-pool storage.
    Allocation,
    /// A response content length cannot be represented by nginx's `off_t`.
    ContentLengthTooLarge,
    /// Content-Length and Transfer-Encoding require the typed output framing API.
    ManagedOutputFraming,
    /// The input header count cannot be represented by nginx.
    CountOverflow,
}

impl From<RequestError> for HeaderBuildError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
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

#[derive(Clone, Copy, Debug)]
pub(super) enum HttpHeaderSource {
    Input,
    Output,
}

/// Checked byte-oriented view over enabled entries in an nginx HTTP header list.
#[derive(Debug)]
pub struct HttpHeaderList<'header> {
    pub(super) headers: &'header ngx_list_t,
    source: HttpHeaderSource,
    len: usize,
}

impl HttpHeaderList<'_> {
    /// Returns the number of enabled entries across all nginx list parts.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the list contains no enabled entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates over checked enabled header entries in list order.
    pub fn iter(&self) -> HttpHeaderIter<'_> {
        let headers = unsafe { NgxList::<ngx_table_elt_t>::raw_iter(self.headers) }
            .expect("validated HTTP header list");
        HttpHeaderIter { headers, source: self.source, remaining: self.len }
    }
}

/// Iterator over enabled [`HttpHeaderList`] entries.
pub struct HttpHeaderIter<'header> {
    headers: NgxListRawIter<'header, ngx_table_elt_t>,
    source: HttpHeaderSource,
    remaining: usize,
}

impl<'header> Iterator for HttpHeaderIter<'header> {
    type Item = HttpHeaderRef<'header>;

    fn next(&mut self) -> Option<Self::Item> {
        for header in self.headers.by_ref() {
            let hash = unsafe { ptr::addr_of!((*header.as_ptr()).hash).read() };
            if hash == 0 {
                continue;
            }

            self.remaining -= 1;
            return Some(unsafe { http_header_from_raw(header, self.source, hash) });
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for HttpHeaderIter<'_> {}

/// Request-pool builder for atomically replacing HTTP input headers.
#[cfg(nginx1_29_8)]
pub struct HttpHeadersInBuilder<'request, 'callback> {
    pub(super) request: &'request mut RequestRefMut<'callback>,
    pub(super) pool: *mut ngx_pool_t,
    pub(super) headers: ngx_http_headers_in_t,
}

#[cfg(nginx1_29_8)]
impl<'request, 'callback> HttpHeadersInBuilder<'request, 'callback> {
    pub(super) fn new(
        request: &'request mut RequestRefMut<'callback>,
        capacity: usize,
    ) -> Result<Self, HeaderBuildError> {
        let pool = request.pool()?.as_ptr();
        let mut headers: ngx_http_headers_in_t = unsafe { core::mem::zeroed() };
        create_header_list(&mut headers.headers, pool, capacity)?;
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

    /// Publishes the complete input-header candidate to the request.
    pub fn commit(self) {
        let request = unsafe { self.request.raw.as_mut() };
        request.headers_in = self.headers;
        repair_header_list_last(&mut request.headers_in.headers);
    }
}

/// Request-pool builder for atomically replacing HTTP output trailers.
pub struct HttpTrailersOutBuilder<'request, 'callback> {
    pub(super) request: &'request mut RequestRefMut<'callback>,
    pub(super) pool: *mut ngx_pool_t,
    pub(super) trailers: ngx_list_t,
    pub(super) has_trailers: bool,
}

impl<'request, 'callback> HttpTrailersOutBuilder<'request, 'callback> {
    pub(super) fn new(
        request: &'request mut RequestRefMut<'callback>,
        capacity: usize,
    ) -> Result<Self, HeaderBuildError> {
        let pool = request.pool()?.as_ptr();
        let mut trailers: ngx_list_t = unsafe { core::mem::zeroed() };
        create_header_list(&mut trailers, pool, capacity)?;
        Ok(Self { request, pool, trailers, has_trailers: false })
    }

    /// Adds a copied raw output trailer to the candidate list.
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> Result<(), HeaderBuildError> {
        append_pool_header(&mut self.trailers, self.pool, key, value)?;
        self.has_trailers = true;
        Ok(())
    }

    /// Publishes the complete output-trailer candidate to the request.
    pub fn commit(self) {
        let Self { request, trailers, has_trailers, .. } = self;
        let request = unsafe { request.raw.as_mut() };
        request.headers_out.trailers = trailers;
        unsafe {
            ngx_rs_http_request_set_expect_trailers(request, has_trailers.into());
        }
        repair_header_list_last(&mut request.headers_out.trailers);
    }
}

/// Request-pool builder for atomically replacing HTTP output headers.
#[cfg(nginx1_29_8)]
pub struct HttpHeadersOutBuilder<'request, 'callback> {
    pub(super) request: &'request mut RequestRefMut<'callback>,
    pub(super) pool: *mut ngx_pool_t,
    pub(super) headers: ngx_http_headers_out_t,
    pub(super) trailer_capacity: usize,
    pub(super) trailers_owned: bool,
    pub(super) expect_trailers: Option<bool>,
    pub(super) content_length_set: bool,
}

#[cfg(nginx1_29_8)]
impl<'request, 'callback> HttpHeadersOutBuilder<'request, 'callback> {
    pub(super) fn new(
        request: &'request mut RequestRefMut<'callback>,
        capacity: usize,
    ) -> Result<Self, HeaderBuildError> {
        let pool = request.pool()?.as_ptr();
        let mut headers = unsafe { request.raw.as_ref().headers_out };
        create_header_list(&mut headers.headers, pool, capacity)?;
        clear_headers_out_slots(&mut headers);

        Ok(Self {
            request,
            pool,
            headers,
            trailer_capacity: capacity,
            trailers_owned: false,
            expect_trailers: None,
            content_length_set: false,
        })
    }

    /// Adds a copied raw output header to the candidate list.
    ///
    /// `Content-Type` is represented by nginx's dedicated output field rather than a list entry.
    /// Content-Length and Transfer-Encoding are rejected because nginx's output filters own
    /// response framing; use [`set_content_length`](Self::set_content_length) for a known length.
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> Result<(), HeaderBuildError> {
        if key.eq_ignore_ascii_case(b"Content-Length")
            || key.eq_ignore_ascii_case(b"Transfer-Encoding")
        {
            return Err(HeaderBuildError::ManagedOutputFraming);
        }
        if key.eq_ignore_ascii_case(b"Content-Type") {
            return self.set_content_type(value);
        }

        let header = append_pool_header(&mut self.headers.headers, self.pool, key, value)?;
        unsafe { bind_headers_out(&mut self.headers, header.as_ptr()) };
        Ok(())
    }

    /// Sets the response Content-Length for nginx's output framing filters.
    pub fn set_content_length(&mut self, length: usize) -> Result<(), HeaderBuildError> {
        self.headers.content_length_n =
            off_t::try_from(length).map_err(|_| HeaderBuildError::ContentLengthTooLarge)?;
        self.headers.content_length = ptr::null_mut();
        self.content_length_set = true;
        Ok(())
    }

    /// Adds a copied raw output trailer to a fresh candidate trailer list.
    pub fn add_trailer(&mut self, key: &[u8], value: &[u8]) -> Result<(), HeaderBuildError> {
        if !self.trailers_owned {
            repair_header_list_last(&mut self.headers.trailers);
            self.headers.trailers =
                clone_header_list(self.pool, &self.headers.trailers, self.trailer_capacity)?;
            self.trailers_owned = true;
        }
        append_pool_header(&mut self.headers.trailers, self.pool, key, value)?;
        self.expect_trailers = Some(true);
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
        let Self { request, headers, expect_trailers, content_length_set, .. } = self;
        let request = unsafe { request.raw.as_mut() };
        request.headers_out = headers;
        if let Some(expect_trailers) = expect_trailers {
            unsafe {
                ngx_rs_http_request_set_expect_trailers(request, expect_trailers.into());
            }
        }
        if content_length_set {
            request.set_chunked(0);
        }
        repair_header_list_last(&mut request.headers_out.headers);
        repair_header_list_last(&mut request.headers_out.trailers);
    }
}

pub(super) fn checked_header_list(
    headers: &ngx_list_t,
    source: HttpHeaderSource,
) -> Result<HttpHeaderList<'_>, HeaderListError> {
    let entries = unsafe { NgxList::<ngx_table_elt_t>::raw_iter(headers) }
        .ok_or(HeaderListError::InvalidList)?;
    let mut len = 0_usize;
    for header in entries {
        let hash = unsafe { ptr::addr_of!((*header.as_ptr()).hash).read() };
        if hash == 0 {
            continue;
        }

        let key = unsafe { ptr::addr_of!((*header.as_ptr()).key).read() };
        checked_header_bytes(key, HeaderListError::MissingKeyData, HeaderListError::KeyTooLong)?;
        checked_header_bytes(
            unsafe { ptr::addr_of!((*header.as_ptr()).value).read() },
            HeaderListError::MissingValueData,
            HeaderListError::ValueTooLong,
        )?;
        len = len.checked_add(1).ok_or(HeaderListError::InvalidList)?;
    }

    Ok(HttpHeaderList { headers, source, len })
}

pub(super) fn checked_header_bytes<'header>(
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

pub(super) unsafe fn http_header_from_raw<'header>(
    header: NonNull<ngx_table_elt_t>,
    source: HttpHeaderSource,
    hash: ngx_uint_t,
) -> HttpHeaderRef<'header> {
    let key = unsafe { ptr::addr_of!((*header.as_ptr()).key).read() };
    let value = unsafe { ptr::addr_of!((*header.as_ptr()).value).read() };
    let lowercase_key = match source {
        HttpHeaderSource::Input => {
            let lowercase_key = unsafe { ptr::addr_of!((*header.as_ptr()).lowcase_key).read() };
            NonNull::new(lowercase_key).map(|lowercase_key| unsafe {
                slice::from_raw_parts(lowercase_key.as_ptr(), key.len)
            })
        }
        HttpHeaderSource::Output => None,
    };

    HttpHeaderRef {
        key: unsafe { header_bytes_unchecked(key) },
        value: unsafe { header_bytes_unchecked(value) },
        lowercase_key,
        hash,
    }
}

pub(super) unsafe fn header_bytes_unchecked<'header>(value: ngx_str_t) -> &'header [u8] {
    if value.len == 0 {
        return &[];
    }

    unsafe { slice::from_raw_parts(value.data, value.len) }
}

pub(super) fn create_header_list(
    headers: &mut ngx_list_t,
    pool: *mut ngx_pool_t,
    capacity: usize,
) -> Result<(), HeaderBuildError> {
    if capacity == 0
        || capacity
            .checked_mul(core::mem::size_of::<ngx_table_elt_t>())
            .is_none_or(|size| size > isize::MAX as usize)
    {
        return Err(HeaderBuildError::InvalidCapacity);
    }

    *headers = unsafe { core::mem::zeroed() };
    if unsafe { ngx_list_init(headers, pool, capacity, core::mem::size_of::<ngx_table_elt_t>()) }
        != NGX_OK as ngx_int_t
    {
        return Err(HeaderBuildError::Allocation);
    }

    Ok(())
}

#[cfg(nginx1_29_8)]
pub(super) fn clone_header_list(
    pool: *mut ngx_pool_t,
    source: &ngx_list_t,
    additional_capacity: usize,
) -> Result<ngx_list_t, HeaderBuildError> {
    let source = checked_header_list(source, HttpHeaderSource::Output)
        .map_err(HeaderBuildError::InvalidSource)?;
    let capacity =
        source.len().checked_add(additional_capacity).ok_or(HeaderBuildError::CountOverflow)?;
    let mut candidate: ngx_list_t = unsafe { core::mem::zeroed() };
    create_header_list(&mut candidate, pool, capacity)?;
    for header in source.iter() {
        let value = ngx_table_elt_t {
            hash: header.hash(),
            key: ngx_str_t { len: header.key().len(), data: header.key().as_ptr().cast_mut() },
            value: ngx_str_t {
                len: header.value().len(),
                data: header.value().as_ptr().cast_mut(),
            },
            lowcase_key: ptr::null_mut(),
            next: ptr::null_mut(),
        };
        append_header(&mut candidate, value)?;
    }
    Ok(candidate)
}

pub(super) fn copy_pool_bytes(
    pool: *mut ngx_pool_t,
    bytes: &[u8],
) -> Result<ngx_str_t, HeaderBuildError> {
    let allocation = bytes.len().checked_add(1).ok_or(HeaderBuildError::Allocation)?;
    let data = NonNull::new(unsafe { ngx_pnalloc(pool, allocation).cast::<u_char>() })
        .ok_or(HeaderBuildError::Allocation)?;
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), data.as_ptr(), bytes.len());
        *data.as_ptr().add(bytes.len()) = 0;
    }
    Ok(ngx_str_t { len: bytes.len(), data: data.as_ptr() })
}

pub(super) fn build_pool_header(
    pool: *mut ngx_pool_t,
    key: &[u8],
    value: &[u8],
) -> Result<ngx_table_elt_t, HeaderBuildError> {
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

    let mut header: ngx_table_elt_t = unsafe { core::mem::zeroed() };
    header.hash = hash;
    header.key = key;
    header.value = value;
    header.lowcase_key = lowcase_key;
    Ok(header)
}

pub(super) fn append_header(
    headers: &mut ngx_list_t,
    value: ngx_table_elt_t,
) -> Result<NonNull<ngx_table_elt_t>, HeaderBuildError> {
    repair_header_list_last(headers);
    let header = NonNull::new(unsafe { ngx_list_push(headers).cast::<ngx_table_elt_t>() })
        .ok_or(HeaderBuildError::Allocation)?;
    unsafe { header.write(value) };
    Ok(header)
}

pub(super) fn append_pool_header(
    headers: &mut ngx_list_t,
    pool: *mut ngx_pool_t,
    key: &[u8],
    value: &[u8],
) -> Result<NonNull<ngx_table_elt_t>, HeaderBuildError> {
    let value = build_pool_header(pool, key, value)?;
    append_header(headers, value)
}

pub(super) fn repair_header_list_last(headers: &mut ngx_list_t) {
    let mut last = &raw mut headers.part;
    while !unsafe { (*last).next }.is_null() {
        last = unsafe { (*last).next };
    }
    headers.last = last;
}

#[cfg(nginx1_29_8)]
pub(super) unsafe fn append_header_slot(
    slot: &mut *mut ngx_table_elt_t,
    header: *mut ngx_table_elt_t,
) {
    let mut tail = slot;
    while !(*tail).is_null() {
        tail = unsafe { &mut (**tail).next };
    }
    unsafe {
        *tail = header;
        (*header).next = ptr::null_mut();
    }
}

#[cfg(nginx1_29_8)]
pub(super) unsafe fn bind_headers_in(
    headers: &mut ngx_http_headers_in_t,
    header: *mut ngx_table_elt_t,
) {
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

#[cfg(nginx1_29_8)]
pub(super) unsafe fn bind_headers_out(
    headers: &mut ngx_http_headers_out_t,
    header: *mut ngx_table_elt_t,
) {
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

#[cfg(nginx1_29_8)]
pub(super) fn clear_headers_out_slots(headers: &mut ngx_http_headers_out_t) {
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

#[cfg(nginx1_29_8)]
pub(super) fn clear_headers_out_metadata(headers: &mut ngx_http_headers_out_t) {
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

pub(super) fn disable_framing_headers(
    headers: &mut ngx_list_t,
    source: HttpHeaderSource,
) -> Result<(), HeaderListError> {
    repair_header_list_last(headers);
    checked_header_list(headers, source)?;
    let entries = unsafe { NgxList::<ngx_table_elt_t>::raw_iter_mut(headers) }
        .ok_or(HeaderListError::InvalidList)?;
    for header in entries {
        let hash = unsafe { ptr::addr_of!((*header.as_ptr()).hash).read() };
        if hash == 0 {
            continue;
        }
        let key = unsafe { header_bytes_unchecked(ptr::addr_of!((*header.as_ptr()).key).read()) };
        if key.eq_ignore_ascii_case(b"Content-Length")
            || key.eq_ignore_ascii_case(b"Transfer-Encoding")
        {
            unsafe { ptr::addr_of_mut!((*header.as_ptr()).hash).write(0) };
        }
    }
    Ok(())
}

pub(super) fn disable_output_framing_headers(
    headers: &mut ngx_http_headers_out_t,
) -> Result<(), HeaderListError> {
    disable_framing_headers(&mut headers.headers, HttpHeaderSource::Output)?;
    headers.content_length = ptr::null_mut();
    Ok(())
}

/// Iterator over enabled HTTP headers in an [`ngx_list_t`].
pub struct NgxListIterator<'a>(NgxListRawIter<'a, ngx_table_elt_t>);

/// Creates a new HTTP header iterator.
///
/// # Safety
///
/// The list parts and element slots must be valid. Every entry's `hash` must be initialized, and
/// enabled entries must have initialized key and value strings that remain valid for the returned
/// borrow. Disabled entries may leave all other fields uninitialized.
pub unsafe fn list_iterator(list: &ngx_list_t) -> NgxListIterator<'_> {
    let headers = unsafe { NgxList::raw_iter(list) }.expect("HTTP header list type");
    NgxListIterator(headers)
}

impl<'a> Iterator for NgxListIterator<'a> {
    type Item = (&'a NgxStr, &'a NgxStr);

    fn next(&mut self) -> Option<Self::Item> {
        for header in self.0.by_ref() {
            let hash = unsafe { ptr::addr_of!((*header.as_ptr()).hash).read() };
            if hash == 0 {
                continue;
            }
            let key = unsafe { ptr::addr_of!((*header.as_ptr()).key).read() };
            let value = unsafe { ptr::addr_of!((*header.as_ptr()).value).read() };
            return unsafe { Some((NgxStr::from_ngx_str(key), NgxStr::from_ngx_str(value))) };
        }
        None
    }
}

impl<'callback> RequestRef<'callback> {
    /// Client HTTP User-Agent, when nginx parsed one.
    pub fn user_agent(&self) -> Result<Option<&NgxStr>, RequestError> {
        let header = unsafe { self.raw.as_ref().headers_in.user_agent };
        if header.is_null() {
            return Ok(None);
        }

        unsafe { checked_ngx_str((*header).value) }.map(Some)
    }

    /// Returns a checked byte-oriented view over input headers.
    pub fn headers_in(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(
            unsafe { &self.raw.as_ref().headers_in.headers },
            HttpHeaderSource::Input,
        )
    }

    /// Returns a checked byte-oriented view over output headers.
    pub fn headers_out(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(
            unsafe { &self.raw.as_ref().headers_out.headers },
            HttpHeaderSource::Output,
        )
    }

    /// Returns a checked byte-oriented view over output trailers.
    pub fn trailers_out(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(
            unsafe { &self.raw.as_ref().headers_out.trailers },
            HttpHeaderSource::Output,
        )
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

impl<'callback> RequestRefMut<'callback> {
    /// Client HTTP User-Agent, when nginx parsed one.
    pub fn user_agent(&self) -> Result<Option<&NgxStr>, RequestError> {
        let header = unsafe { self.raw.as_ref().headers_in.user_agent };
        if header.is_null() {
            return Ok(None);
        }

        unsafe { checked_ngx_str((*header).value) }.map(Some)
    }

    /// Returns a checked byte-oriented view over input headers.
    pub fn headers_in(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(
            unsafe { &self.raw.as_ref().headers_in.headers },
            HttpHeaderSource::Input,
        )
    }

    /// Returns a checked byte-oriented view over output headers.
    pub fn headers_out(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(
            unsafe { &self.raw.as_ref().headers_out.headers },
            HttpHeaderSource::Output,
        )
    }

    /// Starts constructing a raw replacement input-header list in the request pool.
    ///
    /// The builder reconstructs the list and selected pointer slots, but it does not run nginx's
    /// input-header processors or derive every scalar and flag they own.
    ///
    /// # Safety
    ///
    /// Before any native consumer observes a committed candidate, the caller must ensure that the
    /// list, built-in slots, count, parsing scalars, and flags form one coherent request state.
    ///
    /// ```compile_fail
    /// use ngx::http::RequestRefMut;
    ///
    /// fn replace_without_native_state(request: &mut RequestRefMut<'_>) {
    ///     let _ = request.headers_in_builder(1);
    /// }
    /// ```
    #[cfg(nginx1_29_8)]
    pub unsafe fn headers_in_builder(
        &mut self,
        capacity: usize,
    ) -> Result<HttpHeadersInBuilder<'_, 'callback>, HeaderBuildError> {
        HttpHeadersInBuilder::new(self, capacity)
    }

    /// Starts constructing a complete replacement output-header list in the request pool.
    ///
    /// Response framing must be configured through
    /// [`HttpHeadersOutBuilder::set_content_length`], not raw framing headers.
    #[cfg(nginx1_29_8)]
    pub fn headers_out_builder(
        &mut self,
        capacity: usize,
    ) -> Result<HttpHeadersOutBuilder<'_, 'callback>, HeaderBuildError> {
        HttpHeadersOutBuilder::new(self, capacity)
    }

    /// Starts constructing a complete output-header candidate with fresh response metadata.
    ///
    /// Unlike [`headers_out_builder`](Self::headers_out_builder), this clears the status,
    /// trailers, and scalar output metadata inherited from the current response. Response framing
    /// must be configured through [`HttpHeadersOutBuilder::set_content_length`], not raw framing
    /// headers.
    #[cfg(nginx1_29_8)]
    pub fn clean_headers_out_builder(
        &mut self,
        capacity: usize,
    ) -> Result<HttpHeadersOutBuilder<'_, 'callback>, HeaderBuildError> {
        let mut builder = HttpHeadersOutBuilder::new(self, capacity)?;
        clear_headers_out_metadata(&mut builder.headers);
        builder.expect_trailers = Some(false);
        Ok(builder)
    }

    /// Starts constructing a complete replacement output-trailer list in the request pool.
    pub fn trailers_out_builder(
        &mut self,
        capacity: usize,
    ) -> Result<HttpTrailersOutBuilder<'_, 'callback>, HeaderBuildError> {
        HttpTrailersOutBuilder::new(self, capacity)
    }

    /// Returns a checked byte-oriented view over output trailers.
    pub fn trailers_out(&self) -> Result<HttpHeaderList<'_>, HeaderListError> {
        checked_header_list(
            unsafe { &self.raw.as_ref().headers_out.trailers },
            HttpHeaderSource::Output,
        )
    }

    /// Iterates over input headers.
    pub fn headers_in_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.raw.as_ref().headers_in.headers) }
    }

    /// Iterates over output headers.
    pub fn headers_out_iterator(&self) -> NgxListIterator<'_> {
        unsafe { list_iterator(&self.raw.as_ref().headers_out.headers) }
    }

    /// Adds a raw input-header list entry allocated from the request pool.
    ///
    /// This operation does not update nginx's built-in header slots, count, parsing scalars, or
    /// flags.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no subsequent native consumer relies on compiled input-header
    /// state that diverges from the appended list entry.
    ///
    /// ```compile_fail
    /// use ngx::http::RequestRefMut;
    ///
    /// fn append_without_native_state(request: &mut RequestRefMut<'_>) {
    ///     let _ = request.add_header_in("X-Example", "value");
    /// }
    /// ```
    pub unsafe fn add_header_in(&mut self, key: &str, value: &str) -> Result<(), RequestError> {
        let pool = self.pool()?.as_ptr();
        append_pool_header(
            unsafe { &mut self.raw.as_mut().headers_in.headers },
            pool,
            key.as_bytes(),
            value.as_bytes(),
        )
        .map(|_| ())
        .map_err(|_| RequestError::Allocation)
    }

    pub(crate) fn reset_headers_in(&mut self, headers: ngx_list_t) {
        let request = unsafe { self.raw.as_mut() };
        request.headers_in = unsafe { core::mem::zeroed() };
        request.headers_in.headers = headers;
        request.headers_in.headers.last = &raw mut request.headers_in.headers.part;
        request.headers_in.content_length_n = -1;
        request.headers_in.keep_alive_n = -1;
    }

    pub(crate) fn repair_headers_in_last(&mut self) {
        repair_header_list_last(unsafe { &mut self.raw.as_mut().headers_in.headers });
    }

    /// Adds an output header allocated from the request pool.
    ///
    /// Content-Length and Transfer-Encoding are managed through
    /// [`set_content_length_n`](Self::set_content_length_n) and nginx's output filters.
    pub fn add_header_out(&mut self, key: &str, value: &str) -> Result<(), RequestError> {
        if key.eq_ignore_ascii_case("Content-Length")
            || key.eq_ignore_ascii_case("Transfer-Encoding")
        {
            return Err(RequestError::ManagedOutputFraming);
        }
        let pool = self.pool()?.as_ptr();
        append_pool_header(
            unsafe { &mut self.raw.as_mut().headers_out.headers },
            pool,
            key.as_bytes(),
            value.as_bytes(),
        )
        .map(|_| ())
        .map_err(|_| RequestError::Allocation)
    }

    /// Sets the response Content-Length and removes conflicting list framing.
    pub fn set_content_length_n(&mut self, length: usize) -> Result<(), RequestError> {
        let length = off_t::try_from(length).map_err(|_| RequestError::ContentLengthTooLarge)?;
        let request = unsafe { self.raw.as_mut() };
        disable_output_framing_headers(&mut request.headers_out)
            .map_err(RequestError::InvalidHeaderList)?;
        request.headers_out.content_length_n = length;
        request.set_chunked(0);
        Ok(())
    }
}
