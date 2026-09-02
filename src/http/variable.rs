use core::alloc::Layout;
use core::error;
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ops::Deref;
use core::pin::Pin;
use core::ptr::{self, NonNull};

use crate::allocator::Allocator;
use crate::core::{NgxStr, Pool};
use crate::ffi::{
    NGX_ERROR, NGX_HTTP_VAR_CHANGEABLE, NGX_HTTP_VAR_NOCACHEABLE, NGX_HTTP_VAR_NOHASH,
    NGX_HTTP_VAR_PREFIX, NGX_HTTP_VAR_WEAK, NGX_OK, ngx_http_add_variable,
    ngx_http_core_main_conf_t, ngx_http_get_flushed_variable, ngx_http_get_indexed_variable,
    ngx_http_get_variable_index, ngx_http_request_t, ngx_http_variable_t, ngx_int_t, ngx_str_t,
    ngx_uint_t, ngx_variable_value_t,
};
use crate::http::{
    HttpConfigError, HttpConfigurationParser, HttpModuleMainConf, HttpModuleRequestContext,
    IntoHandlerStatus, NgxHttpCoreModule, RequestContextError, RequestError, RequestRef,
    RequestRefMut, request_callback_status,
};

bitflags::bitflags! {
    /// Flags controlling HTTP variable registration and caching.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct HttpVariableFlags: ngx_uint_t {
        /// Allows another module to redefine the variable.
        const CHANGEABLE = NGX_HTTP_VAR_CHANGEABLE as _;
        /// Re-evaluates the variable instead of caching its first value.
        const NOCACHEABLE = NGX_HTTP_VAR_NOCACHEABLE as _;
        /// Excludes the variable from the name hash.
        const NOHASH = NGX_HTTP_VAR_NOHASH as _;
        /// Lets a later non-weak definition replace this variable.
        const WEAK = NGX_HTTP_VAR_WEAK as _;
        /// Native prefix marker applied automatically by [`add_prefix_variable`].
        const PREFIX = NGX_HTTP_VAR_PREFIX as _;
    }
}

/// Error returned when nginx rejects an HTTP variable registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpVariableRegistrationError;

impl fmt::Display for HttpVariableRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("failed to register HTTP variable")
    }
}

impl error::Error for HttpVariableRegistrationError {}

/// Error returned when nginx cannot create an indexed HTTP variable reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVariableIndexError {
    /// The configuration cannot resolve the HTTP core main configuration.
    Configuration(HttpConfigError),
    /// The configuration has no HTTP core main configuration.
    MissingCoreMainConfiguration,
    /// Nginx rejected the variable name or could not allocate its index.
    Registration,
}

impl fmt::Display for HttpVariableIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(_) => {
                formatter.write_str("failed to resolve HTTP variable configuration")
            }
            Self::MissingCoreMainConfiguration => {
                formatter.write_str("HTTP core main configuration is unavailable")
            }
            Self::Registration => formatter.write_str("failed to create HTTP variable index"),
        }
    }
}

impl error::Error for HttpVariableIndexError {}

impl From<HttpConfigError> for HttpVariableIndexError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

/// Opaque index for one HTTP core configuration.
///
/// Create a new index during each configuration pass. An index is not interchangeable between
/// independently allocated HTTP core configurations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpVariableIndex {
    index: ngx_uint_t,
    core_main: NonNull<ngx_http_core_main_conf_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

/// Error returned when nginx's indexed HTTP variable cache cannot be invalidated safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVariableCacheInvalidationError {
    /// The request cannot resolve the HTTP core main configuration.
    Configuration(HttpConfigError),
    /// The request has no HTTP core main configuration.
    MissingCoreMainConfiguration,
    /// A preserved index belongs to a different HTTP core configuration.
    ForeignIndex,
    /// A preserved index is outside the configured definition array.
    IndexOutOfBounds,
    /// Nginx's configured variable-definition array cannot be read safely.
    InvalidDefinitionArray,
    /// The request has no indexed-variable storage.
    MissingRequestVariables,
    /// The request's indexed-variable storage is misaligned.
    MisalignedRequestVariables,
    /// The invalidation was prepared for a different request.
    ForeignRequest,
}

impl fmt::Display for HttpVariableCacheInvalidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(_) => {
                formatter.write_str("failed to resolve HTTP variable configuration")
            }
            Self::MissingCoreMainConfiguration => {
                formatter.write_str("HTTP core main configuration is unavailable")
            }
            Self::ForeignIndex => formatter
                .write_str("preserved HTTP variable index belongs to another configuration"),
            Self::IndexOutOfBounds => {
                formatter.write_str("preserved HTTP variable index is out of bounds")
            }
            Self::InvalidDefinitionArray => {
                formatter.write_str("HTTP variable definitions are invalid")
            }
            Self::MissingRequestVariables => {
                formatter.write_str("request has no indexed HTTP variable storage")
            }
            Self::MisalignedRequestVariables => {
                formatter.write_str("request HTTP variable storage is misaligned")
            }
            Self::ForeignRequest => {
                formatter.write_str("HTTP variable invalidation belongs to another request")
            }
        }
    }
}

impl error::Error for HttpVariableCacheInvalidationError {}

impl From<HttpConfigError> for HttpVariableCacheInvalidationError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

/// Checked one-shot invalidation of getter-backed indexed HTTP variable values.
///
/// Preparation validates every pointer and preserved index before request state changes. Commit
/// clears getter-backed cached values, including changeable computed variables such as maps, while
/// preserving explicitly listed indexes and native weak slots assigned directly by rewrite code.
pub struct HttpVariableCacheInvalidation<'preserved, 'callback> {
    request: NonNull<ngx_http_request_t>,
    definitions: NonNull<ngx_http_variable_t>,
    values: NonNull<ngx_variable_value_t>,
    count: usize,
    preserved: &'preserved [HttpVariableIndex],
    _callback: PhantomData<&'callback mut ngx_http_request_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'preserved, 'callback> HttpVariableCacheInvalidation<'preserved, 'callback> {
    /// Validates the request cache and indexes that must survive invalidation.
    pub fn prepare(
        request: &RequestRefMut<'callback>,
        preserved: &'preserved [HttpVariableIndex],
    ) -> Result<Self, HttpVariableCacheInvalidationError> {
        let core_main = request
            .main_conf::<NgxHttpCoreModule>()?
            .ok_or(HttpVariableCacheInvalidationError::MissingCoreMainConfiguration)?;
        let variables = &core_main.variables;
        if variables.nelts > variables.nalloc
            || variables.size != mem::size_of::<ngx_http_variable_t>()
            || (variables.nelts != 0 && (variables.elts.is_null() || !variables.elts.is_aligned()))
        {
            return Err(HttpVariableCacheInvalidationError::InvalidDefinitionArray);
        }
        for index in preserved {
            if !ptr::eq(core_main, index.core_main.as_ptr()) {
                return Err(HttpVariableCacheInvalidationError::ForeignIndex);
            }
            if index.index >= variables.nelts {
                return Err(HttpVariableCacheInvalidationError::IndexOutOfBounds);
            }
        }

        let raw_request = NonNull::new(unsafe { request.as_ptr() })
            .ok_or(HttpVariableCacheInvalidationError::ForeignRequest)?;
        let values = NonNull::new(unsafe { (*raw_request.as_ptr()).variables });
        if variables.nelts != 0 {
            let values =
                values.ok_or(HttpVariableCacheInvalidationError::MissingRequestVariables)?;
            if !values.as_ptr().is_aligned() {
                return Err(HttpVariableCacheInvalidationError::MisalignedRequestVariables);
            }
        }

        Ok(Self {
            request: raw_request,
            definitions: NonNull::new(variables.elts.cast()).unwrap_or_else(NonNull::dangling),
            values: values.unwrap_or_else(NonNull::dangling),
            count: variables.nelts,
            preserved,
            _callback: PhantomData,
            _not_thread_safe: PhantomData,
        })
    }

    /// Invalidates the prepared request's recomputable variable values.
    pub fn commit(
        self,
        request: &mut RequestRefMut<'callback>,
    ) -> Result<(), HttpVariableCacheInvalidationError> {
        let raw_request = unsafe { request.as_ptr() };
        if !ptr::eq(raw_request, self.request.as_ptr())
            || (self.count != 0 && unsafe { (*raw_request).variables } != self.values.as_ptr())
        {
            return Err(HttpVariableCacheInvalidationError::ForeignRequest);
        }

        for index in 0..self.count {
            let definition = unsafe { &*self.definitions.as_ptr().add(index) };
            if definition.get_handler.is_none()
                || definition.flags & NGX_HTTP_VAR_WEAK as ngx_uint_t != 0
                || self.preserved.iter().any(|preserved| preserved.index == index as ngx_uint_t)
            {
                continue;
            }

            let value = unsafe { &mut *self.values.as_ptr().add(index) };
            value.set_valid(0);
            value.set_not_found(0);
        }

        Ok(())
    }
}

/// Error returned when an indexed HTTP variable cannot be looked up safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVariableLookupError {
    /// The request cannot resolve the HTTP core main configuration.
    Configuration(HttpConfigError),
    /// The request has no HTTP core main configuration.
    MissingCoreMainConfiguration,
    /// The index belongs to a different HTTP core configuration.
    ForeignConfiguration,
    /// The indexed variable is outside the configured definition array.
    IndexOutOfBounds,
    /// Nginx's configured variable-definition array cannot be read safely.
    InvalidDefinitionArray,
    /// The indexed variable has no getter that nginx can invoke.
    MissingHandler,
    /// The request has no indexed-variable storage.
    MissingRequestVariables,
    /// The request's indexed-variable storage is misaligned.
    MisalignedRequestVariables,
    /// Nginx returned no indexed value.
    NullResult,
    /// Nginx returned an indexed value with invalid pointer state.
    InvalidResult,
}

impl fmt::Display for HttpVariableLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(_) => {
                formatter.write_str("failed to resolve HTTP variable configuration")
            }
            Self::MissingCoreMainConfiguration => {
                formatter.write_str("HTTP core main configuration is unavailable")
            }
            Self::ForeignConfiguration => {
                formatter.write_str("HTTP variable index belongs to another configuration")
            }
            Self::IndexOutOfBounds => formatter.write_str("HTTP variable index is out of bounds"),
            Self::InvalidDefinitionArray => {
                formatter.write_str("HTTP variable definitions are invalid")
            }
            Self::MissingHandler => formatter.write_str("HTTP variable has no getter"),
            Self::MissingRequestVariables => {
                formatter.write_str("request has no indexed HTTP variable storage")
            }
            Self::MisalignedRequestVariables => {
                formatter.write_str("request HTTP variable storage is misaligned")
            }
            Self::NullResult => formatter.write_str("nginx returned no HTTP variable value"),
            Self::InvalidResult => {
                formatter.write_str("nginx returned an invalid HTTP variable value")
            }
        }
    }
}

impl error::Error for HttpVariableLookupError {}

impl From<HttpConfigError> for HttpVariableLookupError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

/// Error returned when HTTP variable output cannot be published safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVariableOutputError {
    /// The value exceeds nginx's 28-bit variable length field.
    TooLong,
    /// A nonempty value has no backing bytes.
    NullData,
    /// The request has no usable pool.
    Request(RequestError),
    /// Nginx could not allocate request-pool storage for copied bytes.
    Allocation,
    /// The supplied pool bytes belong to a different request pool.
    PoolMismatch,
}

impl fmt::Display for HttpVariableOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => formatter.write_str("HTTP variable value is too long"),
            Self::NullData => formatter.write_str("HTTP variable value has null data"),
            Self::Request(_) => formatter.write_str("HTTP request has no usable pool"),
            Self::Allocation => formatter.write_str("failed to allocate HTTP variable bytes"),
            Self::PoolMismatch => formatter.write_str("HTTP variable bytes belong to another pool"),
        }
    }
}

impl error::Error for HttpVariableOutputError {}

impl From<RequestError> for HttpVariableOutputError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Bytes copied into the current HTTP request pool for a variable output.
///
/// Pool bytes cannot outlive the request view that created them:
///
/// ```compile_fail
/// use ngx::http::{HttpVariablePoolBytes, RequestRefMut};
///
/// fn escape(request: &RequestRefMut<'_>) -> HttpVariablePoolBytes<'static> {
///     HttpVariablePoolBytes::copy_from_request(request, b"value").unwrap()
/// }
/// ```
pub struct HttpVariablePoolBytes<'pool> {
    data: NonNull<u8>,
    len: usize,
    pool: Pool<'pool>,
}

impl<'pool> HttpVariablePoolBytes<'pool> {
    /// Copies bytes into the pool owned by `request`.
    pub fn copy_from_request(
        request: &'pool RequestRefMut<'_>,
        value: &[u8],
    ) -> Result<Self, HttpVariableOutputError> {
        if value.len() > HttpVariableOutput::MAX_LEN {
            return Err(HttpVariableOutputError::TooLong);
        }

        let pool = request.pool()?;
        let data = if value.is_empty() {
            NonNull::dangling()
        } else {
            let layout = Layout::array::<u8>(value.len())
                .map_err(|_| HttpVariableOutputError::Allocation)?;
            let data = pool
                .allocate(layout)
                .map_err(|_| HttpVariableOutputError::Allocation)?
                .cast::<u8>();
            unsafe { ptr::copy_nonoverlapping(value.as_ptr(), data.as_ptr(), value.len()) };
            data
        };

        Ok(Self { data, len: value.len(), pool })
    }

    /// Returns the bytes retained by the request pool.
    pub fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }

        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}

/// Write-only result supplied to an HTTP variable getter.
pub struct HttpVariableOutput<'callback> {
    raw: NonNull<ngx_variable_value_t>,
    candidate: Option<ngx_variable_value_t>,
    _callback: PhantomData<&'callback mut core::mem::MaybeUninit<ngx_variable_value_t>>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl HttpVariableOutput<'_> {
    const MAX_LEN: usize = (1 << 28) - 1;

    unsafe fn from_raw<'callback>(
        value: *mut ngx_variable_value_t,
    ) -> Option<HttpVariableOutput<'callback>> {
        let raw = NonNull::new(value)?;
        if !value.is_aligned() {
            return None;
        }

        Some(HttpVariableOutput {
            raw,
            candidate: None,
            _callback: PhantomData,
            _not_thread_safe: PhantomData,
        })
    }

    /// Stores bytes whose static lifetime outlives every nginx request.
    ///
    /// ```compile_fail
    /// use ngx::http::HttpVariableOutput;
    ///
    /// fn set_from_callback(output: &mut HttpVariableOutput<'_>, bytes: &[u8]) {
    ///     output.set_static(bytes).unwrap();
    /// }
    /// ```
    pub fn set_static(&mut self, value: &'static [u8]) -> Result<(), HttpVariableOutputError> {
        self.set_found(value.len(), value.as_ptr().cast_mut(), true)
    }

    /// Stores static bytes and asks nginx to evaluate the getter on every access.
    pub fn set_static_uncached(
        &mut self,
        value: &'static [u8],
    ) -> Result<(), HttpVariableOutputError> {
        self.set_found(value.len(), value.as_ptr().cast_mut(), false)
    }

    /// Stores a cacheable value backed by nginx-owned bytes without copying them.
    ///
    /// # Safety
    ///
    /// `data` must point to `len` initialized bytes that remain valid and unchanged until nginx no
    /// longer can read this variable value. The backing storage must not be stack, context, parser,
    /// or other callback-scoped memory.
    pub unsafe fn set_borrowed(
        &mut self,
        data: *mut u8,
        len: usize,
    ) -> Result<(), HttpVariableOutputError> {
        self.set_found(len, data, true)
    }

    /// Stores a noncacheable value backed by nginx-owned bytes without copying them.
    ///
    /// # Safety
    ///
    /// `data` must point to `len` initialized bytes that remain valid and unchanged until nginx no
    /// longer can read this variable value. The backing storage must not be stack, context, parser,
    /// or other callback-scoped memory.
    pub unsafe fn set_borrowed_uncached(
        &mut self,
        data: *mut u8,
        len: usize,
    ) -> Result<(), HttpVariableOutputError> {
        self.set_found(len, data, false)
    }

    /// Stores bytes already retained by the current request pool.
    ///
    /// The setter accepts only bytes retained by the current request pool, so arbitrary stack,
    /// context, and parser slices cannot be cached accidentally:
    ///
    /// ```compile_fail
    /// use ngx::http::{HttpVariableOutput, RequestRefMut};
    ///
    /// fn set(value: &mut HttpVariableOutput<'_>, request: &RequestRefMut<'_>) {
    ///     let stack = *b"stack";
    ///     value.set_pool(request, &stack);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::http::{HttpVariableOutput, RequestRefMut};
    ///
    /// struct Context {
    ///     bytes: [u8; 7],
    /// }
    ///
    /// fn set(
    ///     value: &mut HttpVariableOutput<'_>,
    ///     request: &RequestRefMut<'_>,
    ///     context: &Context,
    /// ) {
    ///     value.set_pool(request, &context.bytes);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::http::{HttpVariableOutput, RequestRefMut};
    ///
    /// fn set(value: &mut HttpVariableOutput<'_>, request: &RequestRefMut<'_>, parser: &[u8]) {
    ///     value.set_pool(request, parser);
    /// }
    /// ```
    pub fn set_pool(
        &mut self,
        request: &RequestRefMut<'_>,
        value: HttpVariablePoolBytes<'_>,
    ) -> Result<(), HttpVariableOutputError> {
        self.set_pool_with_cache(request, value, true)
    }

    /// Stores request-pool bytes and asks nginx to evaluate the getter on every access.
    pub fn set_pool_uncached(
        &mut self,
        request: &RequestRefMut<'_>,
        value: HttpVariablePoolBytes<'_>,
    ) -> Result<(), HttpVariableOutputError> {
        self.set_pool_with_cache(request, value, false)
    }

    /// Copies callback bytes into the current request pool before publishing a cacheable value.
    pub fn copy_from_request(
        &mut self,
        request: &RequestRefMut<'_>,
        value: &[u8],
    ) -> Result<(), HttpVariableOutputError> {
        let value = HttpVariablePoolBytes::copy_from_request(request, value)?;
        self.set_pool(request, value)
    }

    /// Copies callback bytes into the current request pool and marks the result noncacheable.
    pub fn copy_from_request_uncached(
        &mut self,
        request: &RequestRefMut<'_>,
        value: &[u8],
    ) -> Result<(), HttpVariableOutputError> {
        let value = HttpVariablePoolBytes::copy_from_request(request, value)?;
        self.set_pool_uncached(request, value)
    }

    /// Sets a cacheable found value with no bytes.
    pub fn set_empty(&mut self) {
        self.write_found(0, ptr::null_mut(), true);
    }

    /// Sets a noncacheable found value with no bytes.
    pub fn set_empty_uncached(&mut self) {
        self.write_found(0, ptr::null_mut(), false);
    }

    /// Sets nginx's exact noncacheable not-found state.
    pub fn set_not_found(&mut self) {
        self.candidate = Some(Self::not_found());
    }

    fn set_pool_with_cache(
        &mut self,
        request: &RequestRefMut<'_>,
        value: HttpVariablePoolBytes<'_>,
        cacheable: bool,
    ) -> Result<(), HttpVariableOutputError> {
        let request_pool = request.pool()?;
        if !ptr::eq(request_pool.as_ptr(), value.pool.as_ptr()) {
            return Err(HttpVariableOutputError::PoolMismatch);
        }

        self.set_found(value.len, value.data.as_ptr(), cacheable)
    }

    fn set_found(
        &mut self,
        len: usize,
        data: *mut u8,
        cacheable: bool,
    ) -> Result<(), HttpVariableOutputError> {
        if len > Self::MAX_LEN {
            return Err(HttpVariableOutputError::TooLong);
        }
        if len != 0 && data.is_null() {
            return Err(HttpVariableOutputError::NullData);
        }

        self.write_found(len, data, cacheable);
        Ok(())
    }

    fn write_found(&mut self, len: usize, data: *mut u8, cacheable: bool) {
        self.candidate = Some(ngx_variable_value_t {
            _bitfield_align_1: [],
            _bitfield_1: ngx_variable_value_t::new_bitfield_1(
                len as _,
                1,
                (!cacheable).into(),
                0,
                0,
            ),
            data: if len == 0 { ptr::null_mut() } else { data },
        });
    }

    fn not_found() -> ngx_variable_value_t {
        ngx_variable_value_t {
            _bitfield_align_1: [],
            _bitfield_1: ngx_variable_value_t::new_bitfield_1(0, 0, 1, 1, 0),
            data: ptr::null_mut(),
        }
    }

    fn publish_success(self) {
        let candidate = self.candidate.unwrap_or_else(Self::not_found);
        unsafe { self.raw.as_ptr().write(candidate) };
    }
}

/// Checked callback-bound snapshot of an initialized HTTP variable value.
///
/// The descriptor fields are copied so native variable evaluation cannot alias a Rust reference.
/// Its data bytes remain borrowed from the active request or setter callback:
///
/// ```compile_fail
/// use ngx::http::{HttpVariableIndex, HttpVariableValueRef, RequestRefMut};
///
/// fn escape(
///     index: &HttpVariableIndex,
///     request: &mut RequestRefMut<'_>,
/// ) -> HttpVariableValueRef<'static> {
///     index.get_cached(request).unwrap()
/// }
/// ```
///
/// A live value snapshot also keeps the request mutably borrowed, so safe code cannot flush the
/// same indexed slot before it finishes reading the snapshot:
///
/// ```compile_fail
/// use ngx::http::{HttpVariableIndex, RequestRefMut};
///
/// fn flush_while_reading(index: &HttpVariableIndex, request: &mut RequestRefMut<'_>) {
///     let value = index.get_cached(request).unwrap();
///     let _ = index.get_flushed(request);
///     let _ = value.bytes();
/// }
/// ```
pub struct HttpVariableValueRef<'value> {
    raw: ngx_variable_value_t,
    _value: PhantomData<&'value [u8]>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl HttpVariableValueRef<'_> {
    unsafe fn from_raw(value: *const ngx_variable_value_t) -> Option<Self> {
        let raw = NonNull::new(value.cast_mut())?;
        if !raw.as_ptr().is_aligned() {
            return None;
        }

        let raw = unsafe { raw.as_ptr().read() };
        if raw.not_found() == 0 && raw.len() != 0 && raw.data.is_null() {
            return None;
        }

        Some(Self { raw, _value: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Returns the found bytes, or `None` for nginx's not-found state.
    pub fn bytes(&self) -> Option<&[u8]> {
        if self.raw.not_found() != 0 {
            return None;
        }

        let len = self.raw.len() as usize;
        if len == 0 {
            return Some(&[]);
        }

        Some(unsafe { core::slice::from_raw_parts(self.raw.data, len) })
    }

    /// Returns whether nginx can use this value without rerunning the getter.
    pub fn is_valid(&self) -> bool {
        self.raw.valid() != 0
    }

    /// Returns whether nginx may cache this value.
    pub fn is_cacheable(&self) -> bool {
        self.raw.no_cacheable() == 0
    }

    /// Returns whether the getter reported nginx's not-found state.
    pub fn is_not_found(&self) -> bool {
        self.raw.not_found() != 0
    }

    /// Returns whether nginx must escape this value before rendering it.
    pub fn is_escaped(&self) -> bool {
        self.raw.escape() != 0
    }
}

impl HttpVariableIndex {
    /// Looks up the value currently cached for this request.
    pub fn get_cached<'request>(
        &self,
        request: &'request mut RequestRefMut<'_>,
    ) -> Result<HttpVariableValueRef<'request>, HttpVariableLookupError> {
        self.lookup(request, false)
    }

    /// Clears nginx's noncacheable value state before looking up this request's value.
    pub fn get_flushed<'request>(
        &self,
        request: &'request mut RequestRefMut<'_>,
    ) -> Result<HttpVariableValueRef<'request>, HttpVariableLookupError> {
        self.lookup(request, true)
    }

    fn lookup<'request>(
        &self,
        request: &'request mut RequestRefMut<'_>,
        flushed: bool,
    ) -> Result<HttpVariableValueRef<'request>, HttpVariableLookupError> {
        let index = self.index;

        {
            let request_view = request.view();
            let core_main = request_view
                .main_conf::<NgxHttpCoreModule>()?
                .ok_or(HttpVariableLookupError::MissingCoreMainConfiguration)?;
            if !ptr::eq(core_main, self.core_main.as_ptr()) {
                return Err(HttpVariableLookupError::ForeignConfiguration);
            }

            let variables = &core_main.variables;
            if index >= variables.nelts {
                return Err(HttpVariableLookupError::IndexOutOfBounds);
            }
            if variables.elts.is_null()
                || !variables.elts.is_aligned()
                || variables.nelts > variables.nalloc
                || variables.size != mem::size_of::<ngx_http_variable_t>()
            {
                return Err(HttpVariableLookupError::InvalidDefinitionArray);
            }

            let definition = unsafe { &*variables.elts.cast::<ngx_http_variable_t>().add(index) };
            if definition.get_handler.is_none() {
                return Err(HttpVariableLookupError::MissingHandler);
            }
        }

        let raw_request = unsafe { request.as_ptr() };
        let values = unsafe { (*raw_request).variables };
        let values =
            NonNull::new(values).ok_or(HttpVariableLookupError::MissingRequestVariables)?;
        if !values.as_ptr().is_aligned() {
            return Err(HttpVariableLookupError::MisalignedRequestVariables);
        }

        let value = unsafe {
            if flushed {
                ngx_http_get_flushed_variable(raw_request, self.index)
            } else {
                ngx_http_get_indexed_variable(raw_request, self.index)
            }
        };
        let value = NonNull::new(value).ok_or(HttpVariableLookupError::NullResult)?;

        unsafe { HttpVariableValueRef::from_raw(value.as_ptr()) }
            .ok_or(HttpVariableLookupError::InvalidResult)
    }
}

/// Mutable variable-evaluation capability without terminal request authority.
///
/// Shared request operations remain available through dereferencing, while mutable access is
/// limited to module context and indexed-variable evaluation:
///
/// ```compile_fail
/// use ngx::http::{HTTPStatus, HttpVariableRequest};
///
/// fn cannot_finalize(request: &mut HttpVariableRequest<'_, '_>) {
///     request.finalize(HTTPStatus::BAD_REQUEST).unwrap();
/// }
/// ```
pub struct HttpVariableRequest<'request, 'callback> {
    request: &'request mut RequestRefMut<'callback>,
}

impl<'request, 'callback> HttpVariableRequest<'request, 'callback> {
    fn new(request: &'request mut RequestRefMut<'callback>) -> Self {
        Self { request }
    }

    /// Returns exclusive access to a movable request context associated with module `M`.
    pub fn module_context_mut<M>(
        &mut self,
    ) -> Result<Option<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
        M::RequestContext: Unpin,
    {
        self.request.module_context_mut::<M>()
    }

    /// Returns pinned exclusive access to a request context associated with module `M`.
    pub fn pinned_module_context_mut<M>(
        &mut self,
    ) -> Result<Option<Pin<&mut M::RequestContext>>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        self.request.pinned_module_context_mut::<M>()
    }

    /// Looks up the value currently cached for this request.
    pub fn get_cached<'value>(
        &'value mut self,
        index: &HttpVariableIndex,
    ) -> Result<HttpVariableValueRef<'value>, HttpVariableLookupError> {
        index.get_cached(self.request)
    }

    /// Clears a noncacheable value before looking it up for this request.
    pub fn get_flushed<'value>(
        &'value mut self,
        index: &HttpVariableIndex,
    ) -> Result<HttpVariableValueRef<'value>, HttpVariableLookupError> {
        index.get_flushed(self.request)
    }
}

impl<'request, 'callback> Deref for HttpVariableRequest<'request, 'callback> {
    type Target = RequestRefMut<'callback>;

    fn deref(&self) -> &Self::Target {
        self.request
    }
}

/// Typed getter for a registered HTTP variable.
///
/// A getter must not panic; panics terminate the worker process.
/// Getters receive shared access so they cannot terminate or redirect the request while nginx is
/// still evaluating its variable:
///
/// ```compile_fail
/// use ngx::http::{HttpVariableHandler, HttpVariableOutput, RequestRefMut};
///
/// struct TerminalGetter;
///
/// impl HttpVariableHandler for TerminalGetter {
///     type Output = ngx::core::Status;
///
///     fn get(
///         _request: &mut RequestRefMut<'_>,
///         _value: &mut HttpVariableOutput<'_>,
///         _data: usize,
///     ) -> Self::Output {
///         ngx::core::Status::NGX_ERROR
///     }
/// }
/// ```
pub trait HttpVariableHandler {
    /// Getter result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Evaluates the variable for one active request.
    fn get(
        request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        data: usize,
    ) -> Self::Output;
}

/// Typed getter for a prefix-matched HTTP variable.
///
/// A getter must not panic; panics terminate the worker process.
pub trait HttpPrefixVariableHandler {
    /// Getter result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Evaluates the variable for one active request and the full queried variable name.
    fn get(
        request: &mut HttpVariableRequest<'_, '_>,
        value: &mut HttpVariableOutput<'_>,
        name: &NgxStr,
    ) -> Self::Output;
}

/// Typed setter for a registered HTTP variable.
///
/// A setter must not panic; panics terminate the worker process.
/// Setters receive only shared request access, so they cannot safely flush or re-evaluate a
/// variable while retaining the assigned value:
///
/// ```compile_fail
/// use ngx::http::{HttpVariableSetter, HttpVariableValueRef, RequestRefMut};
///
/// struct MutableSetter;
///
/// impl HttpVariableSetter for MutableSetter {
///     fn set(
///         _request: &mut RequestRefMut<'_>,
///         _value: HttpVariableValueRef<'_>,
///         _data: usize,
///     ) {
///     }
/// }
/// ```
pub trait HttpVariableSetter {
    /// Receives an assignment for one active request.
    fn set(request: &RequestRef<'_>, value: HttpVariableValueRef<'_>, data: usize);
}

/// Registers a typed read-only exact HTTP variable.
///
/// Call this function from the module's preconfiguration callback. `name` does not include `$`.
/// Use [`add_prefix_variable`] instead of passing [`HttpVariableFlags::PREFIX`].
///
/// A raw nginx parser is not a safe registration capability:
///
/// ```compile_fail
/// use ngx::core::NgxStr;
/// use ngx::ffi::ngx_conf_t;
/// use ngx::http::{HttpVariableFlags, HttpVariableHandler, add_variable};
///
/// fn register<H: HttpVariableHandler>(parser: &mut ngx_conf_t, name: &NgxStr) {
///     add_variable::<H>(parser, name, HttpVariableFlags::empty(), 0).unwrap();
/// }
/// ```
pub fn add_variable<H>(
    parser: &mut HttpConfigurationParser<'_>,
    name: &NgxStr,
    flags: HttpVariableFlags,
    data: usize,
) -> Result<(), HttpVariableRegistrationError>
where
    H: HttpVariableHandler,
{
    let mut variable = register_variable(parser, name, flags)?;
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_get_handler::<H>);
    variable.set_handler = None;
    variable.data = data;
    Ok(())
}

/// Registers a typed exact HTTP variable with a setter.
///
/// Call this function from the module's preconfiguration callback. `name` does not include `$`.
/// Prefix variables do not have an nginx assignment route and are rejected.
pub fn add_variable_with_setter<H, S>(
    parser: &mut HttpConfigurationParser<'_>,
    name: &NgxStr,
    flags: HttpVariableFlags,
    data: usize,
) -> Result<(), HttpVariableRegistrationError>
where
    H: HttpVariableHandler,
    S: HttpVariableSetter,
{
    let mut variable = register_variable(parser, name, flags)?;
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_get_handler::<H>);
    variable.set_handler = Some(raw_set_handler::<S>);
    variable.data = data;
    Ok(())
}

/// Registers a typed prefix-matched HTTP variable.
///
/// Call this function from the module's preconfiguration callback. `prefix` does not include `$`.
/// The full queried variable name is passed to the handler when nginx finds this prefix. `flags`
/// must not include [`HttpVariableFlags::PREFIX`], which this function applies automatically.
pub fn add_prefix_variable<H>(
    parser: &mut HttpConfigurationParser<'_>,
    prefix: &NgxStr,
    flags: HttpVariableFlags,
) -> Result<(), HttpVariableRegistrationError>
where
    H: HttpPrefixVariableHandler,
{
    if flags.bits() & !HttpVariableFlags::all().bits() != 0
        || flags.contains(HttpVariableFlags::PREFIX)
    {
        return Err(HttpVariableRegistrationError);
    }

    let main = NgxHttpCoreModule::main_conf_mut(parser)
        .ok()
        .flatten()
        .ok_or(HttpVariableRegistrationError)?;
    let original_nelts = main.prefix_variables.nelts;
    let prefix_nelts = &raw mut main.prefix_variables.nelts;
    let mut prefix = prefix.as_ngx_str();
    let Some(mut variable) = NonNull::new(unsafe {
        ngx_http_add_variable(
            parser.as_raw(),
            &raw mut prefix,
            flags.bits() | HttpVariableFlags::PREFIX.bits(),
        )
    }) else {
        unsafe { prefix_nelts.write(original_nelts) };
        return Err(HttpVariableRegistrationError);
    };
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_prefix_get_handler::<H>);
    variable.set_handler = None;
    variable.data = 0;
    Ok(())
}

fn register_variable(
    parser: &mut HttpConfigurationParser<'_>,
    name: &NgxStr,
    flags: HttpVariableFlags,
) -> Result<NonNull<ngx_http_variable_t>, HttpVariableRegistrationError> {
    if flags.bits() & !HttpVariableFlags::all().bits() != 0
        || flags.contains(HttpVariableFlags::PREFIX)
    {
        return Err(HttpVariableRegistrationError);
    }

    let mut name = name.as_ngx_str();
    NonNull::new(unsafe { ngx_http_add_variable(parser.as_raw(), &raw mut name, flags.bits()) })
        .ok_or(HttpVariableRegistrationError)
}

/// Creates an opaque index for an HTTP variable.
///
/// Call this function during the same configuration pass that registers the variable. The index
/// can later be used only with requests from that HTTP core configuration.
///
/// ```compile_fail
/// use ngx::core::NgxStr;
/// use ngx::ffi::ngx_conf_t;
/// use ngx::http::get_variable_index;
///
/// fn index(parser: &mut ngx_conf_t, name: &NgxStr) {
///     let _ = get_variable_index(parser, name);
/// }
/// ```
pub fn get_variable_index(
    parser: &mut HttpConfigurationParser<'_>,
    name: &NgxStr,
) -> Result<HttpVariableIndex, HttpVariableIndexError> {
    let core_main = NgxHttpCoreModule::main_conf_mut(parser)?
        .ok_or(HttpVariableIndexError::MissingCoreMainConfiguration)?;
    let original_nelts = core_main.variables.nelts;
    let variables_nelts = &raw mut core_main.variables.nelts;
    let core_main = NonNull::from(core_main);
    let mut name = name.as_ngx_str();
    let index = unsafe { ngx_http_get_variable_index(parser.as_raw(), &raw mut name) };
    if index == NGX_ERROR as _ {
        unsafe { variables_nelts.write(original_nelts) };
        return Err(HttpVariableIndexError::Registration);
    }
    let index = ngx_uint_t::try_from(index).map_err(|_| HttpVariableIndexError::Registration)?;

    Ok(HttpVariableIndex { index, core_main, _not_thread_safe: PhantomData })
}

/// C-compatible adapter for a typed HTTP variable getter.
///
/// # Safety
/// `request` and `value` must be the valid non-null pointers supplied by nginx for the duration of
/// this callback, and the request must be exclusively available to the getter.
pub(crate) unsafe extern "C" fn raw_get_handler<H>(
    request: *mut ngx_http_request_t,
    value: *mut ngx_variable_value_t,
    data: usize,
) -> ngx_int_t
where
    H: HttpVariableHandler,
{
    unsafe {
        request_callback_status(request, |request| {
            let Some(mut output) = HttpVariableOutput::from_raw(value) else {
                return NGX_ERROR as _;
            };

            let mut request = HttpVariableRequest::new(request);
            let result = H::get(&mut request, &mut output, data);
            let status = result.into_handler_status(&request.view());
            if status == NGX_OK as _ {
                output.publish_success();
            }

            status
        })
    }
}

unsafe fn prefix_name_from_data<'callback>(data: usize) -> Option<&'callback NgxStr> {
    let name = NonNull::new(ptr::with_exposed_provenance_mut::<ngx_str_t>(data))?;
    if !name.as_ptr().is_aligned() {
        return None;
    }

    let name = unsafe { name.as_ptr().read() };
    if name.len == 0 || name.len > isize::MAX as usize || name.data.is_null() {
        return None;
    }

    Some(unsafe { NgxStr::from_ngx_str(name) })
}

/// C-compatible adapter for a typed prefix-matched HTTP variable getter.
///
/// # Safety
/// `request` and `value` must be valid pointers supplied by nginx for this callback, and `data`
/// must encode the live `ngx_str_t` full-name descriptor used by nginx's prefix dispatch.
pub(crate) unsafe extern "C" fn raw_prefix_get_handler<H>(
    request: *mut ngx_http_request_t,
    value: *mut ngx_variable_value_t,
    data: usize,
) -> ngx_int_t
where
    H: HttpPrefixVariableHandler,
{
    unsafe {
        request_callback_status(request, |request| {
            let Some(mut output) = HttpVariableOutput::from_raw(value) else {
                return NGX_ERROR as _;
            };
            let Some(name) = prefix_name_from_data(data) else {
                return NGX_ERROR as _;
            };

            let mut request = HttpVariableRequest::new(request);
            let result = H::get(&mut request, &mut output, name);
            let status = result.into_handler_status(&request.view());
            if status == NGX_OK as _ {
                output.publish_success();
            }

            status
        })
    }
}

/// C-compatible adapter for a typed HTTP variable setter.
///
/// # Safety
/// `request` and `value` must be the valid non-null pointers supplied by nginx for the duration of
/// this callback, and the request must be exclusively available to the setter.
pub(crate) unsafe extern "C" fn raw_set_handler<S>(
    request: *mut ngx_http_request_t,
    value: *mut ngx_variable_value_t,
    data: usize,
) where
    S: HttpVariableSetter,
{
    let _ = unsafe {
        request_callback_status(request, |request| {
            let Some(value) = HttpVariableValueRef::from_raw(value) else {
                return crate::core::Status::NGX_ERROR;
            };

            S::set(&request.view(), value, data);
            crate::core::Status::NGX_OK
        })
    };
}

#[cfg(test)]
#[path = "variable/tests/mod.rs"]
mod tests;
