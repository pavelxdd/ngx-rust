use core::alloc::Layout;
use core::error;
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};

use crate::allocator::Allocator;
use crate::core::{NgxStr, Pool};
use crate::ffi::{
    NGX_ERROR, NGX_HTTP_VAR_CHANGEABLE, NGX_HTTP_VAR_NOCACHEABLE, NGX_HTTP_VAR_NOHASH,
    NGX_HTTP_VAR_PREFIX, NGX_HTTP_VAR_WEAK, ngx_conf_t, ngx_http_add_variable,
    ngx_http_core_main_conf_t, ngx_http_get_flushed_variable, ngx_http_get_indexed_variable,
    ngx_http_get_variable_index, ngx_http_request_t, ngx_http_variable_t, ngx_int_t, ngx_uint_t,
    ngx_variable_value_t,
};
use crate::http::{
    HttpConfigError, HttpModuleMainConf, IntoHandlerStatus, NgxHttpCoreModule, RequestError,
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
        /// Treats the name as a prefix matched against variable names.
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
pub enum HttpVariableValueError {
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

impl fmt::Display for HttpVariableValueError {
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

impl error::Error for HttpVariableValueError {}

impl From<RequestError> for HttpVariableValueError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Error returned when a raw HTTP variable value cannot be read safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVariableValueReadError {
    /// A nonempty found value has a null data pointer.
    NullData,
}

impl fmt::Display for HttpVariableValueReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullData => formatter.write_str("HTTP variable value has null data"),
        }
    }
}

impl error::Error for HttpVariableValueReadError {}

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
    ) -> Result<Self, HttpVariableValueError> {
        if value.len() > HttpVariableValue::MAX_LEN {
            return Err(HttpVariableValueError::TooLong);
        }

        let pool = request.pool()?;
        let data = if value.is_empty() {
            NonNull::dangling()
        } else {
            let layout =
                Layout::array::<u8>(value.len()).map_err(|_| HttpVariableValueError::Allocation)?;
            let data =
                pool.allocate(layout).map_err(|_| HttpVariableValueError::Allocation)?.cast::<u8>();
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

/// Borrowed output value supplied to an HTTP variable getter.
pub struct HttpVariableValue<'callback> {
    raw: NonNull<ngx_variable_value_t>,
    _callback: PhantomData<&'callback mut ngx_variable_value_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl HttpVariableValue<'_> {
    const MAX_LEN: usize = (1 << 28) - 1;

    unsafe fn from_raw<'callback>(
        value: *mut ngx_variable_value_t,
    ) -> Option<HttpVariableValue<'callback>> {
        let raw = NonNull::new(value)?;
        if !value.is_aligned() {
            return None;
        }

        Some(HttpVariableValue { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Returns a checked view of the current output state.
    pub fn read(&self) -> Result<HttpVariableValueRef<'_>, HttpVariableValueReadError> {
        let raw = unsafe { self.raw.as_ref() };
        if raw.not_found() == 0 && raw.len() != 0 && raw.data.is_null() {
            return Err(HttpVariableValueReadError::NullData);
        }

        Ok(HttpVariableValueRef { raw, _not_thread_safe: PhantomData })
    }

    /// Stores bytes whose static lifetime outlives every nginx request.
    ///
    /// ```compile_fail
    /// use ngx::http::HttpVariableValue;
    ///
    /// fn set_from_callback(output: &mut HttpVariableValue<'_>, bytes: &[u8]) {
    ///     output.set_static(bytes).unwrap();
    /// }
    /// ```
    pub fn set_static(&mut self, value: &'static [u8]) -> Result<(), HttpVariableValueError> {
        self.set_found(value.len(), value.as_ptr().cast_mut(), true)
    }

    /// Stores static bytes and asks nginx to evaluate the getter on every access.
    pub fn set_static_uncached(
        &mut self,
        value: &'static [u8],
    ) -> Result<(), HttpVariableValueError> {
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
    ) -> Result<(), HttpVariableValueError> {
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
    ) -> Result<(), HttpVariableValueError> {
        self.set_found(len, data, false)
    }

    /// Stores bytes already retained by the current request pool.
    ///
    /// The setter accepts only bytes retained by the current request pool, so arbitrary stack,
    /// context, and parser slices cannot be cached accidentally:
    ///
    /// ```compile_fail
    /// use ngx::http::{HttpVariableValue, RequestRefMut};
    ///
    /// fn set(value: &mut HttpVariableValue<'_>, request: &RequestRefMut<'_>) {
    ///     let stack = *b"stack";
    ///     value.set_pool(request, &stack);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::http::{HttpVariableValue, RequestRefMut};
    ///
    /// struct Context {
    ///     bytes: [u8; 7],
    /// }
    ///
    /// fn set(
    ///     value: &mut HttpVariableValue<'_>,
    ///     request: &RequestRefMut<'_>,
    ///     context: &Context,
    /// ) {
    ///     value.set_pool(request, &context.bytes);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::http::{HttpVariableValue, RequestRefMut};
    ///
    /// fn set(value: &mut HttpVariableValue<'_>, request: &RequestRefMut<'_>, parser: &[u8]) {
    ///     value.set_pool(request, parser);
    /// }
    /// ```
    pub fn set_pool(
        &mut self,
        request: &RequestRefMut<'_>,
        value: HttpVariablePoolBytes<'_>,
    ) -> Result<(), HttpVariableValueError> {
        self.set_pool_with_cache(request, value, true)
    }

    /// Stores request-pool bytes and asks nginx to evaluate the getter on every access.
    pub fn set_pool_uncached(
        &mut self,
        request: &RequestRefMut<'_>,
        value: HttpVariablePoolBytes<'_>,
    ) -> Result<(), HttpVariableValueError> {
        self.set_pool_with_cache(request, value, false)
    }

    /// Copies callback bytes into the current request pool before publishing a cacheable value.
    pub fn copy_from_request(
        &mut self,
        request: &RequestRefMut<'_>,
        value: &[u8],
    ) -> Result<(), HttpVariableValueError> {
        let value = HttpVariablePoolBytes::copy_from_request(request, value)?;
        self.set_pool(request, value)
    }

    /// Copies callback bytes into the current request pool and marks the result noncacheable.
    pub fn copy_from_request_uncached(
        &mut self,
        request: &RequestRefMut<'_>,
        value: &[u8],
    ) -> Result<(), HttpVariableValueError> {
        let value = HttpVariablePoolBytes::copy_from_request(request, value)?;
        self.set_pool_uncached(request, value)
    }

    /// Publishes a cacheable found value with no bytes.
    pub fn set_empty(&mut self) {
        self.write_found(0, ptr::null_mut(), true);
    }

    /// Publishes a noncacheable found value with no bytes.
    pub fn set_empty_uncached(&mut self) {
        self.write_found(0, ptr::null_mut(), false);
    }

    /// Publishes nginx's exact noncacheable not-found state.
    pub fn set_not_found(&mut self) {
        let raw = unsafe { self.raw.as_mut() };
        raw.data = ptr::null_mut();
        raw.set_len(0);
        raw.set_escape(0);
        raw.set_no_cacheable(1);
        raw.set_valid(0);
        raw.set_not_found(1);
    }

    fn set_pool_with_cache(
        &mut self,
        request: &RequestRefMut<'_>,
        value: HttpVariablePoolBytes<'_>,
        cacheable: bool,
    ) -> Result<(), HttpVariableValueError> {
        let request_pool = request.pool()?;
        if !ptr::eq(request_pool.as_ptr(), value.pool.as_ptr()) {
            return Err(HttpVariableValueError::PoolMismatch);
        }

        self.set_found(value.len, value.data.as_ptr(), cacheable)
    }

    fn set_found(
        &mut self,
        len: usize,
        data: *mut u8,
        cacheable: bool,
    ) -> Result<(), HttpVariableValueError> {
        if len > Self::MAX_LEN {
            return Err(HttpVariableValueError::TooLong);
        }
        if len != 0 && data.is_null() {
            return Err(HttpVariableValueError::NullData);
        }

        self.write_found(len, data, cacheable);
        Ok(())
    }

    fn write_found(&mut self, len: usize, data: *mut u8, cacheable: bool) {
        let raw = unsafe { self.raw.as_mut() };
        raw.data = if len == 0 { ptr::null_mut() } else { data };
        raw.set_len(len as _);
        raw.set_escape(0);
        raw.set_not_found(0);
        raw.set_no_cacheable((!cacheable).into());
        raw.set_valid(1);
    }
}

/// Checked borrowed view of an HTTP variable output.
///
/// Values returned from indexed lookup remain borrowed from the active request:
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
pub struct HttpVariableValueRef<'value> {
    raw: &'value ngx_variable_value_t,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl HttpVariableValueRef<'_> {
    unsafe fn from_raw(value: *const ngx_variable_value_t) -> Option<Self> {
        let raw = NonNull::new(value.cast_mut())?;
        if !raw.as_ptr().is_aligned() {
            return None;
        }

        let raw = unsafe { raw.as_ref() };
        if raw.not_found() == 0 && raw.len() != 0 && raw.data.is_null() {
            return None;
        }

        Some(Self { raw, _not_thread_safe: PhantomData })
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
            let core_main = NgxHttpCoreModule::main_conf(&*request)?
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

/// Typed getter for a registered HTTP variable.
pub trait HttpVariableHandler {
    /// Getter result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Evaluates the variable for one active request.
    fn get(
        request: &mut RequestRefMut<'_>,
        value: &mut HttpVariableValue<'_>,
        data: usize,
    ) -> Self::Output;
}

/// Typed setter for a registered HTTP variable.
pub trait HttpVariableSetter {
    /// Receives an assignment for one active request.
    fn set(request: &mut RequestRefMut<'_>, value: HttpVariableValueRef<'_>, data: usize);
}

/// Registers a typed read-only HTTP variable.
///
/// Call this function from the module's preconfiguration callback. `name` does not include `$`.
pub fn add_variable<H>(
    cf: &mut ngx_conf_t,
    name: &NgxStr,
    flags: HttpVariableFlags,
    data: usize,
) -> Result<(), HttpVariableRegistrationError>
where
    H: HttpVariableHandler,
{
    let mut variable = register_variable(cf, name, flags)?;
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_get_handler::<H>);
    variable.set_handler = None;
    variable.data = data;
    Ok(())
}

/// Registers a typed HTTP variable with a setter.
///
/// Call this function from the module's preconfiguration callback. `name` does not include `$`.
pub fn add_variable_with_setter<H, S>(
    cf: &mut ngx_conf_t,
    name: &NgxStr,
    flags: HttpVariableFlags,
    data: usize,
) -> Result<(), HttpVariableRegistrationError>
where
    H: HttpVariableHandler,
    S: HttpVariableSetter,
{
    let mut variable = register_variable(cf, name, flags)?;
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_get_handler::<H>);
    variable.set_handler = Some(raw_set_handler::<S>);
    variable.data = data;
    Ok(())
}

fn register_variable(
    cf: &mut ngx_conf_t,
    name: &NgxStr,
    flags: HttpVariableFlags,
) -> Result<NonNull<ngx_http_variable_t>, HttpVariableRegistrationError> {
    if flags.bits() & !HttpVariableFlags::all().bits() != 0 {
        return Err(HttpVariableRegistrationError);
    }

    let mut name = name.as_ngx_str();
    NonNull::new(unsafe { ngx_http_add_variable(cf, &raw mut name, flags.bits()) })
        .ok_or(HttpVariableRegistrationError)
}

/// Creates an opaque index for an HTTP variable.
///
/// Call this function during the same configuration pass that registers the variable. The index
/// can later be used only with requests from that HTTP core configuration.
pub fn get_variable_index(
    cf: &mut ngx_conf_t,
    name: &NgxStr,
) -> Result<HttpVariableIndex, HttpVariableIndexError> {
    let core_main = NgxHttpCoreModule::main_conf(&*cf)?
        .ok_or(HttpVariableIndexError::MissingCoreMainConfiguration)?;
    let core_main = NonNull::from(core_main);
    let mut name = name.as_ngx_str();
    let index = unsafe { ngx_http_get_variable_index(cf, &raw mut name) };
    if index == NGX_ERROR as _ {
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
            let Some(mut value) = HttpVariableValue::from_raw(value) else {
                return Err(crate::core::Status::NGX_ERROR);
            };

            Ok::<_, crate::core::Status>(H::get(request, &mut value, data))
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

            S::set(request, value, data);
            crate::core::Status::NGX_OK
        })
    };
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "test-link")]
    use alloc::{boxed::Box, vec::Vec};
    #[cfg(feature = "test-link")]
    use core::ffi::c_void;
    use core::marker::PhantomData;
    use core::mem::MaybeUninit;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "test-link")]
    use std::sync::MutexGuard;

    use super::{
        HttpVariableFlags, HttpVariableHandler, HttpVariableIndex, HttpVariableIndexError,
        HttpVariableLookupError, HttpVariablePoolBytes, HttpVariableSetter, HttpVariableValue,
        HttpVariableValueError, HttpVariableValueReadError, HttpVariableValueRef, add_variable,
        add_variable_with_setter, get_variable_index, raw_get_handler, raw_set_handler,
    };
    use crate::core::{NgxStr, Status};
    use crate::ffi::{
        NGX_ERROR, NGX_HTTP_MODULE, ngx_conf_t, ngx_http_core_main_conf_t, ngx_http_request_t,
        ngx_int_t, ngx_variable_value_t,
    };
    use crate::http::{HttpConfigError, RequestRefMut};

    #[cfg(feature = "test-link")]
    use crate::ffi::{
        NGX_CORE_MODULE, NGX_HTTP_VAR_INDEXED, NGX_OK, ngx_array_t, ngx_connection_t,
        ngx_create_pool, ngx_destroy_pool, ngx_hash_key_t, ngx_http_conf_ctx_t,
        ngx_http_get_variable_pt, ngx_http_variable_t, ngx_http_variables_add_core_vars,
        ngx_http_variables_init_vars, ngx_log_t, ngx_pool_t, ngx_uint_t,
    };

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    fn poisoned_value() -> ngx_variable_value_t {
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };
        value.set_len(17);
        value.set_valid(0);
        value.set_no_cacheable(0);
        value.set_not_found(1);
        value.set_escape(1);
        value.data = NonNull::<u8>::dangling().as_ptr();
        value
    }

    fn assert_found(
        raw: &ngx_variable_value_t,
        value: &HttpVariableValue<'_>,
        bytes: &[u8],
        cacheable: bool,
        data: *mut u8,
    ) {
        assert_eq!(raw.len() as usize, bytes.len());
        assert_eq!(raw.valid(), 1);
        assert_eq!(raw.no_cacheable(), (!cacheable).into());
        assert_eq!(raw.not_found(), 0);
        assert_eq!(raw.escape(), 0);
        assert_eq!(raw.data, data);

        let read = value.read().unwrap();
        assert_eq!(read.bytes(), Some(bytes));
        assert!(read.is_valid());
        assert_eq!(read.is_cacheable(), cacheable);
        assert!(!read.is_not_found());
        assert!(!read.is_escaped());
    }

    fn assert_not_found(raw: &ngx_variable_value_t, value: &HttpVariableValue<'_>) {
        assert_eq!(raw.len(), 0);
        assert_eq!(raw.valid(), 0);
        assert_eq!(raw.no_cacheable(), 1);
        assert_eq!(raw.not_found(), 1);
        assert_eq!(raw.escape(), 0);
        assert!(raw.data.is_null());

        let read = value.read().unwrap();
        assert_eq!(read.bytes(), None);
        assert!(!read.is_valid());
        assert!(!read.is_cacheable());
        assert!(read.is_not_found());
        assert!(!read.is_escaped());
    }

    struct CountingVariable;

    static RAW_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RAW_VARIABLE_DATA: AtomicUsize = AtomicUsize::new(0);

    impl HttpVariableHandler for CountingVariable {
        type Output = Status;

        fn get(
            _request: &mut RequestRefMut<'_>,
            value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            RAW_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
            value.set_empty();
            Status::NGX_OK
        }
    }

    struct DataVariable;

    impl HttpVariableHandler for DataVariable {
        type Output = Status;

        fn get(
            _request: &mut RequestRefMut<'_>,
            value: &mut HttpVariableValue<'_>,
            data: usize,
        ) -> Self::Output {
            RAW_VARIABLE_DATA.store(data, Ordering::Relaxed);
            value.set_empty();
            Status::NGX_DECLINED
        }
    }

    static RAW_SET_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RAW_SET_VARIABLE_DATA: AtomicUsize = AtomicUsize::new(0);

    struct SetVariable;

    impl HttpVariableSetter for SetVariable {
        fn set(_request: &mut RequestRefMut<'_>, value: HttpVariableValueRef<'_>, data: usize) {
            assert_eq!(value.bytes(), Some(&b"set value"[..]));
            assert!(value.is_valid());
            assert!(value.is_cacheable());
            RAW_SET_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
            RAW_SET_VARIABLE_DATA.store(data, Ordering::Relaxed);
        }
    }

    struct CountingSetter;

    impl HttpVariableSetter for CountingSetter {
        fn set(_request: &mut RequestRefMut<'_>, _value: HttpVariableValueRef<'_>, data: usize) {
            let calls = unsafe { &*(data as *const AtomicUsize) };
            calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct TestVariable;

    impl HttpVariableHandler for TestVariable {
        type Output = Status;

        fn get(
            request: &mut RequestRefMut<'_>,
            value: &mut HttpVariableValue<'_>,
            data: usize,
        ) -> Self::Output {
            unsafe { (*request.as_ptr()).headers_out.status = data as _ };
            value.set_static(b"detected").unwrap();
            Status::NGX_OK
        }
    }

    struct RawStatusVariable;

    impl HttpVariableHandler for RawStatusVariable {
        type Output = ngx_int_t;

        fn get(
            _request: &mut RequestRefMut<'_>,
            value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            value.set_empty();
            Status::NGX_OK.0
        }
    }

    struct OptionalStatusVariable;

    impl HttpVariableHandler for OptionalStatusVariable {
        type Output = Option<Status>;

        fn get(
            _request: &mut RequestRefMut<'_>,
            value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            value.set_empty();
            Some(Status::NGX_AGAIN)
        }
    }

    struct MissingStatusVariable;

    impl HttpVariableHandler for MissingStatusVariable {
        type Output = Option<Status>;

        fn get(
            _request: &mut RequestRefMut<'_>,
            _value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            None
        }
    }

    struct ResultStatusVariable;

    impl HttpVariableHandler for ResultStatusVariable {
        type Output = Result<Status, Status>;

        fn get(
            _request: &mut RequestRefMut<'_>,
            value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            value.set_empty();
            Ok(Status::NGX_DECLINED)
        }
    }

    struct ErrorStatusVariable;

    impl HttpVariableHandler for ErrorStatusVariable {
        type Output = Result<Status, Status>;

        fn get(
            _request: &mut RequestRefMut<'_>,
            _value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            Err(Status::NGX_AGAIN)
        }
    }

    #[cfg(feature = "std")]
    struct PanickingVariable;

    #[cfg(feature = "std")]
    impl HttpVariableHandler for PanickingVariable {
        type Output = Status;

        fn get(
            _request: &mut RequestRefMut<'_>,
            _value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            panic!("variable getter panic")
        }
    }

    #[cfg(feature = "std")]
    struct PanickingSetter;

    #[cfg(feature = "std")]
    impl HttpVariableSetter for PanickingSetter {
        fn set(_request: &mut RequestRefMut<'_>, _value: HttpVariableValueRef<'_>, _data: usize) {
            panic!("variable setter panic")
        }
    }

    fn misaligned_ptr<T>(storage: &mut [u8]) -> *mut T {
        let alignment = core::mem::align_of::<T>();
        assert!(alignment > 1);
        let offset = storage.as_mut_ptr().align_offset(alignment);
        assert!(offset + 1 < storage.len());
        unsafe { storage.as_mut_ptr().add(offset + 1).cast() }
    }

    fn raw_handler_status<H>() -> ngx_int_t
    where
        H: HttpVariableHandler,
    {
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        unsafe { raw_get_handler::<H>(&raw mut request, &raw mut value, 0) }
    }

    #[cfg(feature = "test-link")]
    struct TestPool {
        raw: *mut ngx_pool_t,
        log: Box<ngx_log_t>,
    }

    #[cfg(feature = "test-link")]
    impl TestPool {
        fn new() -> Self {
            let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
            let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!raw.is_null());
            Self { raw, log }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }

    #[cfg(feature = "test-link")]
    fn with_request<R>(
        owner: &TestPool,
        f: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
    ) -> R {
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        request.pool = owner.raw;

        unsafe { RequestRefMut::with_raw(&raw mut request, |mut request| f(&mut request)) }.unwrap()
    }

    #[cfg(feature = "test-link")]
    struct VariableGlobalState {
        max_module: ngx_uint_t,
        http_max_module: ngx_uint_t,
        cacheline_size: ngx_uint_t,
        http_module_type: ngx_uint_t,
        http_module_index: ngx_uint_t,
        http_core_module_type: ngx_uint_t,
        http_core_module_index: ngx_uint_t,
        http_core_module_context_index: ngx_uint_t,
    }

    #[cfg(feature = "test-link")]
    struct VariableGlobals {
        _guard: MutexGuard<'static, ()>,
        previous: VariableGlobalState,
    }

    #[cfg(feature = "test-link")]
    impl VariableGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let previous = unsafe {
                VariableGlobalState {
                    max_module: nginx_sys::ngx_max_module,
                    http_max_module: nginx_sys::ngx_http_max_module,
                    cacheline_size: nginx_sys::ngx_cacheline_size,
                    http_module_type: (*core::ptr::addr_of!(nginx_sys::ngx_http_module)).type_,
                    http_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_http_module)).index,
                    http_core_module_type: (*core::ptr::addr_of!(nginx_sys::ngx_http_core_module))
                        .type_,
                    http_core_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_http_core_module))
                        .index,
                    http_core_module_context_index: (*core::ptr::addr_of!(
                        nginx_sys::ngx_http_core_module
                    ))
                    .ctx_index,
                }
            };

            unsafe {
                nginx_sys::ngx_max_module = 1;
                nginx_sys::ngx_http_max_module = 1;
                nginx_sys::ngx_cacheline_size = 64;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).type_ = NGX_CORE_MODULE as _;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index = 0;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).type_ =
                    NGX_HTTP_MODULE as _;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).index = 0;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).ctx_index = 0;
            }

            Self { _guard: guard, previous }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for VariableGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_max_module = self.previous.max_module;
                nginx_sys::ngx_http_max_module = self.previous.http_max_module;
                nginx_sys::ngx_cacheline_size = self.previous.cacheline_size;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).type_ =
                    self.previous.http_module_type;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index =
                    self.previous.http_module_index;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).type_ =
                    self.previous.http_core_module_type;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).index =
                    self.previous.http_core_module_index;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).ctx_index =
                    self.previous.http_core_module_context_index;
            }
        }
    }

    #[cfg(feature = "test-link")]
    struct VariableConfiguration {
        main: Box<ngx_http_core_main_conf_t>,
        main_conf: Box<[*mut c_void; 1]>,
        _context: Box<ngx_http_conf_ctx_t>,
        cf: Box<ngx_conf_t>,
    }

    #[cfg(feature = "test-link")]
    impl VariableConfiguration {
        fn new(pool: &mut TestPool) -> Self {
            let mut main = Box::new(unsafe {
                MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init()
            });
            main.variables_hash_max_size = 1024;
            main.variables_hash_bucket_size = 64;
            let mut main_conf: Box<[*mut c_void; 1]> = Box::new([(&raw mut *main).cast()]);
            let mut context = Box::new(ngx_http_conf_ctx_t {
                main_conf: main_conf.as_mut_ptr(),
                srv_conf: ptr::null_mut(),
                loc_conf: ptr::null_mut(),
            });
            let mut cf = Box::new(unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() });
            cf.pool = pool.raw;
            cf.temp_pool = pool.raw;
            cf.log = &raw mut *pool.log;
            cf.ctx = (&raw mut *context).cast();
            cf.module_type = NGX_HTTP_MODULE as _;

            assert_eq!(unsafe { ngx_http_variables_add_core_vars(&raw mut *cf) }, NGX_OK as _);

            Self { main, main_conf, _context: context, cf }
        }

        fn configuration(&mut self) -> &mut ngx_conf_t {
            &mut self.cf
        }

        fn finalize_variables(&mut self) {
            assert_eq!(unsafe { ngx_http_variables_init_vars(&raw mut *self.cf) }, NGX_OK as _);
        }

        fn exact_variables(&self) -> &[ngx_hash_key_t] {
            let variables_keys = self.main.variables_keys;
            assert!(!variables_keys.is_null());
            array_values(unsafe { &(*variables_keys).keys })
        }

        fn prefix_variables(&self) -> &[ngx_http_variable_t] {
            array_values(&self.main.prefix_variables)
        }

        fn exact_variable(&self, name: &[u8]) -> &ngx_http_variable_t {
            let key = self.exact_variables().iter().find(|key| key.key.as_bytes() == name).unwrap();
            assert!(!key.value.is_null());
            unsafe { &*key.value.cast() }
        }

        fn prefix_variable(&self, name: &[u8]) -> &ngx_http_variable_t {
            self.prefix_variables()
                .iter()
                .find(|variable| variable.name.as_bytes() == name)
                .unwrap()
        }

        fn indexed_variable_mut(&mut self, index: usize) -> &mut ngx_http_variable_t {
            assert!(index < self.main.variables.nelts);
            assert!(!self.main.variables.elts.is_null());
            unsafe { &mut *self.main.variables.elts.cast::<ngx_http_variable_t>().add(index) }
        }

        fn with_request<R>(
            &mut self,
            f: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
        ) -> R {
            let mut values = Vec::with_capacity(self.main.variables.nelts);
            for _ in 0..self.main.variables.nelts {
                values.push(unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() });
            }
            self.with_request_variables(values.as_mut_ptr(), f)
        }

        fn with_request_variables<R>(
            &mut self,
            variables: *mut ngx_variable_value_t,
            f: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
        ) -> R {
            let mut connection: Box<ngx_connection_t> =
                Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
            connection.log = self.cf.log;
            let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
            request.signature = NGX_HTTP_MODULE as _;
            request.main = &raw mut request;
            request.connection = &raw mut *connection;
            request.pool = self.cf.pool;
            request.main_conf = self.main_conf.as_mut_ptr();
            request.variables = variables;

            unsafe { RequestRefMut::with_raw(&raw mut request, |mut request| f(&mut request)) }
                .unwrap()
        }
    }

    #[cfg(feature = "test-link")]
    struct VariableFixture {
        _globals: VariableGlobals,
        pool: TestPool,
        configuration: VariableConfiguration,
    }

    #[cfg(feature = "test-link")]
    impl VariableFixture {
        fn new() -> Self {
            let globals = VariableGlobals::new();
            let mut pool = TestPool::new();
            let configuration = VariableConfiguration::new(&mut pool);
            Self { _globals: globals, pool, configuration }
        }

        fn configuration(&mut self) -> &mut ngx_conf_t {
            self.configuration.configuration()
        }
    }

    #[cfg(feature = "test-link")]
    fn array_values<T>(array: &ngx_array_t) -> &[T] {
        if array.nelts == 0 {
            return &[];
        }

        assert!(!array.elts.is_null());
        unsafe { core::slice::from_raw_parts(array.elts.cast(), array.nelts) }
    }

    #[cfg(feature = "test-link")]
    fn same_handler(left: ngx_http_get_variable_pt, right: ngx_http_get_variable_pt) -> bool {
        match (left, right) {
            (Some(left), Some(right)) => core::ptr::fn_addr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }

    #[cfg(feature = "test-link")]
    fn assert_handler<H>(variable: &ngx_http_variable_t, data: usize)
    where
        H: HttpVariableHandler,
    {
        assert!(same_handler(variable.get_handler, Some(raw_get_handler::<H>)));
        assert_eq!(variable.data, data);
    }

    #[cfg(feature = "test-link")]
    static INDEXED_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    struct IndexedVariable;

    #[cfg(feature = "test-link")]
    impl HttpVariableHandler for IndexedVariable {
        type Output = Status;

        fn get(
            _request: &mut RequestRefMut<'_>,
            value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            INDEXED_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
            value.set_static(b"indexed").unwrap();
            Status::NGX_OK
        }
    }

    #[cfg(feature = "test-link")]
    struct FailingVariable;

    #[cfg(feature = "test-link")]
    impl HttpVariableHandler for FailingVariable {
        type Output = Status;

        fn get(
            _request: &mut RequestRefMut<'_>,
            _value: &mut HttpVariableValue<'_>,
            _data: usize,
        ) -> Self::Output {
            Status::NGX_ERROR
        }
    }

    #[test]
    fn static_values_replace_every_http_output_field() {
        static CACHED: &[u8] = b"cached";
        static UNCACHED: &[u8] = b"uncached";

        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();

        value.set_static(CACHED).unwrap();
        assert_eq!(raw.len() as usize, CACHED.len());
        assert_eq!(raw.valid(), 1);
        assert_eq!(raw.no_cacheable(), 0);
        assert_eq!(raw.not_found(), 0);
        assert_eq!(raw.escape(), 0);
        assert_eq!(raw.data, CACHED.as_ptr().cast_mut());

        value.set_static_uncached(UNCACHED).unwrap();
        assert_eq!(raw.len() as usize, UNCACHED.len());
        assert_eq!(raw.valid(), 1);
        assert_eq!(raw.no_cacheable(), 1);
        assert_eq!(raw.not_found(), 0);
        assert_eq!(raw.escape(), 0);
        assert_eq!(raw.data, UNCACHED.as_ptr().cast_mut());
    }

    #[test]
    fn borrowed_values_keep_their_original_backing() {
        static BACKING: &[u8] = b"borrowed";

        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();

        unsafe { value.set_borrowed(BACKING.as_ptr().cast_mut(), BACKING.len()) }.unwrap();
        assert_found(&raw, &value, BACKING, true, BACKING.as_ptr().cast_mut());
    }

    #[test]
    fn borrowed_uncached_values_keep_their_original_backing() {
        static BACKING: &[u8] = b"borrowed";

        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();

        unsafe { value.set_borrowed_uncached(BACKING.as_ptr().cast_mut(), BACKING.len()) }.unwrap();
        assert_found(&raw, &value, BACKING, false, BACKING.as_ptr().cast_mut());
    }

    #[test]
    fn raw_variable_value_construction_rejects_null_and_misaligned_pointers() {
        assert!(unsafe { HttpVariableValue::from_raw(ptr::null_mut()) }.is_none());

        let mut storage = [0_u8;
            core::mem::size_of::<ngx_variable_value_t>()
                + core::mem::align_of::<ngx_variable_value_t>()];
        let raw = misaligned_ptr::<ngx_variable_value_t>(&mut storage);
        assert!(unsafe { HttpVariableValue::from_raw(raw) }.is_none());
    }

    #[test]
    fn raw_variable_handler_rejects_invalid_callback_pointers_without_calling_the_getter() {
        RAW_VARIABLE_CALLS.store(0, Ordering::Relaxed);
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(ptr::null_mut(), &raw mut value, 0) },
            NGX_ERROR as _
        );
        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(&raw mut request, ptr::null_mut(), 0) },
            NGX_ERROR as _
        );

        let mut request_storage = [0_u8;
            core::mem::size_of::<ngx_http_request_t>()
                + core::mem::align_of::<ngx_http_request_t>()];
        let misaligned_request = misaligned_ptr::<ngx_http_request_t>(&mut request_storage);
        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(misaligned_request, &raw mut value, 0) },
            NGX_ERROR as _
        );

        let mut value_storage = [0_u8;
            core::mem::size_of::<ngx_variable_value_t>()
                + core::mem::align_of::<ngx_variable_value_t>()];
        let value = misaligned_ptr::<ngx_variable_value_t>(&mut value_storage);
        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(&raw mut request, value, 0) },
            NGX_ERROR as _
        );
        assert_eq!(RAW_VARIABLE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn raw_variable_handler_forwards_zero_and_maximum_data() {
        RAW_VARIABLE_DATA.store(1, Ordering::Relaxed);
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        assert_eq!(
            unsafe { raw_get_handler::<DataVariable>(&raw mut request, &raw mut value, 0) },
            Status::NGX_DECLINED.0
        );
        assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), 0);

        assert_eq!(
            unsafe {
                raw_get_handler::<DataVariable>(&raw mut request, &raw mut value, usize::MAX)
            },
            Status::NGX_DECLINED.0
        );
        assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn raw_variable_setter_reads_a_checked_input_value() {
        RAW_SET_VARIABLE_CALLS.store(0, Ordering::Relaxed);
        RAW_SET_VARIABLE_DATA.store(0, Ordering::Relaxed);
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };
        value.data = b"set value".as_ptr().cast_mut();
        value.set_len(b"set value".len() as _);
        value.set_valid(1);

        unsafe { raw_set_handler::<SetVariable>(&raw mut request, &raw mut value, usize::MAX) };

        assert_eq!(RAW_SET_VARIABLE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(RAW_SET_VARIABLE_DATA.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn raw_variable_setter_rejects_invalid_callback_pointers_without_calling_the_setter() {
        let calls = AtomicUsize::new(0);
        let data = (&raw const calls).cast::<AtomicUsize>() as usize;
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        unsafe { raw_set_handler::<CountingSetter>(ptr::null_mut(), &raw mut value, data) };
        unsafe { raw_set_handler::<CountingSetter>(&raw mut request, ptr::null_mut(), data) };

        let mut request_storage = [0_u8;
            core::mem::size_of::<ngx_http_request_t>()
                + core::mem::align_of::<ngx_http_request_t>()];
        let misaligned_request = misaligned_ptr::<ngx_http_request_t>(&mut request_storage);
        unsafe { raw_set_handler::<CountingSetter>(misaligned_request, &raw mut value, data) };

        let mut value_storage = [0_u8;
            core::mem::size_of::<ngx_variable_value_t>()
                + core::mem::align_of::<ngx_variable_value_t>()];
        let value = misaligned_ptr::<ngx_variable_value_t>(&mut value_storage);
        unsafe { raw_set_handler::<CountingSetter>(&raw mut request, value, data) };

        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn raw_variable_setter_catches_a_setter_panic() {
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        unsafe { raw_set_handler::<PanickingSetter>(&raw mut request, &raw mut value, 0) };
    }

    #[test]
    fn raw_variable_handler_converts_every_supported_status_output() {
        assert_eq!(raw_handler_status::<RawStatusVariable>(), Status::NGX_OK.0);
        assert_eq!(raw_handler_status::<OptionalStatusVariable>(), Status::NGX_AGAIN.0);
        assert_eq!(raw_handler_status::<MissingStatusVariable>(), NGX_ERROR as _);
        assert_eq!(raw_handler_status::<ResultStatusVariable>(), Status::NGX_DECLINED.0);
        assert_eq!(raw_handler_status::<ErrorStatusVariable>(), Status::NGX_AGAIN.0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn raw_variable_handler_converts_a_getter_panic_to_ngx_error() {
        assert_eq!(raw_handler_status::<PanickingVariable>(), NGX_ERROR as _);
    }

    #[test]
    fn raw_variable_handler_wraps_the_request_and_value() {
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        let mut raw_value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        let status = unsafe {
            raw_get_handler::<TestVariable>(
                &raw mut request,
                &raw mut raw_value,
                Status::NGX_OK.0 as _,
            )
        };

        assert_eq!(status, Status::NGX_OK.0);
        assert_eq!(request.headers_out.status, Status::NGX_OK.0 as _);
        let value = unsafe { HttpVariableValue::from_raw(&raw mut raw_value) }.unwrap();
        assert_found(&raw_value, &value, b"detected", true, b"detected".as_ptr().cast_mut());
    }

    #[test]
    fn empty_and_not_found_values_replace_every_http_output_field() {
        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();

        value.set_empty();
        assert_found(&raw, &value, b"", true, ptr::null_mut());

        value.set_empty_uncached();
        assert_found(&raw, &value, b"", false, ptr::null_mut());

        value.set_not_found();
        assert_not_found(&raw, &value);
    }

    #[test]
    fn length_and_null_data_errors_preserve_the_previous_output() {
        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();
        let data = NonNull::<u8>::dangling().as_ptr();

        value.set_found(HttpVariableValue::MAX_LEN, data, true).unwrap();
        assert_eq!(raw.len() as usize, HttpVariableValue::MAX_LEN);
        assert_eq!(raw.data, data);
        assert_eq!(raw.valid(), 1);
        assert_eq!(raw.no_cacheable(), 0);
        assert_eq!(raw.not_found(), 0);
        assert_eq!(raw.escape(), 0);

        let before =
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data);
        assert_eq!(
            value.set_found(HttpVariableValue::MAX_LEN + 1, data, true),
            Err(HttpVariableValueError::TooLong)
        );
        assert_eq!(
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data,),
            before
        );

        assert_eq!(
            value.set_found(1, ptr::null_mut(), false),
            Err(HttpVariableValueError::NullData)
        );
        assert_eq!(
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data,),
            before
        );
    }

    #[test]
    fn checked_read_rejects_nonempty_null_data_and_accepts_empty_found_values() {
        let mut raw = poisoned_value();
        raw.set_len(1);
        raw.set_not_found(0);
        raw.data = ptr::null_mut();
        let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();

        assert!(matches!(value.read(), Err(HttpVariableValueReadError::NullData)));

        value.set_empty();
        assert_found(&raw, &value, b"", true, ptr::null_mut());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn request_pool_values_replace_every_output_field() {
        let owner = TestPool::new();

        with_request(&owner, |request| {
            let mut raw = poisoned_value();
            let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();
            let bytes = HttpVariablePoolBytes::copy_from_request(&*request, b"pool").unwrap();
            let data = bytes.data.as_ptr();
            assert_eq!(bytes.bytes(), b"pool");
            assert_ne!(data, b"pool".as_ptr().cast_mut());

            value.set_pool(&*request, bytes).unwrap();
            assert_found(&raw, &value, b"pool", true, data);

            let bytes =
                HttpVariablePoolBytes::copy_from_request(&*request, b"uncached-pool").unwrap();
            let data = bytes.data.as_ptr();
            value.set_pool_uncached(&*request, bytes).unwrap();
            assert_found(&raw, &value, b"uncached-pool", false, data);
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn copied_request_values_replace_every_output_field() {
        let owner = TestPool::new();

        with_request(&owner, |request| {
            let mut raw = poisoned_value();
            let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();
            let copied = *b"copied";

            value.copy_from_request(&*request, &copied).unwrap();
            assert_ne!(raw.data, copied.as_ptr().cast_mut());
            assert_found(&raw, &value, &copied, true, raw.data);

            let uncached = *b"uncached";
            value.copy_from_request_uncached(&*request, &uncached).unwrap();
            assert_ne!(raw.data, uncached.as_ptr().cast_mut());
            assert_found(&raw, &value, &uncached, false, raw.data);

            value.copy_from_request(&*request, b"").unwrap();
            assert_found(&raw, &value, b"", true, ptr::null_mut());
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn foreign_request_pool_bytes_do_not_publish_an_output() {
        let current_owner = TestPool::new();
        let foreign_owner = TestPool::new();

        with_request(&current_owner, |current| {
            with_request(&foreign_owner, |foreign| {
                let bytes =
                    HttpVariablePoolBytes::copy_from_request(&*foreign, b"foreign").unwrap();
                let mut raw = poisoned_value();
                let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();
                let before = (
                    raw.len(),
                    raw.valid(),
                    raw.no_cacheable(),
                    raw.not_found(),
                    raw.escape(),
                    raw.data,
                );

                assert_eq!(
                    value.set_pool(&*current, bytes),
                    Err(HttpVariableValueError::PoolMismatch)
                );
                assert_eq!(
                    (
                        raw.len(),
                        raw.valid(),
                        raw.no_cacheable(),
                        raw.not_found(),
                        raw.escape(),
                        raw.data,
                    ),
                    before
                );
            });
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn allocation_failure_does_not_publish_partial_output() {
        let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let owner = TestPool::new();
        unsafe { (*owner.raw).max = 0 };

        with_request(&owner, |request| {
            let mut raw = poisoned_value();
            let mut value = unsafe { HttpVariableValue::from_raw(&raw mut raw) }.unwrap();
            let before = (
                raw.len(),
                raw.valid(),
                raw.no_cacheable(),
                raw.not_found(),
                raw.escape(),
                raw.data,
            );

            unsafe { ngx_rs_test_fail_allocations_after(0) };
            let result = value.copy_from_request(&*request, b"copied");
            unsafe { ngx_rs_test_reset_allocation_failures() };

            assert_eq!(result, Err(HttpVariableValueError::Allocation));
            assert_eq!(
                (
                    raw.len(),
                    raw.valid(),
                    raw.no_cacheable(),
                    raw.not_found(),
                    raw.escape(),
                    raw.data,
                ),
                before
            );
        });
    }

    #[test]
    fn variable_index_rejects_a_non_http_configuration() {
        let mut cf = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };

        assert_eq!(
            get_variable_index(&mut cf, NgxStr::from_bytes(b"ngx_rs_index")),
            Err(HttpVariableIndexError::Configuration(HttpConfigError::WrongConfigurationContext))
        );
    }

    #[test]
    fn indexed_lookup_rejects_missing_request_configuration() {
        let mut core = unsafe { MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init() };
        let index = HttpVariableIndex {
            index: 0,
            core_main: NonNull::from(&mut core),
            _not_thread_safe: PhantomData,
        };
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;

        unsafe {
            RequestRefMut::with_raw(&raw mut request, |mut request| {
                assert!(matches!(
                    index.get_cached(&mut request),
                    Err(HttpVariableLookupError::Configuration(_)
                        | HttpVariableLookupError::MissingCoreMainConfiguration)
                ));
            })
        }
        .unwrap();
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn indexed_lookup_preserves_nginx_cache_and_flush_semantics() {
        let mut fixture = VariableFixture::new();
        add_variable::<IndexedVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_indexed"),
            HttpVariableFlags::NOCACHEABLE,
            0,
        )
        .unwrap();
        let index =
            get_variable_index(fixture.configuration(), NgxStr::from_bytes(b"ngx_rs_indexed"))
                .unwrap();
        fixture.configuration.finalize_variables();
        INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

        fixture.configuration.with_request(|request| {
            {
                let value = index.get_cached(request).unwrap();
                assert_eq!(value.bytes(), Some(&b"indexed"[..]));
                assert!(!value.is_cacheable());
            }
            assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);

            {
                let value = index.get_cached(request).unwrap();
                assert_eq!(value.bytes(), Some(&b"indexed"[..]));
            }
            assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);

            {
                let value = index.get_flushed(request).unwrap();
                assert_eq!(value.bytes(), Some(&b"indexed"[..]));
            }
            assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 2);
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn flushed_lookup_keeps_a_cacheable_value() {
        let mut fixture = VariableFixture::new();
        add_variable::<IndexedVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_cached_index"),
            HttpVariableFlags::empty(),
            0,
        )
        .unwrap();
        let index =
            get_variable_index(fixture.configuration(), NgxStr::from_bytes(b"ngx_rs_cached_index"))
                .unwrap();
        fixture.configuration.finalize_variables();
        INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

        fixture.configuration.with_request(|request| {
            {
                let value = index.get_flushed(request).unwrap();
                assert_eq!(value.bytes(), Some(&b"indexed"[..]));
                assert!(value.is_cacheable());
            }
            assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);

            {
                let value = index.get_flushed(request).unwrap();
                assert_eq!(value.bytes(), Some(&b"indexed"[..]));
            }
            assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn variable_index_rejects_empty_names_and_allocation_failure() {
        let mut fixture = VariableFixture::new();

        assert_eq!(
            get_variable_index(fixture.configuration(), NgxStr::from_bytes(b"")),
            Err(HttpVariableIndexError::Registration)
        );

        unsafe {
            (*fixture.pool.raw).max = 0;
            ngx_rs_test_fail_allocations_after(0);
        }
        let result = get_variable_index(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_index_allocation_failure"),
        );
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert_eq!(result, Err(HttpVariableIndexError::Registration));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn indexed_lookup_rejects_invalid_bounds_and_request_storage() {
        let mut fixture = VariableFixture::new();
        add_variable::<IndexedVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_lookup_bounds"),
            HttpVariableFlags::empty(),
            0,
        )
        .unwrap();
        let index = get_variable_index(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_lookup_bounds"),
        )
        .unwrap();
        fixture.configuration.finalize_variables();

        let mut out_of_bounds = index;
        out_of_bounds.index = fixture.configuration.main.variables.nelts;
        fixture.configuration.with_request(|request| {
            assert!(matches!(
                out_of_bounds.get_cached(request),
                Err(HttpVariableLookupError::IndexOutOfBounds)
            ));
        });

        fixture.configuration.with_request_variables(ptr::null_mut(), |request| {
            assert!(matches!(
                index.get_cached(request),
                Err(HttpVariableLookupError::MissingRequestVariables)
            ));
        });

        let mut storage = [0_u8;
            core::mem::size_of::<ngx_variable_value_t>()
                + core::mem::align_of::<ngx_variable_value_t>()];
        let variables = misaligned_ptr::<ngx_variable_value_t>(&mut storage);
        fixture.configuration.with_request_variables(variables, |request| {
            assert!(matches!(
                index.get_cached(request),
                Err(HttpVariableLookupError::MisalignedRequestVariables)
            ));
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn indexed_lookup_rejects_invalid_definition_handlers() {
        let mut fixture = VariableFixture::new();
        add_variable::<IndexedVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_missing_handler"),
            HttpVariableFlags::empty(),
            0,
        )
        .unwrap();
        let index = get_variable_index(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_missing_handler"),
        )
        .unwrap();
        fixture.configuration.finalize_variables();

        fixture.configuration.indexed_variable_mut(index.index).get_handler = None;
        fixture.configuration.with_request(|request| {
            assert!(matches!(
                index.get_cached(request),
                Err(HttpVariableLookupError::MissingHandler)
            ));
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn indexed_lookup_maps_a_failed_native_getter_to_a_null_result() {
        let mut fixture = VariableFixture::new();
        add_variable::<FailingVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_failed_index"),
            HttpVariableFlags::empty(),
            0,
        )
        .unwrap();
        let index =
            get_variable_index(fixture.configuration(), NgxStr::from_bytes(b"ngx_rs_failed_index"))
                .unwrap();
        fixture.configuration.finalize_variables();

        fixture.configuration.with_request(|request| {
            assert!(matches!(index.get_cached(request), Err(HttpVariableLookupError::NullResult)));
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn variable_indexes_are_recreated_for_a_reload_configuration() {
        let mut fixture = VariableFixture::new();
        add_variable::<IndexedVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
            HttpVariableFlags::empty(),
            0,
        )
        .unwrap();
        let old_index = get_variable_index(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
        )
        .unwrap();

        let mut reloaded = VariableConfiguration::new(&mut fixture.pool);
        add_variable::<IndexedVariable>(
            reloaded.configuration(),
            NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
            HttpVariableFlags::empty(),
            0,
        )
        .unwrap();
        let new_index = get_variable_index(
            reloaded.configuration(),
            NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
        )
        .unwrap();
        reloaded.finalize_variables();
        INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

        reloaded.with_request(|request| {
            assert!(matches!(
                old_index.get_cached(request),
                Err(HttpVariableLookupError::ForeignConfiguration)
            ));

            {
                let value = new_index.get_cached(request).unwrap();
                assert_eq!(value.bytes(), Some(&b"indexed"[..]));
            }
            assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn add_variable_supports_every_public_flag_and_preserves_name_bytes() {
        let mut fixture = VariableFixture::new();
        let cases: [(&[u8], &[u8], HttpVariableFlags, usize); 5] = [
            (b"ngx_rs_changeable", b"ngx_rs_changeable", HttpVariableFlags::CHANGEABLE, 0),
            (
                b"ngx_rs_nocacheable",
                b"ngx_rs_nocacheable",
                HttpVariableFlags::NOCACHEABLE,
                usize::MAX,
            ),
            (b"ngx_rs_nohash", b"ngx_rs_nohash", HttpVariableFlags::NOHASH, 8),
            (b"ngx_rs_weak", b"ngx_rs_weak", HttpVariableFlags::WEAK, 16),
            (
                b"NgX_Rs_\xFF",
                b"ngx_rs_\xFF",
                HttpVariableFlags::NOCACHEABLE | HttpVariableFlags::NOHASH,
                42,
            ),
        ];

        for (name, lower_name, flags, data) in cases {
            add_variable::<CountingVariable>(
                fixture.configuration(),
                NgxStr::from_bytes(name),
                flags,
                data,
            )
            .unwrap();
            let variable = fixture.configuration.exact_variable(lower_name);
            assert_eq!(variable.flags, flags.bits());
            assert_handler::<CountingVariable>(variable, data);
        }

        let prefix_flags = HttpVariableFlags::PREFIX | HttpVariableFlags::CHANGEABLE;
        add_variable::<CountingVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_PrEfIx_"),
            prefix_flags,
            32,
        )
        .unwrap();
        let prefix = fixture.configuration.prefix_variable(b"ngx_rs_prefix_");
        assert_eq!(prefix.flags, prefix_flags.bits());
        assert_handler::<CountingVariable>(prefix, 32);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn add_variable_with_setter_installs_both_typed_handlers() {
        let mut fixture = VariableFixture::new();
        let calls = AtomicUsize::new(0);
        let data = (&raw const calls).cast::<AtomicUsize>() as usize;
        let name = b"ngx_rs_setter";

        add_variable_with_setter::<CountingVariable, CountingSetter>(
            fixture.configuration(),
            NgxStr::from_bytes(name),
            HttpVariableFlags::CHANGEABLE,
            data,
        )
        .unwrap();
        let variable = fixture.configuration.exact_variable(name);
        assert_eq!(variable.flags, HttpVariableFlags::CHANGEABLE.bits());
        assert_handler::<CountingVariable>(variable, data);
        let setter = variable.set_handler.unwrap();

        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };
        fixture.configuration.with_request(|request| {
            unsafe { setter(request.as_ptr(), &raw mut value, data) };
        });

        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn read_only_redefinition_clears_an_existing_setter() {
        let mut fixture = VariableFixture::new();
        let name = b"ngx_rs_replaced_setter";

        add_variable_with_setter::<CountingVariable, CountingSetter>(
            fixture.configuration(),
            NgxStr::from_bytes(name),
            HttpVariableFlags::CHANGEABLE,
            1,
        )
        .unwrap();
        assert!(fixture.configuration.exact_variable(name).set_handler.is_some());

        add_variable::<DataVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(name),
            HttpVariableFlags::CHANGEABLE,
            2,
        )
        .unwrap();

        let variable = fixture.configuration.exact_variable(name);
        assert_handler::<DataVariable>(variable, 2);
        assert!(variable.set_handler.is_none());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn add_variable_preserves_registration_order() {
        let mut fixture = VariableFixture::new();
        let names: [&[u8]; 3] = [b"ngx_rs_order_one", b"ngx_rs_order_two", b"ngx_rs_order_three"];

        for (index, name) in names.iter().enumerate() {
            add_variable::<CountingVariable>(
                fixture.configuration(),
                NgxStr::from_bytes(name),
                HttpVariableFlags::empty(),
                index,
            )
            .unwrap();
        }

        let mut positions = [usize::MAX; 3];
        for (index, key) in fixture.configuration.exact_variables().iter().enumerate() {
            for (name_index, name) in names.iter().enumerate() {
                if key.key.as_bytes() == *name {
                    positions[name_index] = index;
                }
            }
        }

        assert!(positions.iter().all(|position| *position != usize::MAX));
        assert!(positions[0] < positions[1]);
        assert!(positions[1] < positions[2]);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn rejected_registration_preserves_existing_handler_state() {
        let mut fixture = VariableFixture::new();
        let name = b"ngx_rs_rejected";
        add_variable::<CountingVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(name),
            HttpVariableFlags::empty(),
            0,
        )
        .unwrap();
        let before = fixture.configuration.exact_variable(name);
        let before_handler = before.get_handler;
        let before_flags = before.flags;
        let before_data = before.data;
        let exact_count = fixture.configuration.exact_variables().len();
        let prefix_count = fixture.configuration.prefix_variables().len();

        assert!(
            add_variable::<DataVariable>(
                fixture.configuration(),
                NgxStr::from_bytes(b"NgX_Rs_ReJeCtEd"),
                HttpVariableFlags::empty(),
                usize::MAX,
            )
            .is_err()
        );
        let after = fixture.configuration.exact_variable(name);
        assert!(same_handler(before_handler, after.get_handler));
        assert_eq!(after.flags, before_flags);
        assert_eq!(after.data, before_data);
        assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
        assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);

        assert!(
            add_variable::<DataVariable>(
                fixture.configuration(),
                NgxStr::from_bytes(b""),
                HttpVariableFlags::empty(),
                1,
            )
            .is_err()
        );
        assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
        assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);

        let internal = HttpVariableFlags::from_bits_retain(NGX_HTTP_VAR_INDEXED as _);
        assert!(
            add_variable::<DataVariable>(
                fixture.configuration(),
                NgxStr::from_bytes(b"ngx_rs_internal"),
                internal,
                2,
            )
            .is_err()
        );
        let unknown = HttpVariableFlags::from_bits_retain(1_usize << (usize::BITS - 1));
        assert!(
            add_variable::<DataVariable>(
                fixture.configuration(),
                NgxStr::from_bytes(b"ngx_rs_unknown"),
                unknown,
                3,
            )
            .is_err()
        );
        assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
        assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn allocation_failure_does_not_publish_a_variable_handler() {
        let mut fixture = VariableFixture::new();
        let exact_count = fixture.configuration.exact_variables().len();
        let prefix_count = fixture.configuration.prefix_variables().len();

        unsafe {
            (*fixture.pool.raw).max = 0;
            ngx_rs_test_fail_allocations_after(0);
        }
        let result = add_variable::<DataVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_registration_allocation_failure"),
            HttpVariableFlags::empty(),
            1,
        );
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert!(result.is_err());
        assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
        assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn add_variable_keeps_nginx_duplicate_changeable_and_weak_rules() {
        let mut fixture = VariableFixture::new();
        let exact_name = b"ngx_rs_changeable_weak";
        let weak_flags = HttpVariableFlags::CHANGEABLE | HttpVariableFlags::WEAK;

        add_variable::<CountingVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(exact_name),
            weak_flags,
            1,
        )
        .unwrap();
        let variable = fixture.configuration.exact_variable(exact_name);
        assert_eq!(variable.flags, weak_flags.bits());
        assert_handler::<CountingVariable>(variable, 1);

        add_variable::<DataVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_ChAnGeAbLe_WeAk"),
            weak_flags,
            2,
        )
        .unwrap();
        let variable = fixture.configuration.exact_variable(exact_name);
        assert_eq!(variable.flags, weak_flags.bits());
        assert_handler::<DataVariable>(variable, 2);

        add_variable::<TestVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(exact_name),
            HttpVariableFlags::CHANGEABLE,
            usize::MAX,
        )
        .unwrap();
        let variable = fixture.configuration.exact_variable(exact_name);
        assert_eq!(variable.flags, HttpVariableFlags::CHANGEABLE.bits());
        assert_handler::<TestVariable>(variable, usize::MAX);

        let prefix_name = b"ngx_rs_prefix_weak_";
        add_variable::<CountingVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(prefix_name),
            weak_flags | HttpVariableFlags::PREFIX,
            4,
        )
        .unwrap();
        add_variable::<DataVariable>(
            fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_PrEfIx_WeAk_"),
            HttpVariableFlags::CHANGEABLE | HttpVariableFlags::PREFIX,
            5,
        )
        .unwrap();
        let prefix = fixture.configuration.prefix_variable(prefix_name);
        assert_eq!(
            prefix.flags,
            (HttpVariableFlags::CHANGEABLE | HttpVariableFlags::PREFIX).bits()
        );
        assert_handler::<DataVariable>(prefix, 5);
    }
}
