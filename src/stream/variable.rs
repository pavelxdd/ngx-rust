use core::alloc::Layout;
use core::error;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::allocator::Allocator;
use crate::core::{ConnectionError, NgxStr, Pool};
use crate::ffi::{
    NGX_ERROR, NGX_OK, NGX_STREAM_VAR_CHANGEABLE, NGX_STREAM_VAR_NOCACHEABLE,
    NGX_STREAM_VAR_NOHASH, NGX_STREAM_VAR_PREFIX, NGX_STREAM_VAR_WEAK, ngx_int_t, ngx_str_t,
    ngx_stream_add_variable, ngx_stream_session_t, ngx_uint_t, ngx_variable_value_t,
};
use crate::stream::{
    IntoHandlerStatus, NgxStreamCoreModule, Session, StreamConfigurationParser,
    StreamModuleMainConf,
};

bitflags::bitflags! {
    /// Flags controlling Stream variable registration and caching.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct StreamVariableFlags: ngx_uint_t {
        /// Allows another module to redefine the variable.
        const CHANGEABLE = NGX_STREAM_VAR_CHANGEABLE as _;
        /// Re-evaluates the variable instead of caching its first value.
        const NOCACHEABLE = NGX_STREAM_VAR_NOCACHEABLE as _;
        /// Excludes the variable from the name hash.
        const NOHASH = NGX_STREAM_VAR_NOHASH as _;
        /// Lets a later non-weak definition replace this variable.
        const WEAK = NGX_STREAM_VAR_WEAK as _;
        /// Native prefix marker applied automatically by [`add_prefix_variable`].
        const PREFIX = NGX_STREAM_VAR_PREFIX as _;
    }
}

/// Error returned when nginx rejects a Stream variable registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariableRegistrationError;

impl fmt::Display for VariableRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("failed to register Stream variable")
    }
}

impl error::Error for VariableRegistrationError {}

/// Error returned when Stream variable output cannot be published safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamVariableOutputError {
    /// The value exceeds nginx's 28-bit variable length field.
    TooLong,
    /// A nonempty value has no backing bytes.
    NullData,
    /// The session has no usable client connection or pool.
    Connection(ConnectionError),
    /// Nginx could not allocate session-pool storage for copied bytes.
    Allocation,
    /// The supplied pool bytes belong to a different session pool.
    PoolMismatch,
}

impl fmt::Display for StreamVariableOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => formatter.write_str("Stream variable value is too long"),
            Self::NullData => formatter.write_str("Stream variable value has null data"),
            Self::Connection(_) => formatter.write_str("Stream session has no usable pool"),
            Self::Allocation => formatter.write_str("failed to allocate Stream variable bytes"),
            Self::PoolMismatch => {
                formatter.write_str("Stream variable bytes belong to another pool")
            }
        }
    }
}

impl error::Error for StreamVariableOutputError {}

impl From<ConnectionError> for StreamVariableOutputError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

/// Bytes copied into the current Stream session pool for a variable output.
///
/// The value cannot outlive the session view that allocated it:
///
/// ```compile_fail
/// use ngx::stream::{Session, StreamVariablePoolBytes};
///
/// fn escape(session: &Session<'_>) -> StreamVariablePoolBytes<'static> {
///     StreamVariablePoolBytes::copy_from_session(session, b"value").unwrap()
/// }
/// ```
pub struct StreamVariablePoolBytes<'pool> {
    data: NonNull<u8>,
    len: usize,
    pool: Pool<'pool>,
}

impl<'pool> StreamVariablePoolBytes<'pool> {
    /// Copies bytes into the pool owned by `session`.
    pub fn copy_from_session(
        session: &'pool Session<'_>,
        value: &[u8],
    ) -> Result<Self, StreamVariableOutputError> {
        if value.len() > StreamVariableOutput::MAX_LEN {
            return Err(StreamVariableOutputError::TooLong);
        }

        let pool = session.connection()?.pool()?;
        let data = if value.is_empty() {
            NonNull::dangling()
        } else {
            let layout = Layout::array::<u8>(value.len())
                .map_err(|_| StreamVariableOutputError::Allocation)?;
            let data = pool
                .allocate(layout)
                .map_err(|_| StreamVariableOutputError::Allocation)?
                .cast::<u8>();
            unsafe { ptr::copy_nonoverlapping(value.as_ptr(), data.as_ptr(), value.len()) };
            data
        };

        Ok(Self { data, len: value.len(), pool })
    }

    /// Returns the bytes retained by the session pool.
    pub fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }

        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}

/// Write-only result supplied to a Stream variable getter.
pub struct StreamVariableOutput<'callback> {
    raw: NonNull<ngx_variable_value_t>,
    candidate: Option<ngx_variable_value_t>,
    _callback: PhantomData<&'callback mut core::mem::MaybeUninit<ngx_variable_value_t>>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl StreamVariableOutput<'_> {
    const MAX_LEN: usize = (1 << 28) - 1;

    unsafe fn from_raw<'callback>(
        value: *mut ngx_variable_value_t,
    ) -> Option<StreamVariableOutput<'callback>> {
        let raw = NonNull::new(value)?;
        if !value.is_aligned() {
            return None;
        }

        Some(StreamVariableOutput {
            raw,
            candidate: None,
            _callback: PhantomData,
            _not_thread_safe: PhantomData,
        })
    }

    /// Stores bytes whose static lifetime outlives every nginx session.
    ///
    /// ```compile_fail
    /// # use ngx::stream::StreamVariableOutput;
    /// # fn set(value: &mut StreamVariableOutput, bytes: &[u8]) {
    /// value.set_static(bytes).unwrap();
    /// # }
    /// ```
    pub fn set_static(&mut self, value: &'static [u8]) -> Result<(), StreamVariableOutputError> {
        self.set_found(value.len(), value.as_ptr().cast_mut(), true)
    }

    /// Stores static bytes and asks nginx to evaluate the getter on every access.
    pub fn set_static_uncached(
        &mut self,
        value: &'static [u8],
    ) -> Result<(), StreamVariableOutputError> {
        self.set_found(value.len(), value.as_ptr().cast_mut(), false)
    }

    /// Stores bytes already retained by the current session pool.
    ///
    /// The setter accepts only bytes retained by the current session pool, so arbitrary stack,
    /// context, and TLV slices cannot be cached accidentally:
    ///
    /// ```compile_fail
    /// use ngx::stream::{Session, StreamVariableOutput};
    ///
    /// fn set(value: &mut StreamVariableOutput<'_>, session: &Session<'_>) {
    ///     let stack = *b"stack";
    ///     value.set_pool(session, &stack);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::stream::{Session, StreamVariableOutput};
    ///
    /// struct Context {
    ///     bytes: [u8; 7],
    /// }
    ///
    /// fn set(
    ///     value: &mut StreamVariableOutput<'_>,
    ///     session: &Session<'_>,
    ///     context: &Context,
    /// ) {
    ///     value.set_pool(session, &context.bytes);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::stream::{Session, StreamVariableOutput};
    ///
    /// fn set(value: &mut StreamVariableOutput<'_>, session: &Session<'_>, tlv: &[u8]) {
    ///     value.set_pool(session, tlv);
    /// }
    /// ```
    pub fn set_pool(
        &mut self,
        session: &Session<'_>,
        value: StreamVariablePoolBytes<'_>,
    ) -> Result<(), StreamVariableOutputError> {
        self.set_pool_with_cache(session, value, true)
    }

    /// Stores session-pool bytes and asks nginx to evaluate the getter on every access.
    pub fn set_pool_uncached(
        &mut self,
        session: &Session<'_>,
        value: StreamVariablePoolBytes<'_>,
    ) -> Result<(), StreamVariableOutputError> {
        self.set_pool_with_cache(session, value, false)
    }

    /// Copies callback bytes into the current session pool before publishing a cacheable value.
    pub fn copy_from_session(
        &mut self,
        session: &Session<'_>,
        value: &[u8],
    ) -> Result<(), StreamVariableOutputError> {
        let value = StreamVariablePoolBytes::copy_from_session(session, value)?;
        self.set_pool(session, value)
    }

    /// Copies callback bytes into the current session pool and marks the result noncacheable.
    pub fn copy_from_session_uncached(
        &mut self,
        session: &Session<'_>,
        value: &[u8],
    ) -> Result<(), StreamVariableOutputError> {
        let value = StreamVariablePoolBytes::copy_from_session(session, value)?;
        self.set_pool_uncached(session, value)
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
        session: &Session<'_>,
        value: StreamVariablePoolBytes<'_>,
        cacheable: bool,
    ) -> Result<(), StreamVariableOutputError> {
        let session_pool = session.connection()?.pool()?;
        if !ptr::eq(session_pool.as_ptr(), value.pool.as_ptr()) {
            return Err(StreamVariableOutputError::PoolMismatch);
        }

        self.set_found(value.len, value.data.as_ptr(), cacheable)
    }

    fn set_found(
        &mut self,
        len: usize,
        data: *mut u8,
        cacheable: bool,
    ) -> Result<(), StreamVariableOutputError> {
        if len > Self::MAX_LEN {
            return Err(StreamVariableOutputError::TooLong);
        }
        if len != 0 && data.is_null() {
            return Err(StreamVariableOutputError::NullData);
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

/// Typed getter for a registered Stream variable.
///
/// A getter must not panic; panics terminate the worker process.
pub trait StreamVariableHandler {
    /// Getter result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Evaluates the variable for one active session.
    fn get(
        session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        data: usize,
    ) -> Self::Output;
}

/// Typed getter for a prefix-matched Stream variable.
///
/// A getter must not panic; panics terminate the worker process.
pub trait StreamPrefixVariableHandler {
    /// Getter result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Evaluates the variable for one active session and the full queried variable name.
    fn get(
        session: &mut Session<'_>,
        value: &mut StreamVariableOutput<'_>,
        name: &NgxStr,
    ) -> Self::Output;
}

/// Registers a typed read-only exact Stream variable.
///
/// Call this function from the module's preconfiguration callback. `name` does not include `$`.
/// Use [`add_prefix_variable`] instead of passing [`StreamVariableFlags::PREFIX`].
pub fn add_variable<H>(
    parser: &mut StreamConfigurationParser<'_>,
    name: &NgxStr,
    flags: StreamVariableFlags,
    data: usize,
) -> Result<(), VariableRegistrationError>
where
    H: StreamVariableHandler,
{
    if flags.bits() & !StreamVariableFlags::all().bits() != 0
        || flags.contains(StreamVariableFlags::PREFIX)
    {
        return Err(VariableRegistrationError);
    }

    let mut name = name.as_ngx_str();
    let Some(mut variable) = NonNull::new(unsafe {
        ngx_stream_add_variable(parser.as_raw(), &raw mut name, flags.bits())
    }) else {
        return Err(VariableRegistrationError);
    };
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_get_handler::<H>);
    variable.data = data;
    Ok(())
}

/// Registers a typed prefix-matched Stream variable.
///
/// Call this function from the module's preconfiguration callback. `prefix` does not include `$`.
/// The full queried variable name is passed to the handler when nginx finds this prefix. `flags`
/// must not include [`StreamVariableFlags::PREFIX`], which this function applies automatically.
pub fn add_prefix_variable<H>(
    parser: &mut StreamConfigurationParser<'_>,
    prefix: &NgxStr,
    flags: StreamVariableFlags,
) -> Result<(), VariableRegistrationError>
where
    H: StreamPrefixVariableHandler,
{
    if flags.bits() & !StreamVariableFlags::all().bits() != 0
        || flags.contains(StreamVariableFlags::PREFIX)
    {
        return Err(VariableRegistrationError);
    }

    let main = NgxStreamCoreModule::main_conf_mut(parser)
        .ok()
        .flatten()
        .ok_or(VariableRegistrationError)?;
    let original_nelts = main.prefix_variables.nelts;
    let prefix_nelts = &raw mut main.prefix_variables.nelts;
    let mut prefix = prefix.as_ngx_str();
    let Some(mut variable) = NonNull::new(unsafe {
        ngx_stream_add_variable(
            parser.as_raw(),
            &raw mut prefix,
            flags.bits() | StreamVariableFlags::PREFIX.bits(),
        )
    }) else {
        unsafe { prefix_nelts.write(original_nelts) };
        return Err(VariableRegistrationError);
    };
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_prefix_get_handler::<H>);
    variable.data = 0;
    Ok(())
}

/// C-compatible adapter for a typed Stream variable getter.
///
/// # Safety
/// `session` and `value` must be the valid non-null pointers supplied by nginx for the duration of
/// this callback, and the session must be exclusively available to the getter.
pub(crate) unsafe extern "C" fn raw_get_handler<H>(
    session: *mut ngx_stream_session_t,
    value: *mut ngx_variable_value_t,
    data: usize,
) -> ngx_int_t
where
    H: StreamVariableHandler,
{
    unsafe {
        Session::with_raw(session, |mut session| {
            let Some(mut value) = StreamVariableOutput::from_raw(value) else {
                return NGX_ERROR as _;
            };

            let status = H::get(&mut session, &mut value, data).into_handler_status(&session);

            if status == NGX_OK as _ {
                value.publish_success();
            }

            status
        })
    }
    .unwrap_or(NGX_ERROR as _)
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

/// C-compatible adapter for a typed prefix-matched Stream variable getter.
///
/// # Safety
/// `session` and `value` must be valid pointers supplied by nginx for this callback, and `data`
/// must encode the live `ngx_str_t` full-name descriptor used by nginx's prefix dispatch.
pub(crate) unsafe extern "C" fn raw_prefix_get_handler<H>(
    session: *mut ngx_stream_session_t,
    value: *mut ngx_variable_value_t,
    data: usize,
) -> ngx_int_t
where
    H: StreamPrefixVariableHandler,
{
    unsafe {
        Session::with_raw(session, |mut session| {
            let Some(mut value) = StreamVariableOutput::from_raw(value) else {
                return NGX_ERROR as _;
            };
            let Some(name) = prefix_name_from_data(data) else {
                return NGX_ERROR as _;
            };

            let status = H::get(&mut session, &mut value, name).into_handler_status(&session);

            if status == NGX_OK as _ {
                value.publish_success();
            }

            status
        })
    }
    .unwrap_or(NGX_ERROR as _)
}

#[cfg(test)]
#[path = "variable/tests/mod.rs"]
mod tests;
