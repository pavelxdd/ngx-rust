use core::alloc::Layout;
use core::error;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::allocator::Allocator;
use crate::core::{ConnectionError, NgxStr, Pool};
use crate::ffi::{
    NGX_ERROR, NGX_STREAM_VAR_CHANGEABLE, NGX_STREAM_VAR_NOCACHEABLE, NGX_STREAM_VAR_NOHASH,
    NGX_STREAM_VAR_PREFIX, NGX_STREAM_VAR_WEAK, ngx_conf_t, ngx_int_t, ngx_stream_add_variable,
    ngx_stream_session_t, ngx_uint_t, ngx_variable_value_t,
};
use crate::stream::{IntoHandlerStatus, Session};

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
        /// Treats the name as a prefix matched against variable names.
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
pub enum StreamVariableValueError {
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

impl fmt::Display for StreamVariableValueError {
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

impl error::Error for StreamVariableValueError {}

impl From<ConnectionError> for StreamVariableValueError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

/// Error returned when a raw Stream variable value cannot be read safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamVariableValueReadError {
    /// A nonempty found value has a null data pointer.
    NullData,
}

impl fmt::Display for StreamVariableValueReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullData => formatter.write_str("Stream variable value has null data"),
        }
    }
}

impl error::Error for StreamVariableValueReadError {}

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
    ) -> Result<Self, StreamVariableValueError> {
        if value.len() > StreamVariableValue::MAX_LEN {
            return Err(StreamVariableValueError::TooLong);
        }

        let pool = session.connection()?.pool()?;
        let data = if value.is_empty() {
            NonNull::dangling()
        } else {
            let layout = Layout::array::<u8>(value.len())
                .map_err(|_| StreamVariableValueError::Allocation)?;
            let data = pool
                .allocate(layout)
                .map_err(|_| StreamVariableValueError::Allocation)?
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

/// Borrowed output value supplied to a Stream variable getter.
pub struct StreamVariableValue<'callback> {
    raw: NonNull<ngx_variable_value_t>,
    _callback: PhantomData<&'callback mut ngx_variable_value_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl StreamVariableValue<'_> {
    const MAX_LEN: usize = (1 << 28) - 1;

    unsafe fn from_raw<'callback>(
        value: *mut ngx_variable_value_t,
    ) -> StreamVariableValue<'callback> {
        StreamVariableValue {
            raw: unsafe { NonNull::new_unchecked(value) },
            _callback: PhantomData,
            _not_thread_safe: PhantomData,
        }
    }

    /// Returns a checked view of the current output state.
    pub fn read(&self) -> Result<StreamVariableValueRef<'_>, StreamVariableValueReadError> {
        let raw = unsafe { self.raw.as_ref() };
        if raw.not_found() == 0 && raw.len() != 0 && raw.data.is_null() {
            return Err(StreamVariableValueReadError::NullData);
        }

        Ok(StreamVariableValueRef { raw, _not_thread_safe: PhantomData })
    }

    /// Stores bytes whose static lifetime outlives every nginx session.
    ///
    /// ```compile_fail
    /// # use ngx::stream::StreamVariableValue;
    /// # fn set(value: &mut StreamVariableValue, bytes: &[u8]) {
    /// value.set_static(bytes).unwrap();
    /// # }
    /// ```
    pub fn set_static(&mut self, value: &'static [u8]) -> Result<(), StreamVariableValueError> {
        self.set_found(value.len(), value.as_ptr().cast_mut(), true)
    }

    /// Stores static bytes and asks nginx to evaluate the getter on every access.
    pub fn set_static_uncached(
        &mut self,
        value: &'static [u8],
    ) -> Result<(), StreamVariableValueError> {
        self.set_found(value.len(), value.as_ptr().cast_mut(), false)
    }

    /// Stores bytes already retained by the current session pool.
    ///
    /// The setter accepts only bytes retained by the current session pool, so arbitrary stack,
    /// context, and TLV slices cannot be cached accidentally:
    ///
    /// ```compile_fail
    /// use ngx::stream::{Session, StreamVariableValue};
    ///
    /// fn set(value: &mut StreamVariableValue<'_>, session: &Session<'_>) {
    ///     let stack = *b"stack";
    ///     value.set_pool(session, &stack);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::stream::{Session, StreamVariableValue};
    ///
    /// struct Context {
    ///     bytes: [u8; 7],
    /// }
    ///
    /// fn set(
    ///     value: &mut StreamVariableValue<'_>,
    ///     session: &Session<'_>,
    ///     context: &Context,
    /// ) {
    ///     value.set_pool(session, &context.bytes);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::stream::{Session, StreamVariableValue};
    ///
    /// fn set(value: &mut StreamVariableValue<'_>, session: &Session<'_>, tlv: &[u8]) {
    ///     value.set_pool(session, tlv);
    /// }
    /// ```
    pub fn set_pool(
        &mut self,
        session: &Session<'_>,
        value: StreamVariablePoolBytes<'_>,
    ) -> Result<(), StreamVariableValueError> {
        self.set_pool_with_cache(session, value, true)
    }

    /// Stores session-pool bytes and asks nginx to evaluate the getter on every access.
    pub fn set_pool_uncached(
        &mut self,
        session: &Session<'_>,
        value: StreamVariablePoolBytes<'_>,
    ) -> Result<(), StreamVariableValueError> {
        self.set_pool_with_cache(session, value, false)
    }

    /// Copies callback bytes into the current session pool before publishing a cacheable value.
    pub fn copy_from_session(
        &mut self,
        session: &Session<'_>,
        value: &[u8],
    ) -> Result<(), StreamVariableValueError> {
        let value = StreamVariablePoolBytes::copy_from_session(session, value)?;
        self.set_pool(session, value)
    }

    /// Copies callback bytes into the current session pool and marks the result noncacheable.
    pub fn copy_from_session_uncached(
        &mut self,
        session: &Session<'_>,
        value: &[u8],
    ) -> Result<(), StreamVariableValueError> {
        let value = StreamVariablePoolBytes::copy_from_session(session, value)?;
        self.set_pool_uncached(session, value)
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
        session: &Session<'_>,
        value: StreamVariablePoolBytes<'_>,
        cacheable: bool,
    ) -> Result<(), StreamVariableValueError> {
        let session_pool = session.connection()?.pool()?;
        if !ptr::eq(session_pool.as_ptr(), value.pool.as_ptr()) {
            return Err(StreamVariableValueError::PoolMismatch);
        }

        self.set_found(value.len, value.data.as_ptr(), cacheable)
    }

    fn set_found(
        &mut self,
        len: usize,
        data: *mut u8,
        cacheable: bool,
    ) -> Result<(), StreamVariableValueError> {
        if len > Self::MAX_LEN {
            return Err(StreamVariableValueError::TooLong);
        }
        if len != 0 && data.is_null() {
            return Err(StreamVariableValueError::NullData);
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

/// Checked borrowed view of a Stream variable output.
pub struct StreamVariableValueRef<'value> {
    raw: &'value ngx_variable_value_t,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl StreamVariableValueRef<'_> {
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

/// Typed getter for a registered Stream variable.
pub trait StreamVariableHandler {
    /// Getter result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Evaluates the variable for one active session.
    fn get(
        session: &mut Session<'_>,
        value: &mut StreamVariableValue<'_>,
        data: usize,
    ) -> Self::Output;
}

/// Registers a typed read-only Stream variable.
///
/// Call this function from the module's preconfiguration callback. `name` does not include `$`.
pub fn add_variable<H>(
    cf: &mut ngx_conf_t,
    name: &NgxStr,
    flags: StreamVariableFlags,
    data: usize,
) -> Result<(), VariableRegistrationError>
where
    H: StreamVariableHandler,
{
    if flags.bits() & !StreamVariableFlags::all().bits() != 0 {
        return Err(VariableRegistrationError);
    }

    let mut name = name.as_ngx_str();
    let mut variable =
        NonNull::new(unsafe { ngx_stream_add_variable(cf, &raw mut name, flags.bits()) })
            .ok_or(VariableRegistrationError)?;
    let variable = unsafe { variable.as_mut() };
    variable.get_handler = Some(raw_get_handler::<H>);
    variable.data = data;
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
            let mut value = StreamVariableValue::from_raw(value);
            H::get(&mut session, &mut value, data).into_handler_status(&session)
        })
    }
    .unwrap_or(NGX_ERROR as _)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "test-link")]
    use alloc::boxed::Box;
    use core::mem::MaybeUninit;
    use core::ptr::{self, NonNull};

    #[cfg(feature = "test-link")]
    use super::StreamVariablePoolBytes;
    use super::{
        StreamVariableHandler, StreamVariableValue, StreamVariableValueError,
        StreamVariableValueReadError, raw_get_handler,
    };
    use crate::core::Status;
    use crate::ffi::{NGX_STREAM_OK, ngx_stream_session_t, ngx_variable_value_t};
    #[cfg(feature = "test-link")]
    use crate::ffi::{
        ngx_connection_t, ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_pool_t, ngx_uint_t,
    };
    use crate::stream::Session;

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    struct TestVariable;

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
        value: &StreamVariableValue<'_>,
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

    fn assert_not_found(raw: &ngx_variable_value_t, value: &StreamVariableValue<'_>) {
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
    }

    #[cfg(feature = "test-link")]
    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }

    #[cfg(feature = "test-link")]
    fn with_session<R>(
        owner: &TestPool,
        f: impl for<'scope> FnOnce(&mut Session<'scope>) -> R,
    ) -> R {
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut raw = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        raw.connection = &raw mut *connection;

        unsafe { Session::with_raw(&raw mut raw, |mut session| f(&mut session)) }.unwrap()
    }

    impl StreamVariableHandler for TestVariable {
        type Output = Status;

        fn get(
            session: &mut Session<'_>,
            value: &mut StreamVariableValue<'_>,
            data: usize,
        ) -> Self::Output {
            unsafe { (*session.as_ptr()).status = data as _ };
            value.set_static(b"detected").unwrap();
            Status::NGX_OK
        }
    }

    #[test]
    fn raw_variable_handler_wraps_the_session_and_value() {
        let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        let mut raw_value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        let status = unsafe {
            raw_get_handler::<TestVariable>(
                &raw mut session,
                &raw mut raw_value,
                NGX_STREAM_OK as _,
            )
        };

        assert_eq!(status, Status::NGX_OK.0);
        assert_eq!(session.status, NGX_STREAM_OK as _);
        let value = unsafe { StreamVariableValue::from_raw(&raw mut raw_value) };
        assert_found(&raw_value, &value, b"detected", true, b"detected".as_ptr().cast_mut());
    }

    #[test]
    fn static_values_replace_every_output_field() {
        static CACHED: &[u8] = b"cached";
        static UNCACHED: &[u8] = b"uncached";

        let mut raw = poisoned_value();
        let mut value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };

        value.set_static(CACHED).unwrap();
        assert_found(&raw, &value, CACHED, true, CACHED.as_ptr().cast_mut());

        value.set_static_uncached(UNCACHED).unwrap();
        assert_found(&raw, &value, UNCACHED, false, UNCACHED.as_ptr().cast_mut());
    }

    #[test]
    fn empty_and_not_found_values_replace_every_output_field() {
        let mut raw = poisoned_value();
        let mut value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };

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
        let mut value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };
        let data = NonNull::<u8>::dangling().as_ptr();

        value.set_found(StreamVariableValue::MAX_LEN, data, true).unwrap();
        assert_eq!(raw.len() as usize, StreamVariableValue::MAX_LEN);
        assert_eq!(raw.data, data);
        assert_eq!(raw.valid(), 1);
        assert_eq!(raw.no_cacheable(), 0);
        assert_eq!(raw.not_found(), 0);
        assert_eq!(raw.escape(), 0);

        let before =
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data);
        assert_eq!(
            value.set_found(StreamVariableValue::MAX_LEN + 1, data, true),
            Err(StreamVariableValueError::TooLong)
        );
        assert_eq!(
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data,),
            before
        );

        assert_eq!(
            value.set_found(1, ptr::null_mut(), false),
            Err(StreamVariableValueError::NullData)
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
        let mut value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };

        assert!(matches!(value.read(), Err(StreamVariableValueReadError::NullData)));

        value.set_empty();
        assert_found(&raw, &value, b"", true, ptr::null_mut());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn session_pool_values_replace_every_output_field() {
        let owner = TestPool::new();

        with_session(&owner, |session| {
            let mut raw = poisoned_value();
            let mut value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };
            let bytes = StreamVariablePoolBytes::copy_from_session(&*session, b"pool").unwrap();
            let data = bytes.data.as_ptr();
            assert_eq!(bytes.bytes(), b"pool");
            assert_ne!(data, b"pool".as_ptr().cast_mut());

            value.set_pool(&*session, bytes).unwrap();
            assert_found(&raw, &value, b"pool", true, data);

            let bytes =
                StreamVariablePoolBytes::copy_from_session(&*session, b"uncached-pool").unwrap();
            let data = bytes.data.as_ptr();
            value.set_pool_uncached(&*session, bytes).unwrap();
            assert_found(&raw, &value, b"uncached-pool", false, data);
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn copied_session_values_replace_every_output_field() {
        let owner = TestPool::new();

        with_session(&owner, |session| {
            let mut raw = poisoned_value();
            let mut value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };
            let copied = *b"copied";

            value.copy_from_session(&*session, &copied).unwrap();
            assert_ne!(raw.data, copied.as_ptr().cast_mut());
            assert_found(&raw, &value, &copied, true, raw.data);

            let uncached = *b"uncached";
            value.copy_from_session_uncached(&*session, &uncached).unwrap();
            assert_ne!(raw.data, uncached.as_ptr().cast_mut());
            assert_found(&raw, &value, &uncached, false, raw.data);

            value.copy_from_session(&*session, b"").unwrap();
            assert_found(&raw, &value, b"", true, ptr::null_mut());
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn foreign_session_pool_bytes_do_not_publish_an_output() {
        let current_owner = TestPool::new();
        let foreign_owner = TestPool::new();
        let mut current_connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        current_connection.pool = current_owner.raw;
        let mut foreign_connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        foreign_connection.pool = foreign_owner.raw;
        let mut current = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        current.connection = &raw mut *current_connection;
        let mut foreign = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        foreign.connection = &raw mut *foreign_connection;

        unsafe {
            Session::with_raw(&raw mut current, |current| {
                Session::with_raw(&raw mut foreign, |foreign| {
                    let bytes =
                        StreamVariablePoolBytes::copy_from_session(&foreign, b"foreign").unwrap();
                    let mut raw = poisoned_value();
                    let mut value = StreamVariableValue::from_raw(&raw mut raw);
                    let before = (
                        raw.len(),
                        raw.valid(),
                        raw.no_cacheable(),
                        raw.not_found(),
                        raw.escape(),
                        raw.data,
                    );

                    assert_eq!(
                        value.set_pool(&current, bytes),
                        Err(StreamVariableValueError::PoolMismatch)
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
                })
                .unwrap();
            })
            .unwrap();
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn allocation_failure_does_not_publish_partial_output() {
        let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let owner = TestPool::new();
        unsafe { (*owner.raw).max = 0 };

        with_session(&owner, |session| {
            let mut raw = poisoned_value();
            let mut value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };
            let before = (
                raw.len(),
                raw.valid(),
                raw.no_cacheable(),
                raw.not_found(),
                raw.escape(),
                raw.data,
            );

            unsafe { ngx_rs_test_fail_allocations_after(0) };
            let result = value.copy_from_session(&*session, b"copied");
            unsafe { ngx_rs_test_reset_allocation_failures() };

            assert_eq!(result, Err(StreamVariableValueError::Allocation));
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
}
