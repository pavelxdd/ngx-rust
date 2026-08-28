use core::alloc::Layout;
use core::error;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

#[cfg(feature = "std")]
use core::panic::AssertUnwindSafe;
#[cfg(feature = "std")]
use std::panic::catch_unwind;

use crate::allocator::Allocator;
use crate::core::{ConnectionError, NgxStr, Pool};
use crate::ffi::{
    NGX_ERROR, NGX_OK, NGX_STREAM_VAR_CHANGEABLE, NGX_STREAM_VAR_NOCACHEABLE,
    NGX_STREAM_VAR_NOHASH, NGX_STREAM_VAR_PREFIX, NGX_STREAM_VAR_WEAK, ngx_int_t,
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

/// Registers a typed read-only Stream variable.
///
/// Call this function from the module's preconfiguration callback. `name` does not include `$`.
pub fn add_variable<H>(
    parser: &mut StreamConfigurationParser<'_>,
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

    let prefix_nelts = if flags.contains(StreamVariableFlags::PREFIX) {
        let main = NgxStreamCoreModule::main_conf_mut(parser)
            .ok()
            .flatten()
            .ok_or(VariableRegistrationError)?;
        let original = main.prefix_variables.nelts;
        Some((&raw mut main.prefix_variables.nelts, original))
    } else {
        None
    };

    let mut name = name.as_ngx_str();
    let Some(mut variable) = NonNull::new(unsafe {
        ngx_stream_add_variable(parser.as_raw(), &raw mut name, flags.bits())
    }) else {
        if let Some((nelts, original)) = prefix_nelts {
            unsafe { nelts.write(original) };
        }
        return Err(VariableRegistrationError);
    };
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
            let Some(mut value) = StreamVariableOutput::from_raw(value) else {
                return NGX_ERROR as _;
            };

            #[cfg(feature = "std")]
            let status = catch_unwind(AssertUnwindSafe(|| {
                H::get(&mut session, &mut value, data).into_handler_status(&session)
            }))
            .unwrap_or(NGX_ERROR as _);

            #[cfg(not(feature = "std"))]
            let status = {
                // An `extern "C"` trampoline must never unwind into nginx. A no-std panic that
                // reaches this boundary aborts rather than crossing it.
                H::get(&mut session, &mut value, data).into_handler_status(&session)
            };

            if status == NGX_OK as _ {
                value.publish_success();
            }

            status
        })
    }
    .unwrap_or(NGX_ERROR as _)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "test-link")]
    use alloc::boxed::Box;
    #[cfg(feature = "test-link")]
    use core::ffi::c_void;
    use core::mem::MaybeUninit;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(feature = "test-link")]
    use std::sync::MutexGuard;

    #[cfg(feature = "test-link")]
    use super::StreamVariablePoolBytes;
    use super::{
        StreamVariableFlags, StreamVariableHandler, StreamVariableOutput,
        StreamVariableOutputError, add_variable, raw_get_handler,
    };
    use crate::core::{NgxStr, Status};
    use crate::ffi::{
        NGX_ERROR, NGX_STREAM_OK, ngx_int_t, ngx_stream_session_t, ngx_variable_value_t,
    };
    #[cfg(feature = "test-link")]
    use crate::ffi::{
        NGX_OK, NGX_STREAM_MODULE, NGX_STREAM_VAR_INDEXED, ngx_array_t, ngx_conf_t,
        ngx_connection_t, ngx_create_pool, ngx_destroy_pool, ngx_hash_key_t, ngx_log_t, ngx_pool_t,
        ngx_stream_conf_ctx_t, ngx_stream_core_main_conf_t, ngx_stream_get_variable_pt,
        ngx_stream_variable_t, ngx_stream_variables_add_core_vars, ngx_stream_variables_init_vars,
        ngx_uint_t,
    };
    use crate::stream::{Session, StreamConfigurationParser};

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    struct TestVariable;

    static RAW_VARIABLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RAW_VARIABLE_DATA: AtomicUsize = AtomicUsize::new(0);

    struct CountingVariable;

    impl StreamVariableHandler for CountingVariable {
        type Output = Status;

        fn get(
            _session: &mut Session<'_>,
            value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            RAW_VARIABLE_CALLS.fetch_add(1, Ordering::Relaxed);
            value.set_empty();
            Status::NGX_OK
        }
    }

    struct DataVariable;

    impl StreamVariableHandler for DataVariable {
        type Output = Status;

        fn get(
            _session: &mut Session<'_>,
            value: &mut StreamVariableOutput<'_>,
            data: usize,
        ) -> Self::Output {
            RAW_VARIABLE_DATA.store(data, Ordering::Relaxed);
            value.set_empty();
            Status::NGX_DECLINED
        }
    }

    struct RawStatusVariable;

    impl StreamVariableHandler for RawStatusVariable {
        type Output = ngx_int_t;

        fn get(
            _session: &mut Session<'_>,
            value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            value.set_empty();
            NGX_STREAM_OK as _
        }
    }

    struct OptionalStatusVariable;

    impl StreamVariableHandler for OptionalStatusVariable {
        type Output = Option<Status>;

        fn get(
            _session: &mut Session<'_>,
            value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            value.set_empty();
            Some(Status::NGX_AGAIN)
        }
    }

    struct SuccessfulMissingVariable;

    impl StreamVariableHandler for SuccessfulMissingVariable {
        type Output = Status;

        fn get(
            _session: &mut Session<'_>,
            _value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            Status::NGX_OK
        }
    }

    struct MissingStatusVariable;

    impl StreamVariableHandler for MissingStatusVariable {
        type Output = Option<Status>;

        fn get(
            _session: &mut Session<'_>,
            _value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            None
        }
    }

    struct ResultStatusVariable;

    impl StreamVariableHandler for ResultStatusVariable {
        type Output = Result<Status, Status>;

        fn get(
            _session: &mut Session<'_>,
            value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            value.set_empty();
            Ok(Status::NGX_DECLINED)
        }
    }

    struct ErrorStatusVariable;

    impl StreamVariableHandler for ErrorStatusVariable {
        type Output = Result<Status, Status>;

        fn get(
            _session: &mut Session<'_>,
            _value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            Err(Status::NGX_AGAIN)
        }
    }

    #[cfg(feature = "std")]
    struct PanickingVariable;

    #[cfg(feature = "std")]
    impl StreamVariableHandler for PanickingVariable {
        type Output = Status;

        fn get(
            _session: &mut Session<'_>,
            _value: &mut StreamVariableOutput<'_>,
            _data: usize,
        ) -> Self::Output {
            panic!("variable getter panic")
        }
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

    fn misaligned_ptr<T>(storage: &mut [u8]) -> *mut T {
        let alignment = core::mem::align_of::<T>();
        assert!(alignment > 1);
        let offset = storage.as_mut_ptr().align_offset(alignment);
        assert!(offset + 1 < storage.len());
        unsafe { storage.as_mut_ptr().add(offset + 1).cast() }
    }

    fn raw_handler_status<H>() -> ngx_int_t
    where
        H: StreamVariableHandler,
    {
        let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        unsafe { raw_get_handler::<H>(&raw mut session, &raw mut value, 0) }
    }

    #[test]
    fn raw_variable_value_construction_rejects_null_and_misaligned_pointers() {
        assert!(unsafe { StreamVariableOutput::from_raw(ptr::null_mut()) }.is_none());

        let mut storage = [0_u8;
            core::mem::size_of::<ngx_variable_value_t>()
                + core::mem::align_of::<ngx_variable_value_t>()];
        let raw = misaligned_ptr::<ngx_variable_value_t>(&mut storage);
        assert!(unsafe { StreamVariableOutput::from_raw(raw) }.is_none());
    }

    #[test]
    fn raw_variable_handler_rejects_invalid_callback_pointers_without_calling_the_getter() {
        RAW_VARIABLE_CALLS.store(0, Ordering::Relaxed);
        let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(ptr::null_mut(), &raw mut value, 0) },
            NGX_ERROR as _
        );
        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(&raw mut session, ptr::null_mut(), 0) },
            NGX_ERROR as _
        );

        let mut session_storage = [0_u8;
            core::mem::size_of::<ngx_stream_session_t>()
                + core::mem::align_of::<ngx_stream_session_t>()];
        let misaligned_session = misaligned_ptr::<ngx_stream_session_t>(&mut session_storage);
        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(misaligned_session, &raw mut value, 0) },
            NGX_ERROR as _
        );

        let mut value_storage = [0_u8;
            core::mem::size_of::<ngx_variable_value_t>()
                + core::mem::align_of::<ngx_variable_value_t>()];
        let value = misaligned_ptr::<ngx_variable_value_t>(&mut value_storage);
        assert_eq!(
            unsafe { raw_get_handler::<CountingVariable>(&raw mut session, value, 0) },
            NGX_ERROR as _
        );
        assert_eq!(RAW_VARIABLE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn raw_variable_handler_forwards_zero_and_maximum_data() {
        RAW_VARIABLE_DATA.store(1, Ordering::Relaxed);
        let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        assert_eq!(
            unsafe { raw_get_handler::<DataVariable>(&raw mut session, &raw mut value, 0) },
            Status::NGX_DECLINED.0
        );
        assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), 0);

        assert_eq!(
            unsafe {
                raw_get_handler::<DataVariable>(&raw mut session, &raw mut value, usize::MAX)
            },
            Status::NGX_DECLINED.0
        );
        assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn raw_variable_handler_converts_every_supported_status_output() {
        assert_eq!(raw_handler_status::<RawStatusVariable>(), NGX_STREAM_OK as _);
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
    fn successful_getter_without_a_value_publishes_not_found() {
        let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        let mut value = poisoned_value();

        let status = unsafe {
            raw_get_handler::<SuccessfulMissingVariable>(&raw mut session, &raw mut value, 0)
        };

        assert_eq!(status, Status::NGX_OK.0);
        assert_eq!(value.len(), 0);
        assert_eq!(value.valid(), 0);
        assert_eq!(value.no_cacheable(), 1);
        assert_eq!(value.not_found(), 1);
        assert_eq!(value.escape(), 0);
        assert!(value.data.is_null());
    }

    #[test]
    fn failed_getter_preserves_the_native_output() {
        let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        let mut value = poisoned_value();

        let status =
            unsafe { raw_get_handler::<DataVariable>(&raw mut session, &raw mut value, 0) };

        assert_eq!(status, Status::NGX_DECLINED.0);
        assert_eq!(value.len(), 17);
        assert_eq!(value.valid(), 0);
        assert_eq!(value.no_cacheable(), 0);
        assert_eq!(value.not_found(), 1);
        assert_eq!(value.escape(), 1);
        assert_eq!(value.data, NonNull::<u8>::dangling().as_ptr());
    }

    fn assert_found(raw: &ngx_variable_value_t, bytes: &[u8], cacheable: bool, data: *mut u8) {
        assert_eq!(raw.len() as usize, bytes.len());
        assert_eq!(raw.valid(), 1);
        assert_eq!(raw.no_cacheable(), (!cacheable).into());
        assert_eq!(raw.not_found(), 0);
        assert_eq!(raw.escape(), 0);
        assert_eq!(raw.data, data);
        if !bytes.is_empty() {
            assert_eq!(unsafe { core::slice::from_raw_parts(raw.data, raw.len() as usize) }, bytes);
        }
    }

    fn assert_not_found(raw: &ngx_variable_value_t) {
        assert_eq!(raw.len(), 0);
        assert_eq!(raw.valid(), 0);
        assert_eq!(raw.no_cacheable(), 1);
        assert_eq!(raw.not_found(), 1);
        assert_eq!(raw.escape(), 0);
        assert!(raw.data.is_null());
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
    struct VariableGlobalState {
        max_module: ngx_uint_t,
        stream_max_module: ngx_uint_t,
        cacheline_size: ngx_uint_t,
        stream_module_index: ngx_uint_t,
        stream_core_module_type: ngx_uint_t,
        stream_core_module_index: ngx_uint_t,
        stream_core_module_context_index: ngx_uint_t,
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
                    stream_max_module: nginx_sys::ngx_stream_max_module,
                    cacheline_size: nginx_sys::ngx_cacheline_size,
                    stream_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_stream_module)).index,
                    stream_core_module_type: (*core::ptr::addr_of!(
                        nginx_sys::ngx_stream_core_module
                    ))
                    .type_,
                    stream_core_module_index: (*core::ptr::addr_of!(
                        nginx_sys::ngx_stream_core_module
                    ))
                    .index,
                    stream_core_module_context_index: (*core::ptr::addr_of!(
                        nginx_sys::ngx_stream_core_module
                    ))
                    .ctx_index,
                }
            };

            unsafe {
                nginx_sys::ngx_max_module = 1;
                nginx_sys::ngx_stream_max_module = 1;
                nginx_sys::ngx_cacheline_size = 64;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_module)).index = 0;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).type_ =
                    NGX_STREAM_MODULE as _;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).index = 0;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).ctx_index = 0;
            }

            Self { _guard: guard, previous }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for VariableGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_max_module = self.previous.max_module;
                nginx_sys::ngx_stream_max_module = self.previous.stream_max_module;
                nginx_sys::ngx_cacheline_size = self.previous.cacheline_size;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_module)).index =
                    self.previous.stream_module_index;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).type_ =
                    self.previous.stream_core_module_type;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).index =
                    self.previous.stream_core_module_index;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).ctx_index =
                    self.previous.stream_core_module_context_index;
            }
        }
    }

    #[cfg(feature = "test-link")]
    struct VariableFixture {
        _globals: VariableGlobals,
        main: Box<ngx_stream_core_main_conf_t>,
        _main_conf: Box<[*mut c_void; 1]>,
        _context: Box<ngx_stream_conf_ctx_t>,
        cf: Box<ngx_conf_t>,
        _pool: TestPool,
    }

    #[cfg(feature = "test-link")]
    impl VariableFixture {
        fn new() -> Self {
            let globals = VariableGlobals::new();
            let mut pool = TestPool::new();
            let mut main = Box::new(unsafe {
                MaybeUninit::<ngx_stream_core_main_conf_t>::zeroed().assume_init()
            });
            main.variables_hash_max_size = 1024;
            main.variables_hash_bucket_size = 64;
            let mut main_conf: Box<[*mut c_void; 1]> = Box::new([(&raw mut *main).cast()]);
            let mut context = Box::new(ngx_stream_conf_ctx_t {
                main_conf: main_conf.as_mut_ptr(),
                srv_conf: ptr::null_mut(),
            });
            let mut cf = Box::new(unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() });
            cf.pool = pool.raw;
            cf.temp_pool = pool.raw;
            cf.log = &raw mut *pool._log;
            cf.ctx = (&raw mut *context).cast();
            assert_eq!(unsafe { ngx_stream_variables_add_core_vars(&raw mut *cf) }, NGX_OK as _);

            Self {
                _globals: globals,
                main,
                _main_conf: main_conf,
                _context: context,
                cf,
                _pool: pool,
            }
        }

        fn configuration(&mut self) -> StreamConfigurationParser<'_> {
            StreamConfigurationParser::from_test_callback(&mut self.cf)
        }

        fn finalize_variables(&mut self) {
            assert_eq!(unsafe { ngx_stream_variables_init_vars(&raw mut *self.cf) }, NGX_OK as _);
        }

        fn exact_variables(&self) -> &[ngx_hash_key_t] {
            let variables_keys = self.main.variables_keys;
            assert!(!variables_keys.is_null());
            array_values(unsafe { &(*variables_keys).keys })
        }

        fn prefix_variables(&self) -> &[ngx_stream_variable_t] {
            array_values(&self.main.prefix_variables)
        }

        fn exact_variable(&self, name: &[u8]) -> &ngx_stream_variable_t {
            let key = self.exact_variables().iter().find(|key| key.key.as_bytes() == name).unwrap();
            assert!(!key.value.is_null());
            unsafe { &*key.value.cast() }
        }

        fn prefix_variable(&self, name: &[u8]) -> &ngx_stream_variable_t {
            self.prefix_variables()
                .iter()
                .find(|variable| variable.name.as_bytes() == name)
                .unwrap()
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
    fn same_handler(left: ngx_stream_get_variable_pt, right: ngx_stream_get_variable_pt) -> bool {
        match (left, right) {
            (Some(left), Some(right)) => core::ptr::fn_addr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }

    #[cfg(feature = "test-link")]
    fn assert_handler<H>(variable: &ngx_stream_variable_t, data: usize)
    where
        H: StreamVariableHandler,
    {
        assert!(same_handler(variable.get_handler, Some(raw_get_handler::<H>)));
        assert_eq!(variable.data, data);
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
            value: &mut StreamVariableOutput<'_>,
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
        assert_found(&raw_value, b"detected", true, b"detected".as_ptr().cast_mut());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn add_variable_supports_every_public_flag_and_preserves_name_bytes() {
        let mut fixture = VariableFixture::new();
        let cases: [(&[u8], &[u8], StreamVariableFlags, usize); 5] = [
            (b"ngx_rs_changeable", b"ngx_rs_changeable", StreamVariableFlags::CHANGEABLE, 0),
            (
                b"ngx_rs_nocacheable",
                b"ngx_rs_nocacheable",
                StreamVariableFlags::NOCACHEABLE,
                usize::MAX,
            ),
            (b"ngx_rs_nohash", b"ngx_rs_nohash", StreamVariableFlags::NOHASH, 8),
            (b"ngx_rs_weak", b"ngx_rs_weak", StreamVariableFlags::WEAK, 16),
            (
                b"NgX_Rs_\xFF",
                b"ngx_rs_\xFF",
                StreamVariableFlags::NOCACHEABLE | StreamVariableFlags::NOHASH,
                42,
            ),
        ];

        for (name, lower_name, flags, data) in cases {
            add_variable::<CountingVariable>(
                &mut fixture.configuration(),
                NgxStr::from_bytes(name),
                flags,
                data,
            )
            .unwrap();
            let variable = fixture.exact_variable(lower_name);
            assert_eq!(variable.flags, flags.bits());
            assert_handler::<CountingVariable>(variable, data);
        }

        let prefix_flags = StreamVariableFlags::PREFIX | StreamVariableFlags::CHANGEABLE;
        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_PrEfIx_"),
            prefix_flags,
            32,
        )
        .unwrap();
        let prefix = fixture.prefix_variable(b"ngx_rs_prefix_");
        assert_eq!(prefix.flags, prefix_flags.bits());
        assert_handler::<CountingVariable>(prefix, 32);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn add_variable_preserves_registration_order() {
        let mut fixture = VariableFixture::new();
        let names: [&[u8]; 3] = [b"ngx_rs_order_one", b"ngx_rs_order_two", b"ngx_rs_order_three"];

        for (index, name) in names.iter().enumerate() {
            add_variable::<CountingVariable>(
                &mut fixture.configuration(),
                NgxStr::from_bytes(name),
                StreamVariableFlags::empty(),
                index,
            )
            .unwrap();
        }

        let mut positions = [usize::MAX; 3];
        for (index, key) in fixture.exact_variables().iter().enumerate() {
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
            &mut fixture.configuration(),
            NgxStr::from_bytes(name),
            StreamVariableFlags::empty(),
            0,
        )
        .unwrap();
        let before = fixture.exact_variable(name);
        let before_handler = before.get_handler;
        let before_flags = before.flags;
        let before_data = before.data;
        let exact_count = fixture.exact_variables().len();
        let prefix_count = fixture.prefix_variables().len();

        assert!(
            add_variable::<DataVariable>(
                &mut fixture.configuration(),
                NgxStr::from_bytes(b"NgX_Rs_ReJeCtEd"),
                StreamVariableFlags::empty(),
                usize::MAX,
            )
            .is_err()
        );
        let after = fixture.exact_variable(name);
        assert!(same_handler(before_handler, after.get_handler));
        assert_eq!(after.flags, before_flags);
        assert_eq!(after.data, before_data);
        assert_eq!(fixture.exact_variables().len(), exact_count);
        assert_eq!(fixture.prefix_variables().len(), prefix_count);

        assert!(
            add_variable::<DataVariable>(
                &mut fixture.configuration(),
                NgxStr::from_bytes(b""),
                StreamVariableFlags::empty(),
                1,
            )
            .is_err()
        );
        assert_eq!(fixture.exact_variables().len(), exact_count);
        assert_eq!(fixture.prefix_variables().len(), prefix_count);

        let internal = StreamVariableFlags::from_bits_retain(NGX_STREAM_VAR_INDEXED as _);
        assert!(
            add_variable::<DataVariable>(
                &mut fixture.configuration(),
                NgxStr::from_bytes(b"ngx_rs_internal"),
                internal,
                2,
            )
            .is_err()
        );
        let unknown = StreamVariableFlags::from_bits_retain(1_usize << (usize::BITS - 1));
        assert!(
            add_variable::<DataVariable>(
                &mut fixture.configuration(),
                NgxStr::from_bytes(b"ngx_rs_unknown"),
                unknown,
                3,
            )
            .is_err()
        );
        assert_eq!(fixture.exact_variables().len(), exact_count);
        assert_eq!(fixture.prefix_variables().len(), prefix_count);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn allocation_failure_does_not_publish_a_variable_handler() {
        let mut fixture = VariableFixture::new();
        let exact_count = fixture.exact_variables().len();
        let prefix_count = fixture.prefix_variables().len();

        unsafe {
            (*fixture._pool.raw).max = 0;
            ngx_rs_test_fail_allocations_after(0);
        }
        let result = add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_allocation_failure"),
            StreamVariableFlags::empty(),
            1,
        );
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert!(result.is_err());
        assert_eq!(fixture.exact_variables().len(), exact_count);
        assert_eq!(fixture.prefix_variables().len(), prefix_count);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn prefix_name_allocation_failure_does_not_publish_a_partial_entry() {
        let mut fixture = VariableFixture::new();
        let prefix_count = fixture.prefix_variables().len();

        unsafe {
            (*fixture._pool.raw).max = 0;
            ngx_rs_test_fail_allocations_after(0);
        }
        let result = add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_prefix_allocation_failure_"),
            StreamVariableFlags::PREFIX,
            1,
        );
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert!(result.is_err());
        assert_eq!(fixture.prefix_variables().len(), prefix_count);

        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_prefix_allocation_failure_"),
            StreamVariableFlags::PREFIX,
            2,
        )
        .unwrap();
        assert_eq!(fixture.prefix_variables().len(), prefix_count + 1);
        assert_handler::<CountingVariable>(
            fixture.prefix_variable(b"ngx_rs_prefix_allocation_failure_"),
            2,
        );
        fixture.finalize_variables();
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn add_variable_keeps_nginx_duplicate_changeable_and_weak_rules() {
        let mut fixture = VariableFixture::new();
        let exact_name = b"ngx_rs_changeable_weak";
        let weak_flags = StreamVariableFlags::CHANGEABLE | StreamVariableFlags::WEAK;

        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(exact_name),
            weak_flags,
            1,
        )
        .unwrap();
        let variable = fixture.exact_variable(exact_name);
        assert_eq!(variable.flags, weak_flags.bits());
        assert_handler::<CountingVariable>(variable, 1);

        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_ChAnGeAbLe_WeAk"),
            weak_flags,
            2,
        )
        .unwrap();
        let variable = fixture.exact_variable(exact_name);
        assert_eq!(variable.flags, weak_flags.bits());
        assert_handler::<DataVariable>(variable, 2);

        add_variable::<TestVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(exact_name),
            StreamVariableFlags::CHANGEABLE,
            usize::MAX,
        )
        .unwrap();
        let variable = fixture.exact_variable(exact_name);
        assert_eq!(variable.flags, StreamVariableFlags::CHANGEABLE.bits());
        assert_handler::<TestVariable>(variable, usize::MAX);

        let prefix_name = b"ngx_rs_prefix_weak_";
        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(prefix_name),
            weak_flags | StreamVariableFlags::PREFIX,
            4,
        )
        .unwrap();
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_PrEfIx_WeAk_"),
            StreamVariableFlags::CHANGEABLE | StreamVariableFlags::PREFIX,
            5,
        )
        .unwrap();
        let prefix = fixture.prefix_variable(prefix_name);
        assert_eq!(
            prefix.flags,
            (StreamVariableFlags::CHANGEABLE | StreamVariableFlags::PREFIX).bits()
        );
        assert_handler::<DataVariable>(prefix, 5);
    }

    #[test]
    fn static_values_replace_every_output_field_on_success() {
        static CACHED: &[u8] = b"cached";
        static UNCACHED: &[u8] = b"uncached";

        let mut raw = poisoned_value();
        let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        output.set_static(CACHED).unwrap();
        output.publish_success();
        assert_found(&raw, CACHED, true, CACHED.as_ptr().cast_mut());

        let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        output.set_static_uncached(UNCACHED).unwrap();
        output.publish_success();
        assert_found(&raw, UNCACHED, false, UNCACHED.as_ptr().cast_mut());
    }

    #[test]
    fn empty_and_not_found_values_replace_every_output_field_on_success() {
        let mut raw = poisoned_value();
        let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        output.set_empty();
        output.publish_success();
        assert_found(&raw, b"", true, ptr::null_mut());

        let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        output.set_empty_uncached();
        output.publish_success();
        assert_found(&raw, b"", false, ptr::null_mut());

        let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        output.set_not_found();
        output.publish_success();
        assert_not_found(&raw);
    }

    #[test]
    fn setter_errors_preserve_the_previous_candidate() {
        let mut raw = poisoned_value();
        let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        let data = NonNull::<u8>::dangling().as_ptr();

        output.set_found(StreamVariableOutput::MAX_LEN, data, true).unwrap();
        assert_eq!(raw.len(), 17);
        assert_eq!(
            output.set_found(StreamVariableOutput::MAX_LEN + 1, data, true),
            Err(StreamVariableOutputError::TooLong)
        );
        assert_eq!(
            output.set_found(1, ptr::null_mut(), false),
            Err(StreamVariableOutputError::NullData)
        );

        output.publish_success();
        assert_eq!(raw.len() as usize, StreamVariableOutput::MAX_LEN);
        assert_eq!(raw.data, data);
        assert_eq!(raw.valid(), 1);
        assert_eq!(raw.no_cacheable(), 0);
        assert_eq!(raw.not_found(), 0);
        assert_eq!(raw.escape(), 0);
    }

    #[test]
    fn successful_publication_initializes_uninitialized_storage() {
        let mut raw = MaybeUninit::<ngx_variable_value_t>::uninit();
        let mut output = unsafe { StreamVariableOutput::from_raw(raw.as_mut_ptr()) }.unwrap();

        output.set_empty();
        output.publish_success();

        let raw = unsafe { raw.assume_init() };
        assert_found(&raw, b"", true, ptr::null_mut());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn session_pool_values_replace_every_output_field() {
        let owner = TestPool::new();

        with_session(&owner, |session| {
            let mut raw = poisoned_value();
            let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
            let bytes = StreamVariablePoolBytes::copy_from_session(&*session, b"pool").unwrap();
            let data = bytes.data.as_ptr();
            assert_eq!(bytes.bytes(), b"pool");
            assert_ne!(data, b"pool".as_ptr().cast_mut());

            value.set_pool(&*session, bytes).unwrap();
            value.publish_success();
            assert_found(&raw, b"pool", true, data);

            let bytes =
                StreamVariablePoolBytes::copy_from_session(&*session, b"uncached-pool").unwrap();
            let data = bytes.data.as_ptr();
            let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
            value.set_pool_uncached(&*session, bytes).unwrap();
            value.publish_success();
            assert_found(&raw, b"uncached-pool", false, data);
        });
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn copied_session_values_replace_every_output_field() {
        let owner = TestPool::new();

        with_session(&owner, |session| {
            let mut raw = poisoned_value();
            let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
            let copied = *b"copied";

            value.copy_from_session(&*session, &copied).unwrap();
            value.publish_success();
            assert_ne!(raw.data, copied.as_ptr().cast_mut());
            assert_found(&raw, &copied, true, raw.data);

            let uncached = *b"uncached";
            let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
            value.copy_from_session_uncached(&*session, &uncached).unwrap();
            value.publish_success();
            assert_ne!(raw.data, uncached.as_ptr().cast_mut());
            assert_found(&raw, &uncached, false, raw.data);

            let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
            value.copy_from_session(&*session, b"").unwrap();
            value.publish_success();
            assert_found(&raw, b"", true, ptr::null_mut());
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
                    let mut value = StreamVariableOutput::from_raw(&raw mut raw).unwrap();
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
                        Err(StreamVariableOutputError::PoolMismatch)
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
            let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
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

            assert_eq!(result, Err(StreamVariableOutputError::Allocation));
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
