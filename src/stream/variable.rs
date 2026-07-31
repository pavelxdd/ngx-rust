use core::error;
use core::fmt;
use core::ptr::NonNull;

use crate::core::NgxStr;
use crate::ffi::{
    NGX_STREAM_VAR_CHANGEABLE, NGX_STREAM_VAR_NOCACHEABLE, NGX_STREAM_VAR_NOHASH,
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

/// Error returned when a value exceeds nginx's 28-bit variable length field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariableValueTooLong;

impl fmt::Display for VariableValueTooLong {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Stream variable value is too long")
    }
}

impl error::Error for VariableValueTooLong {}

/// Borrowed output value supplied to a Stream variable getter.
#[repr(transparent)]
pub struct StreamVariableValue(ngx_variable_value_t);

impl StreamVariableValue {
    const MAX_LEN: usize = (1 << 28) - 1;

    unsafe fn from_raw<'a>(value: *mut ngx_variable_value_t) -> &'a mut Self {
        unsafe { &mut *value.cast::<Self>() }
    }

    /// Returns the value bytes, or `None` when the variable was not found.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        (self.0.not_found() == 0).then(|| self.0.as_bytes())
    }

    /// Returns whether the getter produced a value.
    pub fn is_valid(&self) -> bool {
        self.0.valid() != 0
    }

    /// Stores bytes whose static lifetime outlives every nginx session.
    ///
    /// ```compile_fail
    /// # use ngx::stream::StreamVariableValue;
    /// # fn set(value: &mut StreamVariableValue, bytes: &[u8]) {
    /// value.set_static(bytes).unwrap();
    /// # }
    /// ```
    pub fn set_static(&mut self, value: &'static [u8]) -> Result<(), VariableValueTooLong> {
        self.set_static_with_cache(value, true)
    }

    /// Stores static bytes and asks nginx to evaluate the getter on every access.
    pub fn set_static_uncached(
        &mut self,
        value: &'static [u8],
    ) -> Result<(), VariableValueTooLong> {
        self.set_static_with_cache(value, false)
    }

    fn set_static_with_cache(
        &mut self,
        value: &'static [u8],
        cacheable: bool,
    ) -> Result<(), VariableValueTooLong> {
        if value.len() > Self::MAX_LEN {
            return Err(VariableValueTooLong);
        }

        self.0.set_len(value.len() as _);
        self.0.set_valid(1);
        self.0.set_no_cacheable((!cacheable).into());
        self.0.set_not_found(0);
        self.0.set_escape(0);
        self.0.data = value.as_ptr().cast_mut();
        Ok(())
    }
}

/// Typed getter for a registered Stream variable.
pub trait StreamVariableHandler {
    /// Getter result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Evaluates the variable for one active session.
    fn get(session: &mut Session, value: &mut StreamVariableValue, data: usize) -> Self::Output;
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
    let session = unsafe { Session::from_ngx_stream_session(session) };
    let value = unsafe { StreamVariableValue::from_raw(value) };
    H::get(session, value, data).into_handler_status(session)
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use super::{StreamVariableHandler, StreamVariableValue, raw_get_handler};
    use crate::core::Status;
    use crate::ffi::{NGX_STREAM_OK, ngx_stream_session_t, ngx_variable_value_t};
    use crate::stream::Session;

    struct TestVariable;

    impl StreamVariableHandler for TestVariable {
        type Output = Status;

        fn get(
            session: &mut Session,
            value: &mut StreamVariableValue,
            data: usize,
        ) -> Self::Output {
            session.as_mut().status = data as _;
            value.set_static(b"detected").unwrap();
            Status::NGX_OK
        }
    }

    #[test]
    fn raw_variable_handler_wraps_the_session_and_value() {
        let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
        let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

        let status = unsafe {
            raw_get_handler::<TestVariable>(&raw mut session, &raw mut value, NGX_STREAM_OK as _)
        };

        assert_eq!(status, Status::NGX_OK.0);
        assert_eq!(session.status, NGX_STREAM_OK as _);
        assert_eq!(value.as_bytes(), b"detected");
        assert_eq!(value.valid(), 1);
        assert_eq!(value.not_found(), 0);
    }

    #[test]
    fn uncached_static_value_requests_reevaluation() {
        let mut raw = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };
        let value = unsafe { StreamVariableValue::from_raw(&raw mut raw) };

        value.set_static_uncached(b"unknown").unwrap();

        assert_eq!(value.as_bytes(), Some(b"unknown".as_slice()));
        assert!(value.is_valid());
        assert_eq!(raw.no_cacheable(), 1);
    }
}
