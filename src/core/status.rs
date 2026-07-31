use core::ffi::c_char;
use core::fmt;
use core::ptr;

use crate::ffi::*;

/// Status
///
/// Rust native wrapper for NGINX status codes.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub struct Status(pub ngx_int_t);

impl Status {
    /// Is this Status equivalent to NGX_OK?
    pub fn is_ok(&self) -> bool {
        self == &Status::NGX_OK
    }

    /// Converts this status into a result that accepts only [`Status::NGX_OK`].
    ///
    /// Statuses such as [`Status::NGX_AGAIN`], [`Status::NGX_DONE`], and
    /// [`Status::NGX_DECLINED`] can represent normal control flow. Callers that accept them must
    /// handle them before using this method.
    pub fn into_result(self) -> Result<(), Self> {
        if self.is_ok() { Ok(()) } else { Err(self) }
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nginx status {}", self.0)
    }
}

impl core::error::Error for Status {}

impl From<Status> for ngx_int_t {
    fn from(val: Status) -> Self {
        val.0
    }
}

macro_rules! ngx_codes {
    (
        $(
            $(#[$docs:meta])*
            ($konst:ident);
        )+
    ) => {
        impl Status {
        $(
            $(#[$docs])*
            pub const $konst: Status = Status($konst as ngx_int_t);
        )+

        }
    }
}

ngx_codes! {
    /// NGX_OK - Operation succeeded.
    (NGX_OK);
    /// NGX_ERROR - Operation failed.
    (NGX_ERROR);
    /// NGX_AGAIN - Operation incomplete; call the function again.
    (NGX_AGAIN);
    /// NGX_BUSY - Resource is not available.
    (NGX_BUSY);
    /// NGX_DONE - Operation complete or continued elsewhere. Also used as an alternative success code.
    (NGX_DONE);
    /// NGX_DECLINED - Operation rejected, for example, because it is disabled in the configuration.
    /// This is never an error.
    (NGX_DECLINED);
    /// NGX_ABORT - Function was aborted. Also used as an alternative error code.
    (NGX_ABORT);
}

/// An error occurred while parsing and validating configuration.
pub const NGX_CONF_ERROR: *mut c_char = ptr::null_mut::<c_char>().wrapping_offset(-1);
/// Configuration handler succeeded.
pub const NGX_CONF_OK: *mut c_char = ptr::null_mut();

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::string::ToString;

    use super::*;

    fn require_ok(status: Status) -> Result<(), Status> {
        status.into_result()?;
        Ok(())
    }

    #[test]
    fn into_result_accepts_only_ngx_ok() {
        assert_eq!(require_ok(Status::NGX_OK), Ok(()));
        assert_eq!(require_ok(Status::NGX_ERROR), Err(Status::NGX_ERROR));
        assert_eq!(require_ok(Status::NGX_AGAIN), Err(Status::NGX_AGAIN));
        assert_eq!(require_ok(Status::NGX_DONE), Err(Status::NGX_DONE));
        assert_eq!(require_ok(Status::NGX_DECLINED), Err(Status::NGX_DECLINED));
    }

    #[test]
    fn status_implements_error() {
        let error: &dyn core::error::Error = &Status::NGX_ERROR;

        assert_eq!(error.to_string(), "nginx status -1");
    }
}
