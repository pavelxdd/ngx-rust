use crate::core::Status;
use crate::ffi::{NGX_ERROR, ngx_http_request_t, ngx_int_t};
use crate::http::conf::HttpPhase;
use crate::http::status::HTTPStatus;

use context::{cancel_stale_request_contexts, retain_request_for_context_cancellation};

mod view;
pub use view::*;
mod context;
pub use context::*;
mod headers;
pub use headers::*;
mod body;
pub use body::*;
mod temp_file;
pub use temp_file::*;
mod continuation;
pub use continuation::*;
mod method;
pub use method::*;

/// Define a static request handler.
///
/// Handlers are expected to take a single [`RequestRefMut`] argument and return a [`Status`].
#[macro_export]
macro_rules! http_request_handler {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
        ) -> $crate::ffi::ngx_int_t {
            let handler: for<'scope> fn(&mut $crate::http::RequestRefMut<'scope>) -> _ = $handler;
            unsafe { $crate::http::request_callback_status(r, |request| handler(request)) }
        }
    };
}

/// Define a static post subrequest handler.
///
/// Handlers are expected to take a single [`RequestRefMut`] argument and return a [`Status`].
#[macro_export]
macro_rules! http_subrequest_handler {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            data: *mut ::core::ffi::c_void,
            rc: $crate::ffi::ngx_int_t,
        ) -> $crate::ffi::ngx_int_t {
            let handler: for<'scope> fn(
                &mut $crate::http::RequestRefMut<'scope>,
                *mut ::core::ffi::c_void,
                $crate::ffi::ngx_int_t,
            ) -> _ = $handler;
            unsafe {
                $crate::http::request_callback_status(r, |request| handler(request, data, rc))
            }
        }
    };
}

/// Define a static variable setter.
///
/// The set handler allows setting the property referenced by the variable.
/// The set handler expects a [`RequestRefMut`], a mutable
/// [`ngx_variable_value_t`](crate::ffi::ngx_variable_value_t), and a [`usize`].
/// Variables: <https://nginx.org/en/docs/dev/development_guide.html#http_variables>
#[macro_export]
macro_rules! http_variable_set {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            v: *mut $crate::ffi::ngx_variable_value_t,
            data: usize,
        ) {
            let handler: for<'scope> fn(
                &mut $crate::http::RequestRefMut<'scope>,
                *mut $crate::ffi::ngx_variable_value_t,
                usize,
            ) -> _ = $handler;
            let _ = unsafe {
                $crate::http::request_callback_status(r, |request| {
                    handler(request, v, data);
                    $crate::core::Status::NGX_OK
                })
            };
        }
    };
}

/// Define a static variable evaluator.
///
/// The get handler is responsible for evaluating a variable in the context of a specific request.
/// Variable evaluators accept a [`RequestRefMut`] input argument and two output
/// arguments: [`ngx_variable_value_t`](crate::ffi::ngx_variable_value_t) and [`usize`].
/// Variables: <https://nginx.org/en/docs/dev/development_guide.html#http_variables>
#[macro_export]
macro_rules! http_variable_get {
    ( $name: ident, $handler: expr ) => {
        unsafe extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            v: *mut $crate::ffi::ngx_variable_value_t,
            data: usize,
        ) -> $crate::ffi::ngx_int_t {
            let handler: for<'scope> fn(
                &mut $crate::http::RequestRefMut<'scope>,
                *mut $crate::ffi::ngx_variable_value_t,
                usize,
            ) -> _ = $handler;
            unsafe { $crate::http::request_callback_status(r, |request| handler(request, v, data)) }
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
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t;
}

impl<T> IntoHandlerStatus for Option<T>
where
    T: IntoHandlerStatus,
{
    #[inline]
    fn into_handler_status(self, r: &RequestRef<'_>) -> ngx_int_t {
        self.map(|val| val.into_handler_status(r)).unwrap_or(NGX_ERROR as _)
    }
}

impl<T, E> IntoHandlerStatus for Result<T, E>
where
    T: IntoHandlerStatus,
    E: IntoHandlerStatus,
{
    #[inline]
    fn into_handler_status(self, r: &RequestRef<'_>) -> ngx_int_t {
        match self {
            Ok(value) => value.into_handler_status(r),
            Err(error) => error.into_handler_status(r),
        }
    }
}

impl IntoHandlerStatus for ngx_int_t {
    #[inline]
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t {
        self
    }
}

impl IntoHandlerStatus for Status {
    #[inline]
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t {
        self.0
    }
}

impl IntoHandlerStatus for HTTPStatus {
    #[inline]
    fn into_handler_status(self, _r: &RequestRef<'_>) -> ngx_int_t {
        self.0 as _
    }
}

/// Trait for a static request handler.
///
/// A handler must not panic; panics terminate the worker process.
pub trait HttpRequestHandler {
    /// The phase in which the handler is invoked.
    const PHASE: HttpPhase;
    /// The return type of the handler.
    type Output: IntoHandlerStatus;
    /// The handler function.
    fn handler(request: &mut RequestRefMut<'_>) -> Self::Output;
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
    unsafe { request_callback_status(r, |request| H::handler(request)) }
}

/// Runs one HTTP callback with a checked exclusive request view and converts its result to an
/// nginx status. A callback must not panic; panics terminate the worker process.
#[doc(hidden)]
pub unsafe fn request_callback_status<R>(
    request: *mut ngx_http_request_t,
    callback: impl for<'scope> FnOnce(&mut RequestRefMut<'scope>) -> R,
) -> ngx_int_t
where
    R: IntoHandlerStatus,
{
    unsafe {
        RequestRefMut::with_raw(request, |mut request| {
            let Ok(_hold) = retain_request_for_context_cancellation(request.raw) else {
                return NGX_ERROR as _;
            };
            if cancel_stale_request_contexts(request.raw).is_err() {
                return NGX_ERROR as _;
            }
            let result = callback(&mut request);
            let status = result.into_handler_status(&request.view());
            if cancel_stale_request_contexts(request.raw).is_err() {
                return NGX_ERROR as _;
            }
            status
        })
    }
    .unwrap_or(NGX_ERROR as _)
}

#[cfg(all(test, nginx1_29_8))]
#[path = "request/tests.rs"]
mod tests;
