use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ptr;

use crate::core::{ChainMut, Status};
use crate::ffi::{ngx_conf_t, ngx_cycle_t, ngx_http_request_t, ngx_int_t};
use crate::http::{HttpModule, IntoHandlerStatus, RequestRefMut};

type HeaderFilter = unsafe extern "C" fn(*mut ngx_http_request_t) -> ngx_int_t;
type BodyFilter =
    unsafe extern "C" fn(*mut ngx_http_request_t, *mut crate::ffi::ngx_chain_t) -> ngx_int_t;

/// Failure while installing or invoking an HTTP output-filter pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpFilterError {
    /// The slot contains only one saved callback and cannot be safely reused.
    IncompleteInstallation,
    /// The slot already belongs to the current nginx configuration cycle.
    AlreadyInstalled,
    /// Nginx has no header filter to continue.
    MissingHeaderFilter,
    /// Nginx has no body filter to continue.
    MissingBodyFilter,
    /// The current header filter is this slot's trampoline.
    HeaderSelfRecursion,
    /// The current body filter is this slot's trampoline.
    BodySelfRecursion,
    /// No saved header filter is available for an explicit continuation.
    MissingHeaderNext,
    /// No saved body filter is available for an explicit continuation.
    MissingBodyNext,
}

#[derive(Clone, Copy)]
struct FilterState {
    cycle: *mut ngx_cycle_t,
    header: Option<HeaderFilter>,
    body: Option<BodyFilter>,
}

impl FilterState {
    const fn empty() -> Self {
        Self { cycle: ptr::null_mut(), header: None, body: None }
    }

    fn is_empty(self) -> bool {
        self.cycle.is_null() && self.header.is_none() && self.body.is_none()
    }

    fn is_complete(self) -> bool {
        self.header.is_some() && self.body.is_some()
    }
}

/// Per-module process-image storage for one HTTP header/body filter pair.
///
/// Declare one `static` slot for the module implementing [`HttpFilter`]. Nginx configures the
/// slot before forking workers; request callbacks only read its saved continuation pointers.
pub struct HttpFilterSlot<M> {
    state: UnsafeCell<FilterState>,
    _module: PhantomData<fn() -> M>,
}

// Nginx runs HTTP postconfiguration on one configuration thread before worker processes exist.
// Callback APIs require a non-Send request view, so workers only read the established state.
unsafe impl<M> Sync for HttpFilterSlot<M> {}

impl<M> HttpFilterSlot<M> {
    /// Creates an uninstalled slot for one HTTP module.
    pub const fn new() -> Self {
        Self { state: UnsafeCell::new(FilterState::empty()), _module: PhantomData }
    }
}

impl<M> Default for HttpFilterSlot<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M> HttpFilterSlot<M>
where
    M: HttpFilter,
{
    /// Invokes the header filter captured when this module was installed.
    ///
    /// The caller owns continuation policy. In particular, a delayed request context must ensure
    /// that it calls this method at most once for its terminal pass-through path.
    pub fn call_next_header(
        &self,
        request: &mut RequestRefMut<'_>,
    ) -> Result<ngx_int_t, HttpFilterError> {
        let next =
            unsafe { (*self.state.get()).header }.ok_or(HttpFilterError::MissingHeaderNext)?;
        if ptr::fn_addr_eq(next, header_trampoline::<M>()) {
            return Err(HttpFilterError::HeaderSelfRecursion);
        }

        let request = unsafe { request.as_ptr() };
        Ok(unsafe { next(request) })
    }

    /// Invokes the body filter captured when this module was installed.
    ///
    /// The caller owns continuation policy. In particular, a delayed request context must ensure
    /// that it calls this method at most once for its terminal pass-through path.
    pub fn call_next_body(
        &self,
        request: &mut RequestRefMut<'_>,
        chain: ChainMut<'_>,
    ) -> Result<ngx_int_t, HttpFilterError> {
        let next = unsafe { (*self.state.get()).body }.ok_or(HttpFilterError::MissingBodyNext)?;
        if ptr::fn_addr_eq(next, body_trampoline::<M>()) {
            return Err(HttpFilterError::BodySelfRecursion);
        }

        let request = unsafe { request.as_ptr() };
        Ok(unsafe { next(request, chain.as_ptr()) })
    }

    fn validate_installation(&self, cf: &ngx_conf_t) -> Result<FilterState, HttpFilterError> {
        let state = unsafe { *self.state.get() };
        if !state.is_empty() {
            if !state.is_complete() {
                return Err(HttpFilterError::IncompleteInstallation);
            }
            if ptr::eq(state.cycle, cf.cycle) {
                return Err(HttpFilterError::AlreadyInstalled);
            }
        }

        let header = unsafe { nginx_sys::ngx_http_top_header_filter }
            .ok_or(HttpFilterError::MissingHeaderFilter)?;
        let body = unsafe { nginx_sys::ngx_http_top_body_filter }
            .ok_or(HttpFilterError::MissingBodyFilter)?;
        if ptr::fn_addr_eq(header, header_trampoline::<M>()) {
            return Err(HttpFilterError::HeaderSelfRecursion);
        }
        if ptr::fn_addr_eq(body, body_trampoline::<M>()) {
            return Err(HttpFilterError::BodySelfRecursion);
        }

        Ok(FilterState { cycle: cf.cycle, header: Some(header), body: Some(body) })
    }

    fn install(&self, cf: &ngx_conf_t) -> Result<(), HttpFilterError> {
        let next = self.validate_installation(cf)?;

        unsafe {
            *self.state.get() = next;
            nginx_sys::ngx_http_top_header_filter = Some(header_trampoline::<M>());
            nginx_sys::ngx_http_top_body_filter = Some(body_trampoline::<M>());
        }
        Ok(())
    }
}

/// Defines the header/body callbacks and process-image slot of one HTTP filter module.
///
/// # Safety
///
/// `filter_slot` must return this module's unique static slot. The HTTP module descriptor must use
/// [`filter_postconfiguration`] for its postconfiguration callback so nginx installs both filters
/// after the module's [`HttpModule::postconfigure`] work succeeds.
pub unsafe trait HttpFilter: HttpModule + Sized + 'static {
    /// Header-filter return type.
    type HeaderOutput: IntoHandlerStatus;
    /// Body-filter return type.
    type BodyOutput: IntoHandlerStatus;

    /// Returns this module's permanent header/body filter slot.
    fn filter_slot() -> &'static HttpFilterSlot<Self>;

    /// Handles one HTTP response-header filter invocation.
    fn header_filter(request: &mut RequestRefMut<'_>) -> Self::HeaderOutput;

    /// Handles one HTTP response-body filter invocation.
    ///
    /// ```compile_fail
    /// use ngx::http::RequestRefMut;
    ///
    /// fn escape_request<'callback>(
    ///     request: &'callback mut RequestRefMut<'callback>,
    /// ) -> &'static mut RequestRefMut<'static> {
    ///     request
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::core::ChainMut;
    ///
    /// fn escape_chain<'callback>(chain: ChainMut<'callback>) -> ChainMut<'static> {
    ///     chain
    /// }
    /// ```
    fn body_filter(request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput;
}

/// C-compatible HTTP header-filter trampoline for one [`HttpFilter`] module.
unsafe extern "C" fn header_filter<M>(request: *mut ngx_http_request_t) -> ngx_int_t
where
    M: HttpFilter,
{
    unsafe { crate::http::request_callback_status(request, |request| M::header_filter(request)) }
}

fn header_trampoline<M>() -> HeaderFilter
where
    M: HttpFilter,
{
    header_filter::<M>
}

/// C-compatible HTTP body-filter trampoline for one [`HttpFilter`] module.
unsafe extern "C" fn body_filter<M>(
    request: *mut ngx_http_request_t,
    chain: *mut crate::ffi::ngx_chain_t,
) -> ngx_int_t
where
    M: HttpFilter,
{
    unsafe {
        crate::http::request_callback_status(request, |request| {
            let Ok(chain) = ChainMut::from_raw(chain) else {
                return Status::NGX_ERROR.0;
            };
            M::body_filter(request, chain).into_handler_status(&request.view())
        })
    }
}

fn body_trampoline<M>() -> BodyFilter
where
    M: HttpFilter,
{
    body_filter::<M>
}

/// C-compatible postconfiguration callback for a paired HTTP filter module.
///
/// # Safety
///
/// `cf` must point to the live nginx configuration parser state. Null and misaligned pointers,
/// invalid filter chains, and Rust panics return `NGX_ERROR` without publishing a partial pair.
pub unsafe extern "C" fn filter_postconfiguration<M>(cf: *mut ngx_conf_t) -> ngx_int_t
where
    M: HttpFilter,
{
    crate::http::module::configuration_callback_status(cf, |cf| {
        if M::filter_slot().validate_installation(cf).is_err() {
            return Status::NGX_ERROR.0;
        }

        if M::postconfigure(cf) != Status::NGX_OK.0 {
            return Status::NGX_ERROR.0;
        }

        M::filter_slot().install(cf).map_or(Status::NGX_ERROR.0, |_| Status::NGX_OK.0)
    })
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use core::ffi::c_int;
    use core::mem::MaybeUninit;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::process::Command;
    use std::sync::MutexGuard;

    use super::{
        BodyFilter, HeaderFilter, HttpFilter, HttpFilterError, HttpFilterSlot, body_filter,
        filter_postconfiguration, header_filter,
    };
    use crate::core::{ChainMut, ChainRef, ConnectionError, Status};
    use crate::ffi::{
        NGX_HTTP_MODULE, ngx_buf_t, ngx_chain_t, ngx_conf_t, ngx_connection_t, ngx_cycle_t,
        ngx_http_output_body_filter_pt, ngx_http_output_header_filter_pt, ngx_http_request_t,
        ngx_int_t, ngx_log_t, ngx_module_t,
    };
    use crate::http::{
        HttpModule, RequestContinuationError, RequestError, RequestHold, RequestRefMut,
    };

    static HEADER_FILTER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static BODY_FILTER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NEXT_HEADER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NEXT_BODY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FAILING_HEADER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FAILING_BODY_CALLS: AtomicUsize = AtomicUsize::new(0);

    const RELOAD_TEST_CHILD: &str = "NGX_HTTP_FILTER_RELOAD_TEST_CHILD";

    unsafe extern "C" {
        fn fork() -> c_int;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        fn _exit(status: c_int) -> !;
    }

    unsafe extern "C" fn next_header(_request: *mut ngx_http_request_t) -> ngx_int_t {
        NEXT_HEADER_CALLS.fetch_add(1, Ordering::Relaxed);
        Status::NGX_DECLINED.0
    }

    unsafe extern "C" fn next_body(
        _request: *mut ngx_http_request_t,
        _chain: *mut crate::ffi::ngx_chain_t,
    ) -> ngx_int_t {
        NEXT_BODY_CALLS.fetch_add(1, Ordering::Relaxed);
        Status::NGX_DECLINED.0
    }

    unsafe extern "C" fn failing_header(_request: *mut ngx_http_request_t) -> ngx_int_t {
        FAILING_HEADER_CALLS.fetch_add(1, Ordering::Relaxed);
        Status::NGX_ERROR.0
    }

    unsafe extern "C" fn failing_body(
        _request: *mut ngx_http_request_t,
        _chain: *mut crate::ffi::ngx_chain_t,
    ) -> ngx_int_t {
        FAILING_BODY_CALLS.fetch_add(1, Ordering::Relaxed);
        Status::NGX_ERROR.0
    }

    struct FilterGlobals {
        _guard: MutexGuard<'static, ()>,
        header: ngx_http_output_header_filter_pt,
        body: ngx_http_output_body_filter_pt,
    }

    impl FilterGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let (header, body) = unsafe {
                (nginx_sys::ngx_http_top_header_filter, nginx_sys::ngx_http_top_body_filter)
            };
            unsafe {
                nginx_sys::ngx_http_top_header_filter = Some(next_header);
                nginx_sys::ngx_http_top_body_filter = Some(next_body);
            }
            Self { _guard: guard, header, body }
        }

        fn set(&self, header: Option<HeaderFilter>, body: Option<BodyFilter>) {
            unsafe {
                nginx_sys::ngx_http_top_header_filter = header;
                nginx_sys::ngx_http_top_body_filter = body;
            }
        }
    }

    impl Drop for FilterGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_http_top_header_filter = self.header;
                nginx_sys::ngx_http_top_body_filter = self.body;
            }
        }
    }

    fn module() -> &'static ngx_module_t {
        Box::leak(Box::new(ngx_module_t::default()))
    }

    fn request() -> ngx_http_request_t {
        let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
        request.signature = NGX_HTTP_MODULE as _;
        request
    }

    fn configuration(cycle: &mut ngx_cycle_t) -> ngx_conf_t {
        let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
        configuration.cycle = cycle;
        configuration
    }

    fn top_header(request: &mut ngx_http_request_t) -> ngx_int_t {
        unsafe { nginx_sys::ngx_http_top_header_filter.unwrap()(request) }
    }

    fn top_body(request: &mut ngx_http_request_t, chain: *mut ngx_chain_t) -> ngx_int_t {
        unsafe { nginx_sys::ngx_http_top_body_filter.unwrap()(request, chain) }
    }

    struct PassThroughFilter;

    static PASS_THROUGH_SLOT: HttpFilterSlot<PassThroughFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for PassThroughFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for PassThroughFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &PASS_THROUGH_SLOT
        }

        fn header_filter(request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            HEADER_FILTER_CALLS.fetch_add(1, Ordering::Relaxed);
            PASS_THROUGH_SLOT.call_next_header(request).map(Status).unwrap_or(Status::NGX_ERROR)
        }

        fn body_filter(request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput {
            BODY_FILTER_CALLS.fetch_add(1, Ordering::Relaxed);
            PASS_THROUGH_SLOT
                .call_next_body(request, chain)
                .map(Status)
                .unwrap_or(Status::NGX_ERROR)
        }
    }

    struct ConsumingFilter;

    static CONSUMING_SLOT: HttpFilterSlot<ConsumingFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for ConsumingFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for ConsumingFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &CONSUMING_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_OK
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput {
            let expected = chain
                .iter()
                .map(|buffer| buffer.expect("input buffer").len().expect("input length"))
                .sum::<usize>();
            let mut consumed = 0;
            for buffer in chain.into_iter_mut() {
                let mut buffer = buffer.expect("input buffer");
                let length = buffer.len().expect("input length");
                buffer.consume(length).expect("consume input");
                consumed += length;
            }
            assert_eq!(consumed, expected);
            Status::NGX_DONE
        }
    }

    static NULL_CHAIN_HEADER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NULL_CHAIN_BODY_EMPTY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NULL_CHAIN_BODY_MALFORMED_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct NullChainFilter;

    static NULL_CHAIN_SLOT: HttpFilterSlot<NullChainFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for NullChainFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for NullChainFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &NULL_CHAIN_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            NULL_CHAIN_HEADER_CALLS.fetch_add(1, Ordering::Relaxed);
            Status::NGX_DONE
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput {
            let mut has_data = false;
            for buffer in chain.iter() {
                let buffer = match buffer {
                    Ok(buffer) => buffer,
                    Err(_) => {
                        NULL_CHAIN_BODY_MALFORMED_CALLS.fetch_add(1, Ordering::Relaxed);
                        return Status::NGX_ABORT;
                    }
                };
                match buffer.is_empty() {
                    Ok(true) => {}
                    Ok(false) => has_data = true,
                    Err(_) => {
                        NULL_CHAIN_BODY_MALFORMED_CALLS.fetch_add(1, Ordering::Relaxed);
                        return Status::NGX_ABORT;
                    }
                }
            }

            if has_data {
                Status::NGX_ERROR
            } else {
                NULL_CHAIN_BODY_EMPTY_CALLS.fetch_add(1, Ordering::Relaxed);
                Status::NGX_DONE
            }
        }
    }

    static DELAYED_HEADER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DELAYED_BODY_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct DelayedFilter;

    static DELAYED_SLOT: HttpFilterSlot<DelayedFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for DelayedFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for DelayedFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &DELAYED_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            DELAYED_HEADER_CALLS.fetch_add(1, Ordering::Relaxed);
            Status::NGX_DONE
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            DELAYED_BODY_CALLS.fetch_add(1, Ordering::Relaxed);
            Status::NGX_DONE
        }
    }

    struct ContinuationFilter;

    static CONTINUATION_SLOT: HttpFilterSlot<ContinuationFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for ContinuationFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for ContinuationFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &CONTINUATION_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_DONE
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_DONE
        }
    }

    struct FailingContinuationFilter;

    static FAILING_CONTINUATION_SLOT: HttpFilterSlot<FailingContinuationFilter> =
        HttpFilterSlot::new();

    unsafe impl HttpModule for FailingContinuationFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for FailingContinuationFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &FAILING_CONTINUATION_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_DONE
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_DONE
        }
    }

    struct InvalidContinuationFilter;

    static INVALID_CONTINUATION_SLOT: HttpFilterSlot<InvalidContinuationFilter> =
        HttpFilterSlot::new();

    unsafe impl HttpModule for InvalidContinuationFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for InvalidContinuationFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &INVALID_CONTINUATION_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_DONE
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_DONE
        }
    }

    static HEADER_ORDER: AtomicUsize = AtomicUsize::new(0);
    static BODY_ORDER: AtomicUsize = AtomicUsize::new(0);

    fn record(order: &AtomicUsize, value: usize) {
        order
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current * 10 + value)
            })
            .unwrap();
    }

    unsafe extern "C" fn ordered_header(_request: *mut ngx_http_request_t) -> ngx_int_t {
        record(&HEADER_ORDER, 1);
        Status::NGX_DECLINED.0
    }

    unsafe extern "C" fn ordered_body(
        _request: *mut ngx_http_request_t,
        _chain: *mut ngx_chain_t,
    ) -> ngx_int_t {
        record(&BODY_ORDER, 1);
        Status::NGX_DECLINED.0
    }

    struct FirstFilter;

    static FIRST_SLOT: HttpFilterSlot<FirstFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for FirstFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for FirstFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &FIRST_SLOT
        }

        fn header_filter(request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            record(&HEADER_ORDER, 2);
            FIRST_SLOT.call_next_header(request).map(Status).unwrap_or(Status::NGX_ERROR)
        }

        fn body_filter(request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput {
            record(&BODY_ORDER, 2);
            FIRST_SLOT.call_next_body(request, chain).map(Status).unwrap_or(Status::NGX_ERROR)
        }
    }

    struct SecondFilter;

    static SECOND_SLOT: HttpFilterSlot<SecondFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for SecondFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for SecondFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &SECOND_SLOT
        }

        fn header_filter(request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            record(&HEADER_ORDER, 3);
            SECOND_SLOT.call_next_header(request).map(Status).unwrap_or(Status::NGX_ERROR)
        }

        fn body_filter(request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput {
            record(&BODY_ORDER, 3);
            SECOND_SLOT.call_next_body(request, chain).map(Status).unwrap_or(Status::NGX_ERROR)
        }
    }

    struct RepeatedFilter;

    static REPEATED_SLOT: HttpFilterSlot<RepeatedFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for RepeatedFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for RepeatedFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &REPEATED_SLOT
        }

        fn header_filter(request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            REPEATED_SLOT.call_next_header(request).map(Status).unwrap_or(Status::NGX_ERROR)
        }

        fn body_filter(request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput {
            REPEATED_SLOT.call_next_body(request, chain).map(Status).unwrap_or(Status::NGX_ERROR)
        }
    }

    struct PartialFilter;

    static PARTIAL_SLOT: HttpFilterSlot<PartialFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for PartialFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for PartialFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &PARTIAL_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_OK
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_OK
        }
    }

    struct MissingNextFilter;

    static MISSING_NEXT_SLOT: HttpFilterSlot<MissingNextFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for MissingNextFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for MissingNextFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &MISSING_NEXT_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_OK
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_OK
        }
    }

    struct SelfPointerFilter;

    static SELF_POINTER_SLOT: HttpFilterSlot<SelfPointerFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for SelfPointerFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for SelfPointerFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &SELF_POINTER_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_OK
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_OK
        }
    }

    static FAILED_POSTCONFIGURE_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct FailedPostconfigurationFilter;

    static FAILED_POSTCONFIGURATION_SLOT: HttpFilterSlot<FailedPostconfigurationFilter> =
        HttpFilterSlot::new();

    unsafe impl HttpModule for FailedPostconfigurationFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }

        fn postconfigure(_cf: &mut ngx_conf_t) -> ngx_int_t {
            FAILED_POSTCONFIGURE_CALLS.fetch_add(1, Ordering::Relaxed);
            Status::NGX_ERROR.0
        }
    }

    unsafe impl HttpFilter for FailedPostconfigurationFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &FAILED_POSTCONFIGURATION_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_OK
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_OK
        }
    }

    #[cfg(feature = "std")]
    static PANIC_POSTCONFIGURATION_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "std")]
    struct PanicPostconfigurationFilter;

    #[cfg(feature = "std")]
    static PANIC_POSTCONFIGURATION_SLOT: HttpFilterSlot<PanicPostconfigurationFilter> =
        HttpFilterSlot::new();

    #[cfg(feature = "std")]
    unsafe impl HttpModule for PanicPostconfigurationFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }

        fn postconfigure(_cf: &mut ngx_conf_t) -> ngx_int_t {
            PANIC_POSTCONFIGURATION_CALLS.fetch_add(1, Ordering::Relaxed);
            panic!("postconfiguration panic");
        }
    }

    #[cfg(feature = "std")]
    unsafe impl HttpFilter for PanicPostconfigurationFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &PANIC_POSTCONFIGURATION_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            Status::NGX_OK
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            Status::NGX_OK
        }
    }

    #[cfg(feature = "std")]
    struct PanicFilter;

    #[cfg(feature = "std")]
    static PANIC_SLOT: HttpFilterSlot<PanicFilter> = HttpFilterSlot::new();

    #[cfg(feature = "std")]
    unsafe impl HttpModule for PanicFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    #[cfg(feature = "std")]
    unsafe impl HttpFilter for PanicFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &PANIC_SLOT
        }

        fn header_filter(_request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            panic!("header filter panic");
        }

        fn body_filter(_request: &mut RequestRefMut<'_>, _chain: ChainMut<'_>) -> Self::BodyOutput {
            panic!("body filter panic");
        }
    }

    struct ReloadFilter;

    static RELOAD_SLOT: HttpFilterSlot<ReloadFilter> = HttpFilterSlot::new();

    unsafe impl HttpModule for ReloadFilter {
        fn module() -> &'static ngx_module_t {
            module()
        }
    }

    unsafe impl HttpFilter for ReloadFilter {
        type HeaderOutput = Status;
        type BodyOutput = Status;

        fn filter_slot() -> &'static HttpFilterSlot<Self> {
            &RELOAD_SLOT
        }

        fn header_filter(request: &mut RequestRefMut<'_>) -> Self::HeaderOutput {
            RELOAD_SLOT.call_next_header(request).map(Status).unwrap_or(Status::NGX_ERROR)
        }

        fn body_filter(request: &mut RequestRefMut<'_>, chain: ChainMut<'_>) -> Self::BodyOutput {
            RELOAD_SLOT.call_next_body(request, chain).map(Status).unwrap_or(Status::NGX_ERROR)
        }
    }

    unsafe extern "C" fn old_header(_request: *mut ngx_http_request_t) -> ngx_int_t {
        Status::NGX_DONE.0
    }

    unsafe extern "C" fn old_body(
        _request: *mut ngx_http_request_t,
        _chain: *mut ngx_chain_t,
    ) -> ngx_int_t {
        Status::NGX_ABORT.0
    }

    unsafe extern "C" fn new_header(_request: *mut ngx_http_request_t) -> ngx_int_t {
        Status::NGX_AGAIN.0
    }

    unsafe extern "C" fn new_body(
        _request: *mut ngx_http_request_t,
        _chain: *mut ngx_chain_t,
    ) -> ngx_int_t {
        Status::NGX_BUSY.0
    }

    #[test]
    fn paired_filter_installation_preserves_each_next_callback() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        HEADER_FILTER_CALLS.store(0, Ordering::Relaxed);
        BODY_FILTER_CALLS.store(0, Ordering::Relaxed);
        NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
        NEXT_BODY_CALLS.store(0, Ordering::Relaxed);

        assert_eq!(
            unsafe { filter_postconfiguration::<PassThroughFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let mut request = request();
        let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        assert_eq!(top_header(&mut request), Status::NGX_DECLINED.0);
        assert_eq!(top_body(&mut request, &raw mut chain), Status::NGX_DECLINED.0);
        assert_eq!(HEADER_FILTER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(BODY_FILTER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn body_filter_receives_an_exclusive_chain_it_can_consume() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        assert_eq!(
            unsafe { filter_postconfiguration::<ConsumingFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let mut request = request();
        let mut bytes = *b"body";
        let mut buffer = unsafe { MaybeUninit::<ngx_buf_t>::zeroed().assume_init() };
        buffer.pos = bytes.as_mut_ptr();
        buffer.last = unsafe { bytes.as_mut_ptr().add(bytes.len()) };
        buffer.set_memory(1);
        let mut chain = ngx_chain_t { buf: &raw mut buffer, next: ptr::null_mut() };

        assert_eq!(top_body(&mut request, &raw mut chain), Status::NGX_DONE.0);
        assert_eq!(buffer.pos, buffer.last);
    }

    #[test]
    fn filter_postconfiguration_rejects_invalid_parser_contexts() {
        assert_eq!(
            unsafe { filter_postconfiguration::<PassThroughFilter>(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );

        let misaligned = ptr::without_provenance_mut::<ngx_conf_t>(1);
        assert_eq!(
            unsafe { filter_postconfiguration::<PassThroughFilter>(misaligned) },
            Status::NGX_ERROR.0
        );
    }

    #[test]
    fn body_filter_accepts_null_chain_and_rejects_invalid_callback_inputs() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        NULL_CHAIN_HEADER_CALLS.store(0, Ordering::Relaxed);
        NULL_CHAIN_BODY_EMPTY_CALLS.store(0, Ordering::Relaxed);
        NULL_CHAIN_BODY_MALFORMED_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe { filter_postconfiguration::<NullChainFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        assert_eq!(
            unsafe { nginx_sys::ngx_http_top_header_filter.unwrap()(ptr::null_mut()) },
            Status::NGX_ERROR.0
        );
        assert_eq!(
            unsafe {
                nginx_sys::ngx_http_top_body_filter.unwrap()(ptr::null_mut(), ptr::null_mut())
            },
            Status::NGX_ERROR.0
        );
        let misaligned_request = ptr::without_provenance_mut::<ngx_http_request_t>(1);
        assert_eq!(
            unsafe {
                nginx_sys::ngx_http_top_body_filter.unwrap()(misaligned_request, ptr::null_mut())
            },
            Status::NGX_ERROR.0
        );

        let mut request = request();
        assert_eq!(top_body(&mut request, ptr::null_mut()), Status::NGX_DONE.0);
        assert_eq!(NULL_CHAIN_BODY_EMPTY_CALLS.load(Ordering::Relaxed), 1);

        let mut malformed = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        assert_eq!(top_body(&mut request, &raw mut malformed), Status::NGX_ABORT.0);
        assert_eq!(NULL_CHAIN_BODY_MALFORMED_CALLS.load(Ordering::Relaxed), 1);

        let mut control = unsafe { MaybeUninit::<ngx_buf_t>::zeroed().assume_init() };
        control.set_flush(1);
        let mut malformed_link = ngx_chain_t {
            buf: &raw mut control,
            next: ptr::without_provenance_mut::<ngx_chain_t>(1),
        };
        assert_eq!(top_body(&mut request, &raw mut malformed_link), Status::NGX_ABORT.0);
        assert_eq!(NULL_CHAIN_BODY_MALFORMED_CALLS.load(Ordering::Relaxed), 2);

        assert_eq!(top_header(&mut request), Status::NGX_DONE.0);
        assert_eq!(NULL_CHAIN_HEADER_CALLS.load(Ordering::Relaxed), 1);
        let misaligned_chain = ptr::without_provenance_mut::<ngx_chain_t>(1);
        assert_eq!(top_body(&mut request, misaligned_chain), Status::NGX_ERROR.0);
    }

    #[test]
    fn saved_filters_can_be_called_later_from_a_checked_callback() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        DELAYED_HEADER_CALLS.store(0, Ordering::Relaxed);
        DELAYED_BODY_CALLS.store(0, Ordering::Relaxed);
        NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
        NEXT_BODY_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe { filter_postconfiguration::<DelayedFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let mut request = request();
        let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        assert_eq!(top_header(&mut request), Status::NGX_DONE.0);
        assert_eq!(top_body(&mut request, &raw mut chain), Status::NGX_DONE.0);
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 0);

        let header_status = unsafe {
            RequestRefMut::with_raw(&raw mut request, |mut request| {
                DELAYED_SLOT.call_next_header(&mut request)
            })
        }
        .unwrap()
        .unwrap();
        let body_status = unsafe {
            RequestRefMut::with_raw(&raw mut request, |mut request| {
                let chain = ChainMut::from_raw(&raw mut chain).unwrap();
                DELAYED_SLOT.call_next_body(&mut request, chain)
            })
        }
        .unwrap()
        .unwrap();
        assert_eq!(header_status, Status::NGX_DECLINED.0);
        assert_eq!(body_status, Status::NGX_DECLINED.0);
        assert_eq!(DELAYED_HEADER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(DELAYED_BODY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn terminal_continuation_calls_each_saved_filter_once() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
        NEXT_BODY_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe { filter_postconfiguration::<ContinuationFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let mut raw = request();
        let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
        raw.main = &raw mut raw;
        raw.parent = &raw mut raw;
        raw.connection = &raw mut connection;
        raw.set_count(1);
        let mut hold = None;
        let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };
        request.hold(&mut hold).unwrap();
        let mut continuation = RequestHold::take(&mut hold, request).unwrap();
        let chain = unsafe { ChainMut::from_raw(ptr::null_mut()).unwrap() };

        assert_eq!(continuation.call_next_header(&CONTINUATION_SLOT), Ok(Status::NGX_DECLINED));
        assert_eq!(
            continuation.call_next_header(&CONTINUATION_SLOT),
            Err(RequestContinuationError::HeaderAlreadyContinued)
        );
        assert_eq!(
            continuation.call_next_body(&CONTINUATION_SLOT, chain),
            Ok(Status::NGX_DECLINED)
        );
        let chain = unsafe { ChainMut::from_raw(ptr::null_mut()).unwrap() };
        assert_eq!(
            continuation.call_next_body(&CONTINUATION_SLOT, chain),
            Err(RequestContinuationError::BodyAlreadyContinued)
        );
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn terminal_continuation_does_not_retry_failed_saved_filters() {
        let globals = FilterGlobals::new();
        globals.set(Some(failing_header), Some(failing_body));
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        FAILING_HEADER_CALLS.store(0, Ordering::Relaxed);
        FAILING_BODY_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe {
                filter_postconfiguration::<FailingContinuationFilter>(&raw mut configuration)
            },
            Status::NGX_OK.0
        );

        let mut raw = request();
        let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
        raw.main = &raw mut raw;
        raw.parent = &raw mut raw;
        raw.connection = &raw mut connection;
        raw.set_count(1);
        let mut hold = None;
        let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };
        request.hold(&mut hold).unwrap();
        let mut continuation = RequestHold::take(&mut hold, request).unwrap();
        let chain = unsafe { ChainMut::from_raw(ptr::null_mut()).unwrap() };

        assert_eq!(
            continuation.call_next_header(&FAILING_CONTINUATION_SLOT),
            Ok(Status::NGX_ERROR)
        );
        assert_eq!(
            continuation.call_next_header(&FAILING_CONTINUATION_SLOT),
            Err(RequestContinuationError::HeaderAlreadyContinued)
        );
        assert_eq!(
            continuation.call_next_body(&FAILING_CONTINUATION_SLOT, chain),
            Ok(Status::NGX_ERROR)
        );
        let chain = unsafe { ChainMut::from_raw(ptr::null_mut()).unwrap() };
        assert_eq!(
            continuation.call_next_body(&FAILING_CONTINUATION_SLOT, chain),
            Err(RequestContinuationError::BodyAlreadyContinued)
        );
        assert_eq!(FAILING_HEADER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(FAILING_BODY_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn terminal_continuation_propagates_missing_saved_filters() {
        let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
        let mut raw = request();
        raw.main = &raw mut raw;
        raw.parent = &raw mut raw;
        raw.connection = &raw mut connection;
        raw.set_count(1);
        let mut hold = None;
        let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };
        request.hold(&mut hold).unwrap();
        let mut continuation = RequestHold::take(&mut hold, request).unwrap();
        let chain = unsafe { ChainMut::from_raw(ptr::null_mut()).unwrap() };

        assert_eq!(
            continuation.call_next_header(&MISSING_NEXT_SLOT),
            Err(RequestContinuationError::Filter(HttpFilterError::MissingHeaderNext))
        );
        assert_eq!(
            continuation.call_next_body(&MISSING_NEXT_SLOT, chain),
            Err(RequestContinuationError::Filter(HttpFilterError::MissingBodyNext))
        );
    }

    #[test]
    fn terminal_continuation_rejects_invalid_request_before_saved_filter_call() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
        NEXT_BODY_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe {
                filter_postconfiguration::<InvalidContinuationFilter>(&raw mut configuration)
            },
            Status::NGX_OK.0
        );

        let mut raw = request();
        raw.main = &raw mut raw;
        raw.parent = &raw mut raw;
        raw.set_count(1);
        let mut hold = None;
        let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };
        request.hold(&mut hold).unwrap();
        let mut continuation = RequestHold::take(&mut hold, request).unwrap();
        let chain = unsafe { ChainMut::from_raw(ptr::null_mut()).unwrap() };

        assert_eq!(
            continuation.call_next_header(&INVALID_CONTINUATION_SLOT),
            Err(RequestContinuationError::Request(RequestError::Connection(
                ConnectionError::NullConnection
            )))
        );
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(
            continuation.call_next_body(&INVALID_CONTINUATION_SLOT, chain),
            Err(RequestContinuationError::Request(RequestError::Connection(
                ConnectionError::NullConnection
            )))
        );
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn checked_request_output_calls_current_filters_and_preserves_statuses() {
        let globals = FilterGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
        connection.log = &raw mut log;
        let mut raw = request();
        raw.main = &raw mut raw;
        raw.connection = &raw mut connection;
        let chain = unsafe { ChainRef::from_raw(ptr::null_mut()).unwrap() };
        {
            let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };

            NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
            NEXT_BODY_CALLS.store(0, Ordering::Relaxed);
            assert_eq!(request.send_header(), Ok(Status::NGX_DECLINED));
            assert_eq!(request.output_filter(chain), Ok(Status::NGX_DECLINED));
            assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 1);

            globals.set(Some(failing_header), Some(failing_body));
            assert_eq!(request.send_header(), Ok(Status::NGX_ERROR));
            assert_eq!(request.output_filter(chain), Ok(Status::NGX_ERROR));
        }
        assert_eq!(connection.error(), 1);
    }

    #[test]
    fn terminal_continuation_sends_output_without_consuming_its_hold() {
        let _globals = FilterGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
        connection.log = &raw mut log;
        let mut raw = request();
        raw.main = &raw mut raw;
        raw.connection = &raw mut connection;
        raw.set_count(1);
        let mut hold = None;
        let chain = unsafe { ChainRef::from_raw(ptr::null_mut()).unwrap() };
        let mut request = unsafe { RequestRefMut::from_raw(&raw mut raw).unwrap() };
        request.hold(&mut hold).unwrap();
        let mut continuation = RequestHold::take(&mut hold, request).unwrap();

        NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
        NEXT_BODY_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(continuation.send_header(), Ok(Status::NGX_DECLINED));
        assert_eq!(continuation.output_filter(chain), Ok(Status::NGX_DECLINED));
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(continuation.cancel(), Ok(()));
    }

    #[test]
    fn saved_filter_calls_reject_slots_without_a_published_pair() {
        let mut request = request();
        let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        let (header, body) = unsafe {
            RequestRefMut::with_raw(&raw mut request, |mut request| {
                let header = MISSING_NEXT_SLOT.call_next_header(&mut request);
                let chain = ChainMut::from_raw(&raw mut chain).unwrap();
                let body = MISSING_NEXT_SLOT.call_next_body(&mut request, chain);
                (header, body)
            })
        }
        .unwrap();

        assert_eq!(header, Err(HttpFilterError::MissingHeaderNext));
        assert_eq!(body, Err(HttpFilterError::MissingBodyNext));
    }

    #[test]
    fn independent_filter_pairs_preserve_exact_header_and_body_order() {
        let globals = FilterGlobals::new();
        globals.set(Some(ordered_header), Some(ordered_body));
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        HEADER_ORDER.store(0, Ordering::Relaxed);
        BODY_ORDER.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe { filter_postconfiguration::<FirstFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );
        assert_eq!(
            unsafe { filter_postconfiguration::<SecondFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let mut request = request();
        let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        assert_eq!(top_header(&mut request), Status::NGX_DECLINED.0);
        assert_eq!(top_body(&mut request, &raw mut chain), Status::NGX_DECLINED.0);
        assert_eq!(HEADER_ORDER.load(Ordering::Relaxed), 321);
        assert_eq!(BODY_ORDER.load(Ordering::Relaxed), 321);
    }

    #[test]
    fn repeated_filter_configuration_rejects_self_recursion_without_replacing_next() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
        NEXT_BODY_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe { filter_postconfiguration::<RepeatedFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );
        assert_eq!(
            unsafe { filter_postconfiguration::<RepeatedFilter>(&raw mut configuration) },
            Status::NGX_ERROR.0
        );

        let mut request = request();
        let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        assert_eq!(top_header(&mut request), Status::NGX_DECLINED.0);
        assert_eq!(top_body(&mut request, &raw mut chain), Status::NGX_DECLINED.0);
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn partial_pair_failures_leave_the_slot_unpublished() {
        let globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);

        globals.set(None, Some(next_body));
        assert_eq!(
            unsafe { filter_postconfiguration::<PartialFilter>(&raw mut configuration) },
            Status::NGX_ERROR.0
        );
        assert!(unsafe { nginx_sys::ngx_http_top_header_filter }.is_none());
        assert!(unsafe { nginx_sys::ngx_http_top_body_filter }.is_some());

        globals.set(Some(next_header), None);
        assert_eq!(
            unsafe { filter_postconfiguration::<PartialFilter>(&raw mut configuration) },
            Status::NGX_ERROR.0
        );
        assert!(unsafe { nginx_sys::ngx_http_top_header_filter }.is_some());
        assert!(unsafe { nginx_sys::ngx_http_top_body_filter }.is_none());

        globals.set(Some(next_header), Some(next_body));
        assert_eq!(
            unsafe { filter_postconfiguration::<PartialFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );
    }

    #[test]
    fn existing_self_trampolines_reject_both_pair_halves_before_installing() {
        let globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        let own_header: HeaderFilter = header_filter::<SelfPointerFilter>;
        let own_body: BodyFilter = body_filter::<SelfPointerFilter>;

        globals.set(Some(own_header), Some(next_body));
        assert_eq!(
            unsafe { filter_postconfiguration::<SelfPointerFilter>(&raw mut configuration) },
            Status::NGX_ERROR.0
        );

        globals.set(Some(next_header), Some(own_body));
        assert_eq!(
            unsafe { filter_postconfiguration::<SelfPointerFilter>(&raw mut configuration) },
            Status::NGX_ERROR.0
        );

        globals.set(Some(next_header), Some(next_body));
        assert_eq!(
            unsafe { filter_postconfiguration::<SelfPointerFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );
    }

    #[test]
    fn postconfiguration_failure_does_not_install_either_filter() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        FAILED_POSTCONFIGURE_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe {
                filter_postconfiguration::<FailedPostconfigurationFilter>(&raw mut configuration)
            },
            Status::NGX_ERROR.0
        );
        assert_eq!(FAILED_POSTCONFIGURE_CALLS.load(Ordering::Relaxed), 1);

        let expected_header: HeaderFilter = next_header;
        let expected_body: BodyFilter = next_body;
        assert!(ptr::fn_addr_eq(
            unsafe { nginx_sys::ngx_http_top_header_filter }.unwrap(),
            expected_header
        ));
        assert!(ptr::fn_addr_eq(
            unsafe { nginx_sys::ngx_http_top_body_filter }.unwrap(),
            expected_body
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn postconfiguration_panics_without_installing_either_filter() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        PANIC_POSTCONFIGURATION_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe {
                filter_postconfiguration::<PanicPostconfigurationFilter>(&raw mut configuration)
            },
            Status::NGX_ERROR.0
        );
        assert_eq!(PANIC_POSTCONFIGURATION_CALLS.load(Ordering::Relaxed), 1);

        let expected_header: HeaderFilter = next_header;
        let expected_body: BodyFilter = next_body;
        assert!(ptr::fn_addr_eq(
            unsafe { nginx_sys::ngx_http_top_header_filter }.unwrap(),
            expected_header
        ));
        assert!(ptr::fn_addr_eq(
            unsafe { nginx_sys::ngx_http_top_body_filter }.unwrap(),
            expected_body
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn filter_trampolines_catch_panics_without_calling_the_saved_filters() {
        let _globals = FilterGlobals::new();
        let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut cycle);
        NEXT_HEADER_CALLS.store(0, Ordering::Relaxed);
        NEXT_BODY_CALLS.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe { filter_postconfiguration::<PanicFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let mut request = request();
        let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        assert_eq!(top_header(&mut request), Status::NGX_ERROR.0);
        assert_eq!(top_body(&mut request, &raw mut chain), Status::NGX_ERROR.0);
        assert_eq!(NEXT_HEADER_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(NEXT_BODY_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reconfiguration_replaces_new_worker_state_without_changing_old_worker_state() {
        if std::env::var_os(RELOAD_TEST_CHILD).is_some() {
            reconfiguration_in_isolated_test_process();
            return;
        }

        let executable = std::env::current_exe().expect("test executable");
        let status = Command::new(executable)
            .arg("--exact")
            .arg("http::filter::tests::reconfiguration_replaces_new_worker_state_without_changing_old_worker_state")
            .env(RELOAD_TEST_CHILD, "1")
            .env("RUST_TEST_THREADS", "1")
            .status()
            .expect("spawn isolated reload test");
        assert!(status.success(), "isolated reload test failed: {status}");
    }

    fn reconfiguration_in_isolated_test_process() {
        let globals = FilterGlobals::new();
        globals.set(Some(old_header), Some(old_body));
        let mut old_cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        let mut configuration = configuration(&mut old_cycle);
        assert_eq!(
            unsafe { filter_postconfiguration::<ReloadFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let child = unsafe { fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let mut request = request();
            let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
            let header = top_header(&mut request);
            let body = top_body(&mut request, &raw mut chain);
            unsafe {
                _exit(if header == Status::NGX_DONE.0 && body == Status::NGX_ABORT.0 {
                    0
                } else {
                    1
                });
            }
        }

        let mut new_cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
        configuration.cycle = &raw mut new_cycle;
        globals.set(Some(new_header), Some(new_body));
        assert_eq!(
            unsafe { filter_postconfiguration::<ReloadFilter>(&raw mut configuration) },
            Status::NGX_OK.0
        );

        let mut request = request();
        let mut chain = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        assert_eq!(top_header(&mut request), Status::NGX_AGAIN.0);
        assert_eq!(top_body(&mut request, &raw mut chain), Status::NGX_BUSY.0);
        let mut status = 0;
        assert_eq!(unsafe { waitpid(child, &raw mut status, 0) }, child);
        assert_eq!(status, 0);
    }
}
