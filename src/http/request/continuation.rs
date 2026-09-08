use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::core::*;
#[cfg(feature = "async")]
use crate::event::PostedQueue;
use crate::ffi::*;
use crate::http::{HttpFilter, HttpFilterError, HttpFilterSlot};

use super::context::*;
use super::view::*;

/// Failure while acquiring or consuming a delayed HTTP request hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestHoldError {
    /// The request could not be used for the operation.
    Request(RequestError),
    /// The context already owns a hold for this request.
    AlreadyHeld,
    /// The context does not own a hold.
    Missing,
    /// The hold belongs to another request.
    ForeignRequest,
    /// The main request no longer has a live reference count.
    InactiveMain,
    /// Nginx's reserved 16-bit main-request count range cannot accept another hold.
    CountOverflow,
}

impl From<RequestError> for RequestHoldError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Failure while using a terminal request continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestContinuationError {
    /// The request could not be used for the operation.
    Request(RequestError),
    /// Calling the saved filter failed.
    Filter(HttpFilterError),
    /// Phase resumption could not prepare a valid nginx request state.
    Phase(RequestPhaseResumeError),
    /// The delayed request hold could not create its terminal continuation.
    Hold(RequestHoldError),
    /// The continuation has already completed or been cancelled.
    Consumed,
    /// The status resumes nginx processing without consuming the retained request reference.
    NonConsumingStatus,
    /// The saved header filter has already been called for this continuation.
    HeaderAlreadyContinued,
    /// The saved body filter has already been called for this continuation.
    BodyAlreadyContinued,
    /// A continuation that called a saved filter cannot be restored for a terminal retry.
    FilterAlreadyContinued,
}

impl From<RequestError> for RequestContinuationError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<HttpFilterError> for RequestContinuationError {
    fn from(error: HttpFilterError) -> Self {
        Self::Filter(error)
    }
}

impl From<RequestPhaseResumeError> for RequestContinuationError {
    fn from(error: RequestPhaseResumeError) -> Self {
        Self::Phase(error)
    }
}

impl From<RequestHoldError> for RequestContinuationError {
    fn from(error: RequestHoldError) -> Self {
        Self::Hold(error)
    }
}

/// Failure while resuming HTTP phase processing after an asynchronous callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPhaseResumeError {
    /// The request could not be used for the operation.
    Request(RequestError),
    /// The current phase handler index is invalid.
    NegativePhaseHandler,
    /// Advancing the phase handler would overflow nginx's index type.
    PhaseHandlerOverflow,
}

impl From<RequestError> for RequestPhaseResumeError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// One explicit reference retained by a delayed HTTP request context.
///
/// Store this in the pinned request context that owns the delayed operation. Dropping or cancelling
/// an active hold releases its retained main-request reference. Request-pool cleanup must instead
/// disarm it explicitly because nginx already owns the teardown transition.
#[must_use = "a request hold retains the request until it is transferred, released, or disarmed by cleanup"]
pub struct RequestHold {
    pub(super) request: NonNull<ngx_http_request_t>,
    pub(super) main: NonNull<ngx_http_request_t>,
    pub(super) active: bool,
    pub(super) _not_thread_safe: PhantomData<*mut ()>,
}

/// Exclusive terminal owner for a request hold removed from its context.
///
/// The hold is removed before the owner performs a terminal nginx operation, so reentry cannot
/// resume or finalize the request a second time. Fallible operations borrow this owner and leave it
/// active on error. Dropping an active continuation releases its retained request reference.
#[must_use = "a request continuation retains the request until it completes or is cancelled"]
pub struct RequestContinuation<'callback> {
    request: RequestRefMut<'callback>,
    hold: Option<RequestHold>,
    consumed: bool,
    header_continued: bool,
    body_continued: bool,
}

impl RequestHold {
    /// Removes this hold from its context and grants the only terminal continuation.
    ///
    /// A nonzero main-request count may consist solely of this hold after nginx finalized the
    /// original asynchronous callback. Only terminal finalization can consume that reference;
    /// phase resumption still requires a releasable hold. This consumes the callback-scoped
    /// request borrow so a terminal operation cannot leave a safe request view after nginx may
    /// free the request.
    pub fn take<'callback>(
        hold: &mut Option<Self>,
        request: RequestRefMut<'callback>,
    ) -> Result<RequestContinuation<'callback>, RequestHoldError> {
        let current = hold.as_ref().ok_or(RequestHoldError::Missing)?;
        let main = request.view().main_raw()?;
        if current.request != request.raw || current.main != main {
            return Err(RequestHoldError::ForeignRequest);
        }
        if unsafe { main.as_ref().count() } == 0 {
            return Err(RequestHoldError::InactiveMain);
        }

        let hold = hold.take().ok_or(RequestHoldError::Missing)?;
        Ok(RequestContinuation {
            request,
            hold: Some(hold),
            consumed: false,
            header_continued: false,
            body_continued: false,
        })
    }

    /// Cancels a delayed operation and releases its retained request reference.
    pub fn cancel(hold: &mut Option<Self>) -> bool {
        hold.take().is_some()
    }

    #[cfg(feature = "async")]
    pub(crate) fn request_ptr(hold: &Option<Self>) -> Option<NonNull<ngx_http_request_t>> {
        hold.as_ref().map(|hold| hold.request)
    }

    /// Disarms a hold while nginx is already tearing down its request pool.
    ///
    /// # Safety
    ///
    /// The caller must be running from request-pool cleanup after nginx made every terminal
    /// continuation impossible and assumed ownership of request reference-count teardown. Calling
    /// this during normal request processing leaks the retained reference.
    pub unsafe fn disarm_for_cleanup(hold: &mut Option<Self>) -> bool {
        let Some(mut hold) = hold.take() else {
            return false;
        };
        hold.active = false;
        true
    }

    fn release(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        release_request_reference(self.request, self.main);
    }

    #[cfg(feature = "async")]
    pub(crate) fn resume_phase(
        hold: &mut Option<Self>,
        posted_request: &mut ngx_http_posted_request_t,
    ) -> Result<(), RequestContinuationError> {
        let request = hold.as_ref().ok_or(RequestHoldError::Missing)?.request;
        let request = unsafe { RequestRefMut::from_raw(request.as_ptr()) }?;
        let mut continuation = Self::take(hold, request)?;
        match continuation.resume_phase(posted_request) {
            Ok(()) => Ok(()),
            Err(error) => {
                continuation.restore_hold(hold);
                Err(error)
            }
        }
    }
}

impl Drop for RequestHold {
    fn drop(&mut self) {
        self.release();
    }
}

impl RequestContinuation<'_> {
    fn ensure_active(&self) -> Result<(), RequestContinuationError> {
        if self.consumed {
            return Err(RequestContinuationError::Consumed);
        }

        Ok(())
    }

    fn ensure_releasable_hold(&self) -> Result<(), RequestHoldError> {
        let hold = self.hold.as_ref().expect("active continuation owns its request hold");
        if unsafe { hold.main.as_ref().count() } <= 1 {
            return Err(RequestHoldError::InactiveMain);
        }

        Ok(())
    }

    fn release_for_resume(&mut self) {
        let mut hold = self.hold.take().expect("active continuation owns its request hold");
        let mut main = hold.main;
        let count = unsafe { main.as_ref().count() };
        debug_assert!(count > 1);
        unsafe { main.as_mut().set_count(count - 1) };
        hold.active = false;
        self.consumed = true;
    }

    fn transfer_to_nginx(&mut self) {
        let mut hold = self.hold.take().expect("active continuation owns its request hold");
        hold.active = false;
        self.consumed = true;
    }

    fn restore_hold(&mut self, slot: &mut Option<RequestHold>) {
        debug_assert!(slot.is_none());
        *slot = self.hold.take();
        self.consumed = true;
    }

    /// Restores this active continuation to an empty request-hold slot.
    ///
    /// Use this only when a fallible terminal operation returned before transferring ownership to
    /// nginx. The restored hold can then be retried or cancelled through its original owner.
    /// Rejection returns the still-active continuation to the caller.
    pub fn restore(
        mut self,
        slot: &mut Option<RequestHold>,
    ) -> Result<(), (RequestContinuationError, Self)> {
        if let Err(error) = self.ensure_active() {
            return Err((error, self));
        }
        if self.header_continued || self.body_continued {
            return Err((RequestContinuationError::FilterAlreadyContinued, self));
        }
        if slot.is_some() {
            return Err((RequestHoldError::AlreadyHeld.into(), self));
        }
        self.restore_hold(slot);
        Ok(())
    }

    /// Cancels this terminal owner and releases its retained request reference.
    pub fn cancel(&mut self) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.consumed = true;
        self.hold.take();
        Ok(())
    }

    /// Sends this response header while the continuation remains active.
    pub fn send_header(&mut self) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        self.request.send_header().map_err(Into::into)
    }

    /// Transfers this request-pool-owned response chain while the continuation remains active.
    pub fn output_filter(
        &mut self,
        chain: PoolChain<'_>,
    ) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        self.request.output_filter(chain).map_err(Into::into)
    }

    /// Calls the saved header filter once for this delayed terminal path.
    ///
    /// This keeps the continuation active so the caller can pass the terminal status to
    /// [`finalize_after_output`](Self::finalize_after_output) after the complete filter sequence.
    pub fn call_next_header<M: HttpFilter>(
        &mut self,
        filters: &HttpFilterSlot<M>,
    ) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        if self.header_continued {
            return Err(RequestContinuationError::HeaderAlreadyContinued);
        }

        self.request.validate_terminal_operation()?;
        let status = filters.call_next_header(&mut self.request)?;
        self.header_continued = true;
        Ok(Status(status))
    }

    /// Calls the saved body filter once for this delayed terminal path.
    ///
    /// This keeps the continuation active so the caller can pass the terminal status to
    /// [`finalize_after_output`](Self::finalize_after_output) after the complete filter sequence.
    pub fn call_next_body<M: HttpFilter>(
        &mut self,
        filters: &HttpFilterSlot<M>,
        chain: ChainMut<'_>,
    ) -> Result<Status, RequestContinuationError> {
        self.ensure_active()?;
        if self.body_continued {
            return Err(RequestContinuationError::BodyAlreadyContinued);
        }

        self.request.validate_terminal_operation()?;
        let status = filters.call_next_body(&mut self.request, chain)?;
        self.body_continued = true;
        Ok(Status(status))
    }

    /// Finalizes the request and transfers the retained reference to nginx.
    ///
    /// Validation errors leave this continuation active for retry or explicit cancellation.
    /// `NGX_DECLINED` is rejected because nginx resumes phases without consuming the reference.
    pub fn finalize(&mut self, status: impl Into<Status>) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.request.validate_terminal_operation()?;
        let status = status.into();
        if status.0 == NGX_DECLINED as _ {
            return Err(RequestContinuationError::NonConsumingStatus);
        }
        self.transfer_to_nginx();
        unsafe { ngx_http_finalize_request(self.request.raw.as_ptr(), status.0) };
        Ok(())
    }

    /// Finalizes after an output or saved-filter call has transferred buffered work to nginx.
    ///
    /// When an ordinary processing reference remains, the retained reference is released before
    /// finalization so nginx's writer can consume that ordinary reference after `NGX_AGAIN`. For
    /// the final subrequest, nginx consumes one reference while waking its parent, so a count of
    /// two still requires transferring the hold to keep the parent writer live. If the hold is the
    /// request's only live reference, ownership is transferred for the same reason. Validation
    /// errors leave this continuation active for retry or explicit cancellation. `NGX_DECLINED`
    /// is rejected because it resumes phases.
    pub fn finalize_after_output(
        &mut self,
        status: impl Into<Status>,
    ) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.request.validate_terminal_operation()?;
        let status = status.into();
        if status.0 == NGX_DECLINED as _ {
            return Err(RequestContinuationError::NonConsumingStatus);
        }
        let hold = self.hold.as_ref().expect("active continuation owns its request hold");
        let count = unsafe { hold.main.as_ref().count() };
        let final_subrequest = hold.request != hold.main && count == 2;
        if count > 1 && !final_subrequest {
            self.release_for_resume();
        } else {
            self.transfer_to_nginx();
        }
        unsafe { ngx_http_finalize_request(self.request.raw.as_ptr(), status.0) };
        Ok(())
    }

    /// Resumes nginx processing with `NGX_DECLINED` after releasing the retained reference.
    ///
    /// Validation errors leave this continuation active for retry or explicit cancellation.
    pub fn resume_declined(&mut self) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.ensure_releasable_hold()?;
        self.request.validate_terminal_operation()?;
        self.release_for_resume();
        unsafe { ngx_http_finalize_request(self.request.raw.as_ptr(), NGX_DECLINED as _) };
        Ok(())
    }

    /// Resumes PREACCESS processing and releases the retained reference before entering nginx.
    ///
    /// Validation errors leave this continuation active for retry or explicit cancellation.
    pub fn resume_preaccess(&mut self) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.ensure_releasable_hold()?;
        self.request.prepare_preaccess_resume()?;
        self.release_for_resume();
        unsafe { ngx_http_core_run_phases(self.request.raw.as_ptr()) };
        Ok(())
    }

    #[cfg(feature = "async")]
    fn resume_phase(
        &mut self,
        posted_request: &mut ngx_http_posted_request_t,
    ) -> Result<(), RequestContinuationError> {
        self.ensure_active()?;
        self.ensure_releasable_hold()?;
        {
            let request = &mut self.request;
            let hold = self.hold.as_mut().expect("active continuation owns its request hold");
            request.validate_terminal_operation()?;
            if unsafe { request.raw.as_ref().phase_handler } < 0 {
                return Err(RequestPhaseResumeError::NegativePhaseHandler.into());
            }
            let original_handler = unsafe { request.raw.as_ref().write_event_handler };
            unsafe { request.raw.as_mut().write_event_handler = Some(ngx_http_core_run_phases) };
            let request_raw = request.raw.as_ptr();
            let request_is_current = unsafe {
                let connection = request.raw.as_ref().connection;
                (*connection).data == request_raw.cast()
            };
            let posted: Result<(), RequestError> = (|| {
                let mut connection = request.connection_mut()?;
                let mut event = connection.write_event()?;
                if !request_is_current
                    && unsafe { ngx_http_post_request(request_raw, posted_request) } != NGX_OK as _
                {
                    return Err(RequestError::Allocation);
                }

                let mut main = hold.main;
                let count = unsafe { main.as_ref().count() };
                debug_assert!(count > 1);
                unsafe { main.as_mut().set_count(count - 1) };
                hold.active = false;
                // SAFETY: nginx owns the connection write event through next-cycle dispatch; the
                // request is current or was queued before releasing its hold.
                unsafe { event.post(PostedQueue::Next) };
                Ok(())
            })();
            if let Err(error) = posted {
                unsafe { request.raw.as_mut().write_event_handler = original_handler };
                return Err(error.into());
            }
        }
        self.hold.take();
        self.consumed = true;
        Ok(())
    }
}

impl<'callback> RequestRefMut<'callback> {
    /// Retains the main request while a context delays its terminal HTTP operation.
    ///
    /// `hold` must be the one slot in the pinned request context that owns this delayed path.
    /// Call this only after nginx reports that work will continue asynchronously; synchronous
    /// completion leaves `hold` empty. The hold is installed only when the main request count can
    /// be incremented without consuming nginx's reserved lifecycle range.
    ///
    /// # Safety
    ///
    /// `hold` must belong to pinned request-owned state whose pool cleanup calls
    /// [`RequestHold::disarm_for_cleanup`] before that state or the native request is destroyed.
    pub unsafe fn hold(&mut self, hold: &mut Option<RequestHold>) -> Result<(), RequestHoldError> {
        if hold.is_some() {
            return Err(RequestHoldError::AlreadyHeld);
        }

        let mut main = self.view().main_raw()?;
        let count = unsafe { main.as_ref().count() };
        if count == 0 {
            return Err(RequestHoldError::InactiveMain);
        }
        if count >= MAX_REQUEST_COUNT_AFTER_HOLD {
            return Err(RequestHoldError::CountOverflow);
        }

        unsafe { main.as_mut().set_count(count + 1) };
        *hold = Some(RequestHold {
            request: self.raw,
            main,
            active: true,
            _not_thread_safe: PhantomData,
        });
        Ok(())
    }

    /// Finalizes this request with an explicit nginx status.
    ///
    /// This consumes the request because nginx can invalidate it synchronously.
    ///
    /// ```compile_fail
    /// use ngx::http::{HTTPStatus, RequestRefMut};
    ///
    /// fn finalize_then_use(request: RequestRefMut<'_>) {
    ///     let _ = request.finalize(HTTPStatus::BAD_REQUEST);
    ///     let _ = request.is_main();
    /// }
    /// ```
    pub fn finalize(self, status: impl Into<Status>) -> Result<(), RequestError> {
        self.validate_terminal_operation()?;
        let status = status.into();
        unsafe { ngx_http_finalize_request(self.raw.as_ptr(), status.0) };
        Ok(())
    }

    /// Advances a PREACCESS handler after its asynchronous callback completes.
    ///
    /// This consumes the request because running phases can finalize it synchronously.
    pub fn resume_preaccess(mut self) -> Result<(), RequestPhaseResumeError> {
        self.prepare_preaccess_resume()?;
        unsafe { ngx_http_core_run_phases(self.raw.as_ptr()) };
        Ok(())
    }

    /// Performs an internal redirect to a location.
    pub fn internal_redirect(&mut self, location: &str) -> Result<Status, RequestError> {
        if location.is_empty() {
            return Ok(Status::NGX_ERROR);
        }
        let Some(mut uri) = (unsafe { ngx_str_t::from_str(self.pool()?.as_ptr(), location) })
        else {
            return Err(RequestError::Allocation);
        };

        let _hold = retain_request_for_context_cancellation(self.raw)?;
        let generation = request_context_generation(self.raw);
        advance_request_generation(self.raw);
        let status = if location.starts_with('@') {
            unsafe { ngx_http_named_location(self.raw.as_ptr(), &raw mut uri) }
        } else {
            unsafe { ngx_http_internal_redirect(self.raw.as_ptr(), &raw mut uri, ptr::null_mut()) }
        };
        cancel_request_context_generation(generation);
        Ok(Status(status))
    }

    pub(super) fn validate_terminal_operation(&self) -> Result<(), RequestError> {
        self.view().main_raw()?;
        self.connection()?;
        Ok(())
    }

    pub(super) fn prepare_preaccess_resume(&mut self) -> Result<(), RequestPhaseResumeError> {
        self.validate_terminal_operation()?;
        let phase_handler = unsafe { self.raw.as_ref().phase_handler };
        if phase_handler < 0 {
            return Err(RequestPhaseResumeError::NegativePhaseHandler);
        }
        let phase_handler =
            phase_handler.checked_add(1).ok_or(RequestPhaseResumeError::PhaseHandlerOverflow)?;

        let request = unsafe { self.raw.as_mut() };
        request.write_event_handler = Some(ngx_http_core_run_phases);
        request.phase_handler = phase_handler;
        Ok(())
    }
}
