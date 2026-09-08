//! Access to nginx event-loop state.

use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::ffi::{
    NGX_OK, NGX_READ_EVENT, NGX_WRITE_EVENT, ngx_add_timer, ngx_del_timer, ngx_delete_posted_event,
    ngx_event_actions, ngx_event_t, ngx_msec_t, ngx_post_event, ngx_posted_events,
    ngx_posted_next_events,
};
#[cfg(ngx_feature = "stat_stub")]
use crate::ffi::{
    ngx_atomic_t, ngx_stat_accepted, ngx_stat_active, ngx_stat_handled, ngx_stat_reading,
    ngx_stat_requests, ngx_stat_waiting, ngx_stat_writing,
};
mod peer;
pub use peer::*;
mod posted;
pub use posted::{PostedEvent, PostedEventCallback, PostedEventError};
mod timer;
pub use timer::{Timer, TimerCallback, TimerError};
#[cfg(feature = "async")]
mod readiness;
#[cfg(feature = "async")]
pub use readiness::{EventReadiness, Readiness, ReadinessError};

/// Failure returned while validating a native nginx event pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventError {
    /// The event pointer is null.
    NullEvent,
    /// The event pointer does not satisfy `ngx_event_t` alignment.
    MisalignedEvent,
}

/// A selected nginx posted-event queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostedQueue {
    /// The normal posted-event queue.
    Normal,
    /// The next-cycle posted-event queue.
    Next,
}

/// Failure returned by [`notify`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyError {
    /// The selected nginx event module has no cross-thread notification entrypoint.
    Unavailable,
    /// The selected nginx event module rejected the notification.
    Failed,
}

/// Failure returned while unregistering native readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDeleteError {
    /// The selected nginx event module has no delete entrypoint.
    Unavailable,
    /// The selected nginx event module rejected the delete operation.
    Failed,
}

/// Requests that the selected nginx event module invoke a notification handler.
///
/// # Safety
///
/// The selected event module must support notification from the calling thread, `handler` must
/// remain valid until nginx invokes it, and callers selecting different handlers must be
/// serialized according to that module's notification contract.
pub unsafe fn notify(handler: unsafe extern "C" fn(*mut ngx_event_t)) -> Result<(), NotifyError> {
    let Some(notify) = (unsafe { ngx_event_actions.notify }) else {
        return Err(NotifyError::Unavailable);
    };

    if unsafe { notify(Some(handler)) } == NGX_OK as _ { Ok(()) } else { Err(NotifyError::Failed) }
}

/// Exclusive callback-scoped access to an nginx-owned event.
///
/// ```compile_fail
/// use ngx::event::EventRef;
/// use ngx::ffi::ngx_event_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *mut ngx_event_t) {
///     let _ = unsafe { EventRef::with_raw(raw, |event| require_send(event)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::EventRef;
/// use ngx::ffi::ngx_event_t;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// unsafe fn reject(raw: *mut ngx_event_t) {
///     let _ = unsafe { EventRef::with_raw(raw, |event| require_sync(&event)) };
/// }
/// ```
pub struct EventRef<'callback> {
    raw: NonNull<ngx_event_t>,
    _callback: PhantomData<&'callback mut ngx_event_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl EventRef<'_> {
    /// Creates a checked event view from a raw nginx event pointer.
    ///
    /// # Safety
    ///
    /// `event` must point to a live, initialized nginx-owned event that remains exclusively
    /// accessible for `'callback` on its owning nginx event-loop thread.
    ///
    /// ```compile_fail
    /// use ngx::event::EventRef;
    /// use ngx::ffi::ngx_event_t;
    ///
    /// fn construct(raw: *mut ngx_event_t) {
    ///     let _event = EventRef::from_raw(raw);
    /// }
    /// ```
    pub unsafe fn from_raw(event: *mut ngx_event_t) -> Result<Self, EventError> {
        let raw = NonNull::new(event).ok_or(EventError::NullEvent)?;
        if !raw.as_ptr().is_aligned() {
            return Err(EventError::MisalignedEvent);
        }
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with an event view that cannot escape through a safe value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// use ngx::event::EventRef;
    /// use ngx::ffi::ngx_event_t;
    ///
    /// fn escape(raw: *mut ngx_event_t) -> EventRef<'static> {
    ///     unsafe { EventRef::with_raw(raw, |event| event).unwrap() }
    /// }
    /// ```
    pub unsafe fn with_raw<R>(
        event: *mut ngx_event_t,
        f: impl for<'scope> FnOnce(EventRef<'scope>) -> R,
    ) -> Result<R, EventError> {
        let event = unsafe { EventRef::from_raw(event) }?;
        Ok(f(event))
    }

    /// Returns the native event pointer for explicit FFI operations.
    pub fn as_ptr(&self) -> *mut ngx_event_t {
        self.raw.as_ptr()
    }

    /// Returns whether nginx has active readiness registration for this event.
    pub fn is_active(&self) -> bool {
        unsafe { self.raw.as_ref().active() != 0 }
    }

    /// Unregisters active readiness for this event's native direction.
    ///
    /// Returns `false` when the event is already inactive.
    pub fn unregister(&mut self) -> Result<bool, EventDeleteError> {
        if !self.is_active() {
            return Ok(false);
        }

        let kind = if unsafe { self.raw.as_ref().write() } == 0 {
            NGX_READ_EVENT
        } else {
            NGX_WRITE_EVENT
        };
        let delete = (unsafe { ngx_event_actions.del }).ok_or(EventDeleteError::Unavailable)?;
        if unsafe { delete(self.raw.as_ptr(), kind, 0) } != NGX_OK as _ {
            return Err(EventDeleteError::Failed);
        }

        Ok(true)
    }

    /// Returns whether nginx has armed this event in its timer tree.
    pub fn is_timer_set(&self) -> bool {
        unsafe { self.raw.as_ref().timer_set() != 0 }
    }

    /// Returns whether nginx delivered a timer expiry for this event.
    pub fn is_timedout(&self) -> bool {
        unsafe { self.raw.as_ref().timedout() != 0 }
    }

    /// Clears a previously observed timer expiry before a new logical arm.
    pub fn clear_timedout(&mut self) {
        unsafe { self.raw.as_mut().set_timedout(0) }
    }

    /// Arms or updates this event's nginx timer.
    ///
    /// ```compile_fail
    /// use ngx::event::EventRef;
    ///
    /// fn cannot_publish_from_safe_code(event: &mut EventRef<'_>) {
    ///     event.add_timer(1);
    /// }
    /// ```
    ///
    /// # Safety
    ///
    /// The event must remain at a stable, valid address with a live handler, logger, and data until
    /// the timer is deleted and quiesced or its expiry handler returns.
    pub unsafe fn add_timer(&mut self, timeout: ngx_msec_t) {
        unsafe { ngx_add_timer(self.raw.as_ptr(), timeout) }
    }

    /// Deletes this event's timer when it is armed.
    ///
    /// Returns whether a timer was removed.
    pub fn delete_timer(&mut self) -> bool {
        if !self.is_timer_set() {
            return false;
        }
        unsafe { ngx_del_timer(self.raw.as_ptr()) }
        true
    }

    /// Returns whether nginx has posted this event to a queue.
    pub fn is_posted(&self) -> bool {
        unsafe { self.raw.as_ref().posted() != 0 }
    }

    /// Posts this event if it is not already posted.
    ///
    /// ```compile_fail
    /// use ngx::event::{EventRef, PostedQueue};
    ///
    /// fn cannot_publish_from_safe_code(event: &mut EventRef<'_>) {
    ///     event.post(PostedQueue::Normal);
    /// }
    /// ```
    ///
    /// # Safety
    ///
    /// The event must remain at a stable, valid address with a live handler, logger, and data until
    /// it is deleted from the queue and quiesced or its posted handler returns.
    pub unsafe fn post(&mut self, queue: PostedQueue) {
        unsafe {
            let queue = match queue {
                PostedQueue::Normal => &raw mut ngx_posted_events,
                PostedQueue::Next => &raw mut ngx_posted_next_events,
            };
            ngx_post_event(self.raw.as_ptr(), queue);
        }
    }

    /// Deletes this event from its posted queue when it is posted.
    ///
    /// Returns whether a queue entry was removed.
    pub fn delete_posted(&mut self) -> bool {
        if !self.is_posted() {
            return false;
        }
        unsafe { ngx_delete_posted_event(self.raw.as_ptr()) }
        true
    }
}

/// A snapshot of nginx's connection counters.
///
/// Each counter is read independently, so values can change while the snapshot is collected.
#[cfg(ngx_feature = "stat_stub")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct ConnectionStats {
    /// Connections currently in use.
    pub active: u64,
    /// Connections currently reading a request header.
    pub reading: u64,
    /// Connections currently writing a response.
    pub writing: u64,
    /// Connections currently idle in keep-alive.
    pub waiting: u64,
    /// Total accepted connections.
    pub accepted: u64,
    /// Total handled connections.
    pub handled: u64,
    /// Total handled requests.
    pub requests: u64,
}

/// Returns a snapshot of nginx's connection counters.
#[cfg(ngx_feature = "stat_stub")]
pub fn connection_stats() -> ConnectionStats {
    // SAFETY: nginx initializes these pointers to process-lifetime counters before module code can
    // run. The pointers remain valid when nginx moves the counters into shared memory.
    unsafe {
        connection_stats_from_ptrs(
            ngx_stat_active,
            ngx_stat_reading,
            ngx_stat_writing,
            ngx_stat_waiting,
            ngx_stat_accepted,
            ngx_stat_handled,
            ngx_stat_requests,
        )
    }
}

#[cfg(ngx_feature = "stat_stub")]
#[allow(clippy::unnecessary_cast)]
unsafe fn read_counter(counter: *const ngx_atomic_t) -> u64 {
    // SAFETY: the caller guarantees that the counter is valid. Volatile access matches nginx's
    // own reads and is required because other worker processes update the shared counters.
    unsafe { counter.read_volatile() as u64 }
}

#[cfg(ngx_feature = "stat_stub")]
unsafe fn connection_stats_from_ptrs(
    active: *const ngx_atomic_t,
    reading: *const ngx_atomic_t,
    writing: *const ngx_atomic_t,
    waiting: *const ngx_atomic_t,
    accepted: *const ngx_atomic_t,
    handled: *const ngx_atomic_t,
    requests: *const ngx_atomic_t,
) -> ConnectionStats {
    // SAFETY: the caller guarantees that every pointer is valid for a volatile read.
    unsafe {
        ConnectionStats {
            active: read_counter(active),
            reading: read_counter(reading),
            writing: read_counter(writing),
            waiting: read_counter(waiting),
            accepted: read_counter(accepted),
            handled: read_counter(handled),
            requests: read_counter(requests),
        }
    }
}

#[cfg(test)]
mod tests;
