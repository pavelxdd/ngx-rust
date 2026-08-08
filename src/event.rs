//! Access to nginx event-loop state.

use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::ffi::{
    ngx_add_timer, ngx_del_timer, ngx_delete_posted_event, ngx_event_t, ngx_msec_t, ngx_post_event,
    ngx_posted_events, ngx_posted_next_events,
};
#[cfg(ngx_feature = "stat_stub")]
use crate::ffi::{
    ngx_atomic_t, ngx_stat_accepted, ngx_stat_active, ngx_stat_handled, ngx_stat_reading,
    ngx_stat_requests, ngx_stat_waiting, ngx_stat_writing,
};

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
    pub fn add_timer(&mut self, timeout: ngx_msec_t) {
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
    pub fn post(&mut self, queue: PostedQueue) {
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

#[cfg(all(test, ngx_feature = "stat_stub"))]
mod tests {
    use super::*;

    #[test]
    fn connection_stats_map_each_counter() {
        let active: ngx_atomic_t = 7;
        let reading: ngx_atomic_t = 1;
        let writing: ngx_atomic_t = 2;
        let waiting: ngx_atomic_t = 4;
        let accepted: ngx_atomic_t = 100;
        let handled: ngx_atomic_t = 99;
        let requests: ngx_atomic_t = 250;

        let stats = unsafe {
            connection_stats_from_ptrs(
                &raw const active,
                &raw const reading,
                &raw const writing,
                &raw const waiting,
                &raw const accepted,
                &raw const handled,
                &raw const requests,
            )
        };

        assert_eq!(stats.active, 7);
        assert_eq!(stats.reading, 1);
        assert_eq!(stats.writing, 2);
        assert_eq!(stats.waiting, 4);
        assert_eq!(stats.accepted, 100);
        assert_eq!(stats.handled, 99);
        assert_eq!(stats.requests, 250);
    }
}

#[cfg(all(test, feature = "test-link"))]
mod event_tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use core::mem::MaybeUninit;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use super::{EventError, EventRef, PostedQueue};
    use crate::ffi::{
        ngx_current_msec, ngx_cycle_t, ngx_event_move_posted_next, ngx_event_process_posted,
        ngx_event_t, ngx_event_timer_init, ngx_log_t, ngx_posted_events, ngx_posted_next_events,
        ngx_queue_empty, ngx_queue_init, ngx_queue_t,
    };

    static EVENT_GLOBALS: Mutex<()> = Mutex::new(());
    static POSTED_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_POSTED: AtomicUsize = AtomicUsize::new(usize::MAX);

    struct EventGlobals {
        _guard: MutexGuard<'static, ()>,
    }

    impl EventGlobals {
        fn lock() -> Self {
            let guard = EVENT_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            reset_event_globals();
            Self { _guard: guard }
        }
    }

    impl Drop for EventGlobals {
        fn drop(&mut self) {
            reset_event_globals();
        }
    }

    fn reset_event_globals() {
        unsafe {
            assert_eq!(ngx_event_timer_init(ptr::null_mut()), 0);
            ngx_current_msec = 0;
            ngx_queue_init(&raw mut ngx_posted_events);
            ngx_queue_init(&raw mut ngx_posted_next_events);
        }
    }

    fn normal_queue_next() -> *mut ngx_queue_t {
        unsafe { core::ptr::addr_of!(ngx_posted_events).read().next }
    }

    struct TestEvent {
        event: ngx_event_t,
        log: ngx_log_t,
    }

    impl TestEvent {
        fn new() -> Box<Self> {
            let mut event = Box::new(unsafe { MaybeUninit::<Self>::zeroed().assume_init() });
            event.event.log = &raw mut event.log;
            event
        }

        fn raw(&mut self) -> *mut ngx_event_t {
            &raw mut self.event
        }
    }

    struct TestCycle {
        cycle: ngx_cycle_t,
        log: ngx_log_t,
    }

    impl TestCycle {
        fn new() -> Box<Self> {
            let mut cycle = Box::new(unsafe { MaybeUninit::<Self>::zeroed().assume_init() });
            cycle.cycle.log = &raw mut cycle.log;
            cycle
        }

        fn raw(&mut self) -> *mut ngx_cycle_t {
            &raw mut self.cycle
        }
    }

    #[test]
    fn raw_event_construction_rejects_null_and_misaligned_pointers() {
        assert!(matches!(
            unsafe { EventRef::from_raw(ptr::null_mut()) },
            Err(EventError::NullEvent)
        ));

        let misaligned = ptr::without_provenance_mut::<ngx_event_t>(1);
        assert!(matches!(
            unsafe { EventRef::from_raw(misaligned) },
            Err(EventError::MisalignedEvent)
        ));
    }

    #[test]
    fn event_ref_guards_deletion_and_preserves_normal_and_next_queue_semantics() {
        let _globals = EventGlobals::lock();
        let mut event = TestEvent::new();

        unsafe {
            EventRef::with_raw(event.raw(), |mut event| {
                assert!(!event.is_timer_set());
                assert!(!event.delete_timer());
                event.add_timer(5);
                assert!(event.is_timer_set());
                assert!(event.delete_timer());
                assert!(!event.is_timer_set());

                assert!(!event.delete_posted());
                assert!(!event.is_posted());
                event.post(PostedQueue::Normal);
                event.post(PostedQueue::Next);
                assert!(event.is_posted());
            })
            .unwrap();
        }

        unsafe {
            assert_eq!(normal_queue_next(), &raw mut event.event.queue);
            assert!(ngx_queue_empty(&raw const ngx_posted_next_events));
        }

        unsafe {
            EventRef::with_raw(event.raw(), |mut event| {
                assert!(event.delete_posted());
                assert!(!event.is_posted());
                event.post(PostedQueue::Next);
            })
            .unwrap();
        }

        let mut cycle = TestCycle::new();
        unsafe { ngx_event_move_posted_next(cycle.raw()) };
        unsafe {
            assert_eq!(normal_queue_next(), &raw mut event.event.queue);
            assert!(ngx_queue_empty(&raw const ngx_posted_next_events));
        }
        assert_eq!(event.event.ready(), 1);
        assert_eq!(event.event.available, -1);

        unsafe {
            EventRef::with_raw(event.raw(), |mut event| {
                assert!(event.delete_posted());
            })
            .unwrap();
            assert!(ngx_queue_empty(&raw const ngx_posted_events));
        }
    }

    unsafe extern "C" fn repost_once(raw: *mut ngx_event_t) {
        let callback = POSTED_CALLBACKS.fetch_add(1, Ordering::Relaxed);
        let Ok(mut event) = (unsafe { EventRef::from_raw(raw) }) else {
            return;
        };
        CALLBACK_POSTED.store(usize::from(event.is_posted()), Ordering::Relaxed);
        if callback == 0 {
            event.post(PostedQueue::Normal);
        }
    }

    #[test]
    fn posted_dispatcher_clears_posted_before_callback_and_allows_reposting() {
        let _globals = EventGlobals::lock();
        POSTED_CALLBACKS.store(0, Ordering::Relaxed);
        CALLBACK_POSTED.store(usize::MAX, Ordering::Relaxed);

        let mut event = TestEvent::new();
        event.event.handler = Some(repost_once);
        let mut cycle = TestCycle::new();
        unsafe {
            EventRef::with_raw(event.raw(), |mut event| event.post(PostedQueue::Normal)).unwrap();
            ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events);
        }

        assert_eq!(POSTED_CALLBACKS.load(Ordering::Relaxed), 2);
        assert_eq!(CALLBACK_POSTED.load(Ordering::Relaxed), 0);
        assert_eq!(event.event.posted(), 0);
        unsafe { assert!(ngx_queue_empty(&raw const ngx_posted_events)) };
    }

    #[test]
    fn event_ref_clears_timedout_only_when_requested() {
        let mut event = TestEvent::new();
        event.event.set_timedout(1);

        unsafe {
            EventRef::with_raw(event.raw(), |mut event| {
                assert!(event.is_timedout());
                event.clear_timedout();
                assert!(!event.is_timedout());
            })
            .unwrap();
        }
        assert_eq!(event.event.timedout(), 0);
    }
}
