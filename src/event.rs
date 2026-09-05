//! Access to nginx event-loop state.

use core::marker::{PhantomData, PhantomPinned};
use core::mem;
use core::pin::Pin;
use core::ptr::{self, NonNull};

use crate::allocator::AllocError;
use crate::core::{Pool, PoolValue};
use crate::ffi::{
    NGX_OK, NGX_READ_EVENT, NGX_WRITE_EVENT, ngx_add_timer, ngx_connection_t, ngx_del_timer,
    ngx_delete_posted_event, ngx_event_actions, ngx_event_t, ngx_msec_t, ngx_post_event,
    ngx_posted_events, ngx_posted_next_events,
};
#[cfg(ngx_feature = "stat_stub")]
use crate::ffi::{
    ngx_atomic_t, ngx_stat_accepted, ngx_stat_active, ngx_stat_handled, ngx_stat_reading,
    ngx_stat_requests, ngx_stat_waiting, ngx_stat_writing,
};
use crate::log::LogRef;
use crate::ngx_container_of;

mod peer;
pub use peer::*;
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

#[repr(transparent)]
struct TimerDebugIdentity(ngx_connection_t);

// SAFETY: Rust and nginx only read this fully initialized identity through Timer::event.data.
unsafe impl Sync for TimerDebugIdentity {}

static TIMER_IDENT: TimerDebugIdentity = {
    let mut connection = unsafe { mem::zeroed::<ngx_connection_t>() };
    connection.fd = -1;
    TimerDebugIdentity(connection)
};
static POSTED_EVENT_IDENT: [usize; 1] = [0];

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

/// Failure returned while arming a [`Timer`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerError {
    /// The timer is already armed and must be explicitly rearmed or canceled first.
    AlreadyArmed,
}

/// Pinned owner of an nginx timer and its callback state.
///
/// ```compile_fail
/// use ngx::event::Timer;
/// use ngx::log::LogRef;
///
/// fn cannot_arm_from_safe_code(log: LogRef<'_>) {
///     let mut timer = Box::pin(Timer::new(log, (), |_| {}));
///     timer.as_mut().arm(1).unwrap();
/// }
/// ```
///
/// A timer must be pinned before it can be armed. Rust-owned timers are canceled by [`Drop`]; use
/// [`allocate_in_pool`](Self::allocate_in_pool) for a pool-owned timer so its cleanup is registered
/// before the timer can be armed.
///
/// ```compile_fail
/// use core::pin::Pin;
/// use ngx::event::Timer;
/// use ngx::log::LogRef;
///
/// fn cannot_move_after_arming(log: LogRef<'_>) {
///     let mut timer = Box::pin(Timer::new(log, (), |_| {}));
///     timer.as_mut().arm(1).unwrap();
///     let _timer = Pin::into_inner(timer);
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::Timer;
/// use ngx::log::LogRef;
///
/// fn cannot_retain_callback_state(log: LogRef<'_>) {
///     let mut escaped: Option<&mut u8> = None;
///     let _timer = Timer::new(log, 0_u8, |mut timer| {
///         escaped = Some(timer.state_mut());
///     });
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::{Timer, TimerCallback};
/// use ngx::log::LogRef;
///
/// type Callback = for<'callback> fn(TimerCallback<'callback, ()>);
///
/// fn callback(_: TimerCallback<'_, ()>) {}
///
/// fn cannot_outlive_logger<'log>(log: LogRef<'log>) -> Timer<'static, (), Callback> {
///     Timer::new(log, (), callback as Callback)
/// }
/// ```
pub struct Timer<'log, T, F> {
    event: ngx_event_t,
    state: mem::ManuallyDrop<T>,
    callback: mem::ManuallyDrop<F>,
    callback_alive: *mut bool,
    _log: PhantomData<LogRef<'log>>,
    _pin: PhantomPinned,
    _not_thread_safe: PhantomData<*mut ()>,
}

/// Callback-scoped access to a timer's state and event controls.
///
/// A value is created for each timer callback and cannot safely outlive that callback.
pub struct TimerCallback<'callback, T> {
    control: &'callback mut TimerCallbackControl,
    state: &'callback mut T,
}

struct TimerCallbackControl {
    armed: bool,
    timed_out: bool,
    cancelable: bool,
    action: TimerCallbackAction,
}

enum TimerCallbackAction {
    None,
    Cancel,
    Rearm(ngx_msec_t),
}

impl<'log, T, F> Timer<'log, T, F>
where
    F: for<'callback> FnMut(TimerCallback<'callback, T>),
{
    /// Creates an unarmed timer with the supplied state and callback.
    ///
    /// The returned timer must be pinned before calling [`arm`](Self::arm), [`rearm`](Self::rearm),
    /// or [`cancel`](Self::cancel).
    pub fn new(log: LogRef<'log>, state: T, callback: F) -> Self {
        let mut event = unsafe { mem::zeroed::<ngx_event_t>() };
        event.data = (&raw const TIMER_IDENT.0).cast_mut().cast();
        event.handler = Some(timer_handler::<T, F>);
        event.log = log.as_ptr();

        Self {
            event,
            state: mem::ManuallyDrop::new(state),
            callback: mem::ManuallyDrop::new(callback),
            callback_alive: ptr::null_mut(),
            _log: PhantomData,
            _pin: PhantomPinned,
            _not_thread_safe: PhantomData,
        }
    }

    /// Returns the timer state outside a callback without mutable access.
    pub fn state(&self) -> &T {
        &self.state
    }

    /// Returns whether nginx has armed this timer.
    pub fn is_armed(&self) -> bool {
        self.event.timer_set() != 0
    }

    /// Returns whether nginx has delivered an expiry that has not yet been observed.
    pub fn is_timed_out(&self) -> bool {
        self.event.timedout() != 0
    }

    /// Returns whether nginx may cancel this timer during graceful worker shutdown.
    pub fn is_cancelable(&self) -> bool {
        self.event.cancelable() != 0
    }

    /// Arms an unarmed timer.
    ///
    /// Returns [`TimerError::AlreadyArmed`] instead of applying nginx's lazy timer update. Use
    /// [`rearm`](Self::rearm) to replace an existing timeout deliberately.
    ///
    /// # Safety
    ///
    /// This must run on the initialized nginx event-loop thread that owns the timer tree.
    pub unsafe fn arm(mut self: Pin<&mut Self>, timeout: ngx_msec_t) -> Result<(), TimerError> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        if this.event.timer_set() != 0 {
            return Err(TimerError::AlreadyArmed);
        }

        this.event.set_timedout(0);
        unsafe { ngx_add_timer(&raw mut this.event, timeout) };
        Ok(())
    }

    /// Replaces the current timeout, if any, with a fresh timeout.
    ///
    /// # Safety
    ///
    /// This must run on the initialized nginx event-loop thread that owns the timer tree.
    pub unsafe fn rearm(mut self: Pin<&mut Self>, timeout: ngx_msec_t) {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        if this.event.timer_set() != 0 {
            unsafe { ngx_del_timer(&raw mut this.event) };
        }

        this.event.set_timedout(0);
        unsafe { ngx_add_timer(&raw mut this.event, timeout) };
    }

    /// Cancels the timer when it is armed.
    ///
    /// Returns whether a timeout was removed. Repeated cancellation is harmless.
    pub fn cancel(mut self: Pin<&mut Self>) -> bool {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        if this.event.timer_set() == 0 {
            return false;
        }

        unsafe { ngx_del_timer(&raw mut this.event) };
        true
    }

    /// Marks whether nginx may cancel this timer during graceful worker shutdown.
    pub fn set_cancelable(mut self: Pin<&mut Self>, cancelable: bool) {
        unsafe {
            self.as_mut().get_unchecked_mut().event.set_cancelable(u32::from(cancelable));
        }
    }

    /// Observes and clears a delivered timer expiry.
    pub fn take_timeout(mut self: Pin<&mut Self>) -> bool {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        if this.event.timedout() == 0 {
            return false;
        }

        this.event.set_timedout(0);
        true
    }
}

impl<T, F> Timer<'static, T, F>
where
    T: 'static,
    F: for<'callback> FnMut(TimerCallback<'callback, T>) + 'static,
{
    /// Allocates a pinned timer in an nginx pool and registers its destructor before returning it.
    ///
    /// The returned [`PoolValue`] retains the stable address and pool cleanup. Its timer must be
    /// armed through [`PoolValue::as_pin_mut`].
    ///
    /// # Safety
    ///
    /// `log` must remain live and usable on its owning event-loop thread until the pool destroys
    /// this timer or [`PoolValue::remove`] removes it.
    pub unsafe fn allocate_in_pool<'pool>(
        pool: &Pool<'pool>,
        log: LogRef<'_>,
        state: T,
        callback: F,
    ) -> Result<PoolValue<'pool, Self>, AllocError> {
        let log = unsafe { LogRef::from_raw(log.as_ptr()) }.expect("validated timer logger");
        pool.allocate_with_cleanup(|| Self::new(log, state, callback))
    }
}

impl<T> TimerCallback<'_, T> {
    /// Returns the callback-scoped timer state.
    pub fn state(&self) -> &T {
        self.state
    }

    /// Returns mutable timer state for this callback only.
    pub fn state_mut(&mut self) -> &mut T {
        self.state
    }

    /// Returns whether nginx has armed this timer.
    pub fn is_armed(&self) -> bool {
        self.control.armed
    }

    /// Returns whether nginx has delivered this timer expiry.
    pub fn is_timed_out(&self) -> bool {
        self.control.timed_out
    }

    /// Observes and clears a delivered timer expiry.
    pub fn take_timeout(&mut self) -> bool {
        if !self.control.timed_out {
            return false;
        }

        self.control.timed_out = false;
        true
    }

    /// Replaces the current timeout, if any, with a fresh timeout.
    pub fn rearm(&mut self, timeout: ngx_msec_t) {
        self.control.armed = true;
        self.control.timed_out = false;
        self.control.action = TimerCallbackAction::Rearm(timeout);
    }

    /// Cancels the timer when it is armed.
    ///
    /// Returns whether a timeout was removed. Repeated cancellation is harmless.
    pub fn cancel(&mut self) -> bool {
        if !self.control.armed {
            return false;
        }

        self.control.armed = false;
        self.control.action = TimerCallbackAction::Cancel;
        true
    }

    /// Returns whether nginx may cancel this timer during graceful worker shutdown.
    pub fn is_cancelable(&self) -> bool {
        self.control.cancelable
    }

    /// Marks whether nginx may cancel this timer during graceful worker shutdown.
    pub fn set_cancelable(&mut self, cancelable: bool) {
        self.control.cancelable = cancelable;
    }
}

unsafe extern "C" fn timer_handler<T, F>(raw: *mut ngx_event_t)
where
    F: for<'callback> FnMut(TimerCallback<'callback, T>),
{
    let Ok(event) = (unsafe { EventRef::from_raw(raw) }) else {
        return;
    };
    let timer = ngx_container_of!(event.as_ptr(), Timer<'_, T, F>, event);
    let mut control = TimerCallbackControl {
        armed: event.is_timer_set(),
        timed_out: event.is_timedout(),
        cancelable: unsafe { event.raw.as_ref().cancelable() != 0 },
        action: TimerCallbackAction::None,
    };

    // Keep callback-owned values outside the allocation so reentrant Drop cannot invalidate them.
    let mut alive = true;
    unsafe { (*timer).callback_alive = &raw mut alive };
    let mut callback = unsafe { ptr::read(&raw const (*timer).callback) };
    let mut state = unsafe { ptr::read(&raw const (*timer).state) };

    (*callback)(TimerCallback { control: &mut control, state: &mut state });

    if !alive {
        unsafe {
            mem::ManuallyDrop::drop(&mut state);
            mem::ManuallyDrop::drop(&mut callback);
        }
        return;
    }

    let timer = unsafe { &mut *timer };
    timer.callback_alive = ptr::null_mut();
    unsafe {
        ptr::write(&raw mut timer.callback, callback);
        ptr::write(&raw mut timer.state, state);
    }
    timer.event.set_timedout(u32::from(control.timed_out));
    timer.event.set_cancelable(u32::from(control.cancelable));
    match control.action {
        TimerCallbackAction::None => {}
        TimerCallbackAction::Cancel => {
            if timer.event.timer_set() != 0 {
                unsafe { ngx_del_timer(&raw mut timer.event) };
            }
        }
        TimerCallbackAction::Rearm(timeout) => {
            if timer.event.timer_set() != 0 {
                unsafe { ngx_del_timer(&raw mut timer.event) };
            }
            unsafe { ngx_add_timer(&raw mut timer.event, timeout) };
        }
    }
}

impl<T, F> Drop for Timer<'_, T, F> {
    fn drop(&mut self) {
        if !self.callback_alive.is_null() {
            // The active handler owns the moved state and callback until it returns.
            unsafe { *self.callback_alive = false };
            if self.event.timer_set() != 0 {
                unsafe { ngx_del_timer(&raw mut self.event) };
            }
            return;
        }

        if self.event.timer_set() != 0 {
            unsafe { ngx_del_timer(&raw mut self.event) };
        }
        unsafe {
            mem::ManuallyDrop::drop(&mut self.state);
            mem::ManuallyDrop::drop(&mut self.callback);
        }
    }
}

/// Failure returned while posting a [`PostedEvent`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostedEventError {
    /// The event has been shut down and cannot be posted again.
    Shutdown,
}

/// Pinned owner of an nginx posted event and its callback state.
///
/// ```compile_fail
/// use ngx::event::{PostedEvent, PostedQueue};
/// use ngx::log::LogRef;
///
/// fn cannot_post_from_safe_code(log: LogRef<'_>) {
///     let mut event = Box::pin(PostedEvent::new(log, (), |_| {}));
///     event.as_mut().post(PostedQueue::Normal).unwrap();
/// }
/// ```
///
/// A posted event must be pinned before it can be posted, canceled, or shut down. Rust-owned
/// events are canceled by [`Drop`]; use [`allocate_in_pool`](Self::allocate_in_pool) for a
/// pool-owned event so its cleanup is registered before it can be posted.
///
/// ```compile_fail
/// use core::pin::Pin;
/// use ngx::event::{PostedEvent, PostedQueue};
/// use ngx::log::LogRef;
///
/// fn cannot_move_after_post(log: LogRef<'_>) {
///     let mut event = Box::pin(PostedEvent::new(log, (), |_| {}));
///     event.as_mut().post(PostedQueue::Normal).unwrap();
///     let _event = Pin::into_inner(event);
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::PostedEvent;
/// use ngx::log::LogRef;
///
/// fn cannot_retain_callback_state(log: LogRef<'_>) {
///     let mut escaped: Option<&mut u8> = None;
///     let _event = PostedEvent::new(log, 0_u8, |mut event| {
///         escaped = Some(event.state_mut());
///     });
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::PostedEvent;
/// use ngx::log::LogRef;
///
/// fn cannot_move_to_another_thread(log: LogRef<'_>) {
///     let event = PostedEvent::new(log, (), |_| {});
///     std::thread::spawn(move || drop(event));
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::{PostedEvent, PostedEventCallback};
/// use ngx::log::LogRef;
///
/// type Callback = for<'callback> fn(PostedEventCallback<'callback, ()>);
///
/// fn callback(_: PostedEventCallback<'_, ()>) {}
///
/// fn cannot_outlive_logger<'log>(
///     log: LogRef<'log>,
/// ) -> PostedEvent<'static, (), Callback> {
///     PostedEvent::new(log, (), callback as Callback)
/// }
/// ```
pub struct PostedEvent<'log, T, F> {
    event: ngx_event_t,
    state: mem::ManuallyDrop<T>,
    callback: mem::ManuallyDrop<F>,
    stopped: bool,
    callback_alive: *mut bool,
    _log: PhantomData<LogRef<'log>>,
    _pin: PhantomPinned,
    _not_thread_safe: PhantomData<*mut ()>,
}

/// Callback-scoped access to a posted event's state and queue controls.
///
/// A value is created for each posted-event callback and cannot safely outlive that callback.
pub struct PostedEventCallback<'callback, T> {
    control: &'callback mut PostedEventCallbackControl,
    state: &'callback mut T,
}

struct PostedEventCallbackControl {
    posted: bool,
    stopped: bool,
    action: PostedEventCallbackAction,
}

enum PostedEventCallbackAction {
    None,
    Cancel,
    Post(PostedQueue),
}

impl<'log, T, F> PostedEvent<'log, T, F>
where
    F: for<'callback> FnMut(PostedEventCallback<'callback, T>),
{
    /// Creates an event that has not been posted or shut down.
    ///
    /// The returned event must be pinned before calling [`post`](Self::post),
    /// [`cancel`](Self::cancel), or [`shutdown`](Self::shutdown).
    pub fn new(log: LogRef<'log>, state: T, callback: F) -> Self {
        let mut event = unsafe { mem::zeroed::<ngx_event_t>() };
        event.data = (&raw const POSTED_EVENT_IDENT).cast_mut().cast();
        event.handler = Some(posted_event_handler::<T, F>);
        event.log = log.as_ptr();

        Self {
            event,
            state: mem::ManuallyDrop::new(state),
            callback: mem::ManuallyDrop::new(callback),
            stopped: false,
            callback_alive: ptr::null_mut(),
            _log: PhantomData,
            _pin: PhantomPinned,
            _not_thread_safe: PhantomData,
        }
    }

    /// Returns the event state outside a callback without mutable access.
    pub fn state(&self) -> &T {
        &self.state
    }

    /// Returns whether nginx has this event on a posted-event queue.
    pub fn is_posted(&self) -> bool {
        self.event.posted() != 0
    }

    /// Returns whether this event has been shut down permanently.
    pub fn is_shutdown(&self) -> bool {
        self.stopped
    }

    /// Posts this event to the selected nginx queue.
    ///
    /// Returns `Ok(false)` when nginx has already queued the event. Foreign threads must use
    /// [`notify`] instead.
    ///
    /// # Safety
    ///
    /// This must run on the initialized nginx event-loop thread that owns the posted queues.
    pub unsafe fn post(
        mut self: Pin<&mut Self>,
        queue: PostedQueue,
    ) -> Result<bool, PostedEventError> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        post_owned_event(&mut this.event, this.stopped, queue)
    }

    /// Removes this event from its posted queue when it is queued.
    ///
    /// Returns whether a queue entry was removed. Repeated cancellation is harmless.
    pub fn cancel(mut self: Pin<&mut Self>) -> bool {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        cancel_owned_event(&mut this.event)
    }

    /// Permanently stops this event and cancels a pending queue entry.
    ///
    /// Returns whether a queue entry was removed. Repeated shutdown is harmless.
    pub fn shutdown(mut self: Pin<&mut Self>) -> bool {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        this.stopped = true;
        cancel_owned_event(&mut this.event)
    }
}

impl<T, F> PostedEvent<'static, T, F>
where
    T: 'static,
    F: for<'callback> FnMut(PostedEventCallback<'callback, T>) + 'static,
{
    /// Allocates a pinned posted event in an nginx pool and registers its destructor first.
    ///
    /// The returned [`PoolValue`] retains the stable address and pool cleanup. Its event is posted
    /// through [`PoolValue::as_pin_mut`].
    ///
    /// # Safety
    ///
    /// `log` must remain live and usable on its owning event-loop thread until the pool destroys
    /// this event or [`PoolValue::remove`] removes it.
    pub unsafe fn allocate_in_pool<'pool>(
        pool: &Pool<'pool>,
        log: LogRef<'_>,
        state: T,
        callback: F,
    ) -> Result<PoolValue<'pool, Self>, AllocError> {
        let log = unsafe { LogRef::from_raw(log.as_ptr()) }.expect("validated event logger");
        pool.allocate_with_cleanup(|| Self::new(log, state, callback))
    }
}

impl<T> PostedEventCallback<'_, T> {
    /// Returns the callback-scoped event state.
    pub fn state(&self) -> &T {
        self.state
    }

    /// Returns mutable event state for this callback only.
    pub fn state_mut(&mut self) -> &mut T {
        self.state
    }

    /// Returns whether nginx has this event on a posted-event queue.
    pub fn is_posted(&self) -> bool {
        self.control.posted
    }

    /// Returns whether this event has been shut down permanently.
    pub fn is_shutdown(&self) -> bool {
        self.control.stopped
    }

    /// Posts this event to the selected nginx queue.
    ///
    /// Returns `Ok(false)` when nginx has already queued the event.
    pub fn post(&mut self, queue: PostedQueue) -> Result<bool, PostedEventError> {
        if self.control.stopped {
            return Err(PostedEventError::Shutdown);
        }
        if self.control.posted {
            return Ok(false);
        }

        self.control.posted = true;
        self.control.action = PostedEventCallbackAction::Post(queue);
        Ok(true)
    }

    /// Removes this event from its posted queue when it is queued.
    ///
    /// Returns whether a queue entry was removed. Repeated cancellation is harmless.
    pub fn cancel(&mut self) -> bool {
        if !self.control.posted {
            return false;
        }

        self.control.posted = false;
        self.control.action = PostedEventCallbackAction::Cancel;
        true
    }

    /// Permanently stops this event and cancels a pending queue entry.
    ///
    /// Returns whether a queue entry was removed. Repeated shutdown is harmless.
    pub fn shutdown(&mut self) -> bool {
        self.control.stopped = true;
        self.cancel()
    }
}

fn post_owned_event(
    event: &mut ngx_event_t,
    stopped: bool,
    queue: PostedQueue,
) -> Result<bool, PostedEventError> {
    if stopped {
        return Err(PostedEventError::Shutdown);
    }
    if event.posted() != 0 {
        return Ok(false);
    }

    unsafe {
        let queue = match queue {
            PostedQueue::Normal => &raw mut ngx_posted_events,
            PostedQueue::Next => &raw mut ngx_posted_next_events,
        };
        ngx_post_event(event, queue);
    }
    Ok(true)
}

fn cancel_owned_event(event: &mut ngx_event_t) -> bool {
    if event.posted() == 0 {
        return false;
    }

    unsafe { ngx_delete_posted_event(event) };
    true
}

unsafe extern "C" fn posted_event_handler<T, F>(raw: *mut ngx_event_t)
where
    F: for<'callback> FnMut(PostedEventCallback<'callback, T>),
{
    let Ok(event) = (unsafe { EventRef::from_raw(raw) }) else {
        return;
    };
    let posted = ngx_container_of!(event.as_ptr(), PostedEvent<'_, T, F>, event);
    let mut control = PostedEventCallbackControl {
        posted: event.is_posted(),
        stopped: unsafe { (*posted).stopped },
        action: PostedEventCallbackAction::None,
    };

    // Keep callback-owned values outside the allocation so reentrant Drop cannot invalidate them.
    let mut alive = true;
    unsafe { (*posted).callback_alive = &raw mut alive };
    let mut callback = unsafe { ptr::read(&raw const (*posted).callback) };
    let mut state = unsafe { ptr::read(&raw const (*posted).state) };

    (*callback)(PostedEventCallback { control: &mut control, state: &mut state });

    if !alive {
        unsafe {
            mem::ManuallyDrop::drop(&mut state);
            mem::ManuallyDrop::drop(&mut callback);
        }
        return;
    }

    let posted = unsafe { &mut *posted };
    posted.callback_alive = ptr::null_mut();
    unsafe {
        ptr::write(&raw mut posted.callback, callback);
        ptr::write(&raw mut posted.state, state);
    }
    posted.stopped = control.stopped;
    match control.action {
        PostedEventCallbackAction::None => {}
        PostedEventCallbackAction::Cancel => {
            cancel_owned_event(&mut posted.event);
        }
        PostedEventCallbackAction::Post(queue) => {
            let _ = post_owned_event(&mut posted.event, posted.stopped, queue);
        }
    }
}

impl<T, F> Drop for PostedEvent<'_, T, F> {
    fn drop(&mut self) {
        if !self.callback_alive.is_null() {
            // The active handler owns the moved state and callback until it returns.
            unsafe { *self.callback_alive = false };
            cancel_owned_event(&mut self.event);
            return;
        }

        cancel_owned_event(&mut self.event);
        unsafe {
            mem::ManuallyDrop::drop(&mut self.state);
            mem::ManuallyDrop::drop(&mut self.callback);
        }
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
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::any::Any;
    use core::cell::{Cell, RefCell, UnsafeCell};
    use core::mem::MaybeUninit;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use super::{
        EventError, EventRef, NotifyError, PostedEvent, PostedEventError, PostedQueue, Timer,
        TimerError, notify,
    };
    use crate::core::{ConnectionRefMut, Pool};
    #[cfg(ngx_feature = "debug")]
    use crate::ffi::NGX_LOG_DEBUG_EVENT;
    use crate::ffi::{
        NGX_AGAIN, NGX_OK, NGX_READ_EVENT, NGX_WRITE_EVENT, ngx_connection_t, ngx_create_pool,
        ngx_current_msec, ngx_cycle_t, ngx_destroy_pool, ngx_event_actions,
        ngx_event_expire_timers, ngx_event_handler_pt, ngx_event_move_posted_next,
        ngx_event_no_timers_left, ngx_event_process_posted, ngx_event_t, ngx_event_timer_init,
        ngx_int_t, ngx_log_t, ngx_msec_int_t, ngx_msec_t, ngx_pool_t, ngx_posted_events,
        ngx_posted_next_events, ngx_queue_empty, ngx_queue_init, ngx_queue_t, ngx_uint_t,
    };
    use crate::log::LogRef;

    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    static EVENT_GLOBALS: Mutex<()> = Mutex::new(());
    static POSTED_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_POSTED: AtomicUsize = AtomicUsize::new(usize::MAX);
    static NOTIFIED_HANDLER: Mutex<ngx_event_handler_pt> = Mutex::new(None);
    static NOTIFICATION_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static EVENT_DELETE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static EVENT_DELETE_KIND: AtomicUsize = AtomicUsize::new(usize::MAX);

    #[cfg(ngx_feature = "debug")]
    struct LogCapture {
        len: usize,
        bytes: [u8; 256],
    }

    #[cfg(ngx_feature = "debug")]
    impl Default for LogCapture {
        fn default() -> Self {
            Self { len: 0, bytes: [0; 256] }
        }
    }

    #[cfg(ngx_feature = "debug")]
    impl LogCapture {
        fn contains(&self, expected: &[u8]) -> bool {
            self.bytes[..self.len].windows(expected.len()).any(|window| window == expected)
        }
    }

    #[cfg(ngx_feature = "debug")]
    unsafe extern "C" fn capture_log(
        log: *mut ngx_log_t,
        _level: ngx_uint_t,
        bytes: *mut u8,
        len: usize,
    ) {
        let Some(log) = (unsafe { log.as_mut() }) else {
            return;
        };
        let Some(capture) = (unsafe { log.wdata.cast::<LogCapture>().as_mut() }) else {
            return;
        };
        if bytes.is_null() {
            return;
        }

        capture.len = len.min(capture.bytes.len());
        unsafe { ptr::copy_nonoverlapping(bytes, capture.bytes.as_mut_ptr(), capture.len) };
    }

    struct EventGlobals {
        _global: MutexGuard<'static, ()>,
        _guard: MutexGuard<'static, ()>,
    }

    struct NotifyOverride {
        previous: Option<unsafe extern "C" fn(ngx_event_handler_pt) -> ngx_int_t>,
    }

    impl NotifyOverride {
        fn install(replacement: unsafe extern "C" fn(ngx_event_handler_pt) -> ngx_int_t) -> Self {
            let previous = unsafe { ngx_event_actions.notify };
            unsafe { ngx_event_actions.notify = Some(replacement) };
            Self { previous }
        }
    }

    impl Drop for NotifyOverride {
        fn drop(&mut self) {
            unsafe { ngx_event_actions.notify = self.previous };
        }
    }

    struct EventDeleteOverride {
        previous:
            Option<unsafe extern "C" fn(*mut ngx_event_t, ngx_int_t, ngx_uint_t) -> ngx_int_t>,
    }

    impl EventDeleteOverride {
        fn install(
            replacement: unsafe extern "C" fn(*mut ngx_event_t, ngx_int_t, ngx_uint_t) -> ngx_int_t,
        ) -> Self {
            let previous = unsafe { ngx_event_actions.del };
            unsafe { ngx_event_actions.del = Some(replacement) };
            Self { previous }
        }
    }

    impl Drop for EventDeleteOverride {
        fn drop(&mut self) {
            unsafe { ngx_event_actions.del = self.previous };
        }
    }

    impl EventGlobals {
        fn lock() -> Self {
            let global =
                crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let guard = EVENT_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            reset_event_globals();
            Self { _global: global, _guard: guard }
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

    fn log_ref(log: &mut ngx_log_t) -> LogRef<'_> {
        unsafe { LogRef::from_raw(log) }.expect("test logger")
    }

    fn static_log_ref() -> LogRef<'static> {
        let log = Box::leak(Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() }));
        unsafe { LogRef::from_raw(log) }.expect("test logger")
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

    struct TestPool {
        raw: *mut ngx_pool_t,
        log: Box<UnsafeCell<ngx_log_t>>,
    }

    impl TestPool {
        fn new() -> Self {
            let log = Box::new(UnsafeCell::new(unsafe {
                MaybeUninit::<ngx_log_t>::zeroed().assume_init()
            }));
            let raw = unsafe { ngx_create_pool(4096, log.get()) };
            assert!(!raw.is_null());
            Self { raw, log }
        }

        fn handle(&self) -> Pool<'_> {
            unsafe { Pool::from_raw(self.raw) }.unwrap()
        }

        fn log(&self) -> LogRef<'_> {
            unsafe { LogRef::from_raw(self.log.get()) }.expect("test pool logger")
        }
    }

    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }

    struct DropState(Rc<Cell<usize>>);

    impl Drop for DropState {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
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

    unsafe extern "C" fn delete_active_event(
        event: *mut ngx_event_t,
        kind: ngx_int_t,
        flags: ngx_uint_t,
    ) -> ngx_int_t {
        assert_eq!(flags, 0);
        EVENT_DELETE_CALLS.fetch_add(1, Ordering::Relaxed);
        EVENT_DELETE_KIND.store(kind as usize, Ordering::Relaxed);
        unsafe { (*event).set_active(0) };
        NGX_OK as _
    }

    #[test]
    fn event_ref_derives_unregister_direction_and_preserves_the_sibling_event() {
        let _globals = EventGlobals::lock();
        let _delete = EventDeleteOverride::install(delete_active_event);
        let mut read = TestEvent::new();
        read.event.set_active(1);
        let mut write = TestEvent::new();
        write.event.set_write(1);
        write.event.set_active(1);
        let mut raw: ngx_connection_t = unsafe { MaybeUninit::zeroed().assume_init() };
        raw.read = read.raw();
        raw.write = write.raw();
        let mut connection = unsafe { ConnectionRefMut::from_raw(&raw mut raw) }.unwrap();

        EVENT_DELETE_CALLS.store(0, Ordering::Relaxed);
        EVENT_DELETE_KIND.store(usize::MAX, Ordering::Relaxed);
        {
            let mut event = connection.read_event().unwrap();
            assert_eq!(event.unregister(), Ok(true));
            assert_eq!(event.unregister(), Ok(false));
        }
        assert_eq!(EVENT_DELETE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(EVENT_DELETE_KIND.load(Ordering::Relaxed), NGX_READ_EVENT as usize);
        assert_eq!(read.event.active(), 0);
        assert_ne!(write.event.active(), 0);

        read.event.set_active(1);
        EVENT_DELETE_CALLS.store(0, Ordering::Relaxed);
        EVENT_DELETE_KIND.store(usize::MAX, Ordering::Relaxed);
        {
            let mut event = connection.write_event().unwrap();
            assert_eq!(event.unregister(), Ok(true));
            assert_eq!(event.unregister(), Ok(false));
        }
        assert_eq!(EVENT_DELETE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(EVENT_DELETE_KIND.load(Ordering::Relaxed), NGX_WRITE_EVENT as usize);
        assert_ne!(read.event.active(), 0);
        assert_eq!(write.event.active(), 0);
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
            // SAFETY: the test retains the event through the immediately following dispatch.
            unsafe { event.post(PostedQueue::Normal) };
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
    fn posted_owner_coalesces_duplicate_posts_and_preserves_fifo_order() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let order = Rc::new(RefCell::new(Vec::new()));
        let first_order = order.clone();
        let second_order = order.clone();
        let mut first = Box::pin(PostedEvent::new(logger, 1_usize, move |event| {
            first_order.borrow_mut().push(*event.state())
        }));
        let mut second = Box::pin(PostedEvent::new(logger, 2_usize, move |event| {
            second_order.borrow_mut().push(*event.state())
        }));
        let first_address = first.as_ref().get_ref() as *const _;

        assert_eq!(unsafe { first.as_mut().post(PostedQueue::Normal) }, Ok(true));
        assert_eq!(unsafe { first.as_mut().post(PostedQueue::Next) }, Ok(false));
        assert_eq!(unsafe { second.as_mut().post(PostedQueue::Normal) }, Ok(true));
        assert_eq!(first.as_ref().get_ref() as *const _, first_address);

        let mut cycle = TestCycle::new();
        unsafe { ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events) };

        assert_eq!(order.borrow().as_slice(), &[1, 2]);
        assert!(!first.is_posted());
        assert!(!second.is_posted());
    }

    #[test]
    fn posted_owner_moves_next_queue_at_the_next_cycle_boundary() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        let mut posted = Box::pin(PostedEvent::new(logger, (), move |_| {
            callback_calls.set(callback_calls.get() + 1);
        }));

        assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Next) }, Ok(true));
        unsafe {
            assert!(ngx_queue_empty(&raw const ngx_posted_events));
            assert!(!ngx_queue_empty(&raw const ngx_posted_next_events));
        }

        let mut cycle = TestCycle::new();
        unsafe {
            ngx_event_move_posted_next(cycle.raw());
            ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events);
        }

        assert_eq!(calls.get(), 1);
        assert!(!posted.is_posted());
    }

    #[test]
    fn posted_owner_cancels_queued_callback_before_dispatch() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        let mut posted = Box::pin(PostedEvent::new(logger, (), move |_| {
            callback_calls.set(callback_calls.get() + 1);
        }));

        assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Normal) }, Ok(true));
        assert!(posted.as_mut().cancel());
        assert!(!posted.as_mut().cancel());

        let mut cycle = TestCycle::new();
        unsafe { ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events) };

        assert_eq!(calls.get(), 0);
        assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Normal) }, Ok(true));
        unsafe { ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events) };
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn posted_owner_callback_can_repost_after_nginx_clears_its_flag() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        let mut posted = Box::pin(PostedEvent::new(logger, 0_usize, move |mut event| {
            assert!(!event.is_posted());
            *event.state_mut() += 1;
            callback_calls.set(callback_calls.get() + 1);
            if *event.state() == 1 {
                assert_eq!(event.post(PostedQueue::Normal), Ok(true));
            }
        }));

        assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Normal) }, Ok(true));
        let mut cycle = TestCycle::new();
        unsafe { ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events) };

        assert_eq!(calls.get(), 2);
        assert_eq!(*posted.state(), 2);
        assert!(!posted.is_posted());
    }

    #[test]
    fn posted_owner_shutdown_cancels_the_queue_and_rejects_new_posts() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        let mut posted = Box::pin(PostedEvent::new(logger, (), move |_| {
            callback_calls.set(callback_calls.get() + 1);
        }));

        assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Next) }, Ok(true));
        assert!(posted.as_mut().shutdown());
        assert!(posted.is_shutdown());
        assert_eq!(
            unsafe { posted.as_mut().post(PostedQueue::Normal) },
            Err(PostedEventError::Shutdown)
        );
        assert!(!posted.as_mut().shutdown());

        let mut cycle = TestCycle::new();
        unsafe {
            ngx_event_move_posted_next(cycle.raw());
            ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events);
        }
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn dropped_posted_owner_cancels_before_destroying_its_state() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));

        {
            let callback_calls = calls.clone();
            let mut posted =
                Box::pin(PostedEvent::new(logger, DropState(drops.clone()), move |_| {
                    callback_calls.set(callback_calls.get() + 1)
                }));
            assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Normal) }, Ok(true));
        }
        assert_eq!(drops.get(), 1);

        let mut cycle = TestCycle::new();
        unsafe { ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events) };
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn posted_callback_can_drop_its_owner_without_invalidating_callback_state() {
        let _globals = EventGlobals::lock();
        let owner_slot: Rc<RefCell<Option<Box<dyn Any>>>> = Rc::new(RefCell::new(None));
        let callback_owner = owner_slot.clone();
        let callback_finished = Rc::new(Cell::new(false));
        let finished = callback_finished.clone();
        let drops = Rc::new(Cell::new(0));
        let mut posted =
            Box::pin(PostedEvent::new(static_log_ref(), DropState(drops.clone()), move |event| {
                assert_eq!(event.state().0.get(), 0);
                drop(callback_owner.borrow_mut().take());
                finished.set(true);
            }));
        let raw = unsafe { &raw mut posted.as_mut().get_unchecked_mut().event };
        let handler = unsafe { (*raw).handler }.expect("posted event handler");
        *owner_slot.borrow_mut() = Some(Box::new(posted));

        unsafe { handler(raw) };

        assert!(owner_slot.borrow().is_none());
        assert!(callback_finished.get());
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn pool_posted_owner_cancels_queued_callback_before_pool_cleanup_drops_state() {
        let _globals = EventGlobals::lock();
        let owner = TestPool::new();
        let calls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));

        {
            let log = owner.log();
            let pool = owner.handle();
            let callback_calls = calls.clone();
            let posted = unsafe {
                PostedEvent::allocate_in_pool(&pool, log, DropState(drops.clone()), move |_| {
                    callback_calls.set(callback_calls.get() + 1)
                })
            }
            .unwrap();
            let address = posted.as_non_null();
            let mut posted = posted;
            assert_eq!(posted.as_non_null(), address);
            assert_eq!(unsafe { posted.as_pin_mut().post(PostedQueue::Next) }, Ok(true));
            assert_eq!(posted.as_non_null(), address);
        }

        drop(owner);
        assert_eq!(drops.get(), 1);

        let mut cycle = TestCycle::new();
        unsafe {
            ngx_event_move_posted_next(cycle.raw());
            ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events);
        }
        assert_eq!(calls.get(), 0);
    }

    unsafe extern "C" fn capture_notification(handler: ngx_event_handler_pt) -> ngx_int_t {
        *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = handler;
        NGX_OK as _
    }

    unsafe extern "C" fn notification_handler(_event: *mut ngx_event_t) {
        NOTIFICATION_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn foreign_thread_handoff_uses_the_selected_event_module_notification() {
        let _globals = EventGlobals::lock();
        NOTIFICATION_CALLBACKS.store(0, Ordering::Relaxed);
        *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = None;
        let _notify = NotifyOverride::install(capture_notification);

        let result = std::thread::spawn(|| unsafe { notify(notification_handler) }).join().unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(NOTIFICATION_CALLBACKS.load(Ordering::Relaxed), 0);

        let handler = NOTIFIED_HANDLER
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("notification handler was not forwarded");
        unsafe { handler(ptr::null_mut()) };
        assert_eq!(NOTIFICATION_CALLBACKS.load(Ordering::Relaxed), 1);

        unsafe { ngx_event_actions.notify = None };
        assert_eq!(unsafe { notify(notification_handler) }, Err(NotifyError::Unavailable));
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

    #[test]
    fn timer_owner_invokes_callback_on_expiry() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        let mut timer = Box::pin(Timer::new(logger, 0_usize, move |mut timer| {
            assert!(timer.is_timed_out());
            assert!(timer.take_timeout());
            assert!(!timer.is_timed_out());
            *timer.state_mut() += 1;
            callback_calls.set(callback_calls.get() + 1);
            if *timer.state() == 1 {
                timer.rearm(5);
            }
        }));

        unsafe { timer.as_mut().arm(5) }.unwrap();
        unsafe {
            ngx_current_msec = 5;
            ngx_event_expire_timers();
        }

        assert_eq!(calls.get(), 1);
        assert_eq!(*timer.state(), 1);
        assert!(timer.is_armed());
        assert!(!timer.is_timed_out());

        unsafe {
            ngx_current_msec = 10;
            ngx_event_expire_timers();
        }

        assert_eq!(calls.get(), 2);
        assert_eq!(*timer.state(), 2);
        assert!(!timer.is_armed());
        assert!(!timer.is_timed_out());
    }

    #[test]
    fn timer_exposes_explicit_arm_cancelable_and_cancel_states() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let mut timer = Box::pin(Timer::new(logger, (), |_| {}));

        assert!(!timer.is_armed());
        assert!(!timer.is_timed_out());
        assert!(!timer.is_cancelable());

        timer.as_mut().set_cancelable(true);
        assert!(timer.is_cancelable());
        unsafe { timer.as_mut().arm(5) }.unwrap();
        assert_eq!(unsafe { timer.as_mut().arm(5) }, Err(TimerError::AlreadyArmed));
        assert!(timer.as_mut().cancel());
        assert!(!timer.is_armed());
        assert!(!timer.as_mut().cancel());

        timer.as_mut().set_cancelable(false);
        assert!(!timer.is_cancelable());
    }

    #[test]
    fn timer_arms_zero_maximum_and_wrapping_deadlines() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let zero_calls = Rc::new(Cell::new(0));
        let full_range_calls = Rc::new(Cell::new(0));
        let maximum_calls = Rc::new(Cell::new(0));
        let wrapping_calls = Rc::new(Cell::new(0));

        let zero_callback_calls = zero_calls.clone();
        let mut zero = Box::pin(Timer::new(logger, (), move |_| {
            zero_callback_calls.set(zero_callback_calls.get() + 1);
        }));
        unsafe { zero.as_mut().arm(0) }.unwrap();
        unsafe { ngx_event_expire_timers() };
        assert_eq!(zero_calls.get(), 1);

        let full_range_callback_calls = full_range_calls.clone();
        let mut full_range = Box::pin(Timer::new(logger, (), move |_| {
            full_range_callback_calls.set(full_range_callback_calls.get() + 1);
        }));
        unsafe { full_range.as_mut().arm(ngx_msec_t::MAX) }.unwrap();
        unsafe { ngx_event_expire_timers() };
        assert_eq!(full_range_calls.get(), 1);

        let maximum_callback_calls = maximum_calls.clone();
        let mut maximum = Box::pin(Timer::new(logger, (), move |_| {
            maximum_callback_calls.set(maximum_callback_calls.get() + 1);
        }));
        let maximum_timeout = ngx_msec_int_t::MAX as ngx_msec_t;
        unsafe { maximum.as_mut().arm(maximum_timeout) }.unwrap();
        unsafe {
            ngx_current_msec = maximum_timeout - 1;
            ngx_event_expire_timers();
        }
        assert_eq!(maximum_calls.get(), 0);
        unsafe {
            ngx_current_msec = maximum_timeout;
            ngx_event_expire_timers();
        }
        assert_eq!(maximum_calls.get(), 1);

        let wrapping_callback_calls = wrapping_calls.clone();
        let mut wrapping = Box::pin(Timer::new(logger, (), move |_| {
            wrapping_callback_calls.set(wrapping_callback_calls.get() + 1);
        }));
        unsafe { ngx_current_msec = ngx_msec_t::MAX - 2 };
        unsafe { wrapping.as_mut().arm(5) }.unwrap();
        assert_eq!(wrapping.as_ref().get_ref().event.timer.key, 2);
        unsafe {
            ngx_current_msec = 1;
            ngx_event_expire_timers();
        }
        assert_eq!(wrapping_calls.get(), 0);
        unsafe {
            ngx_current_msec = 2;
            ngx_event_expire_timers();
        }
        assert_eq!(wrapping_calls.get(), 1);
    }

    #[cfg(ngx_feature = "debug")]
    #[test]
    fn timer_expiry_logs_the_invalid_connection_identity() {
        let _globals = EventGlobals::lock();
        let mut capture = LogCapture::default();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        log.log_level = NGX_LOG_DEBUG_EVENT as _;
        log.writer = Some(capture_log);
        log.wdata = (&raw mut capture).cast();
        let logger = log_ref(&mut log);
        let mut timer = Box::pin(Timer::new(logger, (), |_| {}));
        unsafe { timer.as_mut().arm(5) }.unwrap();

        unsafe {
            ngx_current_msec = 5;
            ngx_event_expire_timers();
        }

        assert!(
            capture.contains(b"event timer del: -1: 5"),
            "captured log: {:?}",
            &capture.bytes[..capture.len]
        );
    }

    #[test]
    fn timer_rearm_bypasses_nginx_lazy_update() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        let mut timer = Box::pin(Timer::new(logger, (), move |_| {
            callback_calls.set(callback_calls.get() + 1);
        }));

        unsafe { timer.as_mut().arm(300) }.unwrap();
        unsafe { timer.as_mut().rearm(301) };
        assert_eq!(timer.as_ref().get_ref().event.timer.key, 301);

        unsafe {
            ngx_current_msec = 300;
            ngx_event_expire_timers();
        }
        assert_eq!(calls.get(), 0);
        unsafe {
            ngx_current_msec = 301;
            ngx_event_expire_timers();
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn timer_arm_clears_timeout_and_cancel_after_expiry_is_idempotent() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let mut timer = Box::pin(Timer::new(logger, (), |_| {}));

        unsafe { timer.as_mut().arm(5) }.unwrap();
        unsafe {
            ngx_current_msec = 5;
            ngx_event_expire_timers();
        }
        assert!(timer.is_timed_out());
        assert!(!timer.as_mut().cancel());
        assert!(timer.as_mut().take_timeout());
        assert!(!timer.as_mut().take_timeout());

        unsafe { timer.as_mut().arm(5) }.unwrap();
        assert!(!timer.is_timed_out());
        assert!(timer.as_mut().cancel());
        assert!(!timer.as_mut().cancel());
    }

    #[test]
    fn timer_cancelable_state_allows_worker_exit() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let mut timer = Box::pin(Timer::new(logger, (), |_| {}));

        unsafe { timer.as_mut().arm(5) }.unwrap();
        assert_eq!(unsafe { ngx_event_no_timers_left() }, NGX_AGAIN as _);
        timer.as_mut().set_cancelable(true);
        assert_eq!(unsafe { ngx_event_no_timers_left() }, NGX_OK as _);
        assert!(timer.as_mut().cancel());
    }

    #[test]
    fn dropped_timer_cancels_its_pending_callback() {
        let _globals = EventGlobals::lock();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let logger = log_ref(&mut log);
        let calls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));

        {
            let callback_calls = calls.clone();
            let mut timer = Box::pin(Timer::new(logger, DropState(drops.clone()), move |_| {
                callback_calls.set(callback_calls.get() + 1)
            }));
            unsafe { timer.as_mut().arm(5) }.unwrap();
        }
        assert_eq!(drops.get(), 1);

        unsafe {
            ngx_current_msec = 5;
            ngx_event_expire_timers();
        }

        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn timer_callback_can_drop_its_owner_without_invalidating_callback_state() {
        let _globals = EventGlobals::lock();
        let owner_slot: Rc<RefCell<Option<Box<dyn Any>>>> = Rc::new(RefCell::new(None));
        let callback_owner = owner_slot.clone();
        let callback_finished = Rc::new(Cell::new(false));
        let finished = callback_finished.clone();
        let drops = Rc::new(Cell::new(0));
        let mut timer =
            Box::pin(Timer::new(static_log_ref(), DropState(drops.clone()), move |mut timer| {
                assert!(timer.take_timeout());
                drop(callback_owner.borrow_mut().take());
                assert_eq!(timer.state().0.get(), 0);
                timer.set_cancelable(true);
                finished.set(true);
            }));
        let raw = unsafe { &raw mut timer.as_mut().get_unchecked_mut().event };
        unsafe { (*raw).set_timedout(1) };
        let handler = unsafe { (*raw).handler }.expect("timer handler");
        *owner_slot.borrow_mut() = Some(Box::new(timer));

        unsafe { handler(raw) };

        assert!(owner_slot.borrow().is_none());
        assert!(callback_finished.get());
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn pool_owned_timer_cancels_before_pool_cleanup_drops_state() {
        let _globals = EventGlobals::lock();
        let owner = TestPool::new();
        let calls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));

        {
            let log = owner.log();
            let pool = owner.handle();
            let callback_calls = calls.clone();
            let timer = unsafe {
                Timer::allocate_in_pool(&pool, log, DropState(drops.clone()), move |_| {
                    callback_calls.set(1)
                })
            }
            .unwrap();
            let address = timer.as_non_null();
            let mut timer = timer;
            assert_eq!(timer.as_non_null(), address);
            unsafe { timer.as_pin_mut().arm(5) }.unwrap();
            assert_eq!(timer.as_non_null(), address);
        }

        drop(owner);
        assert_eq!(drops.get(), 1);

        unsafe {
            ngx_current_msec = 5;
            ngx_event_expire_timers();
        }

        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn pool_timer_does_not_publish_cleanup_when_allocation_fails() {
        let _globals = EventGlobals::lock();
        let owner = TestPool::new();
        let cleanup = unsafe { (*owner.raw).cleanup };
        unsafe { (*owner.raw).max = 0 };

        for successes in 0..=1 {
            let drops = Rc::new(Cell::new(0));
            let log = owner.log();
            let pool = owner.handle();
            unsafe { ngx_rs_test_fail_allocations_after(successes) };
            let result =
                unsafe { Timer::allocate_in_pool(&pool, log, DropState(drops.clone()), |_| {}) };
            unsafe { ngx_rs_test_reset_allocation_failures() };

            assert!(result.is_err());
            assert_eq!(unsafe { (*owner.raw).cleanup }, cleanup);
            assert_eq!(drops.get(), 1);
        }
    }
}
