//! Owned nginx timers.

use core::marker::{PhantomData, PhantomPinned};
use core::mem;
use core::pin::Pin;
use core::ptr;

use crate::allocator::AllocError;
use crate::core::{Pool, PoolValue};
use crate::ffi::{ngx_add_timer, ngx_connection_t, ngx_del_timer, ngx_event_t, ngx_msec_t};
use crate::log::LogRef;
use crate::ngx_container_of;

use super::EventRef;

#[repr(transparent)]
struct TimerDebugIdentity(ngx_connection_t);

// SAFETY: Rust and nginx only read this fully initialized identity through Timer::event.data.
unsafe impl Sync for TimerDebugIdentity {}

static TIMER_IDENT: TimerDebugIdentity = {
    let mut connection = unsafe { mem::zeroed::<ngx_connection_t>() };
    connection.fd = -1;
    TimerDebugIdentity(connection)
};
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
