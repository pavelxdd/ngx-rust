use core::cell::RefCell;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use nginx_sys::{ngx_msec_int_t, ngx_msec_t};
use pin_project_lite::pin_project;

use crate::event::{Timer, TimerCallback};
use crate::log::LogRef;
use crate::ngx_log_debug;

const MILLISECONDS_PER_SECOND: u128 = 1_000;
const NANOSECONDS_PER_MILLISECOND: u32 = 1_000_000;
const TIMER_DURATION_MAX_MILLISECONDS: u128 = ngx_msec_int_t::MAX as u128;

fn duration_to_milliseconds_ceil(duration: Duration) -> u128 {
    let milliseconds = u128::from(duration.as_secs()) * MILLISECONDS_PER_SECOND
        + u128::from(duration.subsec_millis());

    if duration.subsec_nanos() % NANOSECONDS_PER_MILLISECOND == 0 {
        milliseconds
    } else {
        milliseconds + 1
    }
}

fn bounded_milliseconds(remaining: u128, maximum: u128) -> Option<u128> {
    (remaining != 0).then(|| remaining.min(maximum))
}

fn timer_step(remaining: u128) -> Option<(u128, ngx_msec_t)> {
    let milliseconds = bounded_milliseconds(remaining, TIMER_DURATION_MAX_MILLISECONDS)?;
    let timeout =
        ngx_msec_t::try_from(milliseconds).expect("signed nginx timer bound must fit ngx_msec_t");

    Some((milliseconds, timeout))
}

/// Puts the current task to sleep for at least the specified amount of time.
///
/// # Safety
///
/// The future must be polled and dropped on the initialized nginx event-loop thread that owns the
/// timer tree.
#[inline]
pub unsafe fn sleep(duration: Duration, log: LogRef<'_>) -> Sleep<'_> {
    unsafe { Sleep::new(duration, log) }
}

pin_project! {
/// Future returned by [sleep].
///
/// A sleep stays on the nginx worker thread where it is polled and cannot be moved after polling.
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ngx::async_::Sleep<'static>>();
/// ```
///
/// ```compile_fail
/// fn assert_unpin<T: Unpin>() {}
/// assert_unpin::<ngx::async_::Sleep<'static>>();
/// ```
pub struct Sleep<'log> {
    #[pin]
    timer: Timer<'log, SleepTimerState, SleepTimerCallback>,
    remaining_milliseconds: u128,
    armed_milliseconds: u128,
}
}

struct SleepTimerState {
    waker: RefCell<Option<Waker>>,
}

impl SleepTimerState {
    fn new() -> Self {
        Self { waker: RefCell::new(None) }
    }

    fn replace_waker(&self, waker: &Waker) {
        let mut current = self.waker.borrow_mut();
        match current.as_mut() {
            Some(current) => current.clone_from(waker),
            None => *current = Some(waker.clone()),
        }
    }

    fn take_waker(&self) -> Option<Waker> {
        self.waker.borrow_mut().take()
    }
}

type SleepTimerCallback = for<'callback> fn(TimerCallback<'callback, SleepTimerState>);

fn sleep_timer_callback(timer: TimerCallback<'_, SleepTimerState>) {
    if let Some(waker) = timer.state().take_waker() {
        waker.wake();
    }
}

impl<'log> Sleep<'log> {
    /// Creates a new Sleep with the specified duration and logger for debug messages.
    ///
    /// # Safety
    ///
    /// The future must be polled and dropped on the initialized nginx event-loop thread that owns
    /// the timer tree.
    pub unsafe fn new(duration: Duration, log: LogRef<'log>) -> Self {
        ngx_log_debug!(log.as_ptr(), "async: sleep for {duration:?}");

        Sleep {
            timer: Timer::new(
                log,
                SleepTimerState::new(),
                sleep_timer_callback as SleepTimerCallback,
            ),
            remaining_milliseconds: duration_to_milliseconds_ceil(duration),
            armed_milliseconds: 0,
        }
    }
}

impl Future for Sleep<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if *this.remaining_milliseconds == 0 {
            return Poll::Ready(());
        }

        if this.timer.as_mut().take_timeout() {
            let elapsed = mem::take(this.armed_milliseconds);
            *this.remaining_milliseconds = this
                .remaining_milliseconds
                .checked_sub(elapsed)
                .expect("timer expiry must match the armed sleep step");

            if *this.remaining_milliseconds == 0 {
                return Poll::Ready(());
            }
        }

        if this.timer.as_ref().get_ref().is_armed() {
            this.timer.as_ref().get_ref().state().replace_waker(cx.waker());
            return Poll::Pending;
        }

        let Some((milliseconds, timeout)) = timer_step(*this.remaining_milliseconds) else {
            return Poll::Ready(());
        };
        this.timer.as_ref().get_ref().state().replace_waker(cx.waker());
        this.timer.as_mut().set_cancelable(true);
        unsafe {
            this.timer
                .as_mut()
                .arm(timeout)
                .expect("timer was checked unarmed before arming sleep");
        }
        *this.armed_milliseconds = milliseconds;

        Poll::Pending
    }
}

#[cfg(test)]
mod conversion_tests {
    use super::*;

    #[test]
    fn duration_conversion_uses_ceiling_milliseconds() {
        assert_eq!(duration_to_milliseconds_ceil(Duration::ZERO), 0);
        assert_eq!(duration_to_milliseconds_ceil(Duration::from_nanos(1)), 1);
        assert_eq!(duration_to_milliseconds_ceil(Duration::from_micros(1)), 1);
        assert_eq!(duration_to_milliseconds_ceil(Duration::from_micros(999)), 1);
        assert_eq!(duration_to_milliseconds_ceil(Duration::from_millis(1)), 1);
        assert_eq!(
            duration_to_milliseconds_ceil(Duration::from_millis(1) + Duration::from_nanos(1)),
            2,
        );
        assert_eq!(
            duration_to_milliseconds_ceil(
                Duration::from_millis(TIMER_DURATION_MAX_MILLISECONDS as u64)
                    + Duration::from_nanos(1),
            ),
            TIMER_DURATION_MAX_MILLISECONDS + 1,
        );
    }

    #[test]
    fn bounded_steps_cover_32_and_64_bit_timer_ranges() {
        for maximum in [i32::MAX as u128, i64::MAX as u128] {
            assert_eq!(bounded_milliseconds(0, maximum), None);
            assert_eq!(bounded_milliseconds(maximum, maximum), Some(maximum));
            assert_eq!(
                bounded_milliseconds(maximum.checked_add(1).unwrap(), maximum),
                Some(maximum),
            );
            assert_eq!(
                bounded_milliseconds(maximum.checked_mul(2).unwrap(), maximum),
                Some(maximum),
            );
        }
    }
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::mem::MaybeUninit;
    use core::pin::Pin;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use core::time::Duration;
    use std::sync::MutexGuard;

    use super::Sleep;
    use crate::ffi::{
        ngx_current_msec, ngx_event_expire_timers, ngx_event_no_timers_left, ngx_event_timer_init,
        ngx_log_t, ngx_msec_int_t, ngx_msec_t,
    };
    use crate::log::LogRef;

    struct TimerGlobals {
        _guard: MutexGuard<'static, ()>,
    }

    impl TimerGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            reset_timer_tree();
            Self { _guard: guard }
        }
    }

    impl Drop for TimerGlobals {
        fn drop(&mut self) {
            reset_timer_tree();
        }
    }

    fn reset_timer_tree() {
        unsafe {
            assert_eq!(ngx_event_timer_init(ptr::null_mut()), 0);
            ngx_current_msec = 0;
        }
    }

    fn advance_to(msec: ngx_msec_t) {
        unsafe {
            ngx_current_msec = msec;
            ngx_event_expire_timers();
        }
    }

    fn log_ref(log: &mut ngx_log_t) -> LogRef<'_> {
        unsafe { LogRef::from_raw(log) }.expect("test logger")
    }

    fn poll_sleep(sleep: Pin<&mut Sleep<'_>>, waker: &Waker) -> Poll<()> {
        let mut context = Context::from_waker(waker);
        sleep.poll(&mut context)
    }

    #[derive(Default)]
    struct WakeState {
        wakes: AtomicUsize,
        drops: AtomicUsize,
    }

    struct RecordingWake {
        state: Arc<WakeState>,
    }

    impl Wake for RecordingWake {
        fn wake(self: Arc<Self>) {
            self.state.wakes.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.state.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Drop for RecordingWake {
        fn drop(&mut self) {
            self.state.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn recording_waker() -> (Waker, Arc<WakeState>) {
        let state = Arc::new(WakeState::default());
        let waker = Waker::from(Arc::new(RecordingWake { state: Arc::clone(&state) }));
        (waker, state)
    }

    fn maximum_timer_step() -> u64 {
        ngx_msec_int_t::MAX as u64
    }

    #[test]
    fn zero_duration_is_ready_without_arming_a_timer() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep = Box::pin(unsafe { Sleep::new(Duration::ZERO, log_ref(&mut log)) });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Ready(()));
        advance_to(0);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn positive_submillisecond_duration_rounds_up_to_one_millisecond() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep = Box::pin(unsafe { Sleep::new(Duration::from_nanos(1), log_ref(&mut log)) });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(0);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
        advance_to(1);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Ready(()));
    }

    #[test]
    fn one_millisecond_duration_waits_for_one_millisecond() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(1), log_ref(&mut log)) });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(0);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
        advance_to(1);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Ready(()));
    }

    #[test]
    fn maximum_timer_step_completes_on_its_expiry() {
        let _globals = TimerGlobals::new();
        let maximum = maximum_timer_step();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(maximum), log_ref(&mut log)) });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to((maximum - 1) as ngx_msec_t);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
        advance_to(maximum as ngx_msec_t);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Ready(()));
    }

    #[test]
    fn duration_larger_than_one_timer_step_rearms_for_the_remainder() {
        let _globals = TimerGlobals::new();
        let maximum = maximum_timer_step();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep = Box::pin(unsafe {
            Sleep::new(Duration::from_millis(maximum.checked_add(1).unwrap()), log_ref(&mut log))
        });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(maximum as ngx_msec_t);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(maximum.checked_add(1).unwrap() as ngx_msec_t);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 2);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Ready(()));
    }

    #[test]
    fn duration_spanning_multiple_timer_steps_never_finishes_early() {
        let _globals = TimerGlobals::new();
        let maximum = maximum_timer_step();
        let second = maximum.checked_mul(2).unwrap();
        let total = second.checked_add(1).unwrap();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(total), log_ref(&mut log)) });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(maximum as ngx_msec_t);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(second as ngx_msec_t);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(total as ngx_msec_t);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 3);
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Ready(()));
    }

    #[test]
    fn repeated_poll_replaces_the_pending_waker() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(1), log_ref(&mut log)) });
        let (first, first_state) = recording_waker();
        let (second, second_state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &first), Poll::Pending);
        assert_eq!(poll_sleep(sleep.as_mut(), &second), Poll::Pending);
        advance_to(1);

        assert_eq!(first_state.wakes.load(Ordering::Relaxed), 0);
        assert_eq!(second_state.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(poll_sleep(sleep.as_mut(), &second), Poll::Ready(()));
    }

    #[test]
    fn expiry_wakes_once_until_the_executor_repolls() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(1), log_ref(&mut log)) });
        let (waker, state) = recording_waker();
        let mut polls = 0;

        polls += 1;
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(1);

        assert_eq!(polls, 1);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
        polls += 1;
        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Ready(()));
        assert_eq!(polls, 2);
    }

    #[test]
    fn dropping_pending_sleep_cancels_the_timer_before_waker_state_is_destroyed() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(1), log_ref(&mut log)) });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        drop(waker);
        drop(sleep);

        assert_eq!(state.drops.load(Ordering::Relaxed), 1);
        advance_to(1);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dropping_sleep_after_expiry_leaves_no_timer_callback() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(1), log_ref(&mut log)) });
        let (waker, state) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        advance_to(1);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
        drop(sleep);
        advance_to(2);
        assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sleep_timer_is_cancelable_during_worker_shutdown() {
        let _globals = TimerGlobals::new();
        let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
        let mut sleep =
            Box::pin(unsafe { Sleep::new(Duration::from_millis(1), log_ref(&mut log)) });
        let (waker, _) = recording_waker();

        assert_eq!(poll_sleep(sleep.as_mut(), &waker), Poll::Pending);
        assert_eq!(unsafe { ngx_event_no_timers_left() }, 0);
    }
}
