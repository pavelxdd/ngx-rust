use core::future::Future;
use core::marker::PhantomPinned;
use core::mem;
use core::pin::Pin;
use core::ptr::NonNull;
use core::task::{self, Poll};
use core::time::Duration;

use nginx_sys::{ngx_add_timer, ngx_del_timer, ngx_event_t, ngx_log_t, ngx_msec_int_t, ngx_msec_t};
use pin_project_lite::pin_project;

use crate::{ngx_container_of, ngx_log_debug};

/// Maximum duration that can be achieved using [ngx_add_timer].
const NGX_TIMER_DURATION_MAX: Duration = Duration::from_millis(ngx_msec_int_t::MAX as _);

/// Puts the current task to sleep for at least the specified amount of time.
///
/// The function is a shorthand for [Sleep::new] using the global logger for debug output.
#[inline]
pub fn sleep(duration: Duration) -> Sleep {
    Sleep::new(duration, crate::log::ngx_cycle_log())
}

pin_project! {
/// Future returned by [sleep].
///
/// A sleep stays on the nginx worker thread where it is polled and cannot be moved after polling.
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ngx::async_::Sleep>();
/// ```
///
/// ```compile_fail
/// fn assert_unpin<T: Unpin>() {}
/// assert_unpin::<ngx::async_::Sleep>();
/// ```
pub struct Sleep {
    #[pin]
    timer: TimerEvent,
    duration: Duration,
}
}

impl Sleep {
    /// Creates a new Sleep with the specified duration and logger for debug messages.
    pub fn new(duration: Duration, log: NonNull<ngx_log_t>) -> Self {
        let timer = TimerEvent::new(log);
        ngx_log_debug!(timer.event.log, "async: sleep for {duration:?}");
        Sleep { timer, duration }
    }
}

impl Future for Sleep {
    type Output = ();

    #[cfg(not(target_pointer_width = "32"))]
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let msec = self.duration.min(NGX_TIMER_DURATION_MAX).as_millis() as ngx_msec_t;
        let this = self.project();
        this.timer.poll_sleep(msec, cx)
    }

    #[cfg(target_pointer_width = "32")]
    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        if self.duration.is_zero() {
            return Poll::Ready(());
        }
        let step = self.duration.min(NGX_TIMER_DURATION_MAX);

        let mut this = self.project();
        // Handle ngx_msec_t overflow on 32-bit platforms.
        match this.timer.as_mut().poll_sleep(step.as_millis() as _, cx) {
            // Last step
            Poll::Ready(()) if this.duration == &step => Poll::Ready(()),
            Poll::Ready(()) => {
                *this.duration = this.duration.saturating_sub(step);
                this.timer.as_mut().rearm();
                this.timer.as_mut().poll_sleep(step.as_millis() as _, cx)
            }
            x => x,
        }
    }
}

struct TimerEvent {
    event: ngx_event_t,
    waker: Option<task::Waker>,
    _pin: PhantomPinned,
}

impl TimerEvent {
    pub fn new(log: NonNull<ngx_log_t>) -> Self {
        static IDENT: [usize; 4] = [
            0, 0, 0, 0x4153594e, // ASYN
        ];

        let mut ev: ngx_event_t = unsafe { mem::zeroed() };
        // The data is only used for `ngx_event_ident` and will not be mutated.
        ev.data = (&raw const IDENT).cast_mut().cast();
        ev.handler = Some(Self::timer_handler);
        ev.log = log.as_ptr();
        ev.set_cancelable(1);

        Self { event: ev, waker: None, _pin: PhantomPinned }
    }

    pub fn poll_sleep(
        mut self: Pin<&mut Self>,
        duration: ngx_msec_t,
        context: &mut task::Context<'_>,
    ) -> Poll<()> {
        // SAFETY: no field is moved; the pinned address is the one stored in nginx's timer tree.
        let this = unsafe { self.as_mut().get_unchecked_mut() };

        if this.event.timedout() != 0 {
            Poll::Ready(())
        } else if this.event.timer_set() != 0 {
            if let Some(waker) = this.waker.as_mut() {
                waker.clone_from(context.waker());
            } else {
                this.waker = Some(context.waker().clone());
            }
            Poll::Pending
        } else {
            unsafe { ngx_add_timer(&raw mut this.event, duration) };
            this.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }

    #[cfg(target_pointer_width = "32")]
    fn rearm(mut self: Pin<&mut Self>) {
        // SAFETY: clearing a flag does not move any field of the pinned timer.
        unsafe { self.as_mut().get_unchecked_mut().event.set_timedout(0) };
    }

    unsafe extern "C" fn timer_handler(ev: *mut ngx_event_t) {
        let timer = ngx_container_of!(ev, Self, event);

        if let Some(waker) = unsafe { (*timer).waker.take() } {
            waker.wake();
        }
    }
}

impl Drop for TimerEvent {
    fn drop(&mut self) {
        if self.event.timer_set() != 0 {
            unsafe { ngx_del_timer(&raw mut self.event) };
        }
    }
}
