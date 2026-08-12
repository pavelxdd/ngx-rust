#[cfg(ngx_feature = "debug")]
use ::core::ptr;

use crate::{
    NGX_TIMER_LAZY_DELAY, bindings, ngx_current_msec, ngx_event_t, ngx_event_timer_rbtree,
    ngx_int_t, ngx_msec_int_t, ngx_msec_t, ngx_queue_insert_before, ngx_queue_remove, ngx_queue_t,
    ngx_rbtree_delete, ngx_rbtree_insert,
};

/// Native event type for read readiness.
pub const NGX_READ_EVENT: ngx_int_t = bindings::NGX_RS_READ_EVENT as _;

/// Native event type for write readiness.
pub const NGX_WRITE_EVENT: ngx_int_t = bindings::NGX_RS_WRITE_EVENT as _;

/// Sets a timeout for an event.
///
/// # Safety
///
/// `ev` must be a valid pointer to an `ngx_event_t`.
#[inline]
pub unsafe fn ngx_add_timer(ev: *mut ngx_event_t, timer: ngx_msec_t) {
    unsafe {
        let key: ngx_msec_t = ngx_current_msec.wrapping_add(timer);

        if (*ev).timer_set() != 0 {
            /*
             * Use a previous timer value if difference between it and a new
             * value is less than NGX_TIMER_LAZY_DELAY milliseconds: this allows
             * to minimize the rbtree operations for fast connections.
             */
            let difference = key.wrapping_sub((*ev).timer.key) as ngx_msec_int_t;
            if difference.unsigned_abs() < NGX_TIMER_LAZY_DELAY as _ {
                return;
            }

            ngx_del_timer(ev);
        }

        (*ev).timer.key = key;

        ngx_rbtree_insert(&raw mut ngx_event_timer_rbtree, &raw mut (*ev).timer);

        (*ev).set_timer_set(1);
    }
}

/// Deletes a previously set timeout.
///
/// # Safety
///
/// `ev` must be a valid pointer to an `ngx_event_t`, previously armed with [ngx_add_timer].
#[inline]
pub unsafe fn ngx_del_timer(ev: *mut ngx_event_t) {
    unsafe {
        ngx_rbtree_delete(&raw mut ngx_event_timer_rbtree, &raw mut (*ev).timer);

        #[cfg(ngx_feature = "debug")]
        {
            (*ev).timer.left = ptr::null_mut();
            (*ev).timer.right = ptr::null_mut();
            (*ev).timer.parent = ptr::null_mut();
        }

        (*ev).set_timer_set(0);
    }
}

/// Post the event `ev` to the post queue `q`.
///
/// # Safety
///
/// `ev` must be a valid pointer to an `ngx_event_t`.
/// `q` is a valid pointer to a queue head.
#[inline]
pub unsafe fn ngx_post_event(ev: *mut ngx_event_t, q: *mut ngx_queue_t) {
    unsafe {
        if (*ev).posted() == 0 {
            (*ev).set_posted(1);
            ngx_queue_insert_before(q, &raw mut (*ev).queue);
        }
    }
}

/// Deletes the event `ev` from the queue it's currently posted in.
///
/// # Safety
///
/// `ev` must be a valid pointer to an `ngx_event_t`.
/// `ev` must be currently posted to an initialized queue.
#[inline]
pub unsafe fn ngx_delete_posted_event(ev: *mut ngx_event_t) {
    unsafe {
        (*ev).set_posted(0);
        ngx_queue_remove(&raw mut (*ev).queue);
    }
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use core::mem::MaybeUninit;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use super::{ngx_add_timer, ngx_del_timer, ngx_delete_posted_event, ngx_post_event};
    use crate::{
        NGX_TIMER_LAZY_DELAY, ngx_current_msec, ngx_event_expire_timers, ngx_event_t,
        ngx_event_timer_init, ngx_log_t, ngx_msec_t, ngx_posted_events, ngx_posted_next_events,
        ngx_queue_empty, ngx_queue_init, ngx_queue_t,
    };

    unsafe extern "C" {
        fn ngx_rs_test_add_timer(event: *mut ngx_event_t, timer: ngx_msec_t);
        fn ngx_rs_test_del_timer(event: *mut ngx_event_t);
        fn ngx_rs_test_post_event(event: *mut ngx_event_t, queue: *mut ngx_queue_t);
        fn ngx_rs_test_delete_posted_event(event: *mut ngx_event_t);
    }

    static EVENT_GLOBALS: Mutex<()> = Mutex::new(());
    static TIMER_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_TIMER_SET: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_TIMEDOUT: AtomicUsize = AtomicUsize::new(0);

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

    #[derive(Debug, Eq, PartialEq)]
    struct TimerState {
        key: ngx_msec_t,
        timer_set: bool,
        timedout: bool,
        links_cleared: bool,
    }

    fn timer_state(event: &TestEvent) -> TimerState {
        TimerState {
            key: event.event.timer.key,
            timer_set: event.event.timer_set() != 0,
            timedout: event.event.timedout() != 0,
            links_cleared: event.event.timer.left.is_null()
                && event.event.timer.right.is_null()
                && event.event.timer.parent.is_null(),
        }
    }

    fn cleanup_timer(event: &mut TestEvent) {
        unsafe {
            if event.event.timer_set() != 0 {
                ngx_rs_test_del_timer(event.raw());
            }
        }
    }

    fn timer_add_state(use_c: bool, old_key: ngx_msec_t, new_key: ngx_msec_t) -> TimerState {
        reset_event_globals();
        let mut event = TestEvent::new();

        unsafe {
            ngx_current_msec = 0;
            if use_c {
                ngx_rs_test_add_timer(event.raw(), old_key);
            } else {
                ngx_add_timer(event.raw(), old_key);
            }

            if use_c {
                ngx_rs_test_add_timer(event.raw(), new_key);
            } else {
                ngx_add_timer(event.raw(), new_key);
            }
        }

        let state = timer_state(&event);
        cleanup_timer(&mut event);
        state
    }

    fn assert_timer_add_matches(old_key: ngx_msec_t, new_key: ngx_msec_t) {
        let c = timer_add_state(true, old_key, new_key);
        let rust = timer_add_state(false, old_key, new_key);
        assert_eq!(rust, c, "old key {old_key}, new key {new_key}");
    }

    fn timer_delete_state(use_c: bool) -> TimerState {
        reset_event_globals();
        let mut event = TestEvent::new();

        unsafe {
            if use_c {
                ngx_rs_test_add_timer(event.raw(), 10);
            } else {
                ngx_add_timer(event.raw(), 10);
            }
            event.event.set_timedout(1);
            if use_c {
                ngx_rs_test_del_timer(event.raw());
            } else {
                ngx_del_timer(event.raw());
            }
        }

        timer_state(&event)
    }

    #[test]
    fn timer_helpers_match_lazy_boundaries_and_wrapping_keys() {
        let _globals = EventGlobals::lock();
        let old_key: ngx_msec_t = 5_000;

        for difference in [-301_isize, -300, -299, 0, 299, 300, 301] {
            let new_key = old_key.wrapping_add(difference as ngx_msec_t);
            assert_timer_add_matches(old_key, new_key);

            let expected_key = if difference.unsigned_abs() < NGX_TIMER_LAZY_DELAY as usize {
                old_key
            } else {
                new_key
            };
            assert_eq!(timer_add_state(false, old_key, new_key).key, expected_key);
        }

        assert_timer_add_matches(ngx_msec_t::MAX - 100, 100);
    }

    #[test]
    fn timer_deletion_matches_configured_macro_and_preserves_timedout() {
        let _globals = EventGlobals::lock();
        let c = timer_delete_state(true);
        let rust = timer_delete_state(false);

        assert_eq!(rust, c);
        assert!(!rust.timer_set);
        assert!(rust.timedout);
    }

    unsafe extern "C" fn record_timer_expiry(event: *mut ngx_event_t) {
        unsafe {
            TIMER_CALLBACKS.fetch_add(1, Ordering::Relaxed);
            CALLBACK_TIMER_SET.store((*event).timer_set() as usize, Ordering::Relaxed);
            CALLBACK_TIMEDOUT.store((*event).timedout() as usize, Ordering::Relaxed);
        }
    }

    #[test]
    fn timer_expiry_clears_timer_set_and_keeps_timedout_until_owner_clears_it() {
        let _globals = EventGlobals::lock();
        TIMER_CALLBACKS.store(0, Ordering::Relaxed);
        CALLBACK_TIMER_SET.store(usize::MAX, Ordering::Relaxed);
        CALLBACK_TIMEDOUT.store(usize::MAX, Ordering::Relaxed);

        let mut event = TestEvent::new();
        event.event.handler = Some(record_timer_expiry);
        unsafe {
            ngx_current_msec = 41;
            ngx_add_timer(event.raw(), 5);
            ngx_current_msec = 46;
            ngx_event_expire_timers();
        }

        assert_eq!(TIMER_CALLBACKS.load(Ordering::Relaxed), 1);
        assert_eq!(CALLBACK_TIMER_SET.load(Ordering::Relaxed), 0);
        assert_eq!(CALLBACK_TIMEDOUT.load(Ordering::Relaxed), 1);
        assert_eq!(event.event.timer_set(), 0);
        assert_eq!(event.event.timedout(), 1);

        event.event.set_timedout(0);
        assert_eq!(event.event.timedout(), 0);
    }

    fn post_event(use_c: bool, event: &mut TestEvent, queue: *mut ngx_queue_t) {
        unsafe {
            if use_c {
                ngx_rs_test_post_event(event.raw(), queue);
            } else {
                ngx_post_event(event.raw(), queue);
            }
        }
    }

    fn delete_posted_event(use_c: bool, event: &mut TestEvent) {
        unsafe {
            if use_c {
                ngx_rs_test_delete_posted_event(event.raw());
            } else {
                ngx_delete_posted_event(event.raw());
            }
        }
    }

    fn assert_posted_queue_behavior(use_c: bool) {
        let mut queue = unsafe { MaybeUninit::<ngx_queue_t>::zeroed().assume_init() };
        unsafe { ngx_queue_init(&raw mut queue) };
        let mut first = TestEvent::new();
        let mut second = TestEvent::new();

        post_event(use_c, &mut first, &raw mut queue);
        post_event(use_c, &mut second, &raw mut queue);
        post_event(use_c, &mut first, &raw mut queue);

        assert_eq!(queue.next, &raw mut first.event.queue);
        assert_eq!(queue.prev, &raw mut second.event.queue);
        assert_eq!(first.event.queue.next, &raw mut second.event.queue);
        assert_eq!(second.event.queue.prev, &raw mut first.event.queue);
        assert_eq!(first.event.posted(), 1);
        assert_eq!(second.event.posted(), 1);

        delete_posted_event(use_c, &mut first);
        assert_eq!(first.event.posted(), 0);
        assert_eq!(queue.next, &raw mut second.event.queue);
        assert_eq!(second.event.queue.prev, &raw mut queue);
        assert_eq!(first.event.queue.next.is_null(), cfg!(ngx_feature = "debug"));
        assert_eq!(first.event.queue.prev.is_null(), cfg!(ngx_feature = "debug"));

        delete_posted_event(use_c, &mut second);
        assert!(unsafe { ngx_queue_empty(&raw const queue) });
    }

    #[test]
    fn posted_helpers_match_configured_coalescing_tail_and_deletion_behavior() {
        let _globals = EventGlobals::lock();
        assert_posted_queue_behavior(true);
        assert_posted_queue_behavior(false);
    }
}
