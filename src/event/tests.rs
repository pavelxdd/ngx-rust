#[cfg(all(test, ngx_feature = "stat_stub"))]
mod tests {
    use super::super::*;

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
mod linked {
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

    use super::super::{
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
                assert_eq!(event.state().0.get(), 0);
                finished.set(true);
            }));
        assert_eq!(unsafe { posted.as_mut().post(PostedQueue::Normal) }, Ok(true));
        *owner_slot.borrow_mut() = Some(Box::new(posted));

        let mut cycle = TestCycle::new();
        unsafe { ngx_event_process_posted(cycle.raw(), &raw mut ngx_posted_events) };

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
        unsafe { timer.as_mut().arm(0) }.unwrap();
        *owner_slot.borrow_mut() = Some(Box::new(timer));

        unsafe { ngx_event_expire_timers() };

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
