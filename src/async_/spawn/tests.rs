extern crate std;

use super::*;

#[test]
fn spawn_rejects_before_worker_initialization() {
    let _scheduler = SCHEDULER_TESTS.lock().unwrap_or_else(|error| error.into_inner());
    let result = spawn(async { 7 });

    assert!(matches!(result, Err(SpawnError::Uninitialized)));
}

#[cfg(all(test, feature = "test-link"))]
mod worker_tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use core::future::{Future, poll_fn};
    use core::mem::{self, MaybeUninit};
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::sync::{Mutex, MutexGuard, mpsc};
    use std::thread::{self, ThreadId};

    use super::super::*;
    use crate::ffi::{
        NGX_OK, NGX_USE_CLEAR_EVENT, ngx_connection_t, ngx_cycle, ngx_cycle_t, ngx_event_actions,
        ngx_event_actions_t, ngx_event_flags, ngx_event_handler_pt, ngx_event_move_posted_next,
        ngx_event_process_posted, ngx_event_t, ngx_int_t, ngx_log_t, ngx_posted_events,
        ngx_posted_next_events, ngx_queue_empty, ngx_queue_init, ngx_uint_t,
    };
    use crate::log::LogRef;

    static NOTIFIED_HANDLER: Mutex<ngx_event_handler_pt> = Mutex::new(None);
    static NOTIFY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NATIVE_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct TestGlobals {
        _nginx: MutexGuard<'static, ()>,
        _scheduler: MutexGuard<'static, ()>,
        previous_cycle: *mut ngx_cycle_t,
        previous_actions: ngx_event_actions_t,
        previous_event_flags: ngx_uint_t,
    }

    impl TestGlobals {
        fn new() -> Self {
            let nginx = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let scheduler = SCHEDULER_TESTS.lock().unwrap_or_else(|error| error.into_inner());

            let previous_cycle = unsafe { ngx_cycle };
            let previous_actions = unsafe { ngx_event_actions };
            let previous_event_flags = unsafe { ngx_event_flags };
            reset_event_globals();
            NOTIFY_CALLS.store(0, Ordering::Relaxed);
            NATIVE_HANDLER_CALLS.store(0, Ordering::Relaxed);
            *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = None;

            Self {
                _nginx: nginx,
                _scheduler: scheduler,
                previous_cycle,
                previous_actions,
                previous_event_flags,
            }
        }
    }

    impl Drop for TestGlobals {
        fn drop(&mut self) {
            reset_event_globals();
            unsafe {
                ngx_cycle = self.previous_cycle;
                ngx_event_actions = self.previous_actions;
                ngx_event_flags = self.previous_event_flags;
            }
            *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = None;
        }
    }

    struct TestCycle {
        cycle: ngx_cycle_t,
        connection: ngx_connection_t,
        read: ngx_event_t,
        write: ngx_event_t,
        log: ngx_log_t,
    }

    impl TestCycle {
        fn new() -> Box<Self> {
            let mut cycle = Box::new(unsafe { MaybeUninit::<Self>::zeroed().assume_init() });
            cycle.cycle.log = &raw mut cycle.log;
            cycle.cycle.connection_n = 1;
            cycle.cycle.free_connection_n = 1;
            cycle.cycle.free_connections = &raw mut cycle.connection;
            cycle.connection.read = &raw mut cycle.read;
            cycle.connection.write = &raw mut cycle.write;
            cycle
        }

        fn raw(&mut self) -> *mut ngx_cycle_t {
            &raw mut self.cycle
        }
    }

    struct TestWorker {
        _globals: TestGlobals,
        cycle: Box<TestCycle>,
        lease: Option<WorkerSchedulerLease>,
    }

    impl TestWorker {
        fn new() -> Self {
            let globals = TestGlobals::new();
            let mut cycle = TestCycle::new();
            unsafe {
                ngx_cycle = cycle.raw();
                ngx_event_actions = mem::zeroed();
                ngx_event_actions.add = Some(test_add_event);
                ngx_event_actions.del = Some(test_delete_event);
                ngx_event_actions.notify = Some(test_notify);
                ngx_event_flags = NGX_USE_CLEAR_EVENT as _;
            }
            Self { _globals: globals, cycle, lease: None }
        }

        fn init(&mut self) -> Result<(), SchedulerInitError> {
            let log = unsafe { LogRef::from_raw(&raw mut self.cycle.log) }.expect("test logger");
            self.lease = Some(unsafe { acquire_worker(log) }?);
            Ok(())
        }

        fn release(&mut self) -> Result<bool, SchedulerShutdownError> {
            let Some(mut lease) = self.lease.take() else {
                return Ok(false);
            };
            match lease.release() {
                Ok(stopped) => Ok(stopped),
                Err(error) => {
                    self.lease = Some(lease);
                    Err(error)
                }
            }
        }

        fn process_posted(&mut self) {
            unsafe {
                ngx_event_move_posted_next(self.cycle.raw());
                ngx_event_process_posted(self.cycle.raw(), &raw mut ngx_posted_events);
            }
        }

        fn deliver_notification(&self) {
            let event = WORKER_SCHEDULER.with(|worker| {
                let worker = worker.borrow();
                let connection = worker.as_ref().unwrap().notification.unwrap();
                unsafe { connection.as_ref().read }
            });
            let handler = unsafe { (*event).handler }.expect("notification handler");
            unsafe { handler(event) };
        }

        fn queues_are_empty(&self) -> bool {
            unsafe {
                ngx_queue_empty(&raw const ngx_posted_events)
                    && ngx_queue_empty(&raw const ngx_posted_next_events)
            }
        }

        fn task_registry_is_empty(&self) -> bool {
            WORKER_SCHEDULER.with(|scheduler| {
                scheduler.borrow().as_ref().is_none_or(|scheduler| {
                    scheduler.tasks.is_empty() && scheduler.completed.is_empty()
                })
            })
        }
    }

    impl Drop for TestWorker {
        fn drop(&mut self) {
            let _ = self.release();
        }
    }

    fn reset_event_globals() {
        unsafe {
            ngx_queue_init(&raw mut ngx_posted_events);
            ngx_queue_init(&raw mut ngx_posted_next_events);
        }
    }

    unsafe extern "C" fn test_add_event(
        event: *mut ngx_event_t,
        _event_type: ngx_int_t,
        _flags: ngx_uint_t,
    ) -> ngx_int_t {
        unsafe { (*event).set_active(1) };
        NGX_OK as _
    }

    unsafe extern "C" fn test_delete_event(
        event: *mut ngx_event_t,
        _event_type: ngx_int_t,
        _flags: ngx_uint_t,
    ) -> ngx_int_t {
        unsafe { (*event).set_active(0) };
        NGX_OK as _
    }

    unsafe extern "C" fn test_notify(handler: ngx_event_handler_pt) -> ngx_int_t {
        NOTIFY_CALLS.fetch_add(1, Ordering::Relaxed);
        *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = handler;
        NGX_OK as _
    }

    unsafe extern "C" fn native_notification_handler(_event: *mut ngx_event_t) {
        NATIVE_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    fn assert_private_channel_delivers_with_competing_native_notification(native_first: bool) {
        let mut worker = TestWorker::new();
        *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) =
            Some(native_notification_handler);
        worker.init().unwrap();
        let ready = Arc::new(AtomicBool::new(false));
        let future_ready = Arc::clone(&ready);
        let (waker_tx, waker_rx) = mpsc::channel();
        let task = spawn(poll_fn(move |context| {
            if future_ready.load(Ordering::Acquire) {
                Poll::Ready(7)
            } else {
                waker_tx.send(context.waker().clone()).unwrap();
                Poll::Pending
            }
        }))
        .unwrap();
        worker.process_posted();
        let waker = waker_rx.recv().unwrap();
        let wake_task = || {
            thread::spawn(move || {
                ready.store(true, Ordering::Release);
                waker.wake();
            })
            .join()
            .unwrap();
        };

        if native_first {
            unsafe { test_notify(Some(native_notification_handler)) };
            wake_task();
        } else {
            wake_task();
            unsafe { test_notify(Some(native_notification_handler)) };
        }

        worker.deliver_notification();
        let native = NOTIFIED_HANDLER
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("native notification handler");
        unsafe { native(ptr::null_mut()) };

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(NATIVE_HANDLER_CALLS.load(Ordering::Relaxed), 1);
        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(7)));
    }

    #[test]
    fn private_channel_delivers_both_notification_orders() {
        assert_private_channel_delivers_with_competing_native_notification(false);
        assert_private_channel_delivers_with_competing_native_notification(true);
    }

    #[test]
    fn init_rejects_a_notification_channel_without_a_connection_slot() {
        let mut worker = TestWorker::new();
        worker.cycle.cycle.free_connections = ptr::null_mut();
        worker.cycle.cycle.free_connection_n = 0;

        assert_eq!(worker.init(), Err(SchedulerInitError::NotificationChannel));
        assert!(matches!(spawn(async { 1 }), Err(SpawnError::Uninitialized)));
    }

    #[test]
    fn worker_leases_share_one_scheduler_until_the_last_release() {
        let mut worker = TestWorker::new();
        let log = unsafe { LogRef::from_raw(&raw mut worker.cycle.log) }.expect("test logger");
        let mut first = unsafe { acquire_worker(log) }.expect("first scheduler participant");
        let mut second = unsafe { acquire_worker(log) }.expect("second scheduler participant");

        let first_task = spawn(async { 1 }).expect("first participant task");
        worker.process_posted();
        let mut first_task = core::pin::pin!(first_task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(first_task.as_mut().poll(&mut context), Poll::Ready(Ok(1)));

        let second_task = spawn(async { 2 }).expect("second participant task");
        assert_eq!(first.release(), Ok(false));
        worker.process_posted();
        let mut second_task = core::pin::pin!(second_task);
        assert_eq!(second_task.as_mut().poll(&mut context), Poll::Ready(Ok(2)));
        assert_eq!(second.release(), Ok(true));
        assert!(matches!(spawn(async { 3 }), Err(SpawnError::Uninitialized)));
    }

    #[test]
    fn local_task_returns_its_output_once() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();

        let task = spawn(async { 7 }).unwrap();
        worker.process_posted();

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(7)));
        assert!(matches!(
            task.as_mut().poll(&mut context),
            Poll::Ready(Err(TaskError::OutputTaken))
        ));
    }

    struct PendingDropFuture {
        polls: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        waker: Option<mpsc::Sender<Waker>>,
    }

    impl Future for PendingDropFuture {
        type Output = ();

        fn poll(self: core::pin::Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::Relaxed);
            if let Some(waker) = this.waker.take() {
                waker.send(context.waker().clone()).unwrap();
            }
            Poll::Pending
        }
    }

    impl Drop for PendingDropFuture {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct SelfCancelFuture {
        cancellation: Arc<Mutex<Option<CancellationHandle>>>,
        polls: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }

    impl Future for SelfCancelFuture {
        type Output = ();

        fn poll(self: core::pin::Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::Relaxed);
            if let Some(cancellation) =
                this.cancellation.lock().unwrap_or_else(|error| error.into_inner()).as_ref()
            {
                cancellation.cancel();
            }
            Poll::Pending
        }
    }

    impl Drop for SelfCancelFuture {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct CountedOutput(Arc<AtomicUsize>);

    impl Drop for CountedOutput {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct CountWaker(Arc<AtomicUsize>);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn cancellation_handle_is_send_and_sync() {
        fn require_send_sync<T: Send + Sync>() {}

        require_send_sync::<CancellationHandle>();
    }

    #[test]
    fn task_output_is_destroyed_once_after_consumption() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let output_dropped = Arc::clone(&dropped);

        let task = spawn(async move { CountedOutput(output_dropped) }).unwrap();
        worker.process_posted();

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        let output = match task.as_mut().poll(&mut context) {
            Poll::Ready(Ok(output)) => output,
            Poll::Ready(Err(error)) => panic!("unexpected task error: {error:?}"),
            Poll::Pending => panic!("task output is still pending"),
        };
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(output);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert!(matches!(
            task.as_mut().poll(&mut context),
            Poll::Ready(Err(TaskError::OutputTaken))
        ));
    }

    #[test]
    fn cancellation_before_first_poll_drops_the_future_without_polling() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));

        let task = spawn(PendingDropFuture {
            polls: Arc::clone(&polls),
            dropped: Arc::clone(&dropped),
            waker: None,
        })
        .unwrap();
        task.cancel();
        worker.process_posted();

        assert_eq!(polls.load(Ordering::Relaxed), 0);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Canceled)));
        assert!(worker.queues_are_empty());
    }

    #[test]
    fn cancellation_during_poll_runs_the_destructor_once_after_the_callback() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let cancellation = Arc::new(Mutex::new(None));
        let polls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));

        let task = spawn(SelfCancelFuture {
            cancellation: Arc::clone(&cancellation),
            polls: Arc::clone(&polls),
            dropped: Arc::clone(&dropped),
        })
        .unwrap();
        *cancellation.lock().unwrap_or_else(|error| error.into_inner()) =
            Some(task.cancellation_handle());

        worker.process_posted();
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        worker.process_posted();
        worker.process_posted();
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert!(worker.queues_are_empty());

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Canceled)));
    }

    #[test]
    fn cancellation_after_ready_keeps_the_output_available() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();

        let task = spawn(async { 7 }).unwrap();
        let cancellation = task.cancellation_handle();
        worker.process_posted();
        cancellation.cancel();

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(7)));
    }

    #[test]
    fn cancellation_wakes_an_awaiting_local_task() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let (waker_tx, waker_rx) = mpsc::channel();

        let task = spawn(PendingDropFuture {
            polls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
            waker: Some(waker_tx),
        })
        .unwrap();
        worker.process_posted();
        let _future_waker = waker_rx.recv().unwrap();
        let wakes = Arc::new(AtomicUsize::new(0));
        let task_waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));
        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(&task_waker);
        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);

        task.as_ref().get_ref().cancel();
        worker.process_posted();
        worker.process_posted();

        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Canceled)));
    }

    #[test]
    fn foreign_cancellation_drops_once_and_ignores_a_late_wake() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (waker_tx, waker_rx) = mpsc::channel();

        let task = spawn(PendingDropFuture {
            polls: Arc::clone(&polls),
            dropped: Arc::clone(&dropped),
            waker: Some(waker_tx),
        })
        .unwrap();
        let cancellation = task.cancellation_handle();
        worker.process_posted();
        let waker = waker_rx.recv().unwrap();

        thread::spawn(move || {
            cancellation.cancel();
            cancellation.cancel();
        })
        .join()
        .unwrap();
        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 0);

        worker.deliver_notification();
        worker.process_posted();
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        thread::spawn(move || waker.wake()).join().unwrap();
        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 0);
        assert!(worker.queues_are_empty());

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Canceled)));
    }

    #[test]
    fn attached_owner_drop_requests_cancellation() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));

        let task = spawn(PendingDropFuture {
            polls: Arc::clone(&polls),
            dropped: Arc::clone(&dropped),
            waker: None,
        })
        .unwrap();
        worker.process_posted();
        drop(task);
        worker.process_posted();
        worker.process_posted();

        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert!(worker.queues_are_empty());
    }

    #[test]
    fn detach_keeps_the_task_registered_until_worker_shutdown() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let attached_dropped = Arc::new(AtomicUsize::new(0));
        let detached_dropped = Arc::new(AtomicUsize::new(0));

        let attached = spawn(PendingDropFuture {
            polls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::clone(&attached_dropped),
            waker: None,
        })
        .unwrap();
        let detached = spawn(PendingDropFuture {
            polls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::clone(&detached_dropped),
            waker: None,
        })
        .unwrap();
        let cancellation = detached.detach();
        worker.process_posted();

        assert_eq!(attached_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(detached_dropped.load(Ordering::Relaxed), 0);
        assert!(!worker.task_registry_is_empty());
        assert_eq!(worker.release(), Ok(true));
        assert_eq!(attached_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(detached_dropped.load(Ordering::Relaxed), 1);
        cancellation.cancel();
        assert!(worker.queues_are_empty());
        assert!(worker.task_registry_is_empty());

        let mut attached = core::pin::pin!(attached);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(attached.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Canceled)));
    }

    #[test]
    fn notification_failure_is_a_task_terminal_state() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (waker_tx, waker_rx) = mpsc::channel();

        let task = spawn(PendingDropFuture {
            polls: Arc::clone(&polls),
            dropped: Arc::clone(&dropped),
            waker: Some(waker_tx),
        })
        .unwrap();
        worker.process_posted();
        let waker = waker_rx.recv().unwrap();

        current_scheduler().unwrap().close_notification();
        thread::spawn(move || waker.wake()).join().unwrap();

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::SchedulerFailed)));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(worker.release(), Ok(true));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn scheduler_failure_wakes_an_awaiting_local_task() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let (waker_tx, waker_rx) = mpsc::channel();

        let task = spawn(PendingDropFuture {
            polls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
            waker: Some(waker_tx),
        })
        .unwrap();
        worker.process_posted();
        let future_waker = waker_rx.recv().unwrap();
        let wakes = Arc::new(AtomicUsize::new(0));
        let task_waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));
        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(&task_waker);
        assert_eq!(task.as_mut().poll(&mut context), Poll::Pending);

        current_scheduler().unwrap().close_notification();
        thread::spawn(move || future_waker.wake()).join().unwrap();

        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::SchedulerFailed)));
    }

    #[test]
    fn local_tasks_are_posted_and_worker_can_reinitialize() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));

        let first_calls = Arc::clone(&calls);
        let first = spawn(async move {
            first_calls.fetch_add(1, Ordering::Relaxed);
            1
        })
        .unwrap();
        let second_calls = Arc::clone(&calls);
        let second = spawn(async move {
            second_calls.fetch_add(1, Ordering::Relaxed);
            2
        })
        .unwrap();

        assert!(!worker.queues_are_empty());
        worker.process_posted();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(worker.queues_are_empty());

        let mut first = core::pin::pin!(first);
        let mut second = core::pin::pin!(second);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(first.as_mut().poll(&mut context), Poll::Ready(Ok(1)));
        assert_eq!(second.as_mut().poll(&mut context), Poll::Ready(Ok(2)));

        assert_eq!(worker.release(), Ok(true));
        assert!(worker.queues_are_empty());
        assert_eq!(worker.release(), Ok(false));

        worker.init().unwrap();
        let task = spawn(async { 3 }).unwrap();
        worker.process_posted();
        let mut task = core::pin::pin!(task);
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(3)));
    }

    #[test]
    fn spawn_is_rejected_on_a_foreign_thread() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();

        let rejected = thread::spawn(|| matches!(spawn(async { 1 }), Err(SpawnError::WrongWorker)))
            .join()
            .unwrap();

        assert!(rejected);
    }

    #[test]
    fn foreign_wake_is_delivered_on_the_worker_thread() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let worker_thread = thread::current().id();
        let ready = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(Mutex::new(Vec::new()));
        let (waker_tx, waker_rx) = mpsc::channel();
        let local = Rc::new(());
        let future_ready = Arc::clone(&ready);
        let future_polls = Arc::clone(&polls);

        let task = spawn(poll_fn(move |context| {
            let _ = &local;
            future_polls
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(thread::current().id());
            if future_ready.load(Ordering::Acquire) {
                Poll::Ready(7)
            } else {
                waker_tx.send(context.waker().clone()).unwrap();
                Poll::Pending
            }
        }))
        .unwrap();

        worker.process_posted();
        let waker = waker_rx.recv().unwrap();
        let remote_ready = Arc::clone(&ready);
        let remote_thread = thread::spawn(move || {
            remote_ready.store(true, Ordering::Release);
            waker.wake();
            thread::current().id()
        })
        .join()
        .unwrap();

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 0);
        worker.deliver_notification();
        let polls = polls.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(polls.as_slice(), &[worker_thread, worker_thread]);
        assert_ne!(worker_thread, remote_thread);
        drop(polls);

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(7)));
    }

    #[test]
    fn local_self_wake_reposts_after_the_current_callback() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let future_polls = Arc::clone(&polls);

        let task = spawn(poll_fn(move |context| {
            if future_polls.fetch_add(1, Ordering::Relaxed) == 0 {
                context.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }))
        .unwrap();

        worker.process_posted();
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert!(!worker.queues_are_empty());
        worker.process_posted();
        assert_eq!(polls.load(Ordering::Relaxed), 2);

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(())));
    }

    #[test]
    fn notification_failure_drains_local_tasks_on_the_owner_callback() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let scheduler = current_scheduler().unwrap();
        let owner = thread::current().id();
        let polls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (waker_tx, waker_rx) = mpsc::channel();
        let (drop_tx, drop_rx) = mpsc::channel();
        let future_polls = Arc::clone(&polls);

        struct DropThread {
            sender: mpsc::Sender<ThreadId>,
            dropped: Arc<AtomicUsize>,
        }

        impl Drop for DropThread {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                let _ = self.sender.send(thread::current().id());
            }
        }

        let drop_thread = DropThread { sender: drop_tx, dropped: Arc::clone(&dropped) };
        let task = spawn(poll_fn(move |context| {
            future_polls.fetch_add(1, Ordering::Relaxed);
            waker_tx.send(context.waker().clone()).unwrap();
            let _ = &drop_thread;
            Poll::<()>::Pending
        }))
        .unwrap();

        worker.process_posted();
        current_scheduler().unwrap().close_notification();
        let waker = waker_rx.recv().unwrap();
        thread::spawn(move || waker.wake()).join().unwrap();

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 0);
        assert!(matches!(spawn(async {}), Err(SpawnError::ShuttingDown)));
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);

        worker.deliver_notification();

        assert_eq!(drop_rx.try_recv().unwrap(), owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let inner = scheduler.lock();
        assert!(inner.queue.is_empty());
        assert!(inner.quarantined.is_empty());
        drop(inner);
        assert!(worker.queues_are_empty());
        assert!(worker.task_registry_is_empty());

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::SchedulerFailed)));
    }

    #[test]
    fn shutdown_drains_a_foreign_handoff_started_after_the_first_drain() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let scheduler = current_scheduler().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let task = spawn(PendingDropFuture {
            polls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::clone(&dropped),
            waker: None,
        })
        .unwrap();
        let runnable = scheduler.lock().queue.pop_front().expect("initial runnable");
        let foreign_scheduler = Arc::clone(&scheduler);
        let foreign = thread::spawn(move || {
            loop {
                if !matches!(foreign_scheduler.lock().phase, SchedulerPhase::Running) {
                    break;
                }
                thread::yield_now();
            }
            match foreign_scheduler.queue(runnable) {
                ScheduleAction::RejectedForeign(runnable) => {
                    foreign_scheduler.quarantine(runnable);
                }
                _ => panic!("stopping scheduler accepted a foreign runnable"),
            }
        });

        assert_eq!(worker.release(), Ok(true));
        foreign.join().unwrap();

        let inner = scheduler.lock();
        assert!(inner.queue.is_empty());
        assert!(inner.quarantined.is_empty());
        drop(inner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Canceled)));
    }

    #[test]
    fn late_foreign_wake_after_shutdown_does_not_enqueue_a_runnable() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let scheduler = current_scheduler().unwrap();
        let (waker_tx, waker_rx) = mpsc::channel();
        let task = spawn(poll_fn(move |context| -> Poll<()> {
            waker_tx.send(context.waker().clone()).unwrap();
            Poll::Pending
        }))
        .unwrap();

        worker.process_posted();
        assert_eq!(worker.release(), Ok(true));
        let waker = waker_rx.recv().unwrap();
        thread::spawn(move || waker.wake()).join().unwrap();

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 0);
        let inner = scheduler.lock();
        assert!(inner.queue.is_empty());
        assert!(inner.quarantined.is_empty());
        drop(inner);

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Canceled)));

        worker.init().unwrap();
        assert!(scheduler.lock().quarantined.is_empty());
    }

    struct DropFuture {
        scheduler: Arc<Scheduler>,
        dropped: Arc<AtomicUsize>,
        queue_unlocked: Arc<AtomicBool>,
    }

    impl Future for DropFuture {
        type Output = ();

        fn poll(self: core::pin::Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for DropFuture {
        fn drop(&mut self) {
            self.queue_unlocked.store(self.scheduler.inner.try_lock().is_ok(), Ordering::Release);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn shutdown_drops_queued_runnables_outside_the_queue_lock() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let scheduler = current_scheduler().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let queue_unlocked = Arc::new(AtomicBool::new(false));
        let task = spawn(DropFuture {
            scheduler,
            dropped: Arc::clone(&dropped),
            queue_unlocked: Arc::clone(&queue_unlocked),
        })
        .unwrap();

        task.detach();
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(worker.release(), Ok(true));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert!(queue_unlocked.load(Ordering::Acquire));
        assert!(worker.queues_are_empty());
    }

    #[test]
    fn scheduler_recovers_after_queue_poisoning() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let scheduler = current_scheduler().unwrap();

        let _ = thread::spawn(move || {
            let _queue = scheduler.inner.lock().unwrap();
            panic!("poison scheduler queue");
        })
        .join();

        let task = spawn(async { 9 }).unwrap();
        worker.process_posted();
        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(9)));
    }

    #[test]
    fn shutdown_waits_for_scheduler_callbacks_to_stop() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let lease = Rc::new(RefCell::new(worker.lease.take().expect("worker lease")));
        let result = Arc::new(Mutex::new(None));
        let future_result = Arc::clone(&result);
        let future_lease = Rc::clone(&lease);

        let task = spawn(poll_fn(move |_| -> Poll<()> {
            *future_result.lock().unwrap_or_else(|error| error.into_inner()) =
                Some(future_lease.borrow_mut().release());
            Poll::Pending
        }))
        .unwrap();

        worker.process_posted();
        assert_eq!(
            *result.lock().unwrap_or_else(|error| error.into_inner()),
            Some(Err(SchedulerShutdownError::Processing))
        );
        drop(task);
        assert_eq!(lease.borrow_mut().release(), Ok(true));
    }

    #[test]
    fn shutdown_allows_a_different_worker_to_initialize() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        assert_eq!(worker.release(), Ok(true));

        let result = thread::spawn(|| {
            let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
            let log = unsafe { LogRef::from_raw(&raw mut log) }.expect("test logger");
            let mut lease = unsafe { acquire_worker(log) }.expect("foreign worker lease");
            lease.release()
        })
        .join()
        .unwrap();

        assert_eq!(result, Ok(true));
    }
}
