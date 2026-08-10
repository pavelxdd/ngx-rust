use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use core::cell::RefCell;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::ptr::NonNull;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};

pub use async_task::Task;
use async_task::{Runnable, ScheduleInfo, WithInfo};

use crate::event::{NotifyError, PostedEvent, PostedEventCallback, PostedQueue, notify};
use crate::ffi::{ngx_event_t, ngx_log_t};

static ACTIVE_SCHEDULER: OnceLock<Mutex<Option<Arc<Scheduler>>>> = OnceLock::new();

#[cfg(test)]
static SCHEDULER_TESTS: Mutex<()> = Mutex::new(());

std::thread_local! {
    static WORKER_SCHEDULER: RefCell<Option<WorkerScheduler>> = const { RefCell::new(None) };
}

/// Failure returned while initializing the current nginx worker scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerInitError {
    /// Another worker scheduler is still active in this process.
    AlreadyInitialized,
    /// The selected event module cannot deliver cross-thread notifications.
    Notify(NotifyError),
}

/// Failure returned while spawning an async task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnError {
    /// The current worker did not initialize its scheduler.
    Uninitialized,
    /// The caller is not the initialized nginx worker thread.
    WrongWorker,
    /// The worker scheduler has stopped accepting tasks.
    ShuttingDown,
}

/// Failure returned while shutting down an async worker scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerShutdownError {
    /// Another thread owns the active worker scheduler.
    WrongWorker,
    /// A scheduler callback is currently polling queued tasks.
    Processing,
}

type SchedulerPostedCallback = for<'callback> fn(PostedEventCallback<'callback, Arc<Scheduler>>);
type SchedulerPostedEvent = PostedEvent<Arc<Scheduler>, SchedulerPostedCallback>;

struct WorkerScheduler {
    scheduler: Arc<Scheduler>,
    posted: Pin<Box<SchedulerPostedEvent>>,
}

impl WorkerScheduler {
    fn new(log: NonNull<ngx_log_t>, scheduler: Arc<Scheduler>) -> Self {
        Self {
            posted: Box::pin(PostedEvent::new(
                log,
                Arc::clone(&scheduler),
                posted_scheduler_handler as SchedulerPostedCallback,
            )),
            scheduler,
        }
    }

    fn post(&mut self) -> bool {
        self.posted.as_mut().post(PostedQueue::Next).is_ok()
    }

    fn shutdown(&mut self) {
        self.posted.as_mut().shutdown();
    }
}

struct Scheduler {
    owner: ThreadId,
    inner: Mutex<SchedulerInner>,
}

struct SchedulerInner {
    phase: SchedulerPhase,
    queue: VecDeque<Runnable>,
    // A local runnable may only be destroyed by its owner thread.
    quarantined: VecDeque<Runnable>,
    processing: bool,
}

enum SchedulerPhase {
    Running,
    Stopping,
    Stopped,
}

enum ScheduleAction {
    Deferred,
    Foreign,
    Local,
    RejectedForeign(Runnable),
    RejectedLocal(Runnable),
}

impl Scheduler {
    fn new(worker: ThreadId) -> Self {
        Self {
            owner: worker,
            inner: Mutex::new(SchedulerInner {
                phase: SchedulerPhase::Running,
                queue: VecDeque::new(),
                quarantined: VecDeque::new(),
                processing: false,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SchedulerInner> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn check_spawn(&self) -> Result<(), SpawnError> {
        let current = thread::current().id();
        let inner = self.lock();

        match &inner.phase {
            SchedulerPhase::Running if self.owner == current => Ok(()),
            SchedulerPhase::Running => Err(SpawnError::WrongWorker),
            SchedulerPhase::Stopping | SchedulerPhase::Stopped => Err(SpawnError::ShuttingDown),
        }
    }

    fn queue(&self, runnable: Runnable) -> ScheduleAction {
        let current = thread::current().id();
        let mut inner = self.lock();

        match &inner.phase {
            SchedulerPhase::Running => {
                let local = self.owner == current;
                inner.queue.push_back(runnable);
                if inner.processing {
                    ScheduleAction::Deferred
                } else if local {
                    ScheduleAction::Local
                } else {
                    ScheduleAction::Foreign
                }
            }
            SchedulerPhase::Stopping | SchedulerPhase::Stopped if self.owner == current => {
                ScheduleAction::RejectedLocal(runnable)
            }
            SchedulerPhase::Stopping | SchedulerPhase::Stopped => {
                ScheduleAction::RejectedForeign(runnable)
            }
        }
    }

    fn schedule(self: &Arc<Self>, runnable: Runnable, _info: ScheduleInfo) {
        match self.queue(runnable) {
            ScheduleAction::Deferred => {}
            ScheduleAction::Local => {
                if !self.post_current() {
                    self.stop_and_drop();
                }
            }
            ScheduleAction::Foreign => {
                if unsafe { notify(notification_handler) }.is_err() {
                    self.fail_from_foreign_thread();
                }
            }
            ScheduleAction::RejectedLocal(runnable) => drop(runnable),
            ScheduleAction::RejectedForeign(runnable) => self.quarantine(runnable),
        }
    }

    fn schedule_initial(self: &Arc<Self>, runnable: Runnable) -> Result<(), SpawnError> {
        match self.queue(runnable) {
            ScheduleAction::Deferred => Ok(()),
            ScheduleAction::Local => {
                if self.post_current() {
                    Ok(())
                } else {
                    self.stop_and_drop();
                    Err(SpawnError::ShuttingDown)
                }
            }
            ScheduleAction::Foreign => {
                if unsafe { notify(notification_handler) }.is_ok() {
                    Ok(())
                } else {
                    self.fail_from_foreign_thread();
                    Err(SpawnError::ShuttingDown)
                }
            }
            ScheduleAction::RejectedLocal(runnable) => {
                drop(runnable);
                Err(SpawnError::ShuttingDown)
            }
            ScheduleAction::RejectedForeign(runnable) => {
                self.quarantine(runnable);
                Err(SpawnError::ShuttingDown)
            }
        }
    }

    fn post_current(self: &Arc<Self>) -> bool {
        WORKER_SCHEDULER.with(|worker| {
            let mut worker = worker.borrow_mut();
            let Some(worker) = worker.as_mut() else {
                return false;
            };
            if !Arc::ptr_eq(&worker.scheduler, self) {
                return false;
            }
            worker.post()
        })
    }

    fn process(&self) -> bool {
        let current = thread::current().id();
        let runnables = {
            let mut inner = self.lock();
            match &inner.phase {
                SchedulerPhase::Running if self.owner == current && !inner.processing => {
                    inner.processing = true;
                    mem::take(&mut inner.queue)
                }
                _ => return false,
            }
        };
        let processing = ProcessingGuard { scheduler: self };

        for runnable in runnables {
            runnable.run();
        }

        processing.finish()
    }

    fn finish_processing(&self) -> bool {
        let current = thread::current().id();
        let mut inner = self.lock();
        inner.processing = false;

        matches!(&inner.phase, SchedulerPhase::Running if self.owner == current)
            && !inner.queue.is_empty()
    }

    fn processing_on_current_worker(&self) -> bool {
        let current = thread::current().id();
        let inner = self.lock();

        self.owner == current
            && matches!(&inner.phase, SchedulerPhase::Running | SchedulerPhase::Stopping)
            && inner.processing
    }

    fn fail_from_foreign_thread(&self) {
        let mut inner = self.lock();
        if matches!(&inner.phase, SchedulerPhase::Running) {
            inner.phase = SchedulerPhase::Stopping;
        }
        let mut queued = mem::take(&mut inner.queue);
        inner.quarantined.append(&mut queued);
    }

    fn quarantine(&self, runnable: Runnable) {
        self.lock().quarantined.push_back(runnable);
    }

    fn drain_for_shutdown(&self) -> VecDeque<Runnable> {
        let mut inner = self.lock();
        if matches!(&inner.phase, SchedulerPhase::Running) {
            inner.phase = SchedulerPhase::Stopping;
        }
        let mut queued = mem::take(&mut inner.queue);
        queued.append(&mut inner.quarantined);
        queued
    }

    fn stop_and_drop(&self) {
        drop(self.drain_for_shutdown());
    }

    fn finish_shutdown(&self) {
        let mut inner = self.lock();

        if matches!(&inner.phase, SchedulerPhase::Stopping) {
            inner.phase = SchedulerPhase::Stopped;
        }
    }

    fn is_stopped(&self) -> bool {
        matches!(&self.lock().phase, SchedulerPhase::Stopped)
    }
}

struct ProcessingGuard<'scheduler> {
    scheduler: &'scheduler Scheduler,
}

impl ProcessingGuard<'_> {
    fn finish(self) -> bool {
        let repost = self.scheduler.finish_processing();
        mem::forget(self);
        repost
    }
}

impl Drop for ProcessingGuard<'_> {
    fn drop(&mut self) {
        self.scheduler.finish_processing();
    }
}

fn posted_scheduler_handler(mut event: PostedEventCallback<'_, Arc<Scheduler>>) {
    if event.state().process() {
        let _ = event.post(PostedQueue::Next);
    }
}

unsafe extern "C" fn notification_handler(_event: *mut ngx_event_t) {
    let scheduler = WORKER_SCHEDULER
        .with(|worker| worker.borrow().as_ref().map(|worker| Arc::clone(&worker.scheduler)));

    if let Some(scheduler) = scheduler {
        if scheduler.process() && !scheduler.post_current() {
            scheduler.stop_and_drop();
        }
    }
}

fn active_scheduler() -> &'static Mutex<Option<Arc<Scheduler>>> {
    ACTIVE_SCHEDULER.get_or_init(|| Mutex::new(None))
}

fn current_scheduler() -> Result<Arc<Scheduler>, SpawnError> {
    let scheduler = active_scheduler()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(Arc::clone)
        .ok_or(SpawnError::Uninitialized)?;
    scheduler.check_spawn()?;
    Ok(scheduler)
}

fn clear_active_scheduler(scheduler: &Arc<Scheduler>) {
    let mut active = active_scheduler().lock().unwrap_or_else(|error| error.into_inner());
    if active.as_ref().is_some_and(|active| Arc::ptr_eq(active, scheduler)) {
        *active = None;
    }
}

/// Initializes the async scheduler for the current nginx worker.
///
/// Call this from the module's process-start hook before calling [`spawn`]. The selected nginx
/// event module must accept the notification callback so cloned wakers can safely wake from a
/// foreign thread.
pub fn init_worker(log: NonNull<ngx_log_t>) -> Result<(), SchedulerInitError> {
    let stopped = WORKER_SCHEDULER.with(|worker| match worker.borrow().as_ref() {
        None => Ok(false),
        Some(worker) if worker.scheduler.is_stopped() => Ok(true),
        Some(_) => Err(SchedulerInitError::AlreadyInitialized),
    })?;
    if stopped {
        let worker = WORKER_SCHEDULER
            .with(|worker| worker.borrow_mut().take())
            .ok_or(SchedulerInitError::AlreadyInitialized)?;
        drop(worker.scheduler.drain_for_shutdown());
        drop(worker);
    }

    let scheduler = Arc::new(Scheduler::new(thread::current().id()));
    {
        let mut active = active_scheduler().lock().unwrap_or_else(|error| error.into_inner());
        if active.is_some() {
            return Err(SchedulerInitError::AlreadyInitialized);
        }
        *active = Some(Arc::clone(&scheduler));
    }
    WORKER_SCHEDULER.with(|worker| {
        *worker.borrow_mut() = Some(WorkerScheduler::new(log, scheduler));
    });

    if let Err(error) = unsafe { notify(notification_handler) } {
        let _ = shutdown_worker();
        return Err(SchedulerInitError::Notify(error));
    }

    Ok(())
}

/// Stops the async scheduler for the current nginx worker.
///
/// Returns `Ok(false)` when this thread has no active scheduler. Call this only after nginx has
/// stopped invoking scheduler callbacks; calling it from a running task returns
/// [`SchedulerShutdownError::Processing`].
pub fn shutdown_worker() -> Result<bool, SchedulerShutdownError> {
    let scheduler = match WORKER_SCHEDULER.with(|worker| {
        let worker = worker.borrow();
        let Some(worker) = worker.as_ref() else {
            return Ok(None);
        };
        if worker.scheduler.processing_on_current_worker() {
            return Err(SchedulerShutdownError::Processing);
        }
        Ok(Some(Arc::clone(&worker.scheduler)))
    }) {
        Ok(Some(scheduler)) => scheduler,
        Ok(None) => {
            if active_scheduler().lock().unwrap_or_else(|error| error.into_inner()).is_some() {
                return Err(SchedulerShutdownError::WrongWorker);
            }
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let was_stopped = scheduler.is_stopped();
    let queued = scheduler.drain_for_shutdown();
    WORKER_SCHEDULER.with(|worker| {
        let mut worker = worker.borrow_mut();
        let Some(worker) = worker.as_mut() else {
            return Err(SchedulerShutdownError::WrongWorker);
        };
        if !Arc::ptr_eq(&worker.scheduler, &scheduler) {
            return Err(SchedulerShutdownError::WrongWorker);
        }
        worker.shutdown();
        Ok(())
    })?;
    scheduler.finish_shutdown();
    clear_active_scheduler(&scheduler);
    drop(queued);

    Ok(!was_stopped)
}

/// Creates a new task running on the NGINX event loop.
///
/// This function must be called after [`init_worker`] on the owning nginx worker thread. The task
/// is always polled on that thread even when its waker is invoked from another thread.
pub fn spawn<F, T>(future: F) -> Result<Task<T>, SpawnError>
where
    F: Future<Output = T> + 'static,
    T: 'static,
{
    let scheduler = current_scheduler()?;
    let task_scheduler = Arc::clone(&scheduler);
    let task_scheduler = WithInfo(move |runnable, info| task_scheduler.schedule(runnable, info));
    let (runnable, task) = async_task::spawn_local(future, task_scheduler);

    if let Err(error) = scheduler.schedule_initial(runnable) {
        drop(task);
        return Err(error);
    }

    Ok(task)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn spawn_rejects_before_worker_initialization() {
        let _scheduler = SCHEDULER_TESTS.lock().unwrap_or_else(|error| error.into_inner());
        let result = spawn(async { 7 });

        assert!(matches!(result, Err(SpawnError::Uninitialized)));
    }
}

#[cfg(all(test, feature = "test-link"))]
mod worker_tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::future::{Future, poll_fn};
    use core::mem::MaybeUninit;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::sync::{Mutex, MutexGuard, mpsc};
    use std::thread;

    use super::*;
    use crate::event::NotifyError;
    use crate::ffi::{
        NGX_ERROR, NGX_OK, ngx_cycle_t, ngx_event_actions, ngx_event_handler_pt,
        ngx_event_move_posted_next, ngx_event_process_posted, ngx_int_t, ngx_log_t,
        ngx_posted_events, ngx_posted_next_events, ngx_queue_empty, ngx_queue_init,
    };

    static NOTIFIED_HANDLER: Mutex<ngx_event_handler_pt> = Mutex::new(None);
    static NOTIFY_SUCCEEDS: AtomicBool = AtomicBool::new(true);
    static NOTIFY_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct TestGlobals {
        _nginx: MutexGuard<'static, ()>,
        _scheduler: MutexGuard<'static, ()>,
        previous_notify: Option<unsafe extern "C" fn(ngx_event_handler_pt) -> ngx_int_t>,
    }

    impl TestGlobals {
        fn new() -> Self {
            let nginx = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let scheduler = SCHEDULER_TESTS.lock().unwrap_or_else(|error| error.into_inner());
            assert_eq!(shutdown_worker(), Ok(false));

            let previous_notify = unsafe { ngx_event_actions.notify };
            reset_event_globals();
            NOTIFY_SUCCEEDS.store(true, Ordering::Relaxed);
            NOTIFY_CALLS.store(0, Ordering::Relaxed);
            *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = None;
            unsafe { ngx_event_actions.notify = Some(test_notify) };

            Self { _nginx: nginx, _scheduler: scheduler, previous_notify }
        }
    }

    impl Drop for TestGlobals {
        fn drop(&mut self) {
            let _ = shutdown_worker();
            reset_event_globals();
            unsafe { ngx_event_actions.notify = self.previous_notify };
            *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = None;
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

    struct TestWorker {
        _globals: TestGlobals,
        cycle: Box<TestCycle>,
    }

    impl TestWorker {
        fn new() -> Self {
            Self { _globals: TestGlobals::new(), cycle: TestCycle::new() }
        }

        fn init(&mut self) -> Result<(), SchedulerInitError> {
            init_worker(NonNull::from(&mut self.cycle.log))
        }

        fn process_posted(&mut self) {
            unsafe {
                ngx_event_move_posted_next(self.cycle.raw());
                ngx_event_process_posted(self.cycle.raw(), &raw mut ngx_posted_events);
            }
        }

        fn deliver_notification(&self) {
            let handler = *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner());
            let handler = handler.expect("notification handler was not registered");
            unsafe { handler(ptr::null_mut()) };
        }

        fn queues_are_empty(&self) -> bool {
            unsafe {
                ngx_queue_empty(&raw const ngx_posted_events)
                    && ngx_queue_empty(&raw const ngx_posted_next_events)
            }
        }
    }

    impl Drop for TestWorker {
        fn drop(&mut self) {
            let _ = shutdown_worker();
        }
    }

    fn reset_event_globals() {
        unsafe {
            ngx_queue_init(&raw mut ngx_posted_events);
            ngx_queue_init(&raw mut ngx_posted_next_events);
        }
    }

    unsafe extern "C" fn test_notify(handler: ngx_event_handler_pt) -> ngx_int_t {
        NOTIFY_CALLS.fetch_add(1, Ordering::Relaxed);
        *NOTIFIED_HANDLER.lock().unwrap_or_else(|error| error.into_inner()) = handler;

        if NOTIFY_SUCCEEDS.load(Ordering::Relaxed) { NGX_OK as _ } else { NGX_ERROR as _ }
    }

    #[test]
    fn init_rejects_missing_or_failed_notification_hooks() {
        let mut worker = TestWorker::new();

        unsafe { ngx_event_actions.notify = None };
        assert_eq!(worker.init(), Err(SchedulerInitError::Notify(NotifyError::Unavailable)));
        assert!(matches!(spawn(async { 1 }), Err(SpawnError::Uninitialized)));

        unsafe { ngx_event_actions.notify = Some(test_notify) };
        NOTIFY_SUCCEEDS.store(false, Ordering::Relaxed);
        assert_eq!(worker.init(), Err(SchedulerInitError::Notify(NotifyError::Failed)));
        assert!(matches!(spawn(async { 1 }), Err(SpawnError::Uninitialized)));
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
        assert_eq!(first.as_mut().poll(&mut context), Poll::Ready(1));
        assert_eq!(second.as_mut().poll(&mut context), Poll::Ready(2));

        assert_eq!(shutdown_worker(), Ok(true));
        assert!(worker.queues_are_empty());
        assert_eq!(shutdown_worker(), Ok(false));

        worker.init().unwrap();
        let task = spawn(async { 3 }).unwrap();
        worker.process_posted();
        let mut task = core::pin::pin!(task);
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(3));
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

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 2);
        worker.deliver_notification();
        let polls = polls.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(polls.as_slice(), &[worker_thread, worker_thread]);
        assert_ne!(worker_thread, remote_thread);
        drop(polls);

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(7));
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
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(()));
    }

    #[test]
    fn notification_failure_stops_admission_without_a_dormant_runnable() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let scheduler = current_scheduler().unwrap();
        let ready = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let (waker_tx, waker_rx) = mpsc::channel();
        let future_ready = Arc::clone(&ready);
        let future_polls = Arc::clone(&polls);

        let _task = spawn(poll_fn(move |context| {
            future_polls.fetch_add(1, Ordering::Relaxed);
            if future_ready.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                waker_tx.send(context.waker().clone()).unwrap();
                Poll::Pending
            }
        }))
        .unwrap();

        worker.process_posted();
        NOTIFY_SUCCEEDS.store(false, Ordering::Relaxed);
        let waker = waker_rx.recv().unwrap();
        let remote_ready = Arc::clone(&ready);
        thread::spawn(move || {
            remote_ready.store(true, Ordering::Release);
            waker.wake();
        })
        .join()
        .unwrap();

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 2);
        assert!(matches!(spawn(async {}), Err(SpawnError::ShuttingDown)));
        worker.deliver_notification();
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        let inner = scheduler.lock();
        assert!(inner.queue.is_empty());
        assert_eq!(inner.quarantined.len(), 1);
        drop(inner);
        assert!(worker.queues_are_empty());
    }

    #[test]
    fn late_foreign_wake_is_quarantined_until_its_owner_reinitializes() {
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
        assert_eq!(shutdown_worker(), Ok(true));
        let waker = waker_rx.recv().unwrap();
        thread::spawn(move || waker.wake()).join().unwrap();

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 1);
        let inner = scheduler.lock();
        assert!(inner.queue.is_empty());
        assert_eq!(inner.quarantined.len(), 1);
        drop(inner);

        worker.init().unwrap();
        assert!(scheduler.lock().quarantined.is_empty());
        drop(task);
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
        assert_eq!(shutdown_worker(), Ok(true));
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
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(9));
    }

    #[test]
    fn shutdown_waits_for_scheduler_callbacks_to_stop() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        let result = Arc::new(Mutex::new(None));
        let future_result = Arc::clone(&result);

        let task = spawn(poll_fn(move |_| -> Poll<()> {
            *future_result.lock().unwrap_or_else(|error| error.into_inner()) =
                Some(shutdown_worker());
            Poll::Pending
        }))
        .unwrap();

        worker.process_posted();
        assert_eq!(
            *result.lock().unwrap_or_else(|error| error.into_inner()),
            Some(Err(SchedulerShutdownError::Processing))
        );
        drop(task);
        assert_eq!(shutdown_worker(), Ok(true));
    }

    #[test]
    fn shutdown_allows_a_different_worker_to_initialize() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();
        assert_eq!(shutdown_worker(), Ok(true));

        let result = thread::spawn(|| {
            let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
            let init = init_worker(NonNull::from(&mut log));
            let shutdown = shutdown_worker();
            (init, shutdown)
        })
        .join()
        .unwrap();

        assert_eq!(result, (Ok(()), Ok(true)));
    }
}
