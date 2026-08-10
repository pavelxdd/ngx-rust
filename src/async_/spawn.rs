use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::rc::Rc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::mem;
use core::panic::AssertUnwindSafe;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use std::panic::catch_unwind;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};

use async_task::{Runnable, ScheduleInfo, Task as RawTask, WithInfo};

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

/// Terminal failure returned by a [`LocalTask`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskError {
    /// The task's owner canceled it before it produced an output.
    Canceled,
    /// The task's future panicked while being polled.
    Panicked,
    /// The worker scheduler could no longer deliver task wakeups.
    SchedulerFailed,
    /// The task output was already consumed by an earlier poll.
    OutputTaken,
}

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum TaskStatus {
    Active,
    CancelRequested,
    Ready,
    Canceled,
    Panicked,
    SchedulerFailed,
}

impl TaskStatus {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Active,
            1 => Self::CancelRequested,
            2 => Self::Ready,
            3 => Self::Canceled,
            4 => Self::Panicked,
            _ => Self::SchedulerFailed,
        }
    }

    fn error(self) -> Option<TaskError> {
        match self {
            Self::Canceled => Some(TaskError::Canceled),
            Self::Panicked => Some(TaskError::Panicked),
            Self::SchedulerFailed => Some(TaskError::SchedulerFailed),
            Self::Active | Self::CancelRequested | Self::Ready => None,
        }
    }
}

struct TaskControl {
    scheduler: Weak<Scheduler>,
    status: AtomicU8,
    waker: Mutex<Option<Waker>>,
}

impl TaskControl {
    fn new(scheduler: &Arc<Scheduler>) -> Arc<Self> {
        Arc::new(Self {
            scheduler: Arc::downgrade(scheduler),
            status: AtomicU8::new(TaskStatus::Active as u8),
            waker: Mutex::new(None),
        })
    }

    fn status(&self) -> TaskStatus {
        TaskStatus::from_raw(self.status.load(Ordering::Acquire))
    }

    fn set_waker(&self, waker: &Waker) {
        *self.waker.lock().unwrap_or_else(|error| error.into_inner()) = Some(waker.clone());
    }

    fn wake(&self) {
        let waker = self.waker.lock().unwrap_or_else(|error| error.into_inner()).take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn request_cancel(control: &Arc<Self>) {
        let mut status = control.status();

        loop {
            match status {
                TaskStatus::Active => match control.status.compare_exchange_weak(
                    TaskStatus::Active as u8,
                    TaskStatus::CancelRequested as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        if let Some(scheduler) = control.scheduler.upgrade() {
                            scheduler.request_cancel(Arc::clone(control));
                        } else {
                            control.finish(TaskStatus::SchedulerFailed);
                        }
                        return;
                    }
                    Err(next) => status = TaskStatus::from_raw(next),
                },
                TaskStatus::CancelRequested
                | TaskStatus::Ready
                | TaskStatus::Canceled
                | TaskStatus::Panicked
                | TaskStatus::SchedulerFailed => return,
            }
        }
    }

    fn fail_scheduler(&self) {
        let mut status = self.status();

        loop {
            match status {
                TaskStatus::Active | TaskStatus::CancelRequested => {
                    match self.status.compare_exchange_weak(
                        status as u8,
                        TaskStatus::SchedulerFailed as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            self.wake();
                            return;
                        }
                        Err(next) => status = TaskStatus::from_raw(next),
                    }
                }
                TaskStatus::Ready
                | TaskStatus::Canceled
                | TaskStatus::Panicked
                | TaskStatus::SchedulerFailed => return,
            }
        }
    }

    fn finish(&self, desired: TaskStatus) -> TaskStatus {
        let mut status = self.status();

        loop {
            let next = match status {
                TaskStatus::Active => desired,
                TaskStatus::CancelRequested => TaskStatus::Canceled,
                TaskStatus::Ready
                | TaskStatus::Canceled
                | TaskStatus::Panicked
                | TaskStatus::SchedulerFailed => return status,
            };

            match self.status.compare_exchange_weak(
                status as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if next.error().is_some() {
                        self.wake();
                    }
                    return next;
                }
                Err(current) => status = TaskStatus::from_raw(current),
            }
        }
    }
}

struct TaskState<T> {
    result: Cell<Option<Result<T, TaskError>>>,
}

impl<T> TaskState<T> {
    fn new() -> Rc<Self> {
        Rc::new(Self { result: Cell::new(None) })
    }

    fn resolve(&self, result: Result<T, TaskError>) {
        if let Some(existing) = self.result.take() {
            self.result.set(Some(existing));
            return;
        }

        self.result.set(Some(result));
    }
}

/// A worker-local handle for a spawned async task.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ngx::async_::LocalTask<()>>();
/// ```
#[must_use = "dropping an attached task requests cancellation"]
pub struct LocalTask<T> {
    control: Arc<TaskControl>,
    state: Rc<TaskState<T>>,
    attached: bool,
    completed: bool,
}

impl<T> LocalTask<T> {
    /// Returns a handle that can request cancellation from any thread.
    pub fn cancellation_handle(&self) -> CancellationHandle {
        CancellationHandle { control: Arc::clone(&self.control) }
    }

    /// Requests cancellation of this task on its owning worker.
    pub fn cancel(&self) {
        TaskControl::request_cancel(&self.control);
    }

    /// Transfers task ownership to the worker scheduler and returns a cancellation handle.
    pub fn detach(mut self) -> CancellationHandle {
        self.attached = false;
        self.cancellation_handle()
    }

    pub(crate) fn into_attached(self) -> AttachedTask<T> {
        AttachedTask { _task: self }
    }
}

impl<T> Drop for LocalTask<T> {
    fn drop(&mut self) {
        if self.attached && !self.completed {
            TaskControl::request_cancel(&self.control);
        }
    }
}

impl<T> Future for LocalTask<T> {
    type Output = Result<T, TaskError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        if this.completed {
            return Poll::Ready(Err(TaskError::OutputTaken));
        }

        if let Some(result) = this.state.result.take() {
            this.completed = true;
            return Poll::Ready(result);
        }

        if let Some(error) = this.control.status().error() {
            this.completed = true;
            return Poll::Ready(Err(error));
        }

        this.control.set_waker(context.waker());
        if let Some(error) = this.control.status().error() {
            this.completed = true;
            return Poll::Ready(Err(error));
        }
        Poll::Pending
    }
}

/// A cancellation handle that never polls or drops a worker-local future.
#[derive(Clone)]
pub struct CancellationHandle {
    control: Arc<TaskControl>,
}

impl CancellationHandle {
    /// Requests cancellation on the task's owning worker.
    pub fn cancel(&self) {
        TaskControl::request_cancel(&self.control);
    }
}

pub(crate) struct AttachedTask<T> {
    _task: LocalTask<T>,
}

type SchedulerPostedCallback = for<'callback> fn(PostedEventCallback<'callback, Arc<Scheduler>>);
type SchedulerPostedEvent = PostedEvent<Arc<Scheduler>, SchedulerPostedCallback>;

struct RegisteredTask {
    control: Arc<TaskControl>,
    _task: RawTask<()>,
}

struct WorkerScheduler {
    scheduler: Arc<Scheduler>,
    posted: Pin<Box<SchedulerPostedEvent>>,
    tasks: Vec<RegisteredTask>,
    completed: Vec<Arc<TaskControl>>,
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
            tasks: Vec::new(),
            completed: Vec::new(),
        }
    }

    fn post(&mut self) -> bool {
        self.posted.as_mut().post(PostedQueue::Next).is_ok()
    }

    fn shutdown(&mut self) {
        self.posted.as_mut().shutdown();
    }

    fn register_task(&mut self, control: Arc<TaskControl>, task: RawTask<()>) {
        self.tasks.push(RegisteredTask { control, _task: task });
    }

    fn take_task(&mut self, control: &Arc<TaskControl>) -> Option<RegisteredTask> {
        let position = self.tasks.iter().position(|task| Arc::ptr_eq(&task.control, control))?;
        Some(self.tasks.swap_remove(position))
    }

    fn task_completed(&mut self, control: Arc<TaskControl>) {
        if !self.completed.iter().any(|completed| Arc::ptr_eq(completed, &control)) {
            self.completed.push(control);
        }
    }

    fn take_completed(&mut self) -> Vec<RegisteredTask> {
        let completed = mem::take(&mut self.completed);
        let mut tasks = Vec::new();

        for control in completed {
            if let Some(task) = self.take_task(&control) {
                tasks.push(task);
            }
        }

        tasks
    }

    fn take_all_tasks(&mut self) -> Vec<RegisteredTask> {
        self.completed.clear();
        mem::take(&mut self.tasks)
    }
}

struct Scheduler {
    owner: ThreadId,
    inner: Mutex<SchedulerInner>,
    controls: Mutex<Vec<Weak<TaskControl>>>,
}

struct SchedulerInner {
    phase: SchedulerPhase,
    queue: VecDeque<Runnable>,
    cancellations: VecDeque<Arc<TaskControl>>,
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

enum WakeAction {
    Deferred,
    Foreign,
    Local,
    Rejected,
}

impl Scheduler {
    fn new(worker: ThreadId) -> Self {
        Self {
            owner: worker,
            inner: Mutex::new(SchedulerInner {
                phase: SchedulerPhase::Running,
                queue: VecDeque::new(),
                cancellations: VecDeque::new(),
                quarantined: VecDeque::new(),
                processing: false,
            }),
            controls: Mutex::new(Vec::new()),
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

    fn register_task(
        &self,
        control: Arc<TaskControl>,
        task: RawTask<()>,
    ) -> Result<(), SpawnError> {
        let task = WORKER_SCHEDULER.with(|worker| {
            let mut worker = worker.borrow_mut();
            let Some(worker) = worker.as_mut() else {
                return Err(task);
            };
            if !core::ptr::eq(Arc::as_ptr(&worker.scheduler), self) {
                return Err(task);
            }
            worker.register_task(Arc::clone(&control), task);
            Ok(())
        });
        if let Err(task) = task {
            drop(task);
            return Err(SpawnError::WrongWorker);
        }

        let mut controls = self.controls.lock().unwrap_or_else(|error| error.into_inner());
        controls.retain(|candidate| candidate.strong_count() != 0);
        controls.push(Arc::downgrade(&control));
        Ok(())
    }

    fn untrack_task(&self, control: &Arc<TaskControl>) {
        self.controls.lock().unwrap_or_else(|error| error.into_inner()).retain(|candidate| {
            candidate.upgrade().is_some_and(|candidate| !Arc::ptr_eq(&candidate, control))
        });
    }

    fn fail_live_tasks(&self) {
        let controls = {
            let mut controls = self.controls.lock().unwrap_or_else(|error| error.into_inner());
            controls.retain(|candidate| candidate.strong_count() != 0);
            controls.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        };

        for control in controls {
            control.fail_scheduler();
        }
    }

    fn request_cancel(self: &Arc<Self>, control: Arc<TaskControl>) {
        let current = thread::current().id();
        let action = {
            let mut inner = self.lock();
            match inner.phase {
                SchedulerPhase::Running => {
                    inner.cancellations.push_back(control);
                    if inner.processing {
                        WakeAction::Deferred
                    } else if self.owner == current {
                        WakeAction::Local
                    } else {
                        WakeAction::Foreign
                    }
                }
                SchedulerPhase::Stopping | SchedulerPhase::Stopped => WakeAction::Rejected,
            }
        };

        match action {
            WakeAction::Deferred | WakeAction::Rejected => {}
            WakeAction::Local => {
                if !self.post_current() {
                    self.stop_and_drop();
                }
            }
            WakeAction::Foreign => {
                if unsafe { notify(notification_handler) }.is_err() {
                    self.fail_from_foreign_thread();
                }
            }
        }
    }

    fn take_registered_tasks(&self, controls: Vec<Arc<TaskControl>>) -> Vec<RegisteredTask> {
        WORKER_SCHEDULER.with(|worker| {
            let mut worker = worker.borrow_mut();
            let Some(worker) = worker.as_mut() else {
                return Vec::new();
            };
            if !core::ptr::eq(Arc::as_ptr(&worker.scheduler), self) {
                return Vec::new();
            }

            controls.iter().filter_map(|control| worker.take_task(control)).collect()
        })
    }

    fn drop_registered_tasks(&self, tasks: Vec<RegisteredTask>) {
        for task in &tasks {
            self.untrack_task(&task.control);
        }
        drop(tasks);
    }

    fn cancel_registered_tasks(&self, controls: Vec<Arc<TaskControl>>) {
        self.drop_registered_tasks(self.take_registered_tasks(controls));
    }

    fn reap_completed_tasks(&self) {
        let tasks = WORKER_SCHEDULER.with(|worker| {
            let mut worker = worker.borrow_mut();
            let Some(worker) = worker.as_mut() else {
                return Vec::new();
            };
            if !core::ptr::eq(Arc::as_ptr(&worker.scheduler), self) {
                return Vec::new();
            }
            worker.take_completed()
        });
        self.drop_registered_tasks(tasks);
    }

    fn cancel_all_registered_tasks(&self) {
        let tasks = WORKER_SCHEDULER.with(|worker| {
            let mut worker = worker.borrow_mut();
            let Some(worker) = worker.as_mut() else {
                return Vec::new();
            };
            if !core::ptr::eq(Arc::as_ptr(&worker.scheduler), self) {
                return Vec::new();
            }
            worker.take_all_tasks()
        });
        for task in &tasks {
            task.control.finish(TaskStatus::Canceled);
        }
        self.drop_registered_tasks(tasks);
    }

    fn task_completed(&self, control: Arc<TaskControl>) {
        WORKER_SCHEDULER.with(|worker| {
            let mut worker = worker.borrow_mut();
            let Some(worker) = worker.as_mut() else {
                return;
            };
            if core::ptr::eq(Arc::as_ptr(&worker.scheduler), self) {
                worker.task_completed(control);
            }
        });
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
        let (cancellations, mut runnables) = {
            let mut inner = self.lock();
            match &inner.phase {
                SchedulerPhase::Running if self.owner == current && !inner.processing => {
                    inner.processing = true;
                    (mem::take(&mut inner.cancellations), mem::take(&mut inner.queue))
                }
                _ => return false,
            }
        };
        let processing = ProcessingGuard { scheduler: self };

        self.cancel_registered_tasks(cancellations.into_iter().collect());

        while let Some(runnable) = runnables.pop_front() {
            runnable.run();
            self.reap_completed_tasks();
            if !self.is_running_on_current_worker() {
                drop(runnables);
                self.cancel_all_registered_tasks();
                break;
            }
        }
        self.reap_completed_tasks();

        processing.finish()
    }

    fn finish_processing(&self) -> bool {
        let current = thread::current().id();
        let mut inner = self.lock();
        inner.processing = false;

        matches!(&inner.phase, SchedulerPhase::Running if self.owner == current)
            && (!inner.queue.is_empty() || !inner.cancellations.is_empty())
    }

    fn is_running_on_current_worker(&self) -> bool {
        let inner = self.lock();
        self.owner == thread::current().id() && matches!(inner.phase, SchedulerPhase::Running)
    }

    fn processing_on_current_worker(&self) -> bool {
        let current = thread::current().id();
        let inner = self.lock();

        self.owner == current
            && matches!(&inner.phase, SchedulerPhase::Running | SchedulerPhase::Stopping)
            && inner.processing
    }

    fn fail_from_foreign_thread(&self) {
        {
            let mut inner = self.lock();
            if matches!(&inner.phase, SchedulerPhase::Running) {
                inner.phase = SchedulerPhase::Stopping;
            }
            let mut queued = mem::take(&mut inner.queue);
            inner.quarantined.append(&mut queued);
        }
        self.fail_live_tasks();
    }

    fn quarantine(&self, runnable: Runnable) {
        self.lock().quarantined.push_back(runnable);
    }

    fn drain_for_shutdown(&self) -> VecDeque<Runnable> {
        let mut inner = self.lock();
        if matches!(&inner.phase, SchedulerPhase::Running) {
            inner.phase = SchedulerPhase::Stopping;
        }
        inner.cancellations.clear();
        let mut queued = mem::take(&mut inner.queue);
        queued.append(&mut inner.quarantined);
        queued
    }

    fn stop_and_drop(&self) {
        self.fail_live_tasks();
        let queued = self.drain_for_shutdown();
        let processing = self.processing_on_current_worker();
        if !processing {
            self.cancel_all_registered_tasks();
        }
        drop(queued);
        if !processing {
            self.reap_completed_tasks();
        }
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

struct TaskRunner<F, T> {
    future: Pin<Box<F>>,
    control: Arc<TaskControl>,
    state: Rc<TaskState<T>>,
    scheduler: Arc<Scheduler>,
}

impl<F, T> TaskRunner<F, T> {
    fn finish_ready(&self, output: T) {
        match self.control.finish(TaskStatus::Ready) {
            TaskStatus::Ready => {
                self.state.resolve(Ok(output));
                self.control.wake();
            }
            TaskStatus::Canceled | TaskStatus::Panicked | TaskStatus::SchedulerFailed => {
                drop(output);
                if let Some(error) = self.control.status().error() {
                    self.state.resolve(Err(error));
                }
            }
            TaskStatus::Active | TaskStatus::CancelRequested => {}
        }
        self.scheduler.task_completed(Arc::clone(&self.control));
    }

    fn finish_error(&self, desired: TaskStatus) {
        let status = self.control.finish(desired);
        if let Some(error) = status.error() {
            self.state.resolve(Err(error));
        }
        self.scheduler.task_completed(Arc::clone(&self.control));
    }
}

impl<F, T> Future for TaskRunner<F, T>
where
    F: Future<Output = T>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        match catch_unwind(AssertUnwindSafe(|| this.future.as_mut().poll(context))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => {
                this.finish_ready(output);
                Poll::Ready(())
            }
            Err(_) => {
                this.finish_error(TaskStatus::Panicked);
                Poll::Ready(())
            }
        }
    }
}

impl<F, T> Drop for TaskRunner<F, T> {
    fn drop(&mut self) {
        self.finish_error(TaskStatus::Canceled);
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
        let mut worker = WORKER_SCHEDULER
            .with(|worker| worker.borrow_mut().take())
            .ok_or(SchedulerInitError::AlreadyInitialized)?;
        let scheduler = Arc::clone(&worker.scheduler);
        let queued = scheduler.drain_for_shutdown();
        worker.shutdown();
        let tasks = worker.take_all_tasks();
        for task in &tasks {
            task.control.finish(TaskStatus::Canceled);
        }
        drop(worker);
        scheduler.drop_registered_tasks(tasks);
        drop(queued);
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
    let tasks = WORKER_SCHEDULER.with(|worker| {
        let mut worker = worker.borrow_mut();
        let Some(worker) = worker.as_mut() else {
            return Err(SchedulerShutdownError::WrongWorker);
        };
        if !Arc::ptr_eq(&worker.scheduler, &scheduler) {
            return Err(SchedulerShutdownError::WrongWorker);
        }
        worker.shutdown();
        Ok(worker.take_all_tasks())
    })?;
    scheduler.finish_shutdown();
    for task in &tasks {
        task.control.finish(TaskStatus::Canceled);
    }
    scheduler.drop_registered_tasks(tasks);
    drop(queued);
    scheduler.reap_completed_tasks();
    clear_active_scheduler(&scheduler);

    Ok(!was_stopped)
}

/// Creates a new task running on the NGINX event loop.
///
/// This function must be called after [`init_worker`] on the owning nginx worker thread. The task
/// is always polled on that thread even when its waker is invoked from another thread.
pub fn spawn<F, T>(future: F) -> Result<LocalTask<T>, SpawnError>
where
    F: Future<Output = T> + 'static,
    T: 'static,
{
    let scheduler = current_scheduler()?;
    let control = TaskControl::new(&scheduler);
    let state = TaskState::new();
    let task_scheduler = Arc::clone(&scheduler);
    let task_scheduler = WithInfo(move |runnable, info| task_scheduler.schedule(runnable, info));
    let (runnable, task) = async_task::spawn_local(
        TaskRunner {
            future: Box::pin(future),
            control: Arc::clone(&control),
            state: Rc::clone(&state),
            scheduler: Arc::clone(&scheduler),
        },
        task_scheduler,
    );

    if let Err(error) = scheduler.register_task(Arc::clone(&control), task) {
        drop(runnable);
        return Err(error);
    }

    if let Err(error) = scheduler.schedule_initial(runnable) {
        scheduler.cancel_registered_tasks(Vec::from([Arc::clone(&control)]));
        return Err(error);
    }

    Ok(LocalTask { control, state, attached: true, completed: false })
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
    use alloc::task::Wake;
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
        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 2);

        worker.deliver_notification();
        worker.process_posted();
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        thread::spawn(move || waker.wake()).join().unwrap();
        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 2);
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
        assert_eq!(shutdown_worker(), Ok(true));
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

        NOTIFY_SUCCEEDS.store(false, Ordering::Relaxed);
        thread::spawn(move || waker.wake()).join().unwrap();

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::SchedulerFailed)));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert_eq!(shutdown_worker(), Ok(true));
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

        NOTIFY_SUCCEEDS.store(false, Ordering::Relaxed);
        thread::spawn(move || future_waker.wake()).join().unwrap();

        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::SchedulerFailed)));
    }

    #[test]
    fn task_panic_is_reported_without_crossing_the_scheduler_callback() {
        let mut worker = TestWorker::new();
        worker.init().unwrap();

        let task = spawn(async {
            panic!("task panic");
        })
        .unwrap();
        worker.process_posted();

        let mut task = core::pin::pin!(task);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Err(TaskError::Panicked)));
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

        assert_eq!(shutdown_worker(), Ok(true));
        assert!(worker.queues_are_empty());
        assert_eq!(shutdown_worker(), Ok(false));

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

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 2);
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
        assert_eq!(shutdown_worker(), Ok(true));
        let waker = waker_rx.recv().unwrap();
        thread::spawn(move || waker.wake()).join().unwrap();

        assert_eq!(NOTIFY_CALLS.load(Ordering::Relaxed), 1);
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
        assert_eq!(task.as_mut().poll(&mut context), Poll::Ready(Ok(9)));
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
