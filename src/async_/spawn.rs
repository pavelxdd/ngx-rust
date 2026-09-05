use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::rc::Rc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::marker::PhantomData;
use core::mem;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};

use async_task::{Runnable, ScheduleInfo, Task as RawTask, WithInfo};

use crate::event::{PostedEvent, PostedEventCallback, PostedQueue};
use crate::ffi::{
    NGX_OK, ngx_close_connection, ngx_connection_t, ngx_event_t, ngx_get_connection,
    ngx_handle_read_event, ngx_nonblocking,
};
use crate::log::LogRef;

static ACTIVE_SCHEDULER: OnceLock<Mutex<Option<Arc<Scheduler>>>> = OnceLock::new();

#[cfg(test)]
pub(crate) static SCHEDULER_TESTS: Mutex<()> = Mutex::new(());

std::thread_local! {
    static WORKER_SCHEDULER: RefCell<Option<WorkerScheduler>> = const { RefCell::new(None) };
}

/// Failure returned while initializing the current nginx worker scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerInitError {
    /// Another worker scheduler is still active in this process.
    AlreadyInitialized,
    /// The worker could not create or register its private notification channel.
    NotificationChannel,
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

/// One module's ownership of the async scheduler on the current nginx worker.
#[must_use = "the owning module must retain this lease until its process-exit hook"]
pub struct WorkerSchedulerLease {
    scheduler: Arc<Scheduler>,
    active: bool,
    _not_send: PhantomData<Rc<()>>,
}

impl WorkerSchedulerLease {
    fn new(scheduler: Arc<Scheduler>) -> Self {
        Self { scheduler, active: true, _not_send: PhantomData }
    }

    /// Releases this module's scheduler ownership.
    ///
    /// Returns `Ok(true)` only when this was the final lease and the scheduler was stopped.
    /// Call this from the module's process-exit hook after cancelling its own tasks.
    pub fn release(&mut self) -> Result<bool, SchedulerShutdownError> {
        release_worker_lease(self)
    }
}

impl Drop for WorkerSchedulerLease {
    fn drop(&mut self) {
        let _ = release_worker_lease(self);
    }
}

/// Terminal failure returned by a [`LocalTask`].
///
/// A panic from the task future is not recoverable and terminates the worker process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskError {
    /// The task's owner canceled it before it produced an output.
    Canceled,
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
    SchedulerFailed,
}

impl TaskStatus {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Active,
            1 => Self::CancelRequested,
            2 => Self::Ready,
            3 => Self::Canceled,
            _ => Self::SchedulerFailed,
        }
    }

    fn error(self) -> Option<TaskError> {
        match self {
            Self::Canceled => Some(TaskError::Canceled),
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
                TaskStatus::Ready | TaskStatus::Canceled | TaskStatus::SchedulerFailed => return,
            }
        }
    }

    fn finish(&self, desired: TaskStatus) -> TaskStatus {
        let mut status = self.status();

        loop {
            let next = match status {
                TaskStatus::Active => desired,
                TaskStatus::CancelRequested => TaskStatus::Canceled,
                TaskStatus::Ready | TaskStatus::Canceled | TaskStatus::SchedulerFailed => {
                    return status;
                }
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
type SchedulerPostedEvent = PostedEvent<'static, Arc<Scheduler>, SchedulerPostedCallback>;

struct RegisteredTask {
    control: Arc<TaskControl>,
    _task: RawTask<()>,
}

struct WorkerScheduler {
    scheduler: Arc<Scheduler>,
    posted: Pin<Box<SchedulerPostedEvent>>,
    notification: Option<NonNull<ngx_connection_t>>,
    tasks: Vec<RegisteredTask>,
    completed: Vec<Arc<TaskControl>>,
    leases: usize,
}

impl WorkerScheduler {
    unsafe fn new(log: LogRef<'_>, scheduler: Arc<Scheduler>) -> Result<Self, SchedulerInitError> {
        let log = unsafe { LogRef::from_raw(log.as_ptr()) }.expect("validated worker logger");
        let notification = unsafe { open_notification_channel(log, &scheduler) }
            .ok_or(SchedulerInitError::NotificationChannel)?;
        Ok(Self {
            posted: Box::pin(PostedEvent::new(
                log,
                Arc::clone(&scheduler),
                posted_scheduler_handler as SchedulerPostedCallback,
            )),
            scheduler,
            notification: Some(notification),
            tasks: Vec::new(),
            completed: Vec::new(),
            leases: 1,
        })
    }

    fn post(&mut self) -> bool {
        // WorkerScheduler exists while at least one worker lease is held on its owner thread.
        unsafe { self.posted.as_mut().post(PostedQueue::Next) }.is_ok()
    }

    fn shutdown(&mut self) {
        self.posted.as_mut().shutdown();
        self.scheduler.close_notification();
        if let Some(connection) = self.notification.take() {
            unsafe { ngx_close_connection(connection.as_ptr()) };
        }
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
    task_lifetime: Condvar,
    controls: Mutex<Vec<Weak<TaskControl>>>,
    notification: Mutex<Option<libc::c_int>>,
    notification_pending: AtomicBool,
}

struct SchedulerInner {
    phase: SchedulerPhase,
    queue: VecDeque<Runnable>,
    cancellations: VecDeque<Arc<TaskControl>>,
    // A local runnable may only be destroyed by its owner thread.
    quarantined: VecDeque<Runnable>,
    // Zero proves that no runnable can still carry a worker-local future into quarantine.
    live_tasks: usize,
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
                live_tasks: 0,
                processing: false,
            }),
            task_lifetime: Condvar::new(),
            controls: Mutex::new(Vec::new()),
            notification: Mutex::new(None),
            notification_pending: AtomicBool::new(false),
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

    fn register_task_lifetime(&self) {
        self.lock().live_tasks += 1;
    }

    fn release_task_lifetime(&self) {
        let mut inner = self.lock();
        debug_assert_ne!(inner.live_tasks, 0);
        inner.live_tasks -= 1;
        drop(inner);
        self.task_lifetime.notify_all();
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
                if !self.notify_worker() {
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
                if !self.notify_worker() {
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
                if self.notify_worker() {
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

    fn notify_worker(&self) -> bool {
        // A queued datagram represents the whole shared runnable queue, so concurrent wakes need
        // no additional writes until the worker drains the channel.
        if self.notification_pending.swap(true, Ordering::AcqRel) {
            return true;
        }

        let notification = self.notification.lock().unwrap_or_else(|error| error.into_inner());
        let Some(socket) = *notification else {
            self.notification_pending.store(false, Ordering::Release);
            return false;
        };
        let byte = 1_u8;

        loop {
            let written = unsafe { libc::send(socket, (&raw const byte).cast(), 1, 0) };
            if written == 1 {
                return true;
            }
            if written == -1 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => return true,
                    _ => {}
                }
            }

            self.notification_pending.store(false, Ordering::Release);
            return false;
        }
    }

    fn close_notification(&self) {
        let socket = self.notification.lock().unwrap_or_else(|error| error.into_inner()).take();
        self.notification_pending.store(false, Ordering::Release);
        if let Some(socket) = socket {
            unsafe { libc::close(socket) };
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
        self.task_lifetime.notify_all();
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

    fn drain_task_handoffs(&self) {
        // Dropping the registered task handles closes every future. A foreign wake that won the
        // close race must still hand its runnable to quarantine before that future can disappear.
        loop {
            let mut inner = self.lock();
            while inner.live_tasks != 0 && inner.queue.is_empty() && inner.quarantined.is_empty() {
                inner = self.task_lifetime.wait(inner).unwrap_or_else(|error| error.into_inner());
            }

            let complete = inner.live_tasks == 0;
            let mut queued = mem::take(&mut inner.queue);
            queued.append(&mut inner.quarantined);
            drop(inner);
            drop(queued);

            if complete {
                return;
            }
        }
    }

    fn stop_and_drop(&self) {
        self.fail_live_tasks();
        let queued = self.drain_for_shutdown();
        let processing = self.processing_on_current_worker();
        if processing {
            drop(queued);
            return;
        }

        self.cancel_all_registered_tasks();
        drop(queued);
        self.drain_task_handoffs();
        self.reap_completed_tasks();
    }

    fn finish_shutdown(&self) {
        let mut inner = self.lock();

        if matches!(&inner.phase, SchedulerPhase::Stopping) {
            inner.phase = SchedulerPhase::Stopped;
        }
    }

    fn is_stopping_on_current_worker(&self) -> bool {
        self.owner == thread::current().id()
            && matches!(&self.lock().phase, SchedulerPhase::Stopping)
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
            TaskStatus::Canceled | TaskStatus::SchedulerFailed => {
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
        match this.future.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(output) => {
                this.finish_ready(output);
                Poll::Ready(())
            }
        }
    }
}

impl<F, T> Drop for TaskRunner<F, T> {
    fn drop(&mut self) {
        self.finish_error(TaskStatus::Canceled);
        self.scheduler.release_task_lifetime();
    }
}

fn posted_scheduler_handler(mut event: PostedEventCallback<'_, Arc<Scheduler>>) {
    if event.state().process() {
        let _ = event.post(PostedQueue::Next);
    } else if event.state().is_stopping_on_current_worker() {
        event.state().stop_and_drop();
    }
}

/// # Safety
///
/// The current worker must have an initialized nginx cycle and event backend. `log` and the
/// cycle connection array must remain live until worker shutdown closes the returned connection.
unsafe fn open_notification_channel(
    log: LogRef<'_>,
    scheduler: &Arc<Scheduler>,
) -> Option<NonNull<ngx_connection_t>> {
    let mut sockets = [-1; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sockets.as_mut_ptr()) } != 0 {
        return None;
    }

    let close_sockets = |sockets: [libc::c_int; 2]| unsafe {
        libc::close(sockets[0]);
        libc::close(sockets[1]);
    };
    for socket in sockets {
        if unsafe { ngx_nonblocking(socket) } != 0
            || unsafe { libc::fcntl(socket, libc::F_SETFD, libc::FD_CLOEXEC) } == -1
        {
            close_sockets(sockets);
            return None;
        }
    }

    let Some(connection) = NonNull::new(unsafe { ngx_get_connection(sockets[0], log.as_ptr()) })
    else {
        close_sockets(sockets);
        return None;
    };
    unsafe {
        (*connection.as_ptr()).read.as_mut().unwrap().handler = Some(notification_channel_handler);
        (*connection.as_ptr()).read.as_mut().unwrap().log = log.as_ptr();
        (*connection.as_ptr()).write.as_mut().unwrap().log = log.as_ptr();
    }
    if unsafe { ngx_handle_read_event((*connection.as_ptr()).read, 0) } != NGX_OK as _ {
        unsafe { ngx_close_connection(connection.as_ptr()) };
        unsafe { libc::close(sockets[1]) };
        return None;
    }

    let mut notification = scheduler.notification.lock().unwrap_or_else(|error| error.into_inner());
    if notification.is_some() {
        drop(notification);
        unsafe { ngx_close_connection(connection.as_ptr()) };
        unsafe { libc::close(sockets[1]) };
        return None;
    }
    *notification = Some(sockets[1]);
    drop(notification);

    Some(connection)
}

unsafe extern "C" fn notification_channel_handler(event: *mut ngx_event_t) {
    let scheduler = WORKER_SCHEDULER
        .with(|worker| worker.borrow().as_ref().map(|worker| Arc::clone(&worker.scheduler)));
    let Some(scheduler) = scheduler else {
        return;
    };
    let Some(event) = NonNull::new(event) else {
        scheduler.stop_and_drop();
        return;
    };
    let Some(connection) = NonNull::new(unsafe { event.as_ref().data.cast::<ngx_connection_t>() })
    else {
        scheduler.stop_and_drop();
        return;
    };
    let socket = unsafe { connection.as_ref().fd };
    let mut bytes = [0_u8; 64];

    loop {
        let received = unsafe { libc::recv(socket, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        if received > 0 {
            continue;
        }
        if received == -1 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(error) if error == libc::EAGAIN || error == libc::EWOULDBLOCK => break,
                _ => {
                    scheduler.notification_pending.store(false, Ordering::Release);
                    scheduler.stop_and_drop();
                    return;
                }
            }
        }

        scheduler.notification_pending.store(false, Ordering::Release);
        scheduler.stop_and_drop();
        return;
    }

    unsafe { event.as_ptr().as_mut().unwrap().set_ready(0) };
    scheduler.notification_pending.store(false, Ordering::Release);
    if scheduler.process() {
        if !scheduler.post_current() {
            scheduler.stop_and_drop();
        }
    } else if scheduler.is_stopping_on_current_worker() {
        scheduler.stop_and_drop();
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

/// Acquires one module's lease on the async scheduler for the current nginx worker.
///
/// Call this from the module's process-start hook before calling [`spawn`]. The first participant
/// creates the worker scheduler and requires an available connection slot for its private
/// notification socket. Later participants on the same worker share that scheduler. Every
/// successful acquisition must remain owned until the matching process-exit hook calls
/// [`WorkerSchedulerLease::release`].
///
/// # Safety
///
/// This must run from an nginx module process-start hook on the initialized event-loop thread.
/// `log` must remain live and usable on that thread until every worker lease is released.
pub unsafe fn acquire_worker(log: LogRef<'_>) -> Result<WorkerSchedulerLease, SchedulerInitError> {
    let existing = WORKER_SCHEDULER.with(|current| {
        let mut current = current.borrow_mut();
        let Some(worker) = current.as_mut() else {
            return Ok(None);
        };
        if worker.scheduler.check_spawn().is_ok() {
            worker.leases =
                worker.leases.checked_add(1).ok_or(SchedulerInitError::AlreadyInitialized)?;
            return Ok(Some(Arc::clone(&worker.scheduler)));
        }
        if worker.scheduler.is_stopped() && worker.leases == 0 {
            return Ok(None);
        }
        Err(SchedulerInitError::AlreadyInitialized)
    })?;
    if let Some(scheduler) = existing {
        return Ok(WorkerSchedulerLease::new(scheduler));
    }

    let stopped = WORKER_SCHEDULER.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(|worker| worker.scheduler.is_stopped() && worker.leases == 0)
    });
    if stopped {
        let mut worker = WORKER_SCHEDULER
            .with(|current| current.borrow_mut().take())
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
    let worker = {
        let mut active = active_scheduler().lock().unwrap_or_else(|error| error.into_inner());
        if active.is_some() {
            return Err(SchedulerInitError::AlreadyInitialized);
        }
        let worker = unsafe { WorkerScheduler::new(log, Arc::clone(&scheduler)) }?;
        *active = Some(Arc::clone(&scheduler));
        worker
    };
    WORKER_SCHEDULER.with(|current| {
        *current.borrow_mut() = Some(worker);
    });

    Ok(WorkerSchedulerLease::new(scheduler))
}

fn release_worker_lease(lease: &mut WorkerSchedulerLease) -> Result<bool, SchedulerShutdownError> {
    if !lease.active {
        return Ok(false);
    }

    let final_release = WORKER_SCHEDULER.with(|current| {
        let mut current = current.borrow_mut();
        let Some(worker) = current.as_mut() else {
            return Err(SchedulerShutdownError::WrongWorker);
        };
        if !Arc::ptr_eq(&worker.scheduler, &lease.scheduler) {
            return Err(SchedulerShutdownError::WrongWorker);
        }
        if worker.scheduler.processing_on_current_worker() {
            return Err(SchedulerShutdownError::Processing);
        }
        let Some(leases) = worker.leases.checked_sub(1) else {
            return Err(SchedulerShutdownError::WrongWorker);
        };
        worker.leases = leases;
        Ok(leases == 0)
    })?;
    lease.active = false;
    if !final_release {
        return Ok(false);
    }

    let scheduler = Arc::clone(&lease.scheduler);
    let was_stopped = scheduler.is_stopped();
    let queued = scheduler.drain_for_shutdown();
    let tasks = WORKER_SCHEDULER.with(|current| {
        let mut current = current.borrow_mut();
        let Some(worker) = current.as_mut() else {
            return Err(SchedulerShutdownError::WrongWorker);
        };
        if !Arc::ptr_eq(&worker.scheduler, &scheduler) {
            return Err(SchedulerShutdownError::WrongWorker);
        }
        worker.shutdown();
        Ok(worker.take_all_tasks())
    })?;
    for task in &tasks {
        task.control.finish(TaskStatus::Canceled);
    }
    scheduler.drop_registered_tasks(tasks);
    drop(queued);
    scheduler.drain_task_handoffs();
    scheduler.finish_shutdown();
    scheduler.reap_completed_tasks();
    clear_active_scheduler(&scheduler);

    Ok(!was_stopped)
}

/// Creates a new task running on the NGINX event loop.
///
/// This function must be called while the owning module holds a [`WorkerSchedulerLease`] on the
/// nginx worker thread. The task is always polled on that thread even when its waker is invoked
/// from another thread.
pub fn spawn<F, T>(future: F) -> Result<LocalTask<T>, SpawnError>
where
    F: Future<Output = T> + 'static,
    T: 'static,
{
    let scheduler = current_scheduler()?;
    let control = TaskControl::new(&scheduler);
    let state = TaskState::new();
    scheduler.register_task_lifetime();
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
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::sync::{Mutex, MutexGuard, mpsc};
    use std::thread;

    use super::*;
    use crate::ffi::{
        NGX_OK, NGX_USE_CLEAR_EVENT, ngx_connection_t, ngx_cycle, ngx_cycle_t, ngx_event_actions,
        ngx_event_actions_t, ngx_event_flags, ngx_event_handler_pt, ngx_event_move_posted_next,
        ngx_event_process_posted, ngx_event_t, ngx_int_t, ngx_log_t, ngx_posted_events,
        ngx_posted_next_events, ngx_queue_empty, ngx_queue_init, ngx_uint_t,
    };

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
