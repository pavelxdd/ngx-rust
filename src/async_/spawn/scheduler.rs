//! Worker scheduler lifecycle, queues, and shutdown.

use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::rc::Rc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;
use core::mem;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::Waker;
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};

use async_task::{Runnable, ScheduleInfo, Task as RawTask};

use crate::event::{PostedEvent, PostedEventCallback, PostedQueue};
use crate::ffi::{ngx_close_connection, ngx_connection_t, ngx_event_t};
use crate::log::LogRef;

use super::notification::{
    close_notification, drain_notification, open_notification_channel, send_notification,
};

static ACTIVE_SCHEDULER: OnceLock<Mutex<Option<Arc<Scheduler>>>> = OnceLock::new();

#[cfg(test)]
pub(crate) static SCHEDULER_TESTS: Mutex<()> = Mutex::new(());

std::thread_local! {
    pub(super) static WORKER_SCHEDULER: RefCell<Option<WorkerScheduler>> = const { RefCell::new(None) };
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

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TaskStatus {
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
}

pub(super) struct TaskControl {
    scheduler: Weak<Scheduler>,
    status: AtomicU8,
    waker: Mutex<Option<Waker>>,
}

impl TaskControl {
    pub(super) fn new(scheduler: &Arc<Scheduler>) -> Arc<Self> {
        Arc::new(Self {
            scheduler: Arc::downgrade(scheduler),
            status: AtomicU8::new(TaskStatus::Active as u8),
            waker: Mutex::new(None),
        })
    }

    pub(super) fn status(&self) -> TaskStatus {
        TaskStatus::from_raw(self.status.load(Ordering::Acquire))
    }

    pub(super) fn set_waker(&self, waker: &Waker) {
        *self.waker.lock().unwrap_or_else(|error| error.into_inner()) = Some(waker.clone());
    }

    pub(super) fn wake(&self) {
        let waker = self.waker.lock().unwrap_or_else(|error| error.into_inner()).take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(super) fn request_cancel(control: &Arc<Self>) {
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

    pub(super) fn finish(&self, desired: TaskStatus) -> TaskStatus {
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
                    if matches!(next, TaskStatus::Canceled | TaskStatus::SchedulerFailed) {
                        self.wake();
                    }
                    return next;
                }
                Err(current) => status = TaskStatus::from_raw(current),
            }
        }
    }
}

type SchedulerPostedCallback = for<'callback> fn(PostedEventCallback<'callback, Arc<Scheduler>>);
type SchedulerPostedEvent = PostedEvent<'static, Arc<Scheduler>, SchedulerPostedCallback>;

pub(super) struct RegisteredTask {
    control: Arc<TaskControl>,
    _task: RawTask<()>,
}

pub(super) struct WorkerScheduler {
    scheduler: Arc<Scheduler>,
    posted: Pin<Box<SchedulerPostedEvent>>,
    pub(super) notification: Option<NonNull<ngx_connection_t>>,
    pub(super) tasks: Vec<RegisteredTask>,
    pub(super) completed: Vec<Arc<TaskControl>>,
    leases: usize,
}

impl WorkerScheduler {
    unsafe fn new(log: LogRef<'_>, scheduler: Arc<Scheduler>) -> Result<Self, SchedulerInitError> {
        let log = unsafe { LogRef::from_raw(log.as_ptr()) }.expect("validated worker logger");
        let (notification, sender) =
            unsafe { open_notification_channel(log, notification_channel_handler) }
                .ok_or(SchedulerInitError::NotificationChannel)?;
        let mut channel = scheduler.notification.lock().unwrap_or_else(|error| error.into_inner());
        if channel.is_some() {
            drop(channel);
            unsafe { ngx_close_connection(notification.as_ptr()) };
            close_notification(sender);
            return Err(SchedulerInitError::NotificationChannel);
        }
        *channel = Some(sender);
        drop(channel);
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

    pub(super) fn register_task(&mut self, control: Arc<TaskControl>, task: RawTask<()>) {
        self.tasks.push(RegisteredTask { control, _task: task });
    }

    fn take_task(&mut self, control: &Arc<TaskControl>) -> Option<RegisteredTask> {
        let position = self.tasks.iter().position(|task| Arc::ptr_eq(&task.control, control))?;
        Some(self.tasks.swap_remove(position))
    }

    pub(super) fn task_completed(&mut self, control: Arc<TaskControl>) {
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

pub(super) struct Scheduler {
    owner: ThreadId,
    pub(super) inner: Mutex<SchedulerInner>,
    task_lifetime: Condvar,
    controls: Mutex<Vec<Weak<TaskControl>>>,
    notification: Mutex<Option<libc::c_int>>,
    notification_pending: AtomicBool,
}

pub(super) struct SchedulerInner {
    pub(super) phase: SchedulerPhase,
    pub(super) queue: VecDeque<Runnable>,
    cancellations: VecDeque<Arc<TaskControl>>,
    // A local runnable may only be destroyed by its owner thread.
    pub(super) quarantined: VecDeque<Runnable>,
    // Zero proves that no runnable can still carry a worker-local future into quarantine.
    live_tasks: usize,
    processing: bool,
}

pub(super) enum SchedulerPhase {
    Running,
    Stopping,
    Stopped,
}

pub(super) enum ScheduleAction {
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

    pub(super) fn lock(&self) -> MutexGuard<'_, SchedulerInner> {
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

    pub(super) fn register_task(
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

    pub(super) fn register_task_lifetime(&self) {
        self.lock().live_tasks += 1;
    }

    pub(super) fn release_task_lifetime(&self) {
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

    pub(super) fn cancel_registered_tasks(&self, controls: Vec<Arc<TaskControl>>) {
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

    pub(super) fn task_completed(&self, control: Arc<TaskControl>) {
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

    pub(super) fn queue(&self, runnable: Runnable) -> ScheduleAction {
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

    pub(super) fn schedule(self: &Arc<Self>, runnable: Runnable, _info: ScheduleInfo) {
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

    pub(super) fn schedule_initial(self: &Arc<Self>, runnable: Runnable) -> Result<(), SpawnError> {
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
        if send_notification(socket) {
            return true;
        }

        self.notification_pending.store(false, Ordering::Release);
        false
    }

    pub(super) fn close_notification(&self) {
        let socket = self.notification.lock().unwrap_or_else(|error| error.into_inner()).take();
        self.notification_pending.store(false, Ordering::Release);
        if let Some(socket) = socket {
            close_notification(socket);
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

    pub(super) fn quarantine(&self, runnable: Runnable) {
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

    pub(super) fn is_stopped(&self) -> bool {
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
    } else if event.state().is_stopping_on_current_worker() {
        event.state().stop_and_drop();
    }
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
    if !drain_notification(connection) {
        scheduler.notification_pending.store(false, Ordering::Release);
        scheduler.stop_and_drop();
        return;
    }

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

pub(super) fn current_scheduler() -> Result<Arc<Scheduler>, SpawnError> {
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
/// Call this from the module's process-start hook before calling [`crate::async_::spawn`]. The
/// first participant creates the worker scheduler and requires an available connection slot for its private
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
