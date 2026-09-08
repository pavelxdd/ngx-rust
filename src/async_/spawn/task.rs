//! Worker-local task state, handles, and execution.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use async_task::WithInfo;

use super::scheduler::{Scheduler, SpawnError, TaskControl, TaskStatus, current_scheduler};

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

fn task_error(status: TaskStatus) -> Option<TaskError> {
    match status {
        TaskStatus::Canceled => Some(TaskError::Canceled),
        TaskStatus::SchedulerFailed => Some(TaskError::SchedulerFailed),
        TaskStatus::Active | TaskStatus::CancelRequested | TaskStatus::Ready => None,
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

        if let Some(error) = task_error(this.control.status()) {
            this.completed = true;
            return Poll::Ready(Err(error));
        }

        this.control.set_waker(context.waker());
        if let Some(error) = task_error(this.control.status()) {
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
                if let Some(error) = task_error(self.control.status()) {
                    self.state.resolve(Err(error));
                }
            }
            TaskStatus::Active | TaskStatus::CancelRequested => {}
        }
        self.scheduler.task_completed(Arc::clone(&self.control));
    }

    fn finish_error(&self, desired: TaskStatus) {
        let status = self.control.finish(desired);
        if let Some(error) = task_error(status) {
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

/// Creates a new task running on the NGINX event loop.
///
/// This function must be called while the owning module holds a
/// [`crate::async_::WorkerSchedulerLease`] on the nginx worker thread. The task is always polled
/// on that thread even when its waker is invoked
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
