//! Async task spawning and worker scheduler ownership.

mod notification;
mod scheduler;
#[cfg(test)]
pub(crate) use scheduler::SCHEDULER_TESTS;
#[cfg(test)]
use scheduler::{ScheduleAction, Scheduler, SchedulerPhase, WORKER_SCHEDULER, current_scheduler};
pub use scheduler::{
    SchedulerInitError, SchedulerShutdownError, SpawnError, WorkerSchedulerLease, acquire_worker,
};
mod task;
pub(crate) use task::AttachedTask;
pub use task::{CancellationHandle, LocalTask, TaskError, spawn};

#[cfg(test)]
mod tests;
