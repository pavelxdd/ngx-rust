//! Async runtime and set of utilities on top of the NGINX event loop.
pub use self::sleep::{Sleep, sleep};
pub(crate) use self::spawn::AttachedTask;
#[cfg(test)]
pub(crate) use self::spawn::SCHEDULER_TESTS;
pub use self::spawn::{
    CancellationHandle, LocalTask, SchedulerInitError, SchedulerShutdownError, SpawnError,
    TaskError, init_worker, shutdown_worker, spawn,
};
pub use crate::event::{EventReadiness, Readiness, ReadinessError};

pub mod resolver;

mod sleep;
mod spawn;
