//! Async runtime and set of utilities on top of the NGINX event loop.
//!
//! ```compile_fail
//! use core::time::Duration;
//! use ngx::async_::Sleep;
//! use ngx::log::LogRef;
//!
//! fn sleep_cannot_outlive_logger<'log>(log: LogRef<'log>) -> Sleep<'static> {
//!     ngx::async_::sleep(Duration::from_millis(1), log)
//! }
//! ```
pub use self::sleep::{Sleep, sleep};
pub(crate) use self::spawn::AttachedTask;
#[cfg(test)]
pub(crate) use self::spawn::SCHEDULER_TESTS;
pub use self::spawn::{
    CancellationHandle, LocalTask, SchedulerInitError, SchedulerShutdownError, SpawnError,
    TaskError, WorkerSchedulerLease, acquire_worker, spawn,
};
pub use crate::event::{EventReadiness, Readiness, ReadinessError};

pub mod resolver;

mod sleep;
mod spawn;
