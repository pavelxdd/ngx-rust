//! Async runtime and set of utilities on top of the NGINX event loop.
pub use self::sleep::{Sleep, sleep};
pub(crate) use self::spawn::AttachedTask;
pub use self::spawn::{
    CancellationHandle, LocalTask, SchedulerInitError, SchedulerShutdownError, SpawnError,
    TaskError, init_worker, shutdown_worker, spawn,
};

pub mod resolver;

mod sleep;
mod spawn;
