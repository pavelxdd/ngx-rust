//! Async runtime and set of utilities on top of the NGINX event loop.
pub use self::sleep::{Sleep, sleep};
pub use self::spawn::{
    SchedulerInitError, SchedulerShutdownError, SpawnError, Task, init_worker, shutdown_worker,
    spawn,
};

pub mod resolver;

mod sleep;
mod spawn;
