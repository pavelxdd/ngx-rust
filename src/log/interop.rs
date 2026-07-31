//! Adapter from the [`log`] facade to the current nginx cycle logger.
//!
//! Call [`init`] from the nginx event-loop thread before using the logging macros. Records from
//! other threads are dropped because nginx log objects are not synchronized for external use.

use core::cell::Cell;

use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::sync::OnceLock;
use std::thread_local;

use crate::ffi::{NGX_LOG_DEBUG, NGX_LOG_ERR, NGX_LOG_INFO, NGX_LOG_WARN};
use crate::log::{DebugMask, LOG_BUFFER_SIZE, check_mask, log_debug, log_error, ngx_cycle_log};

static LOGGER: NginxLogger = NginxLogger;
static INITIALIZED: OnceLock<()> = OnceLock::new();

thread_local! {
    static EVENT_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Installs the nginx logger and enables it for the calling event-loop thread.
///
/// Returns an error if another logger has already been installed for this copy of the module.
pub fn init() -> Result<(), SetLoggerError> {
    if INITIALIZED.get().is_none() {
        log::set_logger(&LOGGER)?;
        log::set_max_level(max_level());
        let _ = INITIALIZED.set(());
    }

    EVENT_THREAD.set(true);
    Ok(())
}

const fn max_level() -> LevelFilter {
    if cfg!(feature = "log-trace") {
        LevelFilter::Trace
    } else if cfg!(feature = "log-debug") || cfg!(ngx_feature = "debug") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    }
}

fn level_enabled(level: Level, log_level: usize) -> bool {
    match level {
        Level::Error => NGX_LOG_ERR as usize <= log_level,
        Level::Warn => NGX_LOG_WARN as usize <= log_level,
        Level::Info => NGX_LOG_INFO as usize <= log_level,
        Level::Debug | Level::Trace => check_mask(DebugMask::Core, log_level),
    }
}

fn nginx_level(level: Level) -> crate::ffi::ngx_uint_t {
    match level {
        Level::Error => NGX_LOG_ERR as _,
        Level::Warn => NGX_LOG_WARN as _,
        Level::Info => NGX_LOG_INFO as _,
        Level::Debug | Level::Trace => NGX_LOG_DEBUG as _,
    }
}

struct NginxLogger;

impl Log for NginxLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        EVENT_THREAD.get()
            && level_enabled(metadata.level(), unsafe { ngx_cycle_log().as_ref().log_level })
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let log = ngx_cycle_log();
        let mut buffer = [const { core::mem::MaybeUninit::<u8>::uninit() }; LOG_BUFFER_SIZE];
        let message = super::write_fmt(&mut buffer, *record.args());

        unsafe {
            if record.level() < Level::Debug {
                log_error(nginx_level(record.level()), log.as_ptr(), 0, message);
            } else {
                log_debug(log.as_ptr(), 0, message);
            }
        }
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use log::Level;

    use super::*;
    use crate::ffi::{NGX_LOG_DEBUG_CORE, NGX_LOG_DEBUG_HTTP, NGX_LOG_ERR};

    #[test]
    fn nginx_threshold_includes_the_selected_level() {
        assert!(level_enabled(Level::Error, NGX_LOG_ERR as usize));
        assert!(!level_enabled(Level::Warn, NGX_LOG_ERR as usize));
    }

    #[test]
    fn debug_and_trace_require_the_core_mask() {
        assert!(level_enabled(Level::Debug, NGX_LOG_DEBUG_CORE as usize));
        assert!(level_enabled(Level::Trace, NGX_LOG_DEBUG_CORE as usize));
        assert!(!level_enabled(Level::Debug, NGX_LOG_DEBUG_HTTP as usize));
    }
}
