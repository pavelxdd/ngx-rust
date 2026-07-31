//! Access to nginx event-loop state.

use crate::ffi::{
    ngx_atomic_t, ngx_stat_accepted, ngx_stat_active, ngx_stat_handled, ngx_stat_reading,
    ngx_stat_requests, ngx_stat_waiting, ngx_stat_writing,
};

/// A snapshot of nginx's connection counters.
///
/// Each counter is read independently, so values can change while the snapshot is collected.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct ConnectionStats {
    /// Connections currently in use.
    pub active: u64,
    /// Connections currently reading a request header.
    pub reading: u64,
    /// Connections currently writing a response.
    pub writing: u64,
    /// Connections currently idle in keep-alive.
    pub waiting: u64,
    /// Total accepted connections.
    pub accepted: u64,
    /// Total handled connections.
    pub handled: u64,
    /// Total handled requests.
    pub requests: u64,
}

/// Returns a snapshot of nginx's connection counters.
pub fn connection_stats() -> ConnectionStats {
    // SAFETY: nginx initializes these pointers to process-lifetime counters before module code can
    // run. The pointers remain valid when nginx moves the counters into shared memory.
    unsafe {
        connection_stats_from_ptrs(
            ngx_stat_active,
            ngx_stat_reading,
            ngx_stat_writing,
            ngx_stat_waiting,
            ngx_stat_accepted,
            ngx_stat_handled,
            ngx_stat_requests,
        )
    }
}

#[allow(clippy::unnecessary_cast)]
unsafe fn read_counter(counter: *const ngx_atomic_t) -> u64 {
    // SAFETY: the caller guarantees that the counter is valid. Volatile access matches nginx's
    // own reads and is required because other worker processes update the shared counters.
    unsafe { counter.read_volatile() as u64 }
}

unsafe fn connection_stats_from_ptrs(
    active: *const ngx_atomic_t,
    reading: *const ngx_atomic_t,
    writing: *const ngx_atomic_t,
    waiting: *const ngx_atomic_t,
    accepted: *const ngx_atomic_t,
    handled: *const ngx_atomic_t,
    requests: *const ngx_atomic_t,
) -> ConnectionStats {
    // SAFETY: the caller guarantees that every pointer is valid for a volatile read.
    unsafe {
        ConnectionStats {
            active: read_counter(active),
            reading: read_counter(reading),
            writing: read_counter(writing),
            waiting: read_counter(waiting),
            accepted: read_counter(accepted),
            handled: read_counter(handled),
            requests: read_counter(requests),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_stats_map_each_counter() {
        let active: ngx_atomic_t = 7;
        let reading: ngx_atomic_t = 1;
        let writing: ngx_atomic_t = 2;
        let waiting: ngx_atomic_t = 4;
        let accepted: ngx_atomic_t = 100;
        let handled: ngx_atomic_t = 99;
        let requests: ngx_atomic_t = 250;

        let stats = unsafe {
            connection_stats_from_ptrs(
                &raw const active,
                &raw const reading,
                &raw const writing,
                &raw const waiting,
                &raw const accepted,
                &raw const handled,
                &raw const requests,
            )
        };

        assert_eq!(stats.active, 7);
        assert_eq!(stats.reading, 1);
        assert_eq!(stats.writing, 2);
        assert_eq!(stats.waiting, 4);
        assert_eq!(stats.accepted, 100);
        assert_eq!(stats.handled, 99);
        assert_eq!(stats.requests, 250);
    }
}
