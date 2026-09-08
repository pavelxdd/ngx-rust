//! Event-peer keepalive ownership and active/idle transitions.

use core::error;
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr;

use crate::ffi::{NGX_OK, ngx_connection_t, ngx_handle_read_event, ngx_int_t, ngx_uint_t};
use crate::log::LogRef;

use super::super::{EventRef, PostedQueue};
use super::connection::{
    EventPeer, EventPeerConnection, EventPeerConnectionError, EventPeerPreparation,
    EventPeerReleaseState, checked_event_peer_connection, checked_event_peer_events,
    checked_event_peer_pool, inert_event_handler,
};

impl<'address, 'log> EventPeer<'address, 'log> {
    /// Transfers an externally owned live connection into a keepalive owner.
    ///
    /// # Safety
    ///
    /// `connection` must be a live nginx connection with initialized read and write events and no
    /// SSL state. It must remain plain while owned. On success this owner removes both event
    /// timers, replaces their handlers, clears `connection.data`, and becomes solely responsible
    /// for closing the socket and optional pool.
    #[expect(clippy::result_large_err, reason = "the error returns the allocation-free peer owner")]
    pub unsafe fn attach_keepalive(
        mut self,
        connection: *mut ngx_connection_t,
    ) -> Result<EventPeerKeepalive<'address, 'log>, EventPeerAttachError<'address, 'log>> {
        debug_assert!(self.raw.connection.is_null());
        if let Err(error) = checked_event_peer_connection(connection) {
            return Err(EventPeerAttachError::Connection { error, peer: self });
        }

        self.raw.connection = connection;
        if let Err(error) = self.quiesce(true) {
            self.raw.connection = ptr::null_mut();
            return Err(EventPeerAttachError::Connection { error, peer: self });
        }
        Ok(EventPeerKeepalive { peer: self })
    }

    fn rebind_log<'next_log>(self, log: LogRef<'next_log>) -> EventPeer<'address, 'next_log> {
        debug_assert_eq!(self.raw.log, log.as_ptr());
        let this = mem::ManuallyDrop::new(self);
        EventPeer {
            raw: unsafe { ptr::read(&raw const this.raw) },
            selected: this.selected,
            _address: PhantomData,
            _log: PhantomData,
            _not_thread_safe: PhantomData,
        }
    }

    fn update_log(&mut self, log: LogRef<'_>) -> Result<(), EventPeerConnectionError> {
        let mut connection = self.connection()?;
        let (mut read, mut write) = checked_event_peer_events(connection)?;
        let mut pool = checked_event_peer_pool(connection)?;

        self.raw.log = log.as_ptr();
        unsafe {
            connection.as_mut().log = log.as_ptr();
            read.as_mut().log = log.as_ptr();
            write.as_mut().log = log.as_ptr();
            if let Some(pool) = pool.as_mut() {
                pool.as_mut().log = log.as_ptr();
            }
        }
        Ok(())
    }

    fn quiesce(&mut self, idle: bool) -> Result<(), EventPeerConnectionError> {
        let mut connection = self.connection()?;
        let (mut read, mut write) = checked_event_peer_events(connection)?;

        unsafe {
            if read.as_ref().timer_set() != 0 {
                crate::ffi::ngx_del_timer(read.as_ptr());
            }
            if write.as_ref().timer_set() != 0 {
                crate::ffi::ngx_del_timer(write.as_ptr());
            }

            read.as_mut().handler = Some(inert_event_handler);
            write.as_mut().handler = Some(inert_event_handler);
            connection.as_mut().data = ptr::null_mut();
            connection.as_mut().set_idle(idle.into());
        }

        Ok(())
    }

    fn keepalive_state(&self) -> Result<EventPeerKeepaliveState, EventPeerConnectionError> {
        let connection = self.connection()?;
        let (read, write) = checked_event_peer_events(connection)?;

        unsafe {
            Ok(EventPeerKeepaliveState {
                connection_error: connection.as_ref().error() != 0,
                read_eof: read.as_ref().eof() != 0,
                read_error: read.as_ref().error() != 0,
                read_timed_out: read.as_ref().timedout() != 0,
                write_error: write.as_ref().error() != 0,
                write_timed_out: write.as_ref().timedout() != 0,
                read_ready: read.as_ref().ready() != 0,
            })
        }
    }

    fn validate_keepalive(&self) -> Result<(), EventPeerConnectionError> {
        let state = self.keepalive_state()?;
        if state.connection_error {
            return Err(EventPeerConnectionError::StaleConnectionError);
        }
        if state.read_eof {
            return Err(EventPeerConnectionError::StaleReadEndOfFile);
        }
        if state.read_error {
            return Err(EventPeerConnectionError::StaleReadError);
        }
        if state.read_timed_out {
            return Err(EventPeerConnectionError::StaleReadTimedOut);
        }
        if state.write_error {
            return Err(EventPeerConnectionError::StaleWriteError);
        }
        if state.write_timed_out {
            return Err(EventPeerConnectionError::StaleWriteTimedOut);
        }
        if state.read_ready {
            return Err(EventPeerConnectionError::StaleReadReady);
        }
        Ok(())
    }

    fn register_keepalive_read(&mut self) -> Result<(), EventPeerConnectionError> {
        let connection = self.connection()?;
        let (read, _) = checked_event_peer_events(connection)?;
        if unsafe { ngx_handle_read_event(read.as_ptr(), 0) } != NGX_OK as _ {
            return Err(EventPeerConnectionError::ReadEventRegistration);
        }
        Ok(())
    }
}

impl<'address, 'log> EventPeerConnection<'address, 'log> {
    /// Validates and prepares an idle connection, then registers read monitoring before transfer.
    #[expect(clippy::result_large_err, reason = "the error returns the allocation-free peer owner")]
    pub fn into_keepalive<'idle_log>(
        mut self,
        mut preparation: EventPeerPreparation<'idle_log>,
    ) -> Result<
        EventPeerKeepalive<'address, 'idle_log>,
        EventPeerKeepaliveTransferError<'address, 'log>,
    > {
        if let Err(error) = self.peer.validate_keepalive() {
            return Err(EventPeerKeepaliveTransferError::Connection { error, connection: self });
        }
        if let Err(error) = self.peer.quiesce(true) {
            return Err(EventPeerKeepaliveTransferError::Connection { error, connection: self });
        }

        let active_log = self.peer.log();
        let idle_log = preparation.log;
        preparation.idle = true;
        if let Err(error) = self.peer.prepare(preparation) {
            return Err(EventPeerKeepaliveTransferError::Connection { error, connection: self });
        }
        if let Err(error) = self.peer.register_keepalive_read() {
            let _ = self.peer.quiesce(false);
            let _ = self.peer.update_log(active_log);
            return Err(EventPeerKeepaliveTransferError::Connection { error, connection: self });
        }

        let peer = self.peer.rebind_log(idle_log);
        Ok(EventPeerKeepalive { peer })
    }
}

/// Failure while attaching an externally owned connection to a keepalive owner.
#[derive(Debug)]
pub enum EventPeerAttachError<'address, 'log> {
    /// The supplied native connection does not meet the ownership contract.
    Connection {
        /// The validation failure.
        error: EventPeerConnectionError,
        /// The retained detached peer.
        peer: EventPeer<'address, 'log>,
    },
}

impl<'address, 'log> EventPeerAttachError<'address, 'log> {
    /// Returns the retained peer after a failed attach operation.
    pub fn into_peer(self) -> EventPeer<'address, 'log> {
        match self {
            Self::Connection { peer, .. } => peer,
        }
    }
}

impl fmt::Display for EventPeerAttachError<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { error, .. } => {
                write!(formatter, "invalid keepalive connection: {error}")
            }
        }
    }
}

impl error::Error for EventPeerAttachError<'_, '_> {}

/// Failure while moving an active connection into keepalive storage.
#[derive(Debug)]
pub enum EventPeerKeepaliveTransferError<'address, 'log> {
    /// The native connection could not be validated, prepared, or registered for idle use.
    Connection {
        /// The transition failure.
        error: EventPeerConnectionError,
        /// The retained active connection owner.
        connection: EventPeerConnection<'address, 'log>,
    },
}

impl<'address, 'log> EventPeerKeepaliveTransferError<'address, 'log> {
    /// Returns the retained active connection owner after a failed transfer.
    pub fn into_connection(self) -> EventPeerConnection<'address, 'log> {
        match self {
            Self::Connection { connection, .. } => connection,
        }
    }
}

impl fmt::Display for EventPeerKeepaliveTransferError<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { error, .. } => {
                write!(formatter, "event peer keepalive transfer failed: {error}")
            }
        }
    }
}

impl error::Error for EventPeerKeepaliveTransferError<'_, '_> {}

/// Native state that can make a keepalive connection stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventPeerKeepaliveState {
    /// nginx has recorded a connection error.
    pub connection_error: bool,
    /// The read event reached end of file.
    pub read_eof: bool,
    /// The read event has a terminal error.
    pub read_error: bool,
    /// The read event timed out.
    pub read_timed_out: bool,
    /// The write event has a terminal error.
    pub write_error: bool,
    /// The write event timed out.
    pub write_timed_out: bool,
    /// The read event has unread input available.
    pub read_ready: bool,
}

/// Owner of a reusable event-peer socket outside an active request.
///
/// Idle sockets cannot perform active connection I/O.
///
/// ```compile_fail
/// use ngx::event::EventPeerKeepalive;
///
/// fn reject(mut keepalive: EventPeerKeepalive<'_, '_>) {
///     let _ = keepalive.with_connection(|_| ());
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::EventPeerKeepalive;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// fn reject(keepalive: &EventPeerKeepalive<'_, '_>) {
///     require_sync(keepalive);
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::{EventPeerConnection, EventPeerKeepalive};
/// use ngx::log::LogRef;
///
/// fn reject<'address>(
///     keepalive: EventPeerKeepalive<'address, 'static>,
///     request_log: LogRef<'_>,
/// ) -> EventPeerConnection<'address, 'static> {
///     keepalive.into_connection(request_log).unwrap()
/// }
/// ```
#[derive(Debug)]
pub struct EventPeerKeepalive<'address, 'log> {
    pub(super) peer: EventPeer<'address, 'log>,
}

impl<'address, 'log> EventPeerKeepalive<'address, 'log> {
    /// Posts the idle read event for deferred disposal without exposing active socket I/O.
    ///
    /// # Safety
    ///
    /// The caller must retain this keepalive owner until nginx dispatches or cancels the posted
    /// event, and the installed read handler must accept that dispatch.
    pub unsafe fn post_read_event(
        &mut self,
        queue: PostedQueue,
    ) -> Result<(), EventPeerConnectionError> {
        let connection = self.peer.connection()?;
        let (read, _) = checked_event_peer_events(connection)?;
        unsafe {
            EventRef::with_raw(read.as_ptr(), |mut read| {
                read.post(queue);
            })
        }
        .map_err(Into::into)
    }

    /// Returns the native state that determines whether this connection is stale.
    pub fn stale_state(&self) -> Result<EventPeerKeepaliveState, EventPeerConnectionError> {
        self.peer.keepalive_state()
    }

    /// Rejects a connection with terminal native event state or unread input.
    pub fn validate(&self) -> Result<(), EventPeerConnectionError> {
        self.peer.validate_keepalive()
    }

    /// Installs the active logger and transfers the socket back without allocating a new socket.
    #[expect(clippy::result_large_err, reason = "the error returns the allocation-free peer owner")]
    pub fn into_connection<'active_log>(
        mut self,
        log: LogRef<'active_log>,
    ) -> Result<
        EventPeerConnection<'address, 'active_log>,
        EventPeerKeepaliveIntoConnectionError<'address, 'log>,
    > {
        if let Err(error) = self.validate() {
            return Err(EventPeerKeepaliveIntoConnectionError::Connection {
                error,
                keepalive: self,
            });
        }
        if let Err(error) = self.peer.quiesce(false) {
            return Err(EventPeerKeepaliveIntoConnectionError::Connection {
                error,
                keepalive: self,
            });
        }
        if let Err(error) = self.peer.update_log(log) {
            return Err(EventPeerKeepaliveIntoConnectionError::Connection {
                error,
                keepalive: self,
            });
        }
        let peer = self.peer.rebind_log(log);
        Ok(EventPeerConnection { peer })
    }

    /// Notifies the active selector. Returns `false` when no callback exists.
    pub fn notify(&mut self, type_: ngx_uint_t) -> bool {
        self.peer.notify(type_)
    }

    /// Loads this peer's SSL session when the selector configured a callback.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub fn set_session(&mut self) -> Option<ngx_int_t> {
        self.peer.set_session()
    }

    /// Saves this peer's SSL session when the selector configured a callback.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub fn save_session(&mut self) -> bool {
        self.peer.save_session()
    }

    /// Releases the selected peer exactly once and closes any connection it does not retain.
    pub fn release(self, state: EventPeerReleaseState) {
        self.peer.release(state);
    }

    /// Closes the owned socket and optional pool immediately.
    pub fn close(self) {
        drop(self);
    }
}

/// Failure while moving a keepalive socket back into an active connection owner.
#[derive(Debug)]
pub enum EventPeerKeepaliveIntoConnectionError<'address, 'log> {
    /// The native keepalive connection could not be safely quiesced.
    Connection {
        /// The quiesce failure.
        error: EventPeerConnectionError,
        /// The retained keepalive owner.
        keepalive: EventPeerKeepalive<'address, 'log>,
    },
}

impl<'address, 'log> EventPeerKeepaliveIntoConnectionError<'address, 'log> {
    /// Returns the retained keepalive owner after a failed transfer.
    pub fn into_keepalive(self) -> EventPeerKeepalive<'address, 'log> {
        match self {
            Self::Connection { keepalive, .. } => keepalive,
        }
    }
}

impl fmt::Display for EventPeerKeepaliveIntoConnectionError<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { error, .. } => {
                write!(formatter, "event peer active transfer failed: {error}")
            }
        }
    }
}

impl error::Error for EventPeerKeepaliveIntoConnectionError<'_, '_> {}
