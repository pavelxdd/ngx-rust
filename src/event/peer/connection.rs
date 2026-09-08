//! Active and pending event-peer connection ownership.

use core::error;
use core::ffi::{c_int, c_void};
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};

use crate::core::{ConnectionError, ConnectionRefMut};
use crate::ffi::{
    NGX_AGAIN, NGX_BUSY, NGX_DECLINED, NGX_DONE, NGX_ERROR, NGX_OK, ngx_addr_t, ngx_connection_t,
    ngx_create_pool, ngx_destroy_pool, ngx_event_connect_peer, ngx_event_get_peer,
    ngx_event_handler_pt, ngx_event_t, ngx_int_t, ngx_log_t, ngx_peer_connection_t,
    ngx_pool_large_t, ngx_pool_t, ngx_socket_errno, ngx_uint_t,
};
use crate::log::LogRef;

use super::super::{EventError, EventRef};

const NGX_POOL_ALIGNMENT: usize = 16;
pub(super) const EVENT_PEER_MIN_POOL_SIZE: usize =
    (mem::size_of::<ngx_pool_t>() + 2 * mem::size_of::<ngx_pool_large_t>() + NGX_POOL_ALIGNMENT
        - 1)
        & !(NGX_POOL_ALIGNMENT - 1);

/// Native read and write handlers installed while a peer is active or idle.
#[derive(Clone, Copy)]
pub struct EventPeerHandlers {
    pub(super) read: ngx_event_handler_pt,
    pub(super) write: ngx_event_handler_pt,
}

impl EventPeerHandlers {
    /// Creates a handler pair for the connection read and write events.
    ///
    /// ```compile_fail
    /// use ngx::event::EventPeerHandlers;
    /// use ngx::ffi::ngx_event_t;
    ///
    /// unsafe extern "C" fn handler(_event: *mut ngx_event_t) {}
    ///
    /// let _ = EventPeerHandlers::new(handler, handler);
    /// ```
    ///
    /// # Safety
    ///
    /// Both handlers must accept every event on which this pair is installed and must not unwind.
    /// Their event, logger, connection, and `connection.data` preconditions must be satisfied from
    /// publication until the handlers are replaced or the connection is closed. They must not
    /// install SSL state or invalidate event or owner storage during dispatch.
    pub unsafe fn new(
        read: unsafe extern "C" fn(*mut ngx_event_t),
        write: unsafe extern "C" fn(*mut ngx_event_t),
    ) -> Self {
        Self { read: Some(read), write: Some(write) }
    }
}

/// Connection preparation applied before a peer is used by a request or keepalive wrapper.
pub struct EventPeerPreparation<'log> {
    pub(super) log: LogRef<'log>,
    pub(super) handlers: EventPeerHandlers,
    pub(super) pool_size: usize,
    pub(super) data: *mut c_void,
    pub(super) idle: bool,
}

impl<'log> EventPeerPreparation<'log> {
    /// Creates preparation that uses `log`, installs `handlers`, and creates a pool when absent.
    pub fn new(log: LogRef<'log>, handlers: EventPeerHandlers, pool_size: usize) -> Self {
        Self { log, handlers, pool_size, data: ptr::null_mut(), idle: false }
    }

    /// Supplies opaque connection data for the selected handlers.
    ///
    /// # Safety
    ///
    /// `data` must remain valid while the prepared connection can invoke its handlers.
    pub unsafe fn data(mut self, data: *mut c_void) -> Self {
        self.data = data;
        self
    }
}

/// Failure while operating on a connected event peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerConnectionError {
    /// The peer no longer owns a connection.
    Detached,
    /// nginx has not reported connect readiness yet.
    NotReady,
    /// The requested connection pool is smaller than nginx's minimum layout.
    PoolTooSmall {
        /// The requested pool size.
        requested: usize,
        /// The minimum size required by the native pool layout.
        minimum: usize,
    },
    /// nginx did not create a connection pool.
    PoolAllocation,
    /// The connection has SSL state that this plain-socket owner cannot finalize.
    SslConnection,
    /// The native `getsockopt(SO_ERROR)` call failed.
    SocketOption(ngx_int_t),
    /// The completed socket reported a nonzero `SO_ERROR` value.
    Connect(ngx_int_t),
    /// nginx reported terminal connect event state without a socket error.
    ConnectEvent,
    /// nginx returned an unexpected `SO_ERROR` output length.
    SocketOptionLength,
    /// A keepalive connection has a pending nginx connection error.
    StaleConnectionError,
    /// A keepalive connection reached end of file.
    StaleReadEndOfFile,
    /// A keepalive read event has a terminal error.
    StaleReadError,
    /// A keepalive read event timed out.
    StaleReadTimedOut,
    /// A keepalive write event has a terminal error.
    StaleWriteError,
    /// A keepalive write event timed out.
    StaleWriteTimedOut,
    /// A keepalive connection has unread input.
    StaleReadReady,
    /// nginx could not register the keepalive read event.
    ReadEventRegistration,
    /// The checked connection view is invalid.
    Connection(ConnectionError),
    /// The checked event view is invalid.
    Event(EventError),
}

impl From<ConnectionError> for EventPeerConnectionError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

impl From<EventError> for EventPeerConnectionError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

impl fmt::Display for EventPeerConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detached => formatter.write_str("event peer connection is detached"),
            Self::NotReady => formatter.write_str("event peer connection is not ready"),
            Self::PoolTooSmall { requested, minimum } => write!(
                formatter,
                "event peer connection pool size {requested} is smaller than minimum {minimum}"
            ),
            Self::PoolAllocation => {
                formatter.write_str("event peer connection pool allocation failed")
            }
            Self::SslConnection => formatter.write_str("event peer does not own SSL connections"),
            Self::SocketOption(error) => {
                write!(formatter, "event peer SO_ERROR lookup failed with socket error {error}")
            }
            Self::Connect(error) => {
                write!(formatter, "event peer connect completed with socket error {error}")
            }
            Self::ConnectEvent => {
                formatter.write_str("event peer connect reached terminal event state")
            }
            Self::SocketOptionLength => {
                formatter.write_str("event peer SO_ERROR lookup returned an invalid length")
            }
            Self::StaleConnectionError => {
                formatter.write_str("event peer keepalive connection has an error")
            }
            Self::StaleReadEndOfFile => {
                formatter.write_str("event peer keepalive connection reached end of file")
            }
            Self::StaleReadError => {
                formatter.write_str("event peer keepalive read event has an error")
            }
            Self::StaleReadTimedOut => {
                formatter.write_str("event peer keepalive read event timed out")
            }
            Self::StaleWriteError => {
                formatter.write_str("event peer keepalive write event has an error")
            }
            Self::StaleWriteTimedOut => {
                formatter.write_str("event peer keepalive write event timed out")
            }
            Self::StaleReadReady => {
                formatter.write_str("event peer keepalive connection has unread input")
            }
            Self::ReadEventRegistration => {
                formatter.write_str("event peer keepalive read event registration failed")
            }
            Self::Connection(_) => formatter.write_str("event peer connection is invalid"),
            Self::Event(_) => formatter.write_str("event peer connection event is invalid"),
        }
    }
}

impl error::Error for EventPeerConnectionError {}

/// Native release flags passed to an event peer's `free` callback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventPeerReleaseState(pub(super) ngx_uint_t);

impl EventPeerReleaseState {
    /// Releases a peer without an additional retry or failure flag.
    pub const NONE: Self = Self(0);
    /// The connection may be retained by a keepalive selector.
    pub const KEEPALIVE: Self = Self(1);
    /// The caller will try another peer.
    pub const NEXT: Self = Self(2);
    /// The selected peer failed.
    pub const FAILED: Self = Self(4);

    /// Combines independent native release flags.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One fully initialized native event peer for plain, non-SSL connections.
///
/// Dropping a selected peer releases it with [`EventPeerReleaseState::FAILED`], then closes any
/// connection the release callback did not retain. This owner rejects native connections with SSL
/// state because synchronous [`Drop`] cannot complete nginx's asynchronous SSL shutdown lifecycle.
///
/// ```compile_fail
/// use ngx::event::EventPeer;
///
/// fn require_send<T: Send>(_: T) {}
/// fn require_sync<T: Sync>(_: &T) {}
/// fn reject(peer: EventPeer<'_, '_>) {
///     require_send(peer);
///     require_sync(&peer);
/// }
/// ```
#[derive(Debug)]
pub struct EventPeer<'address, 'log> {
    pub(super) raw: ngx_peer_connection_t,
    pub(super) selected: bool,
    pub(super) _address: PhantomData<&'address ngx_addr_t>,
    pub(super) _log: PhantomData<&'log ngx_log_t>,
    pub(super) _not_thread_safe: PhantomData<*mut ()>,
}

impl<'address, 'log> EventPeer<'address, 'log> {
    /// Invokes nginx's native peer connect operation and preserves its exact result category.
    ///
    /// `NGX_ERROR` is returned as [`EventPeerConnectResult::Error`]. `Err` is reserved for an
    /// invalid native status or connection descriptor.
    #[expect(clippy::result_large_err, reason = "the error returns the allocation-free peer owner")]
    pub fn connect(
        mut self,
    ) -> Result<EventPeerConnectResult<'address, 'log>, EventPeerConnectError<'address, 'log>> {
        debug_assert!(self.raw.connection.is_null());
        let get = self.raw.get.expect("validated event peer selector");
        let selection_status = unsafe { get(&raw mut self.raw, self.raw.data) };
        if selection_status != NGX_OK as _ {
            self.selected = selection_status == NGX_DONE as _;
            if selection_status == NGX_AGAIN as _ {
                return Ok(EventPeerConnectResult::SelectionPending(self));
            }
            return self.classify_connect(selection_status);
        }

        self.selected = true;
        self.raw.get = Some(ngx_event_get_peer);
        let status = unsafe { ngx_event_connect_peer(&raw mut self.raw) };
        self.raw.get = Some(get);
        self.classify_connect(status)
    }

    #[expect(clippy::result_large_err, reason = "the error returns the allocation-free peer owner")]
    pub(super) fn classify_connect(
        mut self,
        status: ngx_int_t,
    ) -> Result<EventPeerConnectResult<'address, 'log>, EventPeerConnectError<'address, 'log>> {
        let status = match status {
            value if value == NGX_OK as _ => EventPeerConnectStatus::Connected,
            value if value == NGX_DONE as _ => EventPeerConnectStatus::Reused,
            value if value == NGX_AGAIN as _ => EventPeerConnectStatus::Pending,
            value if value == NGX_BUSY as _ => EventPeerConnectStatus::Busy,
            value if value == NGX_DECLINED as _ => EventPeerConnectStatus::Declined,
            value if value == NGX_ERROR as _ => EventPeerConnectStatus::Error,
            _ => {
                self.raw.connection = ptr::null_mut();
                return Err(EventPeerConnectError::UnexpectedStatus { status, peer: self });
            }
        };

        match status {
            EventPeerConnectStatus::Connected
            | EventPeerConnectStatus::Reused
            | EventPeerConnectStatus::Pending => {
                let connection = self.raw.connection;
                if connection.is_null() {
                    return Err(EventPeerConnectError::MissingConnection { status, peer: self });
                }
                if !connection.is_aligned() {
                    self.raw.connection = ptr::null_mut();
                    return Err(EventPeerConnectError::MisalignedConnection { status, peer: self });
                }
                let connection = unsafe { NonNull::new_unchecked(connection) };
                let (mut read, mut write) = match checked_event_peer_events(connection) {
                    Ok(events) => events,
                    Err(error) => {
                        self.raw.connection = ptr::null_mut();
                        return Err(EventPeerConnectError::InvalidConnection {
                            status,
                            error,
                            peer: self,
                        });
                    }
                };
                unsafe {
                    read.as_mut().handler = Some(inert_event_handler);
                    write.as_mut().handler = Some(inert_event_handler);
                }
            }
            EventPeerConnectStatus::Busy
            | EventPeerConnectStatus::Declined
            | EventPeerConnectStatus::Error => {
                if !self.raw.connection.is_null() {
                    self.raw.connection = ptr::null_mut();
                    return Err(EventPeerConnectError::ConnectionOnFailure { status, peer: self });
                }
            }
            EventPeerConnectStatus::SelectionPending => unreachable!("classified native status"),
        }

        Ok(match status {
            EventPeerConnectStatus::Connected => {
                EventPeerConnectResult::Connected(EventPeerConnection { peer: self })
            }
            EventPeerConnectStatus::Reused => {
                EventPeerConnectResult::Reused(EventPeerConnection { peer: self })
            }
            EventPeerConnectStatus::Pending => {
                EventPeerConnectResult::Pending(EventPeerPendingConnection { peer: self })
            }
            EventPeerConnectStatus::SelectionPending => unreachable!("classified native status"),
            EventPeerConnectStatus::Busy => EventPeerConnectResult::Busy(self),
            EventPeerConnectStatus::Declined => EventPeerConnectResult::Declined(self),
            EventPeerConnectStatus::Error => EventPeerConnectResult::Error(self),
        })
    }

    /// Releases the selected peer exactly once, then closes any connection the callback did not
    /// retain.
    pub fn release(mut self, state: EventPeerReleaseState) {
        self.release_selection(state);
    }

    /// Notifies the active selector. Returns `false` when no selection or callback exists.
    pub fn notify(&mut self, type_: ngx_uint_t) -> bool {
        let Some(callback) = self.selected.then_some(self.raw.notify).flatten() else {
            return false;
        };
        unsafe { callback(&raw mut self.raw, self.raw.data, type_) };
        true
    }

    /// Loads a selected peer's SSL session when the callback is configured.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub fn set_session(&mut self) -> Option<ngx_int_t> {
        let callback = self.selected.then_some(self.raw.set_session).flatten()?;
        Some(unsafe { callback(&raw mut self.raw, self.raw.data) })
    }

    /// Saves a selected peer's SSL session. Returns `false` when no callback exists.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub fn save_session(&mut self) -> bool {
        let Some(callback) = self.selected.then_some(self.raw.save_session).flatten() else {
            return false;
        };
        unsafe { callback(&raw mut self.raw, self.raw.data) };
        true
    }

    /// Closes the owned socket and optional pool immediately.
    pub fn close(self) {
        drop(self);
    }

    fn release_selection(&mut self, state: EventPeerReleaseState) {
        if !mem::take(&mut self.selected) {
            return;
        }
        if let Some(callback) = self.raw.free {
            unsafe { callback(&raw mut self.raw, self.raw.data, state.0) };
        }
    }

    pub(super) fn log(&self) -> LogRef<'log> {
        // EventPeerBuilder validates the logger and this owner carries its current lifetime.
        unsafe { LogRef::from_raw(self.raw.log) }.expect("validated peer logger")
    }

    pub(super) fn connection(&self) -> Result<NonNull<ngx_connection_t>, EventPeerConnectionError> {
        if self.raw.connection.is_null() {
            return Err(EventPeerConnectionError::Detached);
        }
        checked_plain_event_peer_connection_ptr(self.raw.connection)
    }

    pub(super) fn prepare(
        &mut self,
        preparation: EventPeerPreparation<'_>,
    ) -> Result<(), EventPeerConnectionError> {
        let mut connection = self.connection()?;
        let (mut read, mut write) = checked_event_peer_events(connection)?;
        let mut pool = match checked_event_peer_pool(connection)? {
            Some(pool) => pool,
            None => {
                if preparation.pool_size < EVENT_PEER_MIN_POOL_SIZE {
                    return Err(EventPeerConnectionError::PoolTooSmall {
                        requested: preparation.pool_size,
                        minimum: EVENT_PEER_MIN_POOL_SIZE,
                    });
                }
                let pool = NonNull::new(unsafe {
                    ngx_create_pool(preparation.pool_size, preparation.log.as_ptr())
                })
                .ok_or(EventPeerConnectionError::PoolAllocation)?;
                unsafe { connection.as_mut().pool = pool.as_ptr() };
                pool
            }
        };

        self.raw.log = preparation.log.as_ptr();
        unsafe {
            let connection = connection.as_mut();
            connection.log = preparation.log.as_ptr();
            connection.data = preparation.data;
            connection.set_idle(preparation.idle.into());

            let read = read.as_mut();
            read.log = preparation.log.as_ptr();
            read.handler = preparation.handlers.read;

            let write = write.as_mut();
            write.log = preparation.log.as_ptr();
            write.handler = preparation.handlers.write;

            pool.as_mut().log = preparation.log.as_ptr();
        }

        Ok(())
    }

    fn close_owned(&mut self) {
        let connection = self.raw.connection;
        self.raw.connection = ptr::null_mut();

        let Ok(mut connection) = checked_event_peer_connection_ptr(connection) else {
            return;
        };
        let Ok((mut read, mut write)) = checked_event_peer_events(connection) else {
            return;
        };
        let pool = checked_event_peer_pool(connection).ok().flatten();

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
            connection.as_mut().pool = ptr::null_mut();
            crate::ffi::ngx_close_connection(connection.as_ptr());
        }

        if let Some(pool) = pool {
            unsafe { ngx_destroy_pool(pool.as_ptr()) };
        }
    }
}

impl Drop for EventPeer<'_, '_> {
    fn drop(&mut self) {
        self.release_selection(EventPeerReleaseState::FAILED);
        self.close_owned();
    }
}

pub(super) unsafe extern "C" fn inert_event_handler(_event: *mut ngx_event_t) {}

pub(super) fn checked_event_peer_connection(
    connection: *mut ngx_connection_t,
) -> Result<(), EventPeerConnectionError> {
    let connection = checked_plain_event_peer_connection_ptr(connection)?;
    let _ = checked_event_peer_events(connection)?;
    let _ = checked_event_peer_pool(connection)?;
    Ok(())
}

pub(super) fn checked_plain_event_peer_connection_ptr(
    connection: *mut ngx_connection_t,
) -> Result<NonNull<ngx_connection_t>, EventPeerConnectionError> {
    let connection = checked_event_peer_connection_ptr(connection)?;
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    if !unsafe { connection.as_ref().ssl }.is_null() {
        return Err(EventPeerConnectionError::SslConnection);
    }
    Ok(connection)
}

pub(super) fn checked_event_peer_connection_ptr(
    connection: *mut ngx_connection_t,
) -> Result<NonNull<ngx_connection_t>, EventPeerConnectionError> {
    let connection = NonNull::new(connection).ok_or(ConnectionError::NullConnection)?;
    if !connection.as_ptr().is_aligned() {
        return Err(ConnectionError::MisalignedConnection.into());
    }
    Ok(connection)
}

pub(super) fn checked_event_peer_events(
    connection: NonNull<ngx_connection_t>,
) -> Result<(NonNull<ngx_event_t>, NonNull<ngx_event_t>), EventPeerConnectionError> {
    let read = unsafe { connection.as_ref().read };
    let write = unsafe { connection.as_ref().write };
    let read = NonNull::new(read).ok_or(EventError::NullEvent)?;
    let write = NonNull::new(write).ok_or(EventError::NullEvent)?;
    if !read.as_ptr().is_aligned() || !write.as_ptr().is_aligned() {
        return Err(EventError::MisalignedEvent.into());
    }
    Ok((read, write))
}

pub(super) fn checked_event_peer_pool(
    connection: NonNull<ngx_connection_t>,
) -> Result<Option<NonNull<ngx_pool_t>>, EventPeerConnectionError> {
    let pool = unsafe { connection.as_ref().pool };
    let Some(pool) = NonNull::new(pool) else {
        return Ok(None);
    };
    if !pool.as_ptr().is_aligned() {
        return Err(ConnectionError::MisalignedPool.into());
    }
    Ok(Some(pool))
}

/// Active owner of one native event-peer socket.
///
/// A connected owner cannot start another native connect.
///
/// ```compile_fail
/// use ngx::event::EventPeerConnection;
///
/// fn reject(connection: EventPeerConnection<'_, '_>) {
///     let _ = connection.connect();
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::EventPeerConnection;
///
/// fn require_send<T: Send>(_: T) {}
/// fn reject(connection: EventPeerConnection<'_, '_>) {
///     require_send(connection);
/// }
/// ```
#[derive(Debug)]
pub struct EventPeerConnection<'address, 'log> {
    pub(super) peer: EventPeer<'address, 'log>,
}

/// Owner of a socket with a nonblocking connection in progress.
///
/// Pending sockets expose only connect-event operations, not active socket I/O or keepalive
/// transfer.
///
/// ```compile_fail
/// use ngx::event::EventPeerPendingConnection;
///
/// fn reject(mut connection: EventPeerPendingConnection<'_, '_>) {
///     let _ = connection.with_connection(|_| ());
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::{EventPeerPendingConnection, EventPeerPreparation};
///
/// fn reject(
///     connection: EventPeerPendingConnection<'_, '_>,
///     preparation: EventPeerPreparation<'_>,
/// ) {
///     let _ = connection.into_keepalive(preparation);
/// }
/// ```
#[derive(Debug)]
pub struct EventPeerPendingConnection<'address, 'log> {
    pub(super) peer: EventPeer<'address, 'log>,
}

/// Capability that owns a pending connection after nginx reports readiness or terminal state.
#[derive(Debug)]
pub struct EventPeerConnectReady<'address, 'log> {
    connection: EventPeerPendingConnection<'address, 'log>,
    terminal: bool,
}

impl<'address, 'log> EventPeerConnectReady<'address, 'log> {
    /// Consumes the pending owner and classifies the socket's `SO_ERROR` exactly once.
    pub fn complete(self) -> Result<EventPeerConnection<'address, 'log>, EventPeerConnectionError> {
        let connection = self.connection.peer.connection()?;
        let fd = unsafe { connection.as_ref().fd };
        let mut socket_error: c_int = 0;
        let mut length = mem::size_of_val(&socket_error) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd as _,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut socket_error).cast(),
                &raw mut length,
            )
        };
        if result != 0 {
            return Err(EventPeerConnectionError::SocketOption(ngx_socket_errno() as _));
        }
        if length as usize != mem::size_of_val(&socket_error) {
            return Err(EventPeerConnectionError::SocketOptionLength);
        }
        if socket_error != 0 {
            return Err(EventPeerConnectionError::Connect(socket_error as _));
        }
        if self.terminal {
            return Err(EventPeerConnectionError::ConnectEvent);
        }

        Ok(EventPeerConnection { peer: self.connection.peer })
    }
}

/// A pending connection that was checked before nginx reported readiness.
#[derive(Debug)]
pub struct EventPeerConnectReadyError<'address, 'log> {
    error: EventPeerConnectionError,
    connection: EventPeerPendingConnection<'address, 'log>,
}

impl<'address, 'log> EventPeerConnectReadyError<'address, 'log> {
    /// Returns the reason no completion capability was issued.
    pub fn error(&self) -> EventPeerConnectionError {
        self.error
    }

    /// Returns the pending owner so the caller can wait for another event.
    pub fn into_connection(self) -> EventPeerPendingConnection<'address, 'log> {
        self.connection
    }
}

impl fmt::Display for EventPeerConnectReadyError<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "event peer connect is not ready: {}", self.error)
    }
}

impl error::Error for EventPeerConnectReadyError<'_, '_> {}

impl<'address, 'log> EventPeerPendingConnection<'address, 'log> {
    /// Creates a connection pool when absent, then installs log, data, idle state, and handlers.
    pub fn prepare(
        &mut self,
        preparation: EventPeerPreparation<'log>,
    ) -> Result<(), EventPeerConnectionError> {
        self.peer.prepare(preparation)
    }

    /// Gives callback-scoped access to the write event without exposing socket I/O.
    pub fn with_write_event<R>(
        &mut self,
        f: impl for<'scope> FnOnce(EventRef<'scope>) -> R,
    ) -> Result<R, EventPeerConnectionError> {
        let connection = self.peer.connection()?;
        let (_, write) = checked_event_peer_events(connection)?;
        unsafe { EventRef::with_raw(write.as_ptr(), f) }.map_err(Into::into)
    }

    /// Consumes this owner after nginx reports connect readiness or terminal state.
    #[expect(
        clippy::result_large_err,
        reason = "the error returns the allocation-free pending owner"
    )]
    pub fn connect_ready(
        self,
    ) -> Result<EventPeerConnectReady<'address, 'log>, EventPeerConnectReadyError<'address, 'log>>
    {
        let state = self.peer.connection().and_then(|connection| {
            let (read, write) = checked_event_peer_events(connection)?;
            let ready = unsafe { read.as_ref().ready() != 0 || write.as_ref().ready() != 0 };
            let terminal = unsafe {
                connection.as_ref().error() != 0
                    || read.as_ref().error() != 0
                    || read.as_ref().eof() != 0
                    || read.as_ref().timedout() != 0
                    || write.as_ref().error() != 0
                    || write.as_ref().eof() != 0
                    || write.as_ref().timedout() != 0
            };
            if !ready && !terminal {
                return Err(EventPeerConnectionError::NotReady);
            }
            Ok(terminal)
        });

        match state {
            Ok(terminal) => Ok(EventPeerConnectReady { connection: self, terminal }),
            Err(error) => Err(EventPeerConnectReadyError { error, connection: self }),
        }
    }

    #[cfg(feature = "async")]
    pub(crate) fn readiness_parts(
        &self,
    ) -> Result<(NonNull<ngx_connection_t>, NonNull<ngx_event_t>), EventPeerConnectionError> {
        let connection = self.peer.connection()?;
        let (_, write) = checked_event_peer_events(connection)?;
        Ok((connection, write))
    }

    #[cfg(feature = "async")]
    pub(crate) fn readiness_log(&self) -> LogRef<'log> {
        self.peer.log()
    }

    /// Releases the selected peer exactly once and closes the pending socket.
    pub fn release(self, state: EventPeerReleaseState) {
        self.peer.release(state);
    }

    /// Closes the pending socket immediately.
    pub fn close(self) {
        drop(self);
    }
}

impl<'address, 'log> EventPeerConnection<'address, 'log> {
    #[cfg(feature = "async")]
    pub(crate) fn readiness_parts(
        &self,
        write: bool,
    ) -> Result<(NonNull<ngx_connection_t>, NonNull<ngx_event_t>), EventPeerConnectionError> {
        let connection = self.peer.connection()?;
        let (read, write_event) = checked_event_peer_events(connection)?;
        Ok((connection, if write { write_event } else { read }))
    }

    #[cfg(feature = "async")]
    pub(crate) fn readiness_log(&self) -> LogRef<'log> {
        self.peer.log()
    }

    /// Creates a connection pool when absent, then installs log, data, idle state, and handlers.
    pub fn prepare(
        &mut self,
        preparation: EventPeerPreparation<'log>,
    ) -> Result<(), EventPeerConnectionError> {
        self.peer.prepare(preparation)
    }

    /// Gives a callback-scoped mutable connection view to the caller.
    pub fn with_connection<R>(
        &mut self,
        f: impl for<'scope> FnOnce(ConnectionRefMut<'scope>) -> R,
    ) -> Result<R, EventPeerConnectionError> {
        let connection = self.peer.connection()?;
        unsafe { ConnectionRefMut::with_raw(connection.as_ptr(), f) }.map_err(Into::into)
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

/// Exact nginx status category returned by an event-peer connect operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerConnectStatus {
    /// The socket connected immediately.
    Connected,
    /// The selector returned a cached connection with `NGX_DONE`.
    Reused,
    /// The socket is connecting asynchronously.
    Pending,
    /// The selector asked to resume selection later without acquiring a peer.
    SelectionPending,
    /// The peer selector reported that no resource is currently available.
    Busy,
    /// The peer selector or native connect rejected the peer.
    Declined,
    /// Native connection setup failed.
    Error,
}

/// Result of a fully initialized native event-peer connect operation.
#[derive(Debug)]
pub enum EventPeerConnectResult<'address, 'log> {
    /// nginx connected the socket immediately.
    Connected(EventPeerConnection<'address, 'log>),
    /// The selector returned a cached connection with `NGX_DONE`.
    Reused(EventPeerConnection<'address, 'log>),
    /// nginx started a nonblocking connect operation.
    Pending(EventPeerPendingConnection<'address, 'log>),
    /// The selector returned `NGX_AGAIN` without acquiring a peer.
    SelectionPending(EventPeer<'address, 'log>),
    /// nginx returned `NGX_BUSY` without publishing a connection.
    Busy(EventPeer<'address, 'log>),
    /// nginx returned `NGX_DECLINED` without publishing a connection.
    Declined(EventPeer<'address, 'log>),
    /// nginx returned `NGX_ERROR` without publishing a connection.
    Error(EventPeer<'address, 'log>),
}

impl<'address, 'log> EventPeerConnectResult<'address, 'log> {
    /// Returns the exact native result category.
    pub fn status(&self) -> EventPeerConnectStatus {
        match self {
            Self::Connected(_) => EventPeerConnectStatus::Connected,
            Self::Reused(_) => EventPeerConnectStatus::Reused,
            Self::Pending(_) => EventPeerConnectStatus::Pending,
            Self::SelectionPending(_) => EventPeerConnectStatus::SelectionPending,
            Self::Busy(_) => EventPeerConnectStatus::Busy,
            Self::Declined(_) => EventPeerConnectStatus::Declined,
            Self::Error(_) => EventPeerConnectStatus::Error,
        }
    }
}

/// Native connect result that violates the checked event-peer contract.
///
/// The retained peer is detached from any connection pointer that cannot be safely owned.
#[derive(Debug)]
pub enum EventPeerConnectError<'address, 'log> {
    /// nginx returned a status outside the supported event-peer results.
    UnexpectedStatus {
        /// The raw nginx status.
        status: ngx_int_t,
        /// The retained peer.
        peer: EventPeer<'address, 'log>,
    },
    /// nginx reported an immediate or pending connection without a connection pointer.
    MissingConnection {
        /// The success category that lacked a connection.
        status: EventPeerConnectStatus,
        /// The retained peer.
        peer: EventPeer<'address, 'log>,
    },
    /// nginx reported an immediate or pending connection with a misaligned pointer.
    MisalignedConnection {
        /// The success category that had an invalid pointer.
        status: EventPeerConnectStatus,
        /// The retained peer.
        peer: EventPeer<'address, 'log>,
    },
    /// nginx returned a success category with invalid embedded events.
    InvalidConnection {
        /// The success category that had invalid connection state.
        status: EventPeerConnectStatus,
        /// The embedded event validation failure.
        error: EventPeerConnectionError,
        /// The retained detached peer.
        peer: EventPeer<'address, 'log>,
    },
    /// nginx returned a failure category after publishing a connection pointer.
    ///
    /// The pointer is detached because a failed peer selector can retain its own connection.
    ConnectionOnFailure {
        /// The failure category that unexpectedly published a connection.
        status: EventPeerConnectStatus,
        /// The retained peer.
        peer: EventPeer<'address, 'log>,
    },
}

impl<'address, 'log> EventPeerConnectError<'address, 'log> {
    /// Returns the retained detached peer after a checked failure.
    pub fn into_peer(self) -> EventPeer<'address, 'log> {
        match self {
            Self::UnexpectedStatus { peer, .. }
            | Self::MissingConnection { peer, .. }
            | Self::MisalignedConnection { peer, .. }
            | Self::InvalidConnection { peer, .. }
            | Self::ConnectionOnFailure { peer, .. } => peer,
        }
    }
}

impl fmt::Display for EventPeerConnectError<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedStatus { status, .. } => {
                write!(formatter, "event peer returned unexpected nginx status {status}")
            }
            Self::MissingConnection { .. } => {
                formatter.write_str("event peer connected without a connection")
            }
            Self::MisalignedConnection { .. } => {
                formatter.write_str("event peer connected with a misaligned connection")
            }
            Self::InvalidConnection { error, .. } => {
                write!(formatter, "event peer connected with invalid native events: {error}")
            }
            Self::ConnectionOnFailure { .. } => {
                formatter.write_str("event peer failed after publishing a connection")
            }
        }
    }
}

impl error::Error for EventPeerConnectError<'_, '_> {}
