use core::error;
use core::ffi::{c_int, c_uint, c_void};
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};
use core::slice;

use super::EventError;
use crate::core::{
    ConnectionError, ConnectionRefMut, NgxStr, SocketAddress, SocketAddressError, SocketType,
    parse_socket_address,
};
use crate::ffi::{
    NGX_AGAIN, NGX_BUSY, NGX_DECLINED, NGX_ERROR, NGX_OK, ngx_addr_t, ngx_connection_t,
    ngx_create_pool, ngx_destroy_pool, ngx_event_connect_peer, ngx_event_free_peer_pt,
    ngx_event_get_peer, ngx_event_get_peer_pt, ngx_event_handler_pt, ngx_event_notify_peer_pt,
    ngx_event_t, ngx_int_t, ngx_log_t, ngx_msec_t, ngx_peer_connection_t, ngx_pool_t,
    ngx_socket_errno, ngx_str_t, ngx_uint_t,
};
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
use crate::ffi::{ngx_event_save_peer_session_pt, ngx_event_set_peer_session_pt};

/// Failure while validating an nginx address used for an outbound event peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerAddressError {
    /// The nginx address pointer is null.
    NullAddress,
    /// The nginx address pointer is misaligned.
    MisalignedAddress,
    /// The selected native socket address is invalid.
    SocketAddress(SocketAddressError),
    /// The nginx address name has bytes but no backing storage.
    MissingName,
    /// The nginx address name exceeds Rust's slice limit.
    NameTooLong,
}

impl fmt::Display for EventPeerAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullAddress => formatter.write_str("event peer address is null"),
            Self::MisalignedAddress => formatter.write_str("event peer address is misaligned"),
            Self::SocketAddress(_) => formatter.write_str("event peer socket address is invalid"),
            Self::MissingName => formatter.write_str("event peer address name has no bytes"),
            Self::NameTooLong => formatter.write_str("event peer address name is too large"),
        }
    }
}

impl error::Error for EventPeerAddressError {}

impl From<SocketAddressError> for EventPeerAddressError {
    fn from(error: SocketAddressError) -> Self {
        Self::SocketAddress(error)
    }
}

/// A checked nginx address retained by an event peer.
///
/// The address and its name must remain valid until the peer is released. Values returned by
/// [`crate::http::ConfiguredUpstreamUrl`] satisfy this through their configuration-pool lifetime.
///
/// ```compile_fail
/// use ngx::event::EventPeerAddress;
/// use ngx::ffi::ngx_addr_t;
///
/// fn construct(address: &ngx_addr_t) {
///     let _ = EventPeerAddress::from_raw(address);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventPeerAddress<'address> {
    raw: NonNull<ngx_addr_t>,
    _address: PhantomData<&'address ngx_addr_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl EventPeerAddress<'_> {
    /// Validates one live nginx address pointer.
    ///
    /// # Safety
    ///
    /// `address` must point to a live `ngx_addr_t`. Any non-null socket-address or name pointer
    /// must be valid for the bytes validated here. After success, both ranges must remain valid
    /// and unchanged for `'address` on this nginx worker.
    pub unsafe fn from_raw(address: *const ngx_addr_t) -> Result<Self, EventPeerAddressError> {
        let raw = NonNull::new(address.cast_mut()).ok_or(EventPeerAddressError::NullAddress)?;
        if !address.is_aligned() {
            return Err(EventPeerAddressError::MisalignedAddress);
        }

        let address = unsafe { raw.as_ref() };
        let _ = unsafe { parse_socket_address(address.sockaddr, address.socklen) }?;
        let _ = checked_name(&address.name)?;

        Ok(Self { raw, _address: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Returns the selected socket address after revalidating its native representation.
    pub fn socket_address(&self) -> Result<SocketAddress<'_>, EventPeerAddressError> {
        let address = unsafe { self.raw.as_ref() };
        unsafe { parse_socket_address(address.sockaddr, address.socklen) }.map_err(Into::into)
    }

    /// Returns the nginx-formatted peer name after revalidating its bytes.
    pub fn name(&self) -> Result<&NgxStr, EventPeerAddressError> {
        let address = unsafe { self.raw.as_ref() };
        Ok(NgxStr::from_bytes(checked_name(&address.name)?))
    }

    pub(crate) fn as_ptr(&self) -> *const ngx_addr_t {
        self.raw.as_ptr().cast_const()
    }
}

fn checked_name(name: &ngx_str_t) -> Result<&[u8], EventPeerAddressError> {
    if name.len == 0 {
        return Ok(&[]);
    }
    if name.len > isize::MAX as usize {
        return Err(EventPeerAddressError::NameTooLong);
    }
    let data = NonNull::new(name.data).ok_or(EventPeerAddressError::MissingName)?;
    Ok(unsafe { slice::from_raw_parts(data.as_ptr(), name.len) })
}

/// Native callback set supplied to an [`EventPeerBuilder`].
///
/// Every callback must obey nginx's ABI and must not unwind through nginx. The get callback is
/// required; the remaining callbacks are optional and default to absent.
#[derive(Clone, Copy, Default)]
pub struct EventPeerCallbacks {
    get: ngx_event_get_peer_pt,
    free: ngx_event_free_peer_pt,
    notify: ngx_event_notify_peer_pt,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    set_session: ngx_event_set_peer_session_pt,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    save_session: ngx_event_save_peer_session_pt,
}

impl EventPeerCallbacks {
    /// Uses nginx's direct peer selector for a preselected address.
    pub fn direct() -> Self {
        Self::default().get(ngx_event_get_peer)
    }

    /// Installs the required peer selector.
    pub fn get(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void) -> ngx_int_t,
    ) -> Self {
        self.get = Some(callback);
        self
    }

    /// Installs an optional peer-release callback.
    pub fn free(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void, ngx_uint_t),
    ) -> Self {
        self.free = Some(callback);
        self
    }

    /// Installs an optional peer-notification callback.
    pub fn notify(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void, ngx_uint_t),
    ) -> Self {
        self.notify = Some(callback);
        self
    }

    /// Installs an optional SSL peer-session lookup callback.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub fn set_session(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void) -> ngx_int_t,
    ) -> Self {
        self.set_session = Some(callback);
        self
    }

    /// Installs an optional SSL peer-session save callback.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub fn save_session(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void),
    ) -> Self {
        self.save_session = Some(callback);
        self
    }
}

/// Controls nginx's connection-close logging for an event peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerLogError {
    /// Log close failures at alert level.
    Alert,
    /// Log close failures at error level.
    Error,
    /// Log close failures at info level.
    Info,
    /// Ignore connection-reset errors.
    IgnoreConnectionReset,
}

impl EventPeerLogError {
    fn raw(self) -> c_uint {
        match self {
            Self::Alert => 0,
            Self::Error => 1,
            Self::Info => 2,
            Self::IgnoreConnectionReset => 3,
        }
    }
}

/// Native read and write handlers installed while a peer is active or idle.
#[derive(Clone, Copy)]
pub struct EventPeerHandlers {
    read: ngx_event_handler_pt,
    write: ngx_event_handler_pt,
}

impl EventPeerHandlers {
    /// Creates a handler pair for the connection read and write events.
    pub fn new(
        read: unsafe extern "C" fn(*mut ngx_event_t),
        write: unsafe extern "C" fn(*mut ngx_event_t),
    ) -> Self {
        Self { read: Some(read), write: Some(write) }
    }
}

/// Connection preparation applied before a peer is used by a request or keepalive wrapper.
pub struct EventPeerPreparation<'address> {
    log: NonNull<ngx_log_t>,
    handlers: EventPeerHandlers,
    pool_size: usize,
    data: *mut c_void,
    idle: bool,
    _address: PhantomData<&'address ngx_log_t>,
}

impl<'address> EventPeerPreparation<'address> {
    /// Creates preparation that uses `log`, installs `handlers`, and creates a pool when absent.
    pub fn new(log: &'address ngx_log_t, handlers: EventPeerHandlers, pool_size: usize) -> Self {
        Self {
            log: NonNull::from(log),
            handlers,
            pool_size,
            data: ptr::null_mut(),
            idle: false,
            _address: PhantomData,
        }
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

    /// Marks the connection idle for the module-owned keepalive wrapper.
    pub fn idle(mut self, idle: bool) -> Self {
        self.idle = idle;
        self
    }
}

/// State of an event-peer connection owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerConnectionState {
    /// nginx connected the socket immediately or connect completion succeeded.
    Connected,
    /// nginx has a nonblocking connect in progress.
    Pending,
    /// The connection returned from a keepalive owner and is not newly allocated.
    Borrowed,
}

/// Failure while operating on a connected event peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerConnectionError {
    /// The peer no longer owns a connection.
    Detached,
    /// The requested operation requires a pending nonblocking connect.
    NotPending,
    /// nginx did not create a connection pool.
    PoolAllocation,
    /// The native `getsockopt(SO_ERROR)` call failed.
    SocketOption(ngx_int_t),
    /// The completed socket reported a nonzero `SO_ERROR` value.
    Connect(ngx_int_t),
    /// nginx returned an unexpected `SO_ERROR` output length.
    SocketOptionLength,
    /// A keepalive connection has a pending nginx connection error.
    StaleConnectionError,
    /// A keepalive connection reached end of file.
    StaleReadEndOfFile,
    /// A keepalive connection has unread input.
    StaleReadReady,
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
            Self::NotPending => formatter.write_str("event peer connection is not pending"),
            Self::PoolAllocation => {
                formatter.write_str("event peer connection pool allocation failed")
            }
            Self::SocketOption(error) => {
                write!(formatter, "event peer SO_ERROR lookup failed with socket error {error}")
            }
            Self::Connect(error) => {
                write!(formatter, "event peer connect completed with socket error {error}")
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
            Self::StaleReadReady => {
                formatter.write_str("event peer keepalive connection has unread input")
            }
            Self::Connection(_) => formatter.write_str("event peer connection is invalid"),
            Self::Event(_) => formatter.write_str("event peer connection event is invalid"),
        }
    }
}

impl error::Error for EventPeerConnectionError {}

/// Failure while fully initializing an event peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerBuildError {
    /// No nginx logger was supplied.
    MissingLog,
    /// The supplied nginx logger is misaligned.
    MisalignedLog,
    /// No peer selector was supplied.
    MissingGetCallback,
    /// The requested receive-buffer size is negative.
    NegativeReceiveBuffer,
    /// The requested send-buffer size is negative.
    NegativeSendBuffer,
}

impl fmt::Display for EventPeerBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLog => formatter.write_str("event peer has no logger"),
            Self::MisalignedLog => formatter.write_str("event peer logger is misaligned"),
            Self::MissingGetCallback => formatter.write_str("event peer has no get callback"),
            Self::NegativeReceiveBuffer => {
                formatter.write_str("event peer receive buffer is negative")
            }
            Self::NegativeSendBuffer => formatter.write_str("event peer send buffer is negative"),
        }
    }
}

impl error::Error for EventPeerBuildError {}

/// Builder that initializes every configured field of one `ngx_peer_connection_t`.
pub struct EventPeerBuilder<'address> {
    address: EventPeerAddress<'address>,
    local: Option<EventPeerAddress<'address>>,
    log: Option<NonNull<ngx_log_t>>,
    callbacks: EventPeerCallbacks,
    data: *mut c_void,
    tries: ngx_uint_t,
    start_time: ngx_msec_t,
    socket_type: SocketType,
    receive_buffer: c_int,
    send_buffer: c_int,
    cached: bool,
    transparent: bool,
    keepalive: bool,
    down: bool,
    log_error: EventPeerLogError,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'address> EventPeerBuilder<'address> {
    /// Starts an event peer for one checked remote address.
    pub fn new(address: EventPeerAddress<'address>) -> Self {
        Self {
            address,
            local: None,
            log: None,
            callbacks: EventPeerCallbacks::default(),
            data: ptr::null_mut(),
            tries: 0,
            start_time: 0,
            socket_type: SocketType::Stream,
            receive_buffer: 0,
            send_buffer: 0,
            cached: false,
            transparent: false,
            keepalive: false,
            down: false,
            log_error: EventPeerLogError::Alert,
            _not_thread_safe: PhantomData,
        }
    }

    /// Supplies the nginx logger used by native connect diagnostics.
    pub fn log(mut self, log: &'address ngx_log_t) -> Self {
        self.log = Some(NonNull::from(log));
        self
    }

    /// Supplies a raw nginx logger used by native connect diagnostics.
    ///
    /// # Safety
    ///
    /// `log` must point to a live `ngx_log_t` for `'address` on this nginx worker.
    pub unsafe fn log_from_raw(mut self, log: *mut ngx_log_t) -> Result<Self, EventPeerBuildError> {
        let log = NonNull::new(log).ok_or(EventPeerBuildError::MissingLog)?;
        if !log.as_ptr().is_aligned() {
            return Err(EventPeerBuildError::MisalignedLog);
        }
        self.log = Some(log);
        Ok(self)
    }

    /// Supplies the native callbacks used while nginx selects and releases this peer.
    pub fn callbacks(mut self, callbacks: EventPeerCallbacks) -> Self {
        self.callbacks = callbacks;
        self
    }

    /// Supplies opaque callback data. Null is valid when the selected callbacks permit it.
    ///
    /// # Safety
    ///
    /// `data` must remain valid while nginx can invoke a selected callback with this peer.
    pub unsafe fn data(mut self, data: *mut c_void) -> Self {
        self.data = data;
        self
    }

    /// Sets the optional checked local bind address.
    pub fn local_address(mut self, address: EventPeerAddress<'address>) -> Self {
        self.local = Some(address);
        self
    }

    /// Sets the remaining native peer attempts.
    pub fn tries(mut self, tries: ngx_uint_t) -> Self {
        self.tries = tries;
        self
    }

    /// Sets the native peer start time used by a caller's timeout policy.
    pub fn start_time(mut self, start_time: ngx_msec_t) -> Self {
        self.start_time = start_time;
        self
    }

    /// Selects the native socket type.
    pub fn socket_type(mut self, socket_type: SocketType) -> Self {
        self.socket_type = socket_type;
        self
    }

    /// Sets optional native receive/send socket-buffer sizes.
    pub fn buffer_sizes(
        mut self,
        receive: c_int,
        send: c_int,
    ) -> Result<Self, EventPeerBuildError> {
        if receive < 0 {
            return Err(EventPeerBuildError::NegativeReceiveBuffer);
        }
        if send < 0 {
            return Err(EventPeerBuildError::NegativeSendBuffer);
        }
        self.receive_buffer = receive;
        self.send_buffer = send;
        Ok(self)
    }

    /// Selects whether nginx may treat the resulting connection as cached.
    pub fn cached(mut self, cached: bool) -> Self {
        self.cached = cached;
        self
    }

    /// Selects transparent local binding when a local address is present.
    pub fn transparent(mut self, transparent: bool) -> Self {
        self.transparent = transparent;
        self
    }

    /// Selects `SO_KEEPALIVE` for the native socket.
    pub fn keepalive(mut self, keepalive: bool) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Marks the peer as down for the caller's own selection policy.
    pub fn down(mut self, down: bool) -> Self {
        self.down = down;
        self
    }

    /// Selects native connection-close logging behavior.
    pub fn log_error(mut self, log_error: EventPeerLogError) -> Self {
        self.log_error = log_error;
        self
    }

    /// Creates the fully initialized peer. Patched device and socket-mark fields are always zero.
    pub fn build(self) -> Result<EventPeer<'address>, EventPeerBuildError> {
        let log = self.log.ok_or(EventPeerBuildError::MissingLog)?;
        let get = self.callbacks.get.ok_or(EventPeerBuildError::MissingGetCallback)?;
        let mut raw: ngx_peer_connection_t = unsafe { mem::zeroed() };

        raw.connection = ptr::null_mut();
        raw.sockaddr = unsafe { self.address.raw.as_ref().sockaddr };
        raw.socklen = unsafe { self.address.raw.as_ref().socklen };
        raw.name = unsafe { core::ptr::addr_of!((*self.address.as_ptr()).name).cast_mut() };
        raw.tries = self.tries;
        raw.start_time = self.start_time;
        raw.get = Some(get);
        raw.free = self.callbacks.free;
        raw.notify = self.callbacks.notify;
        raw.data = self.data;
        #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
        {
            raw.set_session = self.callbacks.set_session;
            raw.save_session = self.callbacks.save_session;
        }
        raw.local = self.local.map_or(ptr::null_mut(), |address| address.as_ptr().cast_mut());
        raw.type_ = socket_type_raw(self.socket_type);
        raw.rcvbuf = self.receive_buffer;
        raw.sndbuf = self.send_buffer;
        raw.log = log.as_ptr();
        #[cfg(any(ngx_feature = "http_upstream_sid", ngx_feature = "compat"))]
        {
            raw.hint = ptr::null_mut();
            raw.sid = ptr::null_mut();
        }
        #[cfg(ngx_feature = "have_bindtodevice")]
        {
            raw.device = ptr::null();
        }
        #[cfg(ngx_feature = "have_so_mark")]
        {
            raw.so_mark = 0;
        }
        raw.set_cached(self.cached.into());
        raw.set_transparent(self.transparent.into());
        raw.set_so_keepalive(self.keepalive.into());
        raw.set_down(self.down.into());
        raw.set_log_error(self.log_error.raw());

        Ok(EventPeer {
            raw,
            state: EventPeerState::Detached,
            _address: PhantomData,
            _not_thread_safe: PhantomData,
        })
    }
}

fn socket_type_raw(socket_type: SocketType) -> c_int {
    match socket_type {
        SocketType::Stream => libc::SOCK_STREAM,
        SocketType::Datagram => libc::SOCK_DGRAM,
    }
}

/// One fully initialized native event peer.
///
/// Dropping a peer that still owns a connected nginx socket closes that socket.
///
/// ```compile_fail
/// use ngx::event::{EventPeer, EventPeerAddress, EventPeerBuilder, EventPeerCallbacks};
/// use ngx::ffi::ngx_log_t;
///
/// fn escape<'address>(address: EventPeerAddress<'address>) -> EventPeer<'address> {
///     let log = unsafe { core::mem::zeroed::<ngx_log_t>() };
///     EventPeerBuilder::new(address)
///         .log(&log)
///         .callbacks(EventPeerCallbacks::direct())
///         .build()
///         .unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::EventPeer;
///
/// fn require_send<T: Send>(_: T) {}
/// fn require_sync<T: Sync>(_: &T) {}
/// fn reject(peer: EventPeer<'_>) {
///     require_send(peer);
///     require_sync(&peer);
/// }
/// ```
#[derive(Debug)]
pub struct EventPeer<'address> {
    raw: ngx_peer_connection_t,
    state: EventPeerState,
    _address: PhantomData<&'address ngx_addr_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventPeerState {
    Detached,
    Connected,
    Pending,
    Keepalive,
}

impl<'address> EventPeer<'address> {
    /// Invokes nginx's native peer connect operation and preserves its exact result category.
    ///
    /// `NGX_ERROR` is returned as [`EventPeerConnectResult::Error`]. `Err` is reserved for an
    /// invalid native status or ownership transition.
    pub fn connect(
        mut self,
    ) -> Result<EventPeerConnectResult<'address>, EventPeerConnectError<'address>> {
        if self.state != EventPeerState::Detached || !self.raw.connection.is_null() {
            return Err(EventPeerConnectError::AlreadyOwned { peer: self });
        }
        let status = unsafe { ngx_event_connect_peer(&raw mut self.raw) };
        self.classify_connect(status)
    }

    fn classify_connect(
        mut self,
        status: ngx_int_t,
    ) -> Result<EventPeerConnectResult<'address>, EventPeerConnectError<'address>> {
        let status = match status {
            value if value == NGX_OK as _ => EventPeerConnectStatus::Connected,
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
            EventPeerConnectStatus::Connected | EventPeerConnectStatus::Pending => {
                let connection = self.raw.connection;
                if connection.is_null() {
                    return Err(EventPeerConnectError::MissingConnection { status, peer: self });
                }
                if !connection.is_aligned() {
                    self.raw.connection = ptr::null_mut();
                    return Err(EventPeerConnectError::MisalignedConnection { status, peer: self });
                }
                self.state = if status == EventPeerConnectStatus::Connected {
                    EventPeerState::Connected
                } else {
                    EventPeerState::Pending
                };
            }
            EventPeerConnectStatus::Busy
            | EventPeerConnectStatus::Declined
            | EventPeerConnectStatus::Error => {
                if !self.raw.connection.is_null() {
                    self.raw.connection = ptr::null_mut();
                    return Err(EventPeerConnectError::ConnectionOnFailure { status, peer: self });
                }
            }
        }

        Ok(match status {
            EventPeerConnectStatus::Connected => EventPeerConnectResult::Connected(self),
            EventPeerConnectStatus::Pending => EventPeerConnectResult::Pending(self),
            EventPeerConnectStatus::Busy => EventPeerConnectResult::Busy(self),
            EventPeerConnectStatus::Declined => EventPeerConnectResult::Declined(self),
            EventPeerConnectStatus::Error => EventPeerConnectResult::Error(self),
        })
    }

    /// Transfers a connected or pending socket into its explicit connection owner.
    pub fn into_connection(
        self,
    ) -> Result<EventPeerConnection<'address>, EventPeerIntoConnectionError<'address>> {
        let state = match self.state {
            EventPeerState::Connected => EventPeerConnectionState::Connected,
            EventPeerState::Pending => EventPeerConnectionState::Pending,
            EventPeerState::Detached => {
                return Err(EventPeerIntoConnectionError::Detached { peer: self });
            }
            EventPeerState::Keepalive => {
                return Err(EventPeerIntoConnectionError::Keepalive { peer: self });
            }
        };

        Ok(EventPeerConnection { peer: self, state })
    }

    /// Transfers an externally owned live connection into a keepalive owner.
    ///
    /// # Safety
    ///
    /// `connection` must be a live nginx connection with initialized read and write events. On
    /// success this owner becomes solely responsible for closing its socket and optional pool.
    pub unsafe fn attach_keepalive(
        mut self,
        connection: *mut ngx_connection_t,
    ) -> Result<EventPeerKeepalive<'address>, EventPeerAttachError<'address>> {
        if self.state != EventPeerState::Detached || !self.raw.connection.is_null() {
            return Err(EventPeerAttachError::AlreadyOwned { peer: self });
        }
        if let Err(error) = checked_event_peer_connection(connection) {
            return Err(EventPeerAttachError::Connection { error, peer: self });
        }

        self.raw.connection = connection;
        self.state = EventPeerState::Keepalive;
        Ok(EventPeerKeepalive { peer: self })
    }

    /// Closes the owned socket and optional pool immediately.
    pub fn close(self) {
        drop(self);
    }

    fn connection(&self) -> Result<NonNull<ngx_connection_t>, EventPeerConnectionError> {
        if self.raw.connection.is_null() {
            return Err(EventPeerConnectionError::Detached);
        }
        checked_event_peer_connection_ptr(self.raw.connection)
    }

    fn prepare(
        &mut self,
        preparation: EventPeerPreparation<'address>,
    ) -> Result<(), EventPeerConnectionError> {
        let mut connection = self.connection()?;
        let (mut read, mut write) = checked_event_peer_events(connection)?;
        let mut pool = match checked_event_peer_pool(connection)? {
            Some(pool) => pool,
            None => {
                let pool = NonNull::new(unsafe {
                    ngx_create_pool(preparation.pool_size, preparation.log.as_ptr())
                })
                .ok_or(EventPeerConnectionError::PoolAllocation)?;
                unsafe { connection.as_mut().pool = pool.as_ptr() };
                pool
            }
        };

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

    fn close_owned(&mut self) {
        let connection = self.raw.connection;
        self.raw.connection = ptr::null_mut();
        self.state = EventPeerState::Detached;

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

impl Drop for EventPeer<'_> {
    fn drop(&mut self) {
        self.close_owned();
    }
}

unsafe extern "C" fn inert_event_handler(_event: *mut ngx_event_t) {}

fn checked_event_peer_connection(
    connection: *mut ngx_connection_t,
) -> Result<(), EventPeerConnectionError> {
    let connection = checked_event_peer_connection_ptr(connection)?;
    let _ = checked_event_peer_events(connection)?;
    let _ = checked_event_peer_pool(connection)?;
    Ok(())
}

fn checked_event_peer_connection_ptr(
    connection: *mut ngx_connection_t,
) -> Result<NonNull<ngx_connection_t>, EventPeerConnectionError> {
    let connection = NonNull::new(connection).ok_or(ConnectionError::NullConnection)?;
    if !connection.as_ptr().is_aligned() {
        return Err(ConnectionError::MisalignedConnection.into());
    }
    Ok(connection)
}

fn checked_event_peer_events(
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

fn checked_event_peer_pool(
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

/// Failure while turning an event peer into its connection owner.
#[derive(Debug)]
pub enum EventPeerIntoConnectionError<'address> {
    /// The peer has no owned socket.
    Detached {
        /// The retained peer.
        peer: EventPeer<'address>,
    },
    /// The peer is currently represented by a keepalive owner.
    Keepalive {
        /// The retained peer.
        peer: EventPeer<'address>,
    },
}

impl<'address> EventPeerIntoConnectionError<'address> {
    /// Returns the retained peer after a failed ownership transition.
    pub fn into_peer(self) -> EventPeer<'address> {
        match self {
            Self::Detached { peer } | Self::Keepalive { peer } => peer,
        }
    }
}

impl fmt::Display for EventPeerIntoConnectionError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detached { .. } => formatter.write_str("event peer has no owned connection"),
            Self::Keepalive { .. } => {
                formatter.write_str("event peer connection is owned by a keepalive wrapper")
            }
        }
    }
}

impl error::Error for EventPeerIntoConnectionError<'_> {}

/// Failure while attaching an externally owned connection to a keepalive owner.
#[derive(Debug)]
pub enum EventPeerAttachError<'address> {
    /// The peer already owns a connection.
    AlreadyOwned {
        /// The retained peer.
        peer: EventPeer<'address>,
    },
    /// The supplied native connection does not meet the ownership contract.
    Connection {
        /// The validation failure.
        error: EventPeerConnectionError,
        /// The retained detached peer.
        peer: EventPeer<'address>,
    },
}

impl<'address> EventPeerAttachError<'address> {
    /// Returns the retained peer after a failed attach operation.
    pub fn into_peer(self) -> EventPeer<'address> {
        match self {
            Self::AlreadyOwned { peer } | Self::Connection { peer, .. } => peer,
        }
    }
}

impl fmt::Display for EventPeerAttachError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOwned { .. } => {
                formatter.write_str("event peer already owns a connection")
            }
            Self::Connection { error, .. } => {
                write!(formatter, "invalid keepalive connection: {error}")
            }
        }
    }
}

impl error::Error for EventPeerAttachError<'_> {}

/// Active owner of one native event-peer socket.
///
/// ```compile_fail
/// use ngx::event::EventPeerConnection;
///
/// fn require_send<T: Send>(_: T) {}
/// fn reject(connection: EventPeerConnection<'_>) {
///     require_send(connection);
/// }
/// ```
#[derive(Debug)]
pub struct EventPeerConnection<'address> {
    peer: EventPeer<'address>,
    state: EventPeerConnectionState,
}

impl<'address> EventPeerConnection<'address> {
    /// Returns whether this socket is connected, connecting, or borrowed from keepalive storage.
    pub fn state(&self) -> EventPeerConnectionState {
        self.state
    }

    /// Checks `SO_ERROR` after nginx reports readiness for a pending connect.
    ///
    /// Call this from the connection's read or write handler. Checking before readiness can
    /// observe a transient zero.
    pub fn complete_connect(&mut self) -> Result<(), EventPeerConnectionError> {
        if self.state == EventPeerConnectionState::Connected {
            return Ok(());
        }
        if self.state == EventPeerConnectionState::Borrowed {
            return Err(EventPeerConnectionError::NotPending);
        }

        let connection = self.peer.connection()?;
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

        self.state = EventPeerConnectionState::Connected;
        self.peer.state = EventPeerState::Connected;
        Ok(())
    }

    /// Creates a connection pool when absent, then installs log, data, idle state, and handlers.
    pub fn prepare(
        &mut self,
        preparation: EventPeerPreparation<'address>,
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

    /// Clears active handlers, timers, and connection data before keepalive transfer.
    pub fn into_keepalive(
        mut self,
    ) -> Result<EventPeerKeepalive<'address>, EventPeerKeepaliveTransferError<'address>> {
        if self.state == EventPeerConnectionState::Pending {
            return Err(EventPeerKeepaliveTransferError::Pending { connection: self });
        }
        if let Err(error) = self.peer.quiesce(true) {
            return Err(EventPeerKeepaliveTransferError::Connection { error, connection: self });
        }

        self.peer.state = EventPeerState::Keepalive;
        Ok(EventPeerKeepalive { peer: self.peer })
    }

    /// Closes the owned socket and optional pool immediately.
    pub fn close(self) {
        drop(self);
    }
}

/// Failure while moving an active connection into keepalive storage.
#[derive(Debug)]
pub enum EventPeerKeepaliveTransferError<'address> {
    /// A pending connect must be completed or closed instead.
    Pending {
        /// The retained active connection owner.
        connection: EventPeerConnection<'address>,
    },
    /// The native connection could not be safely quiesced.
    Connection {
        /// The quiesce failure.
        error: EventPeerConnectionError,
        /// The retained active connection owner.
        connection: EventPeerConnection<'address>,
    },
}

impl<'address> EventPeerKeepaliveTransferError<'address> {
    /// Returns the retained active connection owner after a failed transfer.
    pub fn into_connection(self) -> EventPeerConnection<'address> {
        match self {
            Self::Pending { connection } | Self::Connection { connection, .. } => connection,
        }
    }
}

impl fmt::Display for EventPeerKeepaliveTransferError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending { .. } => {
                formatter.write_str("event peer pending connect cannot enter keepalive storage")
            }
            Self::Connection { error, .. } => {
                write!(formatter, "event peer keepalive transfer failed: {error}")
            }
        }
    }
}

impl error::Error for EventPeerKeepaliveTransferError<'_> {}

/// Owner of a reusable event-peer socket outside an active request.
///
/// ```compile_fail
/// use ngx::event::EventPeerKeepalive;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// fn reject(keepalive: &EventPeerKeepalive<'_>) {
///     require_sync(keepalive);
/// }
/// ```
#[derive(Debug)]
pub struct EventPeerKeepalive<'address> {
    peer: EventPeer<'address>,
}

impl<'address> EventPeerKeepalive<'address> {
    /// Creates a connection pool when absent, then installs idle log, data, and handlers.
    pub fn prepare(
        &mut self,
        preparation: EventPeerPreparation<'address>,
    ) -> Result<(), EventPeerConnectionError> {
        self.peer.prepare(preparation)
    }

    /// Rejects a connection with an nginx error, end of file, or unread input.
    pub fn validate(&self) -> Result<(), EventPeerConnectionError> {
        let connection = self.peer.connection()?;
        let (read, _) = checked_event_peer_events(connection)?;

        unsafe {
            if connection.as_ref().error() != 0 {
                return Err(EventPeerConnectionError::StaleConnectionError);
            }
            if read.as_ref().eof() != 0 {
                return Err(EventPeerConnectionError::StaleReadEndOfFile);
            }
            if read.as_ref().ready() != 0 {
                return Err(EventPeerConnectionError::StaleReadReady);
            }
        }

        Ok(())
    }

    /// Gives a callback-scoped mutable connection view to the caller.
    pub fn with_connection<R>(
        &mut self,
        f: impl for<'scope> FnOnce(ConnectionRefMut<'scope>) -> R,
    ) -> Result<R, EventPeerConnectionError> {
        let connection = self.peer.connection()?;
        unsafe { ConnectionRefMut::with_raw(connection.as_ptr(), f) }.map_err(Into::into)
    }

    /// Clears idle state and transfers the socket back without allocating a new socket.
    pub fn into_connection(
        mut self,
    ) -> Result<EventPeerConnection<'address>, EventPeerKeepaliveIntoConnectionError<'address>>
    {
        if let Err(error) = self.peer.quiesce(false) {
            return Err(EventPeerKeepaliveIntoConnectionError::Connection {
                error,
                keepalive: self,
            });
        }
        self.peer.state = EventPeerState::Connected;
        Ok(EventPeerConnection { peer: self.peer, state: EventPeerConnectionState::Borrowed })
    }

    /// Closes the owned socket and optional pool immediately.
    pub fn close(self) {
        drop(self);
    }
}

/// Failure while moving a keepalive socket back into an active connection owner.
#[derive(Debug)]
pub enum EventPeerKeepaliveIntoConnectionError<'address> {
    /// The native keepalive connection could not be safely quiesced.
    Connection {
        /// The quiesce failure.
        error: EventPeerConnectionError,
        /// The retained keepalive owner.
        keepalive: EventPeerKeepalive<'address>,
    },
}

impl<'address> EventPeerKeepaliveIntoConnectionError<'address> {
    /// Returns the retained keepalive owner after a failed transfer.
    pub fn into_keepalive(self) -> EventPeerKeepalive<'address> {
        match self {
            Self::Connection { keepalive, .. } => keepalive,
        }
    }
}

impl fmt::Display for EventPeerKeepaliveIntoConnectionError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { error, .. } => {
                write!(formatter, "event peer active transfer failed: {error}")
            }
        }
    }
}

impl error::Error for EventPeerKeepaliveIntoConnectionError<'_> {}

/// Exact nginx status category returned by an event-peer connect operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventPeerConnectStatus {
    /// The socket connected immediately.
    Connected,
    /// The socket is connecting asynchronously.
    Pending,
    /// The peer selector reported that no resource is currently available.
    Busy,
    /// The peer selector or native connect rejected the peer.
    Declined,
    /// Native connection setup failed.
    Error,
}

/// Result of a fully initialized native event-peer connect operation.
#[derive(Debug)]
pub enum EventPeerConnectResult<'address> {
    /// nginx connected the socket immediately.
    Connected(EventPeer<'address>),
    /// nginx started a nonblocking connect operation.
    Pending(EventPeer<'address>),
    /// nginx returned `NGX_BUSY` without publishing a connection.
    Busy(EventPeer<'address>),
    /// nginx returned `NGX_DECLINED` without publishing a connection.
    Declined(EventPeer<'address>),
    /// nginx returned `NGX_ERROR` without publishing a connection.
    Error(EventPeer<'address>),
}

impl<'address> EventPeerConnectResult<'address> {
    /// Returns the exact native result category.
    pub fn status(&self) -> EventPeerConnectStatus {
        match self {
            Self::Connected(_) => EventPeerConnectStatus::Connected,
            Self::Pending(_) => EventPeerConnectStatus::Pending,
            Self::Busy(_) => EventPeerConnectStatus::Busy,
            Self::Declined(_) => EventPeerConnectStatus::Declined,
            Self::Error(_) => EventPeerConnectStatus::Error,
        }
    }

    /// Returns the peer so the caller can apply its own retry or connection policy.
    pub fn into_peer(self) -> EventPeer<'address> {
        match self {
            Self::Connected(peer)
            | Self::Pending(peer)
            | Self::Busy(peer)
            | Self::Declined(peer)
            | Self::Error(peer) => peer,
        }
    }
}

/// Native connect result that violates the checked event-peer contract.
///
/// The retained peer is detached from any connection pointer that cannot be safely owned.
#[derive(Debug)]
pub enum EventPeerConnectError<'address> {
    /// The peer already owns a connection and cannot start another native connect.
    AlreadyOwned {
        /// The retained peer.
        peer: EventPeer<'address>,
    },
    /// nginx returned a status outside the five documented event-peer results.
    UnexpectedStatus {
        /// The raw nginx status.
        status: ngx_int_t,
        /// The retained peer.
        peer: EventPeer<'address>,
    },
    /// nginx reported an immediate or pending connection without a connection pointer.
    MissingConnection {
        /// The success category that lacked a connection.
        status: EventPeerConnectStatus,
        /// The retained peer.
        peer: EventPeer<'address>,
    },
    /// nginx reported an immediate or pending connection with a misaligned pointer.
    MisalignedConnection {
        /// The success category that had an invalid pointer.
        status: EventPeerConnectStatus,
        /// The retained peer.
        peer: EventPeer<'address>,
    },
    /// nginx returned a failure category after publishing a connection pointer.
    ///
    /// The pointer is detached because a failed peer selector can retain its own connection.
    ConnectionOnFailure {
        /// The failure category that unexpectedly published a connection.
        status: EventPeerConnectStatus,
        /// The retained peer.
        peer: EventPeer<'address>,
    },
}

impl<'address> EventPeerConnectError<'address> {
    /// Returns the retained detached peer after a checked failure.
    pub fn into_peer(self) -> EventPeer<'address> {
        match self {
            Self::AlreadyOwned { peer }
            | Self::UnexpectedStatus { peer, .. }
            | Self::MissingConnection { peer, .. }
            | Self::MisalignedConnection { peer, .. }
            | Self::ConnectionOnFailure { peer, .. } => peer,
        }
    }
}

impl fmt::Display for EventPeerConnectError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOwned { .. } => {
                formatter.write_str("event peer already owns a connection")
            }
            Self::UnexpectedStatus { status, .. } => {
                write!(formatter, "event peer returned unexpected nginx status {status}")
            }
            Self::MissingConnection { .. } => {
                formatter.write_str("event peer connected without a connection")
            }
            Self::MisalignedConnection { .. } => {
                formatter.write_str("event peer connected with a misaligned connection")
            }
            Self::ConnectionOnFailure { .. } => {
                formatter.write_str("event peer failed after publishing a connection")
            }
        }
    }
}

impl error::Error for EventPeerConnectError<'_> {}

#[cfg(all(test, feature = "test-link"))]
#[path = "peer/tests.rs"]
mod tests;
