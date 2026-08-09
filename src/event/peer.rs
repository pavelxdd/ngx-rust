use core::error;
use core::ffi::{c_int, c_uint, c_void};
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};
use core::slice;

use crate::core::{NgxStr, SocketAddress, SocketAddressError, SocketType, parse_socket_address};
use crate::ffi::{
    NGX_AGAIN, NGX_BUSY, NGX_DECLINED, NGX_ERROR, NGX_OK, ngx_addr_t, ngx_event_connect_peer,
    ngx_event_free_peer_pt, ngx_event_get_peer, ngx_event_get_peer_pt, ngx_event_notify_peer_pt,
    ngx_int_t, ngx_log_t, ngx_msec_t, ngx_peer_connection_t, ngx_str_t, ngx_uint_t,
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

        Ok(EventPeer { raw, _address: PhantomData, _not_thread_safe: PhantomData })
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
    _address: PhantomData<&'address ngx_addr_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'address> EventPeer<'address> {
    /// Invokes nginx's native peer connect operation and preserves its exact result category.
    ///
    /// `NGX_ERROR` is returned as [`EventPeerConnectResult::Error`]. `Err` is reserved for an
    /// invalid native status or ownership transition.
    pub fn connect(
        mut self,
    ) -> Result<EventPeerConnectResult<'address>, EventPeerConnectError<'address>> {
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
}

impl Drop for EventPeer<'_> {
    fn drop(&mut self) {
        let connection = self.raw.connection;
        if connection.is_null() || !connection.is_aligned() {
            return;
        }

        unsafe { crate::ffi::ngx_close_connection(connection) };
        self.raw.connection = ptr::null_mut();
    }
}

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
            Self::UnexpectedStatus { peer, .. }
            | Self::MissingConnection { peer, .. }
            | Self::MisalignedConnection { peer, .. }
            | Self::ConnectionOnFailure { peer, .. } => peer,
        }
    }
}

impl fmt::Display for EventPeerConnectError<'_> {
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
