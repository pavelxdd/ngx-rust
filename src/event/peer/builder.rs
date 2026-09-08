//! Event-peer address validation and native peer construction.

use core::error;
use core::ffi::{c_int, c_uint, c_void};
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};
use core::slice;

use crate::core::{NgxStr, SocketAddress, SocketAddressError, SocketType, parse_socket_address};
use crate::ffi::{
    ngx_addr_t, ngx_event_free_peer_pt, ngx_event_get_peer, ngx_event_get_peer_pt,
    ngx_event_notify_peer_pt, ngx_int_t, ngx_log_t, ngx_msec_t, ngx_peer_connection_t, ngx_str_t,
    ngx_uint_t,
};
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
use crate::ffi::{ngx_event_save_peer_session_pt, ngx_event_set_peer_session_pt};
use crate::log::LogRef;

use super::connection::EventPeer;

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
    /// Uses nginx's direct selector for a preselected address.
    pub fn direct() -> Self {
        Self { get: Some(ngx_event_get_peer), ..Self::default() }
    }

    /// Installs the required peer selector.
    ///
    /// ```compile_fail
    /// use core::ffi::c_void;
    /// use ngx::event::EventPeerCallbacks;
    /// use ngx::ffi::{ngx_int_t, ngx_peer_connection_t};
    ///
    /// unsafe extern "C" fn get(
    ///     _peer: *mut ngx_peer_connection_t,
    ///     _data: *mut c_void,
    /// ) -> ngx_int_t {
    ///     0
    /// }
    ///
    /// let _ = EventPeerCallbacks::default().get(get);
    /// ```
    ///
    /// # Safety
    ///
    /// `callback` must accept the builder's `data` and a live peer pointer, uphold nginx's
    /// selection contract for its returned status and any published connection, publish only a
    /// plain connection without SSL state, and not unwind. Its required data and owner state must
    /// remain valid through the call to `connect`.
    pub unsafe fn get(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void) -> ngx_int_t,
    ) -> Self {
        self.get = Some(callback);
        self
    }

    /// Installs the optional peer-release callback.
    ///
    /// # Safety
    ///
    /// `callback` must accept the builder's `data` and live peer pointer after every successful
    /// selection, support exactly one invocation with native release flags, and not unwind. Any
    /// state it accesses must remain valid until the selection is released.
    pub unsafe fn free(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void, ngx_uint_t),
    ) -> Self {
        self.free = Some(callback);
        self
    }

    /// Installs the optional peer-notification callback.
    ///
    /// # Safety
    ///
    /// `callback` must accept the builder's `data`, live selected peer pointer, and every
    /// notification value supplied by the caller, and must not unwind or invalidate the owner.
    pub unsafe fn notify(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void, ngx_uint_t),
    ) -> Self {
        self.notify = Some(callback);
        self
    }

    /// Installs the optional SSL session lookup callback.
    ///
    /// # Safety
    ///
    /// `callback` must accept the builder's `data` and live selected peer pointer, obey nginx's
    /// SSL session lookup contract, and not unwind or invalidate the owner.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub unsafe fn set_session(
        mut self,
        callback: unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void) -> ngx_int_t,
    ) -> Self {
        self.set_session = Some(callback);
        self
    }

    /// Installs the optional SSL session save callback.
    ///
    /// # Safety
    ///
    /// `callback` must accept the builder's `data` and live selected peer pointer, obey nginx's
    /// SSL session save contract, and not unwind or invalidate the owner.
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub unsafe fn save_session(
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
    pub(super) fn raw(self) -> c_uint {
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
        }
    }
}

impl error::Error for EventPeerBuildError {}

/// Builder that initializes every configured field of one `ngx_peer_connection_t`.
pub struct EventPeerBuilder<'address, 'log> {
    address: EventPeerAddress<'address>,
    local: Option<EventPeerAddress<'address>>,
    log: Option<LogRef<'log>>,
    callbacks: EventPeerCallbacks,
    data: *mut c_void,
    tries: ngx_uint_t,
    start_time: ngx_msec_t,
    socket_type: SocketType,
    receive_buffer: c_int,
    cached: bool,
    transparent: bool,
    keepalive: bool,
    down: bool,
    log_error: EventPeerLogError,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'address, 'log> EventPeerBuilder<'address, 'log> {
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
            cached: false,
            transparent: false,
            keepalive: false,
            down: false,
            log_error: EventPeerLogError::Alert,
            _not_thread_safe: PhantomData,
        }
    }

    /// Supplies the nginx logger used by native connect diagnostics.
    pub fn log(mut self, log: LogRef<'log>) -> Self {
        self.log = Some(log);
        self
    }

    /// Supplies a raw nginx logger used by native connect diagnostics.
    ///
    /// # Safety
    ///
    /// `log` must point to a live `ngx_log_t` for `'log` on this nginx worker.
    pub unsafe fn log_from_raw(self, log: *mut ngx_log_t) -> Result<Self, EventPeerBuildError> {
        let log = unsafe { LogRef::from_raw(log) }.ok_or_else(|| {
            if log.is_null() {
                EventPeerBuildError::MissingLog
            } else {
                EventPeerBuildError::MisalignedLog
            }
        })?;
        Ok(self.log(log))
    }

    /// Supplies the native callbacks used to select and release this peer.
    pub fn callbacks(mut self, callbacks: EventPeerCallbacks) -> Self {
        self.callbacks = callbacks;
        self
    }

    /// Supplies opaque callback data.
    ///
    /// # Safety
    ///
    /// `data` must satisfy every installed callback and remain live until selection is released.
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

    /// Sets the optional native receive socket-buffer size.
    pub fn receive_buffer(mut self, size: c_int) -> Result<Self, EventPeerBuildError> {
        if size < 0 {
            return Err(EventPeerBuildError::NegativeReceiveBuffer);
        }
        self.receive_buffer = size;
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

    /// Creates the fully initialized peer.
    pub fn build(self) -> Result<EventPeer<'address, 'log>, EventPeerBuildError> {
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
        raw.log = log.as_ptr();
        #[cfg(all(nginx1_29_6, any(ngx_feature = "http_upstream_sid", ngx_feature = "compat")))]
        {
            raw.hint = ptr::null_mut();
            raw.sid = ptr::null_mut();
        }
        raw.set_cached(self.cached.into());
        raw.set_transparent(self.transparent.into());
        raw.set_so_keepalive(self.keepalive.into());
        raw.set_down(self.down.into());
        raw.set_log_error(self.log_error.raw());

        Ok(EventPeer {
            raw,
            selected: false,
            _address: PhantomData,
            _log: PhantomData,
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
