use core::ffi::c_int;
use core::marker::PhantomData;
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull};
use core::slice;

use crate::core::{
    BufferError, BufferMut, BufferRef, ChainError, ChainMut, Pool, PoolBuffer, Status,
};
use crate::event::{EventError, EventRef};
#[cfg(unix)]
use crate::ffi::sockaddr_un;
use crate::ffi::{
    NGX_AGAIN, NGX_DECLINED, NGX_ERROR, NGX_OK, NGX_PROXY_PROTOCOL_MAX_HEADER, in_addr, in6_addr,
    in6_addr__bindgen_ty_1, ngx_buf_t, ngx_chain_t, ngx_connection_local_sockaddr,
    ngx_connection_t, ngx_int_t, ngx_listening_t, ngx_log_t, ngx_proxy_protocol_lookup_tlv,
    ngx_proxy_protocol_t, ngx_sin_addr_t, ngx_sock_ntop, ngx_str_t, off_t, sa_family_t, sockaddr,
    sockaddr_in, sockaddr_in6, socklen_t,
};

/// Failure returned while validating a native socket address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketAddressError {
    /// The address pointer is null.
    NullAddress,
    /// The address pointer does not satisfy its native alignment.
    MisalignedAddress,
    /// The reported address length cannot hold its family field.
    TruncatedAddress,
    /// The reported address length does not match the address family.
    InvalidLength,
    /// Nginx reported an address family this API does not support.
    UnsupportedFamily(u16),
}

/// Failure returned while validating a native nginx connection view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionError {
    /// The connection pointer is null.
    NullConnection,
    /// The connection pointer does not satisfy `ngx_connection_t` alignment.
    MisalignedConnection,
    /// The connection has no memory pool.
    MissingPool,
    /// The connection pool pointer does not satisfy `ngx_pool_t` alignment.
    MisalignedPool,
    /// The connection has no listening socket.
    MissingListener,
    /// The listening socket pointer does not satisfy `ngx_listening_t` alignment.
    MisalignedListener,
    /// The connection logger pointer does not satisfy `ngx_log_t` alignment.
    MisalignedLog,
    /// The connection sent-byte counter cannot be represented as an unsigned value.
    NegativeBytesSent,
    /// The connection or listener has an unsupported socket type.
    UnsupportedSocketType(c_int),
    /// A socket address is invalid.
    Address(SocketAddressError),
    /// A buffer is invalid.
    Buffer(BufferError),
    /// An event pointer is invalid.
    Event(EventError),
    /// A replacement buffer belongs to a different nginx pool.
    ForeignPool,
}

/// Result of one native connection receive operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionReadResult {
    /// The connection received this many bytes.
    Data(usize),
    /// The connection reached end of file.
    EndOfFile,
    /// The native connection would block before receiving data.
    Again,
}

/// Result of one native connection send operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionWriteResult {
    /// The connection sent this many bytes.
    Written(usize),
    /// The native connection would block before sending data.
    Again,
}

/// Result of one native chain send operation.
#[derive(Debug)]
pub enum ConnectionChainWriteResult<'chain> {
    /// Nginx consumed the complete input chain.
    Complete,
    /// Nginx left this tail unsent for a later writable event.
    Pending(ChainMut<'chain>),
}

impl ConnectionChainWriteResult<'_> {
    /// Transfers the nullable unsent native chain head to its pool-owning caller.
    pub fn into_raw(self) -> *mut ngx_chain_t {
        match self {
            Self::Complete => ptr::null_mut(),
            Self::Pending(chain) => chain.as_ptr(),
        }
    }
}

/// Failure returned by one native chain send operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionChainWriteError {
    /// The connection has no chain-send callback.
    MissingSendChain,
    /// Nginx returned its chain error sentinel.
    SendChainFailed,
    /// Nginx returned a tail that does not belong to the input chain.
    UnexpectedTail,
    /// Nginx returned an invalid unsent chain tail.
    Chain(ChainError),
}

/// Failure returned by one native connection I/O operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionIoError {
    /// The connection has no receive callback.
    MissingReceive,
    /// The connection has no send callback.
    MissingSend,
    /// The native receive callback failed.
    ReceiveFailed,
    /// The native send callback failed.
    SendFailed,
    /// The native receive callback reported more bytes than fit in the supplied output.
    ReceiveTooLarge,
    /// The native send callback reported more bytes than the supplied input.
    SendTooLarge,
}

impl From<BufferError> for ConnectionError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

impl From<ChainError> for ConnectionChainWriteError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<EventError> for ConnectionError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

/// A configured socket type supported by nginx connection APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketType {
    /// A byte-stream socket.
    Stream,
    /// A datagram socket.
    Datagram,
}

impl SocketType {
    /// Parses an nginx native socket type.
    pub fn from_raw(raw: c_int) -> Result<Self, ConnectionError> {
        socket_type(raw)
    }
}

/// The family represented by a checked socket address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketAddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
    /// Unix-domain socket.
    #[cfg(unix)]
    Unix,
}

/// A socket port preserved in both host and network byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketPort {
    network_order: [u8; 2],
}

impl SocketPort {
    fn from_native(port: u16) -> Self {
        Self::from_network_order(port.to_ne_bytes())
    }

    /// Creates a port from its host-order value.
    pub fn from_host_order(port: u16) -> Self {
        Self { network_order: port.to_be_bytes() }
    }

    /// Creates a port from its exact network-order bytes.
    pub fn from_network_order(network_order: [u8; 2]) -> Self {
        Self { network_order }
    }

    /// Returns the port in host byte order.
    pub fn host_order(self) -> u16 {
        u16::from_be_bytes(self.network_order)
    }

    /// Returns the exact two bytes stored in network byte order.
    pub fn network_order(self) -> [u8; 2] {
        self.network_order
    }
}

/// A failure while reading or attaching PROXY protocol metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocolError {
    /// The metadata pointer does not satisfy `ngx_proxy_protocol_t` alignment.
    MisalignedMetadata,
    /// Nginx reported an unsupported PROXY address family.
    UnsupportedFamily(c_int),
    /// Nginx reported an unsupported PROXY transport.
    UnsupportedTransport(c_int),
    /// A nonempty metadata field has no backing bytes.
    MissingData,
    /// A metadata field is too large to form a Rust slice.
    DataTooLong,
    /// The TLV bytes exceed the configured PROXY protocol bound.
    TlvsTooLong,
    /// Source and destination endpoints use different address families.
    EndpointFamilyMismatch,
    /// Metadata transport does not match the non-Unix connection carrier.
    TransportMismatch {
        /// The carrier socket type.
        connection: SocketType,
        /// The requested PROXY metadata transport.
        metadata: SocketType,
    },
    /// Nginx did not format a canonical endpoint address.
    CanonicalText,
    /// Nginx could not allocate pool-owned metadata.
    Allocation,
    /// The connection has no logger for nginx's TLV parser diagnostics.
    MissingConnectionLog,
    /// A checked connection operation failed.
    Connection(ConnectionError),
    /// The nginx TLV lookup returned an unexpected status.
    UnexpectedLookupStatus(ngx_int_t),
    /// The nginx TLV lookup returned bytes outside the configured TLV slice.
    LookupValueOutsideTlvs,
}

/// A binary Internet endpoint stored in PROXY protocol metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocolAddress {
    /// An IPv4 endpoint.
    Ipv4 {
        /// Address octets in network byte order.
        octets: [u8; 4],
        /// Port in host and network byte order.
        port: SocketPort,
    },
    /// An IPv6 endpoint.
    Ipv6 {
        /// Address octets in network byte order.
        octets: [u8; 16],
        /// Port in host and network byte order.
        port: SocketPort,
    },
}

impl ProxyProtocolAddress {
    /// Returns the address family.
    pub fn family(self) -> SocketAddressFamily {
        match self {
            Self::Ipv4 { .. } => SocketAddressFamily::Ipv4,
            Self::Ipv6 { .. } => SocketAddressFamily::Ipv6,
        }
    }

    /// Returns the endpoint port.
    pub fn port(self) -> SocketPort {
        match self {
            Self::Ipv4 { port, .. } | Self::Ipv6 { port, .. } => port,
        }
    }

    /// Returns IPv4 octets for an IPv4 endpoint.
    pub fn ipv4_octets(self) -> Option<[u8; 4]> {
        match self {
            Self::Ipv4 { octets, .. } => Some(octets),
            Self::Ipv6 { .. } => None,
        }
    }

    /// Returns IPv6 octets for an IPv6 endpoint.
    pub fn ipv6_octets(self) -> Option<[u8; 16]> {
        match self {
            Self::Ipv4 { .. } => None,
            Self::Ipv6 { octets, .. } => Some(octets),
        }
    }

    fn wire_len(self) -> usize {
        match self {
            Self::Ipv4 { .. } => 12,
            Self::Ipv6 { .. } => 36,
        }
    }
}

/// The result of an nginx PROXY TLV lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocolTlvLookup<'callback> {
    /// Nginx returned `NGX_OK` with the matching TLV bytes.
    Ok(&'callback [u8]),
    /// Nginx returned `NGX_DECLINED` because the type is absent.
    Declined,
    /// Nginx returned `NGX_ERROR` because the encoded TLVs are malformed.
    Error,
}

/// Pool-owned PROXY protocol metadata prepared for a connection attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyProtocolBuilder<'input> {
    source: ProxyProtocolAddress,
    destination: ProxyProtocolAddress,
    transport: SocketType,
    tlvs: &'input [u8],
}

impl<'input> ProxyProtocolBuilder<'input> {
    /// Starts metadata construction for matching Internet endpoint families.
    pub fn new(
        source: ProxyProtocolAddress,
        destination: ProxyProtocolAddress,
        transport: SocketType,
    ) -> Result<Self, ProxyProtocolError> {
        if source.family() != destination.family() {
            return Err(ProxyProtocolError::EndpointFamilyMismatch);
        }

        Ok(Self { source, destination, transport, tlvs: &[] })
    }

    /// Sets opaque PROXY protocol TLV bytes after enforcing the carrier-specific bound.
    pub fn tlvs(mut self, tlvs: &'input [u8]) -> Result<Self, ProxyProtocolError> {
        if tlvs.len() > proxy_protocol_tlv_limit(self.source, self.transport) {
            return Err(ProxyProtocolError::TlvsTooLong);
        }

        self.tlvs = tlvs;
        Ok(self)
    }
}

/// A checked callback-scoped socket address.
///
/// ```compile_fail
/// use ngx::core::{ConnectionRef, SocketAddress};
/// use ngx::ffi::ngx_connection_t;
///
/// unsafe fn escape(raw: *const ngx_connection_t) -> SocketAddress<'static> {
///     unsafe { ConnectionRef::with_raw(raw, |connection| connection.peer_address().unwrap()) }
///         .unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ConnectionRef;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *const ngx_connection_t) {
///     let _ = unsafe {
///         ConnectionRef::with_raw(raw, |connection| require_send(connection.peer_address().unwrap()))
///     };
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketAddress<'callback> {
    /// An IPv4 address and port.
    Ipv4 {
        /// Address octets in network byte order.
        octets: [u8; 4],
        /// Port in host and network byte order.
        port: SocketPort,
        /// Binds this view to the originating nginx callback.
        _callback: PhantomData<&'callback ()>,
        /// Prevents moving this view to another thread.
        _not_thread_safe: PhantomData<*mut ()>,
    },
    /// An IPv6 address and port.
    Ipv6 {
        /// Address octets in network byte order.
        octets: [u8; 16],
        /// Port in host and network byte order.
        port: SocketPort,
        /// Native IPv6 flow information.
        flowinfo: u32,
        /// Native IPv6 scope identifier.
        scope_id: u32,
        /// Binds this view to the originating nginx callback.
        _callback: PhantomData<&'callback ()>,
        /// Prevents moving this view to another thread.
        _not_thread_safe: PhantomData<*mut ()>,
    },
    /// A Unix-domain socket path with its exact reported length.
    #[cfg(unix)]
    Unix {
        /// Raw path bytes, including a leading NUL for Linux abstract addresses when present.
        path: &'callback [u8],
        /// Binds this view to the originating nginx callback.
        _callback: PhantomData<&'callback ()>,
        /// Prevents moving this view to another thread.
        _not_thread_safe: PhantomData<*mut ()>,
    },
}

impl SocketAddress<'_> {
    /// Returns the address family.
    pub fn family(&self) -> SocketAddressFamily {
        match self {
            Self::Ipv4 { .. } => SocketAddressFamily::Ipv4,
            Self::Ipv6 { .. } => SocketAddressFamily::Ipv6,
            #[cfg(unix)]
            Self::Unix { .. } => SocketAddressFamily::Unix,
        }
    }

    /// Returns the port for Internet addresses.
    pub fn port(&self) -> Option<SocketPort> {
        match self {
            Self::Ipv4 { port, .. } | Self::Ipv6 { port, .. } => Some(*port),
            #[cfg(unix)]
            Self::Unix { .. } => None,
        }
    }

    /// Returns IPv4 octets for an IPv4 address.
    pub fn ipv4_octets(&self) -> Option<[u8; 4]> {
        match self {
            Self::Ipv4 { octets, .. } => Some(*octets),
            _ => None,
        }
    }

    /// Returns IPv6 octets for an IPv6 address.
    pub fn ipv6_octets(&self) -> Option<[u8; 16]> {
        match self {
            Self::Ipv6 { octets, .. } => Some(*octets),
            _ => None,
        }
    }

    /// Returns native IPv6 flow information for an IPv6 address.
    pub fn flowinfo(&self) -> Option<u32> {
        match self {
            Self::Ipv6 { flowinfo, .. } => Some(*flowinfo),
            _ => None,
        }
    }

    /// Returns native IPv6 scope identifier for an IPv6 address.
    pub fn scope_id(&self) -> Option<u32> {
        match self {
            Self::Ipv6 { scope_id, .. } => Some(*scope_id),
            _ => None,
        }
    }

    /// Returns Unix-domain socket path bytes.
    #[cfg(unix)]
    pub fn unix_path(&self) -> Option<&[u8]> {
        match self {
            Self::Unix { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// A checked callback-scoped view of configured PROXY protocol metadata.
///
/// ```compile_fail
/// use ngx::core::{ConnectionRef, ProxyProtocolRef};
/// use ngx::ffi::ngx_connection_t;
///
/// unsafe fn escape(raw: *const ngx_connection_t) -> ProxyProtocolRef<'static> {
///     unsafe {
///         ConnectionRef::with_raw(raw, |connection| connection.proxy_protocol().unwrap().unwrap())
///     }
///     .unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ConnectionRef;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *const ngx_connection_t) {
///     let _ = unsafe {
///         ConnectionRef::with_raw(raw, |connection| {
///             require_send(connection.proxy_protocol().unwrap().unwrap())
///         })
///     };
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyProtocolRef<'callback> {
    connection: NonNull<ngx_connection_t>,
    source: ProxyProtocolAddress,
    destination: ProxyProtocolAddress,
    transport: SocketType,
    source_text: &'callback [u8],
    destination_text: &'callback [u8],
    tlvs: &'callback [u8],
    _callback: PhantomData<&'callback ngx_proxy_protocol_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> ProxyProtocolRef<'callback> {
    /// Returns the binary source endpoint.
    pub fn source(&self) -> ProxyProtocolAddress {
        self.source
    }

    /// Returns the binary destination endpoint.
    pub fn destination(&self) -> ProxyProtocolAddress {
        self.destination
    }

    /// Returns the configured PROXY transport.
    pub fn transport(&self) -> SocketType {
        self.transport
    }

    /// Returns the source address text exactly as nginx stored it.
    pub fn source_text(&self) -> &'callback [u8] {
        self.source_text
    }

    /// Returns the destination address text exactly as nginx stored it.
    pub fn destination_text(&self) -> &'callback [u8] {
        self.destination_text
    }

    /// Returns the opaque encoded TLV bytes.
    pub fn tlvs(&self) -> &'callback [u8] {
        self.tlvs
    }

    /// Looks up one PROXY TLV through nginx's configured parser.
    pub fn lookup_tlv(
        &self,
        type_: u8,
    ) -> Result<ProxyProtocolTlvLookup<'callback>, ProxyProtocolError> {
        if connection_log(self.connection).map_err(ProxyProtocolError::Connection)?.is_none() {
            return Err(ProxyProtocolError::MissingConnectionLog);
        }

        let mut tlvs = ngx_str_t { len: self.tlvs.len(), data: self.tlvs.as_ptr().cast_mut() };
        let mut value = ngx_str_t::empty();
        let status = unsafe {
            ngx_proxy_protocol_lookup_tlv(
                self.connection.as_ptr(),
                &raw mut tlvs,
                type_.into(),
                &raw mut value,
            )
        };

        if status == NGX_OK as ngx_int_t {
            return checked_tlv_lookup_value(self.tlvs, value).map(ProxyProtocolTlvLookup::Ok);
        }
        if status == NGX_DECLINED as ngx_int_t {
            return Ok(ProxyProtocolTlvLookup::Declined);
        }
        if status == NGX_ERROR as ngx_int_t {
            return Ok(ProxyProtocolTlvLookup::Error);
        }

        Err(ProxyProtocolError::UnexpectedLookupStatus(status))
    }
}

/// Shared callback-scoped access to an nginx connection.
///
/// ```compile_fail
/// use ngx::core::ConnectionRef;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *const ngx_connection_t) {
///     let _ = unsafe { ConnectionRef::with_raw(raw, |connection| require_send(connection)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ConnectionRef;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// unsafe fn reject(raw: *const ngx_connection_t) {
///     let _ = unsafe { ConnectionRef::with_raw(raw, |connection| require_sync(&connection)) };
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionRef<'callback> {
    raw: NonNull<ngx_connection_t>,
    _callback: PhantomData<&'callback ngx_connection_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> ConnectionRef<'callback> {
    /// Creates a checked shared connection view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `connection` must point to a live initialized nginx connection for `'callback`. Its memory
    /// pool must not be reset before that pool is destroyed. Nginx must not mutably access the
    /// connection while this shared view exists, and the view must remain on its owning event-loop
    /// thread.
    pub unsafe fn from_raw(connection: *const ngx_connection_t) -> Result<Self, ConnectionError> {
        let raw = checked_connection_ptr(connection)?;
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with a shared view that cannot escape the nginx callback through a safe
    /// value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// use ngx::core::ConnectionRef;
    /// use ngx::ffi::ngx_connection_t;
    ///
    /// unsafe fn escape(raw: *const ngx_connection_t) -> ConnectionRef<'static> {
    ///     unsafe { ConnectionRef::with_raw(raw, |connection| connection) }.unwrap()
    /// }
    /// ```
    pub unsafe fn with_raw<R>(
        connection: *const ngx_connection_t,
        f: impl for<'scope> FnOnce(ConnectionRef<'scope>) -> R,
    ) -> Result<R, ConnectionError> {
        let connection = unsafe { Self::from_raw(connection) }?;
        Ok(f(connection))
    }

    /// Returns the connection memory pool.
    pub fn pool(&self) -> Result<Pool<'callback>, ConnectionError> {
        connection_pool(self.raw)
    }

    /// Returns the connection logger when nginx configured one.
    pub fn log(&self) -> Result<Option<NonNull<ngx_log_t>>, ConnectionError> {
        connection_log(self.raw)
    }

    /// Returns the client connection's sent-byte counter.
    pub fn bytes_sent(&self) -> Result<u64, ConnectionError> {
        u64::try_from(unsafe { self.raw.as_ref().sent })
            .map_err(|_| ConnectionError::NegativeBytesSent)
    }

    /// Returns the configured socket type.
    pub fn socket_type(&self) -> Result<SocketType, ConnectionError> {
        connection_socket_type(self.raw)
    }

    /// Returns the listener that accepted this connection.
    pub fn listener(&self) -> Result<ListenerRef<'callback>, ConnectionError> {
        connection_listener(self.raw)
    }

    /// Returns the checked peer address.
    pub fn peer_address(&self) -> Result<SocketAddress<'callback>, ConnectionError> {
        connection_peer_address(self.raw)
    }

    /// Returns the checked local address recorded by nginx.
    pub fn local_address(&self) -> Result<SocketAddress<'callback>, ConnectionError> {
        connection_local_address(self.raw)
    }

    /// Returns configured PROXY protocol metadata when nginx attached it.
    pub fn proxy_protocol(
        &self,
    ) -> Result<Option<ProxyProtocolRef<'callback>>, ProxyProtocolError> {
        connection_proxy_protocol(self.raw)
    }

    /// Returns the active input buffer when nginx has installed one.
    ///
    /// ```compile_fail
    /// use ngx::core::{BufferRef, ConnectionRef};
    /// use ngx::ffi::ngx_connection_t;
    ///
    /// unsafe fn escape(raw: *const ngx_connection_t) -> BufferRef<'static> {
    ///     unsafe { ConnectionRef::with_raw(raw, |connection| connection.buffer().unwrap().unwrap()) }
    ///         .unwrap()
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::core::ConnectionRef;
    /// use ngx::ffi::ngx_connection_t;
    ///
    /// fn require_send<T: Send>(_: T) {}
    /// unsafe fn reject(raw: *const ngx_connection_t) {
    ///     let _ = unsafe {
    ///         ConnectionRef::with_raw(raw, |connection| require_send(connection.buffer().unwrap().unwrap()))
    ///     };
    /// }
    /// ```
    pub fn buffer(&self) -> Result<Option<BufferRef<'callback>>, ConnectionError> {
        connection_buffer(self.raw)
    }
}

/// Exclusive callback-scoped access to an nginx connection.
///
/// ```compile_fail
/// use ngx::core::ConnectionRefMut;
/// use ngx::event::EventRef;
/// use ngx::ffi::ngx_connection_t;
///
/// unsafe fn escape(raw: *mut ngx_connection_t) -> EventRef<'static> {
///     unsafe { ConnectionRefMut::with_raw(raw, |mut connection| connection.read_event().unwrap()) }
///         .unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ConnectionRefMut;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *mut ngx_connection_t) {
///     let _ = unsafe {
///         ConnectionRefMut::with_raw(raw, |mut connection| require_send(connection.read_event().unwrap()))
///     };
/// }
/// ```
pub struct ConnectionRefMut<'callback> {
    raw: NonNull<ngx_connection_t>,
    _callback: PhantomData<&'callback mut ngx_connection_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> ConnectionRefMut<'callback> {
    /// Creates a checked exclusive connection view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `connection` must point to a live initialized nginx connection for `'callback`. Its memory
    /// pool must not be reset before that pool is destroyed. No other mutable or shared Rust view
    /// may exist for the same connection, and the view must remain on its owning event-loop thread.
    pub unsafe fn from_raw(connection: *mut ngx_connection_t) -> Result<Self, ConnectionError> {
        let raw = checked_connection_ptr(connection)?;
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with an exclusive view that cannot escape the nginx callback through a
    /// safe value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    pub unsafe fn with_raw<R>(
        connection: *mut ngx_connection_t,
        f: impl for<'scope> FnOnce(ConnectionRefMut<'scope>) -> R,
    ) -> Result<R, ConnectionError> {
        let connection = unsafe { Self::from_raw(connection) }?;
        Ok(f(connection))
    }

    /// Returns a shared reborrow of this connection.
    pub fn view(&self) -> ConnectionRef<'_> {
        ConnectionRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
    }

    /// Returns the connection memory pool.
    pub fn pool(&self) -> Result<Pool<'callback>, ConnectionError> {
        connection_pool(self.raw)
    }

    /// Returns the connection logger when nginx configured one.
    pub fn log(&self) -> Result<Option<NonNull<ngx_log_t>>, ConnectionError> {
        connection_log(self.raw)
    }

    /// Returns the client connection's sent-byte counter.
    pub fn bytes_sent(&self) -> Result<u64, ConnectionError> {
        self.view().bytes_sent()
    }

    /// Receives bytes through nginx's configured connection callback.
    pub fn receive(
        &mut self,
        output: &mut [u8],
    ) -> Result<ConnectionReadResult, ConnectionIoError> {
        if output.is_empty() {
            return Ok(ConnectionReadResult::Data(0));
        }

        let receive = unsafe { self.raw.as_ref().recv }.ok_or(ConnectionIoError::MissingReceive)?;
        let result = unsafe { receive(self.raw.as_ptr(), output.as_mut_ptr(), output.len()) };
        if result > 0 {
            let received = result as usize;
            return (received <= output.len())
                .then_some(ConnectionReadResult::Data(received))
                .ok_or(ConnectionIoError::ReceiveTooLarge);
        }
        if result == 0 {
            return Ok(ConnectionReadResult::EndOfFile);
        }
        if result == NGX_AGAIN as _ {
            return Ok(ConnectionReadResult::Again);
        }

        Err(ConnectionIoError::ReceiveFailed)
    }

    /// Sends bytes through nginx's configured connection callback.
    pub fn send(&mut self, input: &[u8]) -> Result<ConnectionWriteResult, ConnectionIoError> {
        if input.is_empty() {
            return Ok(ConnectionWriteResult::Written(0));
        }

        let send = unsafe { self.raw.as_ref().send }.ok_or(ConnectionIoError::MissingSend)?;
        let result = unsafe { send(self.raw.as_ptr(), input.as_ptr().cast_mut(), input.len()) };
        if result >= 0 {
            let written = result as usize;
            return (written <= input.len())
                .then_some(ConnectionWriteResult::Written(written))
                .ok_or(ConnectionIoError::SendTooLarge);
        }
        if result == NGX_AGAIN as _ {
            return Ok(ConnectionWriteResult::Again);
        }

        Err(ConnectionIoError::SendFailed)
    }

    /// Sends a chain through nginx and returns the unconsumed tail, if any.
    ///
    /// Nginx may advance the chain's buffer cursors, so the input is exclusive.
    ///
    /// # Safety
    /// Every chain link, buffer descriptor, and selected memory or file resource must remain valid
    /// and exclusively owned until nginx completes or cancels any asynchronous send started by
    /// this call. Dropping a pending result does not cancel native sendfile work.
    pub unsafe fn send_chain<'chain>(
        &mut self,
        input: ChainMut<'chain>,
        limit: off_t,
    ) -> Result<ConnectionChainWriteResult<'chain>, ConnectionChainWriteError> {
        let send_chain = unsafe { self.raw.as_ref().send_chain }
            .ok_or(ConnectionChainWriteError::MissingSendChain)?;
        let tail = unsafe { send_chain(self.raw.as_ptr(), input.as_ptr(), limit) };
        if tail == ptr::without_provenance_mut(NGX_ERROR as usize) {
            return Err(ConnectionChainWriteError::SendChainFailed);
        }
        if tail.is_null() {
            return Ok(ConnectionChainWriteResult::Complete);
        }
        if !input.contains_link(tail) {
            return Err(ConnectionChainWriteError::UnexpectedTail);
        }

        let tail = unsafe { ChainMut::from_raw(tail) }?;
        Ok(ConnectionChainWriteResult::Pending(tail))
    }

    /// Returns the configured socket type.
    pub fn socket_type(&self) -> Result<SocketType, ConnectionError> {
        connection_socket_type(self.raw)
    }

    /// Returns the listener that accepted this connection.
    pub fn listener(&self) -> Result<ListenerRef<'_>, ConnectionError> {
        connection_listener(self.raw)
    }

    /// Returns the checked peer address.
    pub fn peer_address(&self) -> Result<SocketAddress<'_>, ConnectionError> {
        connection_peer_address(self.raw)
    }

    /// Returns the checked local address recorded by nginx.
    pub fn local_address(&self) -> Result<SocketAddress<'_>, ConnectionError> {
        connection_local_address(self.raw)
    }

    /// Populates the local address through nginx when it was not resolved at accept time.
    ///
    /// Nginx may allocate the refreshed address from this connection's pool.
    pub fn refresh_local_address(&mut self) -> Result<(), Status> {
        Status(unsafe { ngx_connection_local_sockaddr(self.raw.as_ptr(), ptr::null_mut(), 0) })
            .into_result()
    }

    /// Returns configured PROXY protocol metadata when nginx attached it.
    pub fn proxy_protocol(&self) -> Result<Option<ProxyProtocolRef<'_>>, ProxyProtocolError> {
        connection_proxy_protocol(self.raw)
    }

    /// Returns the active input buffer when nginx has installed one.
    pub fn buffer(&self) -> Result<Option<BufferRef<'_>>, ConnectionError> {
        connection_buffer(self.raw)
    }

    /// Returns exclusive access to the active input buffer when nginx has installed one.
    pub fn buffer_mut(&mut self) -> Result<Option<BufferMut<'_>>, ConnectionError> {
        let buffer = unsafe { self.raw.as_ref().buffer };
        if buffer.is_null() {
            return Ok(None);
        }
        unsafe { BufferMut::from_raw(buffer) }.map(Some).map_err(ConnectionError::Buffer)
    }

    /// Permanently installs a descriptor owned by this connection's pool.
    pub fn replace_buffer(&mut self, buffer: PoolBuffer<'callback>) -> Result<(), ConnectionError> {
        if !ptr::eq(self.pool()?.as_ptr(), buffer.pool_ptr()) {
            return Err(ConnectionError::ForeignPool);
        }
        unsafe { self.raw.as_mut().buffer = buffer.into_non_null().as_ptr() };
        Ok(())
    }

    /// Copies validated metadata into this connection's pool and attaches it atomically.
    pub fn attach_proxy_protocol(
        &mut self,
        metadata: ProxyProtocolBuilder<'_>,
    ) -> Result<(), ProxyProtocolError> {
        metadata.attach(self)
    }

    /// Temporarily installs a caller-owned synchronous buffer descriptor.
    pub fn swap_buffer<'connection, 'scratch>(
        &'connection mut self,
        scratch: &'scratch mut ngx_buf_t,
    ) -> Result<BufferSwap<'connection, 'callback, 'scratch>, ConnectionError> {
        let scratch = NonNull::from(scratch);
        let scratch_view =
            unsafe { BufferMut::from_raw(scratch.as_ptr()) }.map_err(ConnectionError::Buffer)?;
        scratch_view.view().kind().map_err(ConnectionError::Buffer)?;
        scratch_view.view().has_space().map_err(ConnectionError::Buffer)?;
        let original = unsafe { self.raw.as_ref().buffer };
        unsafe { self.raw.as_mut().buffer = scratch.as_ptr() };
        Ok(BufferSwap { connection: self, original, scratch, _scratch: PhantomData })
    }

    /// Returns exclusive access to the connection read event.
    pub fn read_event(&mut self) -> Result<EventRef<'_>, ConnectionError> {
        unsafe { EventRef::from_raw(self.raw.as_ref().read) }.map_err(ConnectionError::Event)
    }

    /// Returns exclusive access to the connection write event.
    pub fn write_event(&mut self) -> Result<EventRef<'_>, ConnectionError> {
        unsafe { EventRef::from_raw(self.raw.as_ref().write) }.map_err(ConnectionError::Event)
    }
}

impl ProxyProtocolBuilder<'_> {
    fn attach(self, connection: &mut ConnectionRefMut<'_>) -> Result<(), ProxyProtocolError> {
        let carrier = connection.socket_type().map_err(ProxyProtocolError::Connection)?;
        if carrier != self.transport && !connection_has_unix_listener(connection)? {
            return Err(ProxyProtocolError::TransportMismatch {
                connection: carrier,
                metadata: self.transport,
            });
        }

        let (source_text, source_text_len) = canonical_proxy_protocol_text(self.source)?;
        let (destination_text, destination_text_len) =
            canonical_proxy_protocol_text(self.destination)?;
        let pool = connection.pool().map_err(ProxyProtocolError::Connection)?;
        let metadata = NonNull::new(pool.calloc_type::<ngx_proxy_protocol_t>())
            .ok_or(ProxyProtocolError::Allocation)?;
        let source =
            unsafe { ngx_str_t::from_bytes(pool.as_ptr(), &source_text[..source_text_len]) }
                .ok_or(ProxyProtocolError::Allocation)?;
        let destination = unsafe {
            ngx_str_t::from_bytes(pool.as_ptr(), &destination_text[..destination_text_len])
        }
        .ok_or(ProxyProtocolError::Allocation)?;
        let tlvs = if self.tlvs.is_empty() {
            ngx_str_t::empty()
        } else {
            unsafe { ngx_str_t::from_bytes(pool.as_ptr(), self.tlvs) }
                .ok_or(ProxyProtocolError::Allocation)?
        };

        unsafe {
            let metadata = metadata.as_ptr();
            (*metadata).src_addr = source;
            (*metadata).dst_addr = destination;
            (*metadata).src_port = self.source.port().host_order();
            (*metadata).dst_port = self.destination.port().host_order();
            (*metadata).tlvs = tlvs;
            (*metadata).family = proxy_protocol_family(self.source);
            (*metadata).transport = socket_type_raw(self.transport);
            write_proxy_protocol_address(&mut (*metadata).src_sa, self.source);
            write_proxy_protocol_address(&mut (*metadata).dst_sa, self.destination);
            connection.raw.as_mut().proxy_protocol = metadata;
        }

        Ok(())
    }
}

/// A synchronous buffer-pointer swap that restores the original connection state on drop.
pub struct BufferSwap<'connection, 'callback, 'scratch> {
    connection: &'connection mut ConnectionRefMut<'callback>,
    original: *mut ngx_buf_t,
    scratch: NonNull<ngx_buf_t>,
    _scratch: PhantomData<&'scratch mut ngx_buf_t>,
}

impl<'callback> BufferSwap<'_, 'callback, '_> {
    /// Returns the temporary buffer as a checked shared view.
    pub fn buffer(&self) -> Result<BufferRef<'_>, ConnectionError> {
        unsafe { BufferRef::from_raw(self.scratch.as_ptr()) }.map_err(ConnectionError::Buffer)
    }

    /// Returns the temporary buffer as a checked exclusive view.
    pub fn buffer_mut(&mut self) -> Result<BufferMut<'_>, ConnectionError> {
        unsafe { BufferMut::from_raw(self.scratch.as_ptr()) }.map_err(ConnectionError::Buffer)
    }

    /// Replaces the buffer visible through the connection until this swap ends.
    pub fn replace_buffer(&mut self, buffer: PoolBuffer<'callback>) -> Result<(), ConnectionError> {
        self.connection.replace_buffer(buffer)
    }

    /// Copies the currently installed descriptor into the caller-owned scratch descriptor.
    ///
    /// Call this before the guard ends when an nginx callback must publish its final buffer range
    /// through the caller's synchronous scratch descriptor.
    pub fn copy_current_to_scratch(&mut self) -> Result<(), ConnectionError> {
        let current = unsafe { self.connection.raw.as_ref().buffer };
        let current = unsafe { BufferRef::from_raw(current) }.map_err(ConnectionError::Buffer)?;
        current.kind().map_err(ConnectionError::Buffer)?;
        current.has_space().map_err(ConnectionError::Buffer)?;
        unsafe { ptr::copy(current.as_ptr(), self.scratch.as_ptr(), 1) };
        Ok(())
    }
}

impl Drop for BufferSwap<'_, '_, '_> {
    fn drop(&mut self) {
        unsafe { self.connection.raw.as_mut().buffer = self.original };
    }
}

/// Callback-scoped access to an nginx listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerRef<'callback> {
    raw: NonNull<ngx_listening_t>,
    _callback: PhantomData<&'callback ngx_listening_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> ListenerRef<'callback> {
    /// Returns the configured listener socket type.
    pub fn socket_type(&self) -> Result<SocketType, ConnectionError> {
        socket_type(unsafe { self.raw.as_ref().type_ })
    }

    /// Returns the checked listener address.
    pub fn address(&self) -> Result<SocketAddress<'callback>, ConnectionError> {
        let listener = unsafe { self.raw.as_ref() };
        unsafe { parse_socket_address(listener.sockaddr, listener.socklen) }
            .map_err(ConnectionError::Address)
    }
}

fn checked_connection_ptr(
    connection: *const ngx_connection_t,
) -> Result<NonNull<ngx_connection_t>, ConnectionError> {
    let raw = NonNull::new(connection.cast_mut()).ok_or(ConnectionError::NullConnection)?;
    if !connection.is_aligned() {
        return Err(ConnectionError::MisalignedConnection);
    }
    Ok(raw)
}

fn connection_pool<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<Pool<'callback>, ConnectionError> {
    let pool = unsafe { connection.as_ref().pool };
    if pool.is_null() {
        return Err(ConnectionError::MissingPool);
    }
    if !pool.is_aligned() {
        return Err(ConnectionError::MisalignedPool);
    }
    unsafe { Pool::from_raw(pool) }.ok_or(ConnectionError::MisalignedPool)
}

fn connection_log(
    connection: NonNull<ngx_connection_t>,
) -> Result<Option<NonNull<ngx_log_t>>, ConnectionError> {
    let log = unsafe { connection.as_ref().log };
    let Some(log) = NonNull::new(log) else {
        return Ok(None);
    };
    if !log.as_ptr().is_aligned() {
        return Err(ConnectionError::MisalignedLog);
    }
    Ok(Some(log))
}

fn connection_socket_type(
    connection: NonNull<ngx_connection_t>,
) -> Result<SocketType, ConnectionError> {
    socket_type(unsafe { connection.as_ref().type_ })
}

fn connection_listener<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<ListenerRef<'callback>, ConnectionError> {
    let listener = unsafe { connection.as_ref().listening };
    let raw = NonNull::new(listener).ok_or(ConnectionError::MissingListener)?;
    if !listener.is_aligned() {
        return Err(ConnectionError::MisalignedListener);
    }
    Ok(ListenerRef { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
}

fn connection_peer_address<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<SocketAddress<'callback>, ConnectionError> {
    let connection = unsafe { connection.as_ref() };
    unsafe { parse_socket_address(connection.sockaddr, connection.socklen) }
        .map_err(ConnectionError::Address)
}

fn connection_local_address<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<SocketAddress<'callback>, ConnectionError> {
    let connection = unsafe { connection.as_ref() };
    unsafe { parse_socket_address(connection.local_sockaddr, connection.local_socklen) }
        .map_err(ConnectionError::Address)
}

fn connection_buffer<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<Option<BufferRef<'callback>>, ConnectionError> {
    let buffer = unsafe { connection.as_ref().buffer };
    if buffer.is_null() {
        return Ok(None);
    }
    unsafe { BufferRef::from_raw(buffer) }.map(Some).map_err(ConnectionError::Buffer)
}

const PROXY_PROTOCOL_V2_HEADER_LEN: usize = 16;
const PROXY_PROTOCOL_TEXT_CAPACITY: usize = 45;

fn connection_proxy_protocol<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<Option<ProxyProtocolRef<'callback>>, ProxyProtocolError> {
    let metadata = unsafe { connection.as_ref().proxy_protocol };
    let Some(metadata) = NonNull::new(metadata) else {
        return Ok(None);
    };
    if !metadata.as_ptr().is_aligned() {
        return Err(ProxyProtocolError::MisalignedMetadata);
    }

    let metadata = unsafe { metadata.as_ref() };
    let source = proxy_protocol_address(metadata, true)?;
    let destination = proxy_protocol_address(metadata, false)?;
    let transport = proxy_protocol_transport(metadata.transport)?;
    let source_text = checked_proxy_protocol_bytes(metadata.src_addr)?;
    let destination_text = checked_proxy_protocol_bytes(metadata.dst_addr)?;
    let tlvs = checked_proxy_protocol_bytes(metadata.tlvs)?;
    if tlvs.len() > proxy_protocol_tlv_limit(source, transport) {
        return Err(ProxyProtocolError::TlvsTooLong);
    }

    Ok(Some(ProxyProtocolRef {
        connection,
        source,
        destination,
        transport,
        source_text,
        destination_text,
        tlvs,
        _callback: PhantomData,
        _not_thread_safe: PhantomData,
    }))
}

fn proxy_protocol_address(
    metadata: &ngx_proxy_protocol_t,
    source: bool,
) -> Result<ProxyProtocolAddress, ProxyProtocolError> {
    let port = if source { metadata.src_port } else { metadata.dst_port };
    let port = SocketPort::from_host_order(port);

    if metadata.family == libc::AF_INET {
        let octets = unsafe {
            if source {
                metadata.src_sa.addr4.s_addr.to_ne_bytes()
            } else {
                metadata.dst_sa.addr4.s_addr.to_ne_bytes()
            }
        };
        return Ok(ProxyProtocolAddress::Ipv4 { octets, port });
    }
    if metadata.family == libc::AF_INET6 {
        let octets = unsafe {
            if source {
                metadata.src_sa.addr6.__in6_u.__u6_addr8
            } else {
                metadata.dst_sa.addr6.__in6_u.__u6_addr8
            }
        };
        return Ok(ProxyProtocolAddress::Ipv6 { octets, port });
    }

    Err(ProxyProtocolError::UnsupportedFamily(metadata.family))
}

fn proxy_protocol_family(address: ProxyProtocolAddress) -> c_int {
    match address {
        ProxyProtocolAddress::Ipv4 { .. } => libc::AF_INET,
        ProxyProtocolAddress::Ipv6 { .. } => libc::AF_INET6,
    }
}

fn proxy_protocol_transport(transport: c_int) -> Result<SocketType, ProxyProtocolError> {
    match transport {
        libc::SOCK_STREAM => Ok(SocketType::Stream),
        libc::SOCK_DGRAM => Ok(SocketType::Datagram),
        transport => Err(ProxyProtocolError::UnsupportedTransport(transport)),
    }
}

fn socket_type_raw(socket_type: SocketType) -> c_int {
    match socket_type {
        SocketType::Stream => libc::SOCK_STREAM,
        SocketType::Datagram => libc::SOCK_DGRAM,
    }
}

fn proxy_protocol_tlv_limit(address: ProxyProtocolAddress, transport: SocketType) -> usize {
    let address_len = address.wire_len();
    let declared_limit = usize::from(u16::MAX) - address_len;

    match transport {
        SocketType::Stream => declared_limit.min(
            (NGX_PROXY_PROTOCOL_MAX_HEADER as usize)
                .saturating_sub(PROXY_PROTOCOL_V2_HEADER_LEN + address_len),
        ),
        SocketType::Datagram => declared_limit,
    }
}

fn checked_proxy_protocol_bytes<'callback>(
    value: ngx_str_t,
) -> Result<&'callback [u8], ProxyProtocolError> {
    if value.len == 0 {
        return Ok(&[]);
    }
    if value.len > isize::MAX as usize {
        return Err(ProxyProtocolError::DataTooLong);
    }
    let data = NonNull::new(value.data).ok_or(ProxyProtocolError::MissingData)?;

    Ok(unsafe { slice::from_raw_parts(data.as_ptr(), value.len) })
}

fn checked_tlv_lookup_value(tlvs: &[u8], value: ngx_str_t) -> Result<&[u8], ProxyProtocolError> {
    if value.len == 0 {
        return Ok(&[]);
    }
    if value.len > isize::MAX as usize {
        return Err(ProxyProtocolError::DataTooLong);
    }
    let data = NonNull::new(value.data).ok_or(ProxyProtocolError::MissingData)?;
    let tlvs_start = tlvs.as_ptr() as usize;
    let tlvs_end =
        tlvs_start.checked_add(tlvs.len()).ok_or(ProxyProtocolError::LookupValueOutsideTlvs)?;
    let value_start = data.as_ptr() as usize;
    let value_end =
        value_start.checked_add(value.len).ok_or(ProxyProtocolError::LookupValueOutsideTlvs)?;
    if value_start < tlvs_start || value_end > tlvs_end {
        return Err(ProxyProtocolError::LookupValueOutsideTlvs);
    }

    Ok(unsafe { slice::from_raw_parts(data.as_ptr(), value.len) })
}

fn connection_has_unix_listener(
    connection: &ConnectionRefMut<'_>,
) -> Result<bool, ProxyProtocolError> {
    #[cfg(unix)]
    {
        let listener = match connection.listener() {
            Ok(listener) => listener,
            Err(ConnectionError::MissingListener) => return Ok(false),
            Err(error) => return Err(ProxyProtocolError::Connection(error)),
        };
        Ok(matches!(
            listener.address().map_err(ProxyProtocolError::Connection)?,
            SocketAddress::Unix { .. }
        ))
    }

    #[cfg(not(unix))]
    {
        let _ = connection;
        Ok(false)
    }
}

fn canonical_proxy_protocol_text(
    address: ProxyProtocolAddress,
) -> Result<([u8; PROXY_PROTOCOL_TEXT_CAPACITY], usize), ProxyProtocolError> {
    let mut text = [0_u8; PROXY_PROTOCOL_TEXT_CAPACITY];
    let len = match address {
        ProxyProtocolAddress::Ipv4 { octets, .. } => {
            let mut address: sockaddr_in = unsafe { core::mem::zeroed() };
            address.sin_family = libc::AF_INET as _;
            address.sin_addr = in_addr { s_addr: u32::from_ne_bytes(octets) };
            unsafe {
                ngx_sock_ntop(
                    (&raw mut address).cast(),
                    size_of::<sockaddr_in>() as socklen_t,
                    text.as_mut_ptr(),
                    text.len(),
                    0,
                )
            }
        }
        ProxyProtocolAddress::Ipv6 { octets, .. } => {
            let mut address: sockaddr_in6 = unsafe { core::mem::zeroed() };
            address.sin6_family = libc::AF_INET6 as _;
            address.sin6_addr = in6_addr { __in6_u: in6_addr__bindgen_ty_1 { __u6_addr8: octets } };
            unsafe {
                ngx_sock_ntop(
                    (&raw mut address).cast(),
                    size_of::<sockaddr_in6>() as socklen_t,
                    text.as_mut_ptr(),
                    text.len(),
                    0,
                )
            }
        }
    };

    if len == 0 || len > text.len() {
        return Err(ProxyProtocolError::CanonicalText);
    }

    Ok((text, len))
}

fn write_proxy_protocol_address(target: &mut ngx_sin_addr_t, address: ProxyProtocolAddress) {
    match address {
        ProxyProtocolAddress::Ipv4 { octets, .. } => {
            target.addr4 = in_addr { s_addr: u32::from_ne_bytes(octets) };
        }
        ProxyProtocolAddress::Ipv6 { octets, .. } => {
            target.addr6 = in6_addr { __in6_u: in6_addr__bindgen_ty_1 { __u6_addr8: octets } };
        }
    }
}

fn socket_type(raw: c_int) -> Result<SocketType, ConnectionError> {
    match raw {
        libc::SOCK_STREAM => Ok(SocketType::Stream),
        libc::SOCK_DGRAM => Ok(SocketType::Datagram),
        _ => Err(ConnectionError::UnsupportedSocketType(raw)),
    }
}

/// Parses an nginx-owned socket address into a callback-scoped address view.
///
/// # Safety
///
/// `address` must point to a live native socket address for `'callback`. The address must not be
/// mutated while the returned view exists.
pub unsafe fn parse_socket_address<'callback>(
    address: *const sockaddr,
    socklen: socklen_t,
) -> Result<SocketAddress<'callback>, SocketAddressError> {
    let address = NonNull::new(address.cast_mut()).ok_or(SocketAddressError::NullAddress)?;
    if !address.as_ptr().is_aligned() {
        return Err(SocketAddressError::MisalignedAddress);
    }
    let len = usize::try_from(socklen).map_err(|_| SocketAddressError::InvalidLength)?;
    let family_offset = offset_of!(sockaddr, sa_family);
    let family_end = family_offset
        .checked_add(size_of::<sa_family_t>())
        .ok_or(SocketAddressError::InvalidLength)?;
    if len < family_end {
        return Err(SocketAddressError::TruncatedAddress);
    }

    let family = unsafe {
        address.as_ptr().cast::<u8>().add(family_offset).cast::<sa_family_t>().read_unaligned()
    };
    if c_int::from(family) == libc::AF_INET {
        return parse_ipv4_address(address, len);
    }
    if c_int::from(family) == libc::AF_INET6 {
        return parse_ipv6_address(address, len);
    }
    #[cfg(unix)]
    if c_int::from(family) == libc::AF_UNIX {
        return parse_unix_address(address, len);
    }
    Err(SocketAddressError::UnsupportedFamily(family))
}

fn parse_ipv4_address<'callback>(
    address: NonNull<sockaddr>,
    len: usize,
) -> Result<SocketAddress<'callback>, SocketAddressError> {
    if len != size_of::<sockaddr_in>() {
        return Err(SocketAddressError::InvalidLength);
    }
    let address = address.cast::<sockaddr_in>();
    if !address.as_ptr().is_aligned() {
        return Err(SocketAddressError::MisalignedAddress);
    }
    let address = unsafe { address.as_ref() };
    Ok(SocketAddress::Ipv4 {
        octets: address.sin_addr.s_addr.to_ne_bytes(),
        port: SocketPort::from_native(address.sin_port),
        _callback: PhantomData,
        _not_thread_safe: PhantomData,
    })
}

fn parse_ipv6_address<'callback>(
    address: NonNull<sockaddr>,
    len: usize,
) -> Result<SocketAddress<'callback>, SocketAddressError> {
    if len != size_of::<sockaddr_in6>() {
        return Err(SocketAddressError::InvalidLength);
    }
    let address = address.cast::<sockaddr_in6>();
    if !address.as_ptr().is_aligned() {
        return Err(SocketAddressError::MisalignedAddress);
    }
    let address = unsafe { address.as_ref() };
    Ok(SocketAddress::Ipv6 {
        octets: unsafe { address.sin6_addr.__in6_u.__u6_addr8 },
        port: SocketPort::from_native(address.sin6_port),
        flowinfo: address.sin6_flowinfo,
        scope_id: address.sin6_scope_id,
        _callback: PhantomData,
        _not_thread_safe: PhantomData,
    })
}

#[cfg(unix)]
fn parse_unix_address<'callback>(
    address: NonNull<sockaddr>,
    len: usize,
) -> Result<SocketAddress<'callback>, SocketAddressError> {
    let path_offset = offset_of!(sockaddr_un, sun_path);
    if len < path_offset || len > size_of::<sockaddr_un>() {
        return Err(SocketAddressError::InvalidLength);
    }
    let path = unsafe {
        slice::from_raw_parts(address.as_ptr().cast::<u8>().add(path_offset), len - path_offset)
    };
    Ok(SocketAddress::Unix { path, _callback: PhantomData, _not_thread_safe: PhantomData })
}

#[cfg(test)]
#[path = "connection/tests.rs"]
mod tests;
