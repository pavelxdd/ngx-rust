use core::ffi::c_int;
use core::marker::PhantomData;
use core::mem::{offset_of, size_of};
use core::ptr::{self, NonNull};
#[cfg(unix)]
use core::slice;

use crate::core::{BufferError, BufferMut, BufferRef, Pool, PoolBuffer};
use crate::event::{EventError, EventRef};
#[cfg(unix)]
use crate::ffi::sockaddr_un;
use crate::ffi::{
    ngx_buf_t, ngx_connection_t, ngx_listening_t, ngx_log_t, sa_family_t, sockaddr, sockaddr_in,
    sockaddr_in6, socklen_t,
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

impl From<BufferError> for ConnectionError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
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
        Self { network_order: port.to_ne_bytes() }
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
    /// `connection` must point to a live initialized nginx connection for `'callback`. Nginx must
    /// not mutably access it while this shared view exists, and the view must remain on its owning
    /// event-loop thread.
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
    /// `connection` must point to a live initialized nginx connection for `'callback`. No other
    /// mutable or shared Rust view may exist for the same connection, and the view must remain on
    /// its owning event-loop thread.
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

impl ListenerRef<'_> {
    /// Returns the configured listener socket type.
    pub fn socket_type(&self) -> Result<SocketType, ConnectionError> {
        socket_type(unsafe { self.raw.as_ref().type_ })
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
    parse_socket_address(connection.sockaddr, connection.socklen).map_err(ConnectionError::Address)
}

fn connection_local_address<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<SocketAddress<'callback>, ConnectionError> {
    let connection = unsafe { connection.as_ref() };
    parse_socket_address(connection.local_sockaddr, connection.local_socklen)
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

fn socket_type(raw: c_int) -> Result<SocketType, ConnectionError> {
    match raw {
        libc::SOCK_STREAM => Ok(SocketType::Stream),
        libc::SOCK_DGRAM => Ok(SocketType::Datagram),
        _ => Err(ConnectionError::UnsupportedSocketType(raw)),
    }
}

fn parse_socket_address<'callback>(
    address: *const sockaddr,
    socklen: socklen_t,
) -> Result<SocketAddress<'callback>, SocketAddressError> {
    let address = NonNull::new(address.cast_mut()).ok_or(SocketAddressError::NullAddress)?;
    if !address.as_ptr().is_aligned() {
        return Err(SocketAddressError::MisalignedAddress);
    }
    let len = usize::try_from(socklen).map_err(|_| SocketAddressError::InvalidLength)?;
    if len < size_of::<sa_family_t>() {
        return Err(SocketAddressError::TruncatedAddress);
    }

    let family = unsafe { address.as_ref().sa_family };
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
    let address = address.cast::<sockaddr_un>();
    if !address.as_ptr().is_aligned() {
        return Err(SocketAddressError::MisalignedAddress);
    }
    let address = unsafe { address.as_ref() };
    let path =
        unsafe { slice::from_raw_parts(address.sun_path.as_ptr().cast(), len - path_offset) };
    Ok(SocketAddress::Unix { path, _callback: PhantomData, _not_thread_safe: PhantomData })
}

#[cfg(test)]
#[path = "connection/tests.rs"]
mod tests;
