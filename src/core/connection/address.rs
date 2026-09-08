use core::ffi::c_int;
use core::marker::PhantomData;
use core::mem::{offset_of, size_of};
use core::ptr::NonNull;
use core::slice;

#[cfg(unix)]
use crate::ffi::sockaddr_un;
use crate::ffi::{sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, socklen_t};

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
    UnsupportedFamily(c_int),
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
    Err(SocketAddressError::UnsupportedFamily(c_int::from(family)))
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
