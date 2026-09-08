use core::fmt::{self, Write};
use core::marker::PhantomData;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ptr::NonNull;
use core::slice;

use crate::ffi::{
    NGX_PROXY_PROTOCOL_MAX_HEADER, ngx_connection_t, ngx_proxy_protocol_t, ngx_str_t,
};

use super::address::{SocketAddressFamily, SocketPort};
use super::{ConnectionError, ConnectionRefMut, SocketType, connection_socket_type};

/// A failure while reading or attaching PROXY protocol metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocolError {
    /// The metadata pointer does not satisfy `ngx_proxy_protocol_t` alignment.
    MisalignedMetadata,
    /// Nginx stored an address that is not canonical IPv4 or IPv6 text.
    InvalidAddressText,
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
    /// A checked connection operation failed.
    Connection(ConnectionError),
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
        #[cfg(nginx1_23_2)]
        let limit = proxy_protocol_tlv_limit(self.source, self.transport);
        #[cfg(not(nginx1_23_2))]
        let limit = 0;
        if tlvs.len() > limit {
            return Err(ProxyProtocolError::TlvsTooLong);
        }

        self.tlvs = tlvs;
        Ok(self)
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

    /// Looks up one top-level PROXY protocol v2 TLV.
    pub fn lookup_tlv(
        &self,
        type_: u8,
    ) -> Result<ProxyProtocolTlvLookup<'callback>, ProxyProtocolError> {
        Ok(lookup_proxy_protocol_tlv(self.tlvs, type_))
    }
}

impl ProxyProtocolBuilder<'_> {
    pub(super) fn attach(
        self,
        connection: &mut ConnectionRefMut<'_>,
    ) -> Result<(), ProxyProtocolError> {
        let carrier = connection.socket_type().map_err(ProxyProtocolError::Connection)?;
        if carrier != self.transport {
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
        #[cfg(nginx1_23_2)]
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
            #[cfg(nginx1_23_2)]
            {
                (*metadata).tlvs = tlvs;
            }
            connection.raw.as_mut().proxy_protocol = metadata;
        }

        Ok(())
    }
}

const PROXY_PROTOCOL_V2_HEADER_LEN: usize = 16;
const PROXY_PROTOCOL_TEXT_CAPACITY: usize = 45;

pub(super) fn connection_proxy_protocol<'callback>(
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
    let source_text = checked_proxy_protocol_bytes(metadata.src_addr)?;
    let destination_text = checked_proxy_protocol_bytes(metadata.dst_addr)?;
    let source = proxy_protocol_address(source_text, metadata.src_port)?;
    let destination = proxy_protocol_address(destination_text, metadata.dst_port)?;
    let transport = connection_socket_type(connection).map_err(ProxyProtocolError::Connection)?;
    #[cfg(nginx1_23_2)]
    let tlvs = checked_proxy_protocol_bytes(metadata.tlvs)?;
    #[cfg(not(nginx1_23_2))]
    let tlvs = &[];
    if tlvs.len() > proxy_protocol_tlv_limit(source, transport) {
        return Err(ProxyProtocolError::TlvsTooLong);
    }

    Ok(Some(ProxyProtocolRef {
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
    text: &[u8],
    port: u16,
) -> Result<ProxyProtocolAddress, ProxyProtocolError> {
    let text = core::str::from_utf8(text).map_err(|_| ProxyProtocolError::InvalidAddressText)?;
    let port = SocketPort::from_host_order(port);

    if let Ok(address) = text.parse::<Ipv4Addr>() {
        return Ok(ProxyProtocolAddress::Ipv4 { octets: address.octets(), port });
    }
    if let Ok(address) = text.parse::<Ipv6Addr>() {
        return Ok(ProxyProtocolAddress::Ipv6 { octets: address.octets(), port });
    }

    Err(ProxyProtocolError::InvalidAddressText)
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

fn lookup_proxy_protocol_tlv(tlvs: &[u8], type_: u8) -> ProxyProtocolTlvLookup<'_> {
    let mut remaining = tlvs;

    while !remaining.is_empty() {
        if remaining.len() < 3 {
            return ProxyProtocolTlvLookup::Error;
        }

        let entry_type = remaining[0];
        let value_len = usize::from(u16::from_be_bytes([remaining[1], remaining[2]]));
        remaining = &remaining[3..];
        if remaining.len() < value_len {
            return ProxyProtocolTlvLookup::Error;
        }

        let (value, tail) = remaining.split_at(value_len);
        if entry_type == type_ {
            return ProxyProtocolTlvLookup::Ok(value);
        }
        remaining = tail;
    }

    ProxyProtocolTlvLookup::Declined
}

fn canonical_proxy_protocol_text(
    address: ProxyProtocolAddress,
) -> Result<([u8; PROXY_PROTOCOL_TEXT_CAPACITY], usize), ProxyProtocolError> {
    let mut text = ProxyProtocolText::default();
    match address {
        ProxyProtocolAddress::Ipv4 { octets, .. } => write!(text, "{}", Ipv4Addr::from(octets)),
        ProxyProtocolAddress::Ipv6 { octets, .. } => write!(text, "{}", Ipv6Addr::from(octets)),
    }
    .map_err(|_| ProxyProtocolError::CanonicalText)?;

    Ok((text.bytes, text.len))
}

struct ProxyProtocolText {
    bytes: [u8; PROXY_PROTOCOL_TEXT_CAPACITY],
    len: usize,
}

impl Default for ProxyProtocolText {
    fn default() -> Self {
        Self { bytes: [0; PROXY_PROTOCOL_TEXT_CAPACITY], len: 0 }
    }
}

impl Write for ProxyProtocolText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
