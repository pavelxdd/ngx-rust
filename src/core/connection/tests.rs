extern crate alloc;
extern crate std;

#[cfg(unix)]
use alloc::alloc::{alloc_zeroed, dealloc};
use alloc::boxed::Box;
#[cfg(feature = "test-link")]
use alloc::vec;
#[cfg(unix)]
use core::alloc::Layout;
use core::mem::{self, size_of};
use core::panic::AssertUnwindSafe;
use core::ptr;
#[cfg(all(feature = "test-link", unix))]
use std::net::{TcpListener, TcpStream};
#[cfg(all(feature = "test-link", unix))]
use std::os::fd::AsRawFd;

#[cfg(unix)]
use super::parse_socket_address;
use super::{
    ConnectionChainWriteError, ConnectionChainWriteResult, ConnectionError, ConnectionIoError,
    ConnectionReadResult, ConnectionRef, ConnectionRefMut, ConnectionWriteResult,
    ProxyProtocolAddress, ProxyProtocolBuilder, ProxyProtocolError, ProxyProtocolTlvLookup,
    SocketAddressError, SocketPort, SocketType,
};
use crate::core::{BufferError, BufferFlags, ChainMut, Pool};
#[cfg(feature = "test-link")]
use crate::ffi::ngx_proxy_protocol_read;
use crate::ffi::{
    NGX_AGAIN, NGX_ERROR, in6_addr__bindgen_ty_1, ngx_buf_t, ngx_chain_t, ngx_connection_t,
    ngx_create_pool, ngx_destroy_pool, ngx_event_t, ngx_listening_t, ngx_log_t, ngx_pool_t,
    ngx_proxy_protocol_t, ngx_str_t, ngx_uint_t, off_t, sockaddr, sockaddr_in, sockaddr_in6,
};
#[cfg(unix)]
use crate::ffi::{sa_family_t, sockaddr_un};

#[cfg(feature = "test-link")]
unsafe extern "C" {
    fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
    fn ngx_rs_test_reset_allocation_failures();
}

fn zeroed_connection() -> ngx_connection_t {
    unsafe { mem::zeroed() }
}

fn raw_connection(connection: &mut ngx_connection_t) -> *mut ngx_connection_t {
    &raw mut *connection
}

fn memory_buffer(bytes: &[u8]) -> ngx_buf_t {
    let mut buffer: ngx_buf_t = unsafe { mem::zeroed() };
    buffer.pos = bytes.as_ptr().cast_mut();
    buffer.last = unsafe { buffer.pos.add(bytes.len()) };
    buffer.start = buffer.pos;
    buffer.end = buffer.last;
    buffer.set_memory(1);
    buffer
}

unsafe extern "C" fn receive_three(
    _connection: *mut ngx_connection_t,
    output: *mut u8,
    size: usize,
) -> isize {
    if size < 3 {
        return NGX_ERROR as _;
    }

    unsafe { ptr::copy_nonoverlapping(b"abc".as_ptr(), output, 3) };
    3
}

unsafe extern "C" fn receive_again(
    _connection: *mut ngx_connection_t,
    _output: *mut u8,
    _size: usize,
) -> isize {
    NGX_AGAIN as _
}

unsafe extern "C" fn send_two(
    _connection: *mut ngx_connection_t,
    input: *mut u8,
    size: usize,
) -> isize {
    if size != 3 || unsafe { *input } != b'x' {
        return NGX_ERROR as _;
    }

    2
}

unsafe extern "C" fn send_again(
    _connection: *mut ngx_connection_t,
    _input: *mut u8,
    _size: usize,
) -> isize {
    NGX_AGAIN as _
}

unsafe extern "C" fn io_end_of_file(
    _connection: *mut ngx_connection_t,
    _buffer: *mut u8,
    _size: usize,
) -> isize {
    0
}

unsafe extern "C" fn send_empty_datagram(
    connection: *mut ngx_connection_t,
    _input: *mut u8,
    size: usize,
) -> isize {
    assert_eq!(size, 0);
    unsafe { (*connection).sent += 1 };
    0
}

unsafe extern "C" fn io_error(
    _connection: *mut ngx_connection_t,
    _buffer: *mut u8,
    _size: usize,
) -> isize {
    NGX_ERROR as _
}

unsafe extern "C" fn io_too_large(
    _connection: *mut ngx_connection_t,
    _buffer: *mut u8,
    _size: usize,
) -> isize {
    5
}

unsafe extern "C" fn send_chain_tail(
    _connection: *mut ngx_connection_t,
    input: *mut ngx_chain_t,
    limit: off_t,
) -> *mut ngx_chain_t {
    assert_eq!(limit, 0);
    assert!(!input.is_null());
    unsafe { (*input).next }
}

unsafe extern "C" fn send_chain_record_limit(
    connection: *mut ngx_connection_t,
    input: *mut ngx_chain_t,
    limit: off_t,
) -> *mut ngx_chain_t {
    unsafe { (*connection).sent = limit };
    unsafe { (*input).next }
}

unsafe extern "C" fn send_chain_complete(
    _connection: *mut ngx_connection_t,
    _input: *mut ngx_chain_t,
    _limit: off_t,
) -> *mut ngx_chain_t {
    ptr::null_mut()
}

unsafe extern "C" fn send_chain_error(
    _connection: *mut ngx_connection_t,
    _input: *mut ngx_chain_t,
    _limit: off_t,
) -> *mut ngx_chain_t {
    ptr::without_provenance_mut(NGX_ERROR as usize)
}

unsafe extern "C" fn send_chain_foreign_tail(
    _connection: *mut ngx_connection_t,
    _input: *mut ngx_chain_t,
    _limit: off_t,
) -> *mut ngx_chain_t {
    ptr::without_provenance_mut(core::mem::align_of::<ngx_chain_t>())
}

#[cfg(feature = "test-link")]
fn parse_proxy_protocol(connection: &mut ngx_connection_t, bytes: &mut [u8]) {
    let last = unsafe { bytes.as_mut_ptr().add(bytes.len()) };
    assert_eq!(
        unsafe { ngx_proxy_protocol_read(raw_connection(connection), bytes.as_mut_ptr(), last) },
        last
    );
}

#[test]
fn raw_connection_construction_rejects_null_inputs() {
    assert_eq!(
        unsafe { ConnectionRef::from_raw(ptr::null::<ngx_connection_t>()) },
        Err(ConnectionError::NullConnection)
    );
    assert!(matches!(
        unsafe { ConnectionRefMut::from_raw(ptr::null_mut::<ngx_connection_t>()) },
        Err(ConnectionError::NullConnection)
    ));

    let misaligned = ptr::without_provenance_mut::<ngx_connection_t>(1);
    assert_eq!(
        unsafe { ConnectionRef::from_raw(misaligned) },
        Err(ConnectionError::MisalignedConnection)
    );
    assert!(matches!(
        unsafe { ConnectionRefMut::from_raw(misaligned) },
        Err(ConnectionError::MisalignedConnection)
    ));
}

#[test]
fn connection_io_preserves_partial_and_would_block_results() {
    let mut raw = zeroed_connection();
    raw.recv = Some(receive_three);
    raw.send = Some(send_two);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    let mut output = [0; 4];

    assert_eq!(connection.receive(&mut output), Ok(ConnectionReadResult::Data(3)));
    assert_eq!(&output[..3], b"abc");
    assert_eq!(connection.send(b"xyz"), Ok(ConnectionWriteResult::Written(2)));

    let mut raw = zeroed_connection();
    raw.recv = Some(receive_again);
    raw.send = Some(send_again);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();

    assert_eq!(connection.receive(&mut output), Ok(ConnectionReadResult::Again));
    assert_eq!(connection.send(b"xyz"), Ok(ConnectionWriteResult::Again));

    let mut raw = zeroed_connection();
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    assert_eq!(connection.receive(&mut output), Err(ConnectionIoError::MissingReceive));
    assert_eq!(connection.send(b"xyz"), Err(ConnectionIoError::MissingSend));
}

#[test]
fn connection_io_distinguishes_zero_length_streams_and_datagrams() {
    let mut output = [0; 1];

    let mut datagram = zeroed_connection();
    datagram.type_ = libc::SOCK_DGRAM;
    datagram.recv = Some(io_end_of_file);
    datagram.send = Some(send_empty_datagram);
    {
        let mut connection =
            unsafe { ConnectionRefMut::from_raw(raw_connection(&mut datagram)) }.unwrap();
        assert_eq!(connection.receive(&mut output), Ok(ConnectionReadResult::Data(0)));
        assert_eq!(connection.send(&[]), Ok(ConnectionWriteResult::Written(0)));
    }
    assert_eq!(datagram.sent, 1);

    let mut stream = zeroed_connection();
    stream.type_ = libc::SOCK_STREAM;
    stream.recv = Some(io_end_of_file);
    stream.send = Some(io_error);
    let mut connection =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut stream)) }.unwrap();
    assert_eq!(connection.receive(&mut output), Ok(ConnectionReadResult::EndOfFile));
    assert_eq!(connection.send(&[]), Ok(ConnectionWriteResult::Written(0)));
}

#[test]
fn connection_io_maps_eof_failures_and_invalid_counts() {
    let mut output = [0; 4];

    let mut raw = zeroed_connection();
    raw.type_ = libc::SOCK_STREAM;
    raw.recv = Some(io_end_of_file);
    raw.send = Some(io_end_of_file);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    assert_eq!(connection.receive(&mut output), Ok(ConnectionReadResult::EndOfFile));
    assert_eq!(connection.send(b"xyz"), Ok(ConnectionWriteResult::Written(0)));

    let mut raw = zeroed_connection();
    raw.recv = Some(io_error);
    raw.send = Some(io_error);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    assert_eq!(connection.receive(&mut output), Err(ConnectionIoError::ReceiveFailed));
    assert_eq!(connection.send(b"xyz"), Err(ConnectionIoError::SendFailed));

    let mut raw = zeroed_connection();
    raw.recv = Some(io_too_large);
    raw.send = Some(io_too_large);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    assert_eq!(connection.receive(&mut output), Err(ConnectionIoError::ReceiveTooLarge));
    assert_eq!(connection.send(b"xyz"), Err(ConnectionIoError::SendTooLarge));
}

#[test]
fn connection_chain_send_preserves_the_unsent_tail_and_maps_terminal_results() {
    let first = b"first";
    let second = b"second";
    let mut first_buffer = memory_buffer(first);
    let mut second_buffer = memory_buffer(second);
    let mut tail = ngx_chain_t { buf: &raw mut second_buffer, next: ptr::null_mut() };
    let mut head = ngx_chain_t { buf: &raw mut first_buffer, next: &raw mut tail };
    let mut raw = zeroed_connection();
    raw.send_chain = Some(send_chain_tail);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    let input = unsafe { ChainMut::from_raw(&raw mut head) }.unwrap();
    assert_eq!(unsafe { connection.send_chain(input, 0) }.unwrap().into_raw(), &raw mut tail,);

    raw.send_chain = Some(send_chain_complete);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    let input = unsafe { ChainMut::from_raw(&raw mut head) }.unwrap();
    assert!(matches!(
        unsafe { connection.send_chain(input, 0) },
        Ok(ConnectionChainWriteResult::Complete)
    ));

    raw.send_chain = Some(send_chain_error);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    let input = unsafe { ChainMut::from_raw(&raw mut head) }.unwrap();
    assert!(matches!(
        unsafe { connection.send_chain(input, 0) },
        Err(ConnectionChainWriteError::SendChainFailed)
    ));

    raw.send_chain = Some(send_chain_foreign_tail);
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    let input = unsafe { ChainMut::from_raw(&raw mut head) }.unwrap();
    assert!(matches!(
        unsafe { connection.send_chain(input, 0) },
        Err(ConnectionChainWriteError::UnexpectedTail)
    ));

    raw.send_chain = None;
    let mut connection = unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
    let input = unsafe { ChainMut::from_raw(&raw mut head) }.unwrap();
    assert!(matches!(
        unsafe { connection.send_chain(input, 0) },
        Err(ConnectionChainWriteError::MissingSendChain)
    ));
}

#[test]
fn connection_chain_send_rejects_negative_and_forwards_positive_limits() {
    let first = b"first";
    let second = b"second";
    let mut first_buffer = memory_buffer(first);
    let mut second_buffer = memory_buffer(second);
    let mut tail = ngx_chain_t { buf: &raw mut second_buffer, next: ptr::null_mut() };
    let mut head = ngx_chain_t { buf: &raw mut first_buffer, next: &raw mut tail };
    let mut raw = zeroed_connection();
    raw.send_chain = Some(send_chain_record_limit);

    let result = {
        let mut connection =
            unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
        let input = unsafe { ChainMut::from_raw(&raw mut head) }.unwrap();
        unsafe { connection.send_chain(input, -1) }
    };
    assert_eq!(raw.sent, 0);
    assert!(matches!(result, Err(ConnectionChainWriteError::InvalidLimit)));

    let result = {
        let mut connection =
            unsafe { ConnectionRefMut::from_raw(raw_connection(&mut raw)) }.unwrap();
        let input = unsafe { ChainMut::from_raw(&raw mut head) }.unwrap();
        unsafe { connection.send_chain(input, 17) }
    };
    assert_eq!(raw.sent, 17);
    assert_eq!(result.unwrap().into_raw(), &raw mut tail);
}

#[test]
fn proxy_protocol_view_reports_absent_metadata() {
    let mut connection = zeroed_connection();
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();

    assert_eq!(connection.proxy_protocol(), Ok(None));
}

#[test]
fn proxy_protocol_view_keeps_binary_addresses_host_ports_and_raw_text() {
    let source_text = b"192.0.2.10";
    let destination_text = b"198.51.100.20";
    let mut metadata: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
    metadata.src_addr = ngx_str_t { len: source_text.len(), data: source_text.as_ptr().cast_mut() };
    metadata.dst_addr =
        ngx_str_t { len: destination_text.len(), data: destination_text.as_ptr().cast_mut() };
    metadata.src_port = 0;
    metadata.dst_port = u16::MAX;

    let mut connection = zeroed_connection();
    connection.type_ = libc::SOCK_STREAM;
    connection.proxy_protocol = &raw mut metadata;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    let metadata = connection.proxy_protocol().unwrap().unwrap();

    assert_eq!(
        metadata.source(),
        ProxyProtocolAddress::Ipv4 {
            octets: [192, 0, 2, 10],
            port: SocketPort::from_host_order(0),
        }
    );
    assert_eq!(
        metadata.destination(),
        ProxyProtocolAddress::Ipv4 {
            octets: [198, 51, 100, 20],
            port: SocketPort::from_host_order(u16::MAX),
        }
    );
    assert_eq!(metadata.source_text(), source_text);
    assert_eq!(metadata.destination_text(), destination_text);
    assert_eq!(metadata.transport(), SocketType::Stream);
}

#[test]
fn proxy_protocol_view_rejects_invalid_address_text() {
    let invalid = b"not-an-address";
    let mut metadata: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
    metadata.src_addr = ngx_str_t { len: invalid.len(), data: invalid.as_ptr().cast_mut() };
    metadata.dst_addr = metadata.src_addr;
    let mut connection = zeroed_connection();
    connection.type_ = libc::SOCK_STREAM;
    connection.proxy_protocol = &raw mut metadata;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();

    assert_eq!(connection.proxy_protocol(), Err(ProxyProtocolError::InvalidAddressText));
}

#[test]
fn proxy_protocol_view_rejects_unbacked_and_oversized_metadata_bytes() {
    let mut metadata: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
    metadata.src_addr.len = 1;
    let mut connection = zeroed_connection();
    connection.proxy_protocol = &raw mut metadata;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();

    assert_eq!(connection.proxy_protocol(), Err(ProxyProtocolError::MissingData));

    let mut metadata: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
    metadata.src_addr.len = isize::MAX as usize + 1;
    let mut connection = zeroed_connection();
    connection.proxy_protocol = &raw mut metadata;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    assert_eq!(connection.proxy_protocol(), Err(ProxyProtocolError::DataTooLong));
}

#[cfg(feature = "test-link")]
#[test]
fn proxy_protocol_view_preserves_noncanonical_text_from_the_c_v1_parser() {
    let mut owner = TestPool::new();
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.log = &raw mut *owner._log;
    connection.type_ = libc::SOCK_STREAM;
    let source_text = b"2001:0db8:0000:0000:0000:0000:0000:0001";
    let destination_text = b"2001:0db8:0000:0000:0000:0000:0000:0002";
    let mut header = [
        b"PROXY TCP6 ".as_slice(),
        source_text.as_slice(),
        b" ".as_slice(),
        destination_text.as_slice(),
        b" 1 65535\r\n".as_slice(),
    ]
    .concat();

    parse_proxy_protocol(&mut connection, &mut header);

    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    let metadata = connection.proxy_protocol().unwrap().unwrap();
    assert_eq!(metadata.source_text(), source_text);
    assert_eq!(metadata.destination_text(), destination_text);
    assert_eq!(
        metadata.source(),
        ProxyProtocolAddress::Ipv6 {
            octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: SocketPort::from_host_order(1),
        }
    );
    assert_eq!(
        metadata.destination(),
        ProxyProtocolAddress::Ipv6 {
            octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            port: SocketPort::from_host_order(u16::MAX),
        }
    );
}

#[test]
fn peer_and_local_ipv4_addresses_keep_port_byte_order() {
    let mut peer: sockaddr_in = unsafe { mem::zeroed() };
    peer.sin_family = libc::AF_INET as _;
    peer.sin_port = 8443_u16.to_be();
    peer.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 10]);
    let mut local: sockaddr_in = unsafe { mem::zeroed() };
    local.sin_family = libc::AF_INET as _;
    local.sin_port = 443_u16.to_be();
    local.sin_addr.s_addr = u32::from_ne_bytes([198, 51, 100, 20]);
    let mut connection = zeroed_connection();
    connection.sockaddr = (&raw mut peer).cast();
    connection.socklen = size_of::<sockaddr_in>() as _;
    connection.local_sockaddr = (&raw mut local).cast();
    connection.local_socklen = size_of::<sockaddr_in>() as _;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();

    let peer = connection.peer_address().unwrap();
    assert_eq!(peer.ipv4_octets(), Some([192, 0, 2, 10]));
    assert_eq!(peer.port().unwrap().host_order(), 8443);
    assert_eq!(peer.port().unwrap().network_order(), [0x20, 0xfb]);
    let local = connection.local_address().unwrap();
    assert_eq!(local.ipv4_octets(), Some([198, 51, 100, 20]));
    assert_eq!(local.port().unwrap().host_order(), 443);
    assert_eq!(local.port().unwrap().network_order(), [0x01, 0xbb]);
}

#[cfg(all(feature = "test-link", unix))]
#[test]
fn local_address_refreshes_a_wildcard_placeholder_through_nginx() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let _client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (server, _) = listener.accept().unwrap();

    let owner = TestPool::new();
    let mut placeholder: sockaddr_in = unsafe { mem::zeroed() };
    placeholder.sin_family = libc::AF_INET as _;
    placeholder.sin_port = port.to_be();

    let mut connection = zeroed_connection();
    connection.fd = server.as_raw_fd();
    connection.pool = owner.raw;
    connection.local_sockaddr = (&raw mut placeholder).cast();
    connection.local_socklen = size_of::<sockaddr_in>() as _;
    let mut connection =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();

    connection.refresh_local_address().unwrap();
    let local = connection.local_address().unwrap();
    assert_eq!(local.ipv4_octets(), Some([127, 0, 0, 1]));
    assert_eq!(local.port().unwrap().host_order(), port);
}

#[test]
fn ipv6_addresses_keep_native_scope_and_flow_information() {
    let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut peer: sockaddr_in6 = unsafe { mem::zeroed() };
    peer.sin6_family = libc::AF_INET6 as _;
    peer.sin6_port = 5353_u16.to_be();
    peer.sin6_flowinfo = 7;
    peer.sin6_scope_id = 3;
    peer.sin6_addr.__in6_u = in6_addr__bindgen_ty_1 { __u6_addr8: octets };
    let mut connection = zeroed_connection();
    connection.sockaddr = (&raw mut peer).cast();
    connection.socklen = size_of::<sockaddr_in6>() as _;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();

    let peer = connection.peer_address().unwrap();
    assert_eq!(peer.ipv6_octets(), Some(octets));
    assert_eq!(peer.port().unwrap().host_order(), 5353);
    assert_eq!(peer.port().unwrap().network_order(), [0x14, 0xe9]);
    assert_eq!(peer.flowinfo(), Some(7));
    assert_eq!(peer.scope_id(), Some(3));
}

#[cfg(unix)]
#[test]
fn unix_addresses_preserve_the_reported_path_bytes() {
    let path = b"\0ngx-rust";
    let mut peer: sockaddr_un = unsafe { mem::zeroed() };
    peer.sun_family = libc::AF_UNIX as _;
    for (slot, byte) in peer.sun_path.iter_mut().zip(path) {
        *slot = *byte as _;
    }
    let mut connection = zeroed_connection();
    connection.sockaddr = (&raw mut peer).cast();
    connection.socklen = (core::mem::offset_of!(sockaddr_un, sun_path) + path.len()) as _;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();

    let peer = connection.peer_address().unwrap();
    assert_eq!(peer.unix_path(), Some(path.as_slice()));
    assert_eq!(peer.port(), None);
}

#[cfg(unix)]
#[test]
fn unix_addresses_accept_exact_short_backing_allocations() {
    let family_offset = core::mem::offset_of!(sockaddr_un, sun_family);
    let path_offset = core::mem::offset_of!(sockaddr_un, sun_path);

    for path in [b"".as_slice(), b"\0ngx-rust".as_slice()] {
        let len = path_offset + path.len();
        let layout = Layout::from_size_align(len, core::mem::align_of::<sockaddr_un>()).unwrap();
        let raw = unsafe { alloc_zeroed(layout) };
        assert!(!raw.is_null());
        unsafe {
            raw.add(family_offset).cast::<sa_family_t>().write_unaligned(libc::AF_UNIX as _);
            ptr::copy_nonoverlapping(path.as_ptr(), raw.add(path_offset), path.len());
        }

        {
            let address = unsafe { parse_socket_address(raw.cast(), len as _) }.unwrap();
            assert_eq!(address.unix_path(), Some(path));
        }
        unsafe { dealloc(raw, layout) };
    }
}

#[test]
fn address_views_reject_truncated_wrong_and_missing_addresses() {
    let mut ipv4: sockaddr_in = unsafe { mem::zeroed() };
    ipv4.sin_family = libc::AF_INET as _;
    let mut connection = zeroed_connection();
    connection.sockaddr = (&raw mut ipv4).cast();
    connection.socklen = (size_of::<sockaddr_in>() - 1) as _;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    assert_eq!(
        connection.peer_address(),
        Err(ConnectionError::Address(SocketAddressError::InvalidLength))
    );

    let mut unknown: sockaddr = unsafe { mem::zeroed() };
    unknown.sa_family = 0xff;
    let mut connection = zeroed_connection();
    connection.sockaddr = (&raw mut unknown).cast();
    connection.socklen = size_of::<sockaddr>() as _;
    let connection = unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    assert_eq!(
        connection.peer_address(),
        Err(ConnectionError::Address(SocketAddressError::UnsupportedFamily(0xff)))
    );
    assert_eq!(
        connection.local_address(),
        Err(ConnectionError::Address(SocketAddressError::NullAddress))
    );
}

#[test]
fn input_buffer_views_distinguish_absent_invalid_and_control_buffers() {
    let mut connection = zeroed_connection();
    assert!(
        unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }
            .unwrap()
            .buffer()
            .unwrap()
            .is_none()
    );

    let bytes = *b"abc";
    let mut invalid = memory_buffer(&bytes);
    invalid.pos = unsafe { invalid.pos.add(2) };
    invalid.last = bytes.as_ptr().cast_mut();
    connection.buffer = &raw mut invalid;
    {
        let connection_view =
            unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
        let buffer = connection_view.buffer().unwrap().unwrap();
        assert_eq!(buffer.bytes(), Err(BufferError::InvalidMemoryRange));
    }

    let mut control: ngx_buf_t = unsafe { mem::zeroed() };
    control.set_flush(1);
    connection.buffer = &raw mut control;
    {
        let connection_view =
            unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
        let buffer = connection_view.buffer().unwrap().unwrap();
        assert_eq!(buffer.bytes(), Ok(None));
        assert_eq!(buffer.has_space(), Ok(false));
    }

    let mut reversed_end = memory_buffer(&bytes);
    reversed_end.last = unsafe { reversed_end.pos.add(2) };
    reversed_end.end = unsafe { reversed_end.pos.add(1) };
    connection.buffer = &raw mut reversed_end;
    let connection_view =
        unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    let buffer = connection_view.buffer().unwrap().unwrap();
    assert_eq!(buffer.has_space(), Ok(false));
}

#[test]
fn buffer_swap_rejects_invalid_scratch_without_changing_the_connection() {
    let bytes = *b"abc";
    let mut original = memory_buffer(&bytes);
    let original_ptr = &raw mut original;
    let mut scratch = memory_buffer(&bytes);
    scratch.set_temporary(1);
    scratch.last = unsafe { scratch.pos.add(2) };
    scratch.end = unsafe { scratch.pos.add(1) };
    let mut connection = zeroed_connection();
    connection.buffer = original_ptr;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();

    assert!(matches!(
        connection_view.swap_buffer(&mut scratch),
        Err(ConnectionError::Buffer(BufferError::InvalidMemoryRange))
    ));
    assert_eq!(connection.buffer, original_ptr);
}

#[test]
fn listener_and_socket_type_views_reject_missing_and_unknown_values() {
    let mut stream_listener: ngx_listening_t = unsafe { mem::zeroed() };
    stream_listener.type_ = libc::SOCK_STREAM;
    let mut connection = zeroed_connection();
    connection.type_ = libc::SOCK_STREAM;
    connection.listening = &raw mut stream_listener;
    {
        let connection_view =
            unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
        assert_eq!(connection_view.socket_type(), Ok(SocketType::Stream));
        assert_eq!(connection_view.listener().unwrap().socket_type(), Ok(SocketType::Stream));
    }

    let mut datagram_listener: ngx_listening_t = unsafe { mem::zeroed() };
    datagram_listener.type_ = libc::SOCK_DGRAM;
    let mut connection = zeroed_connection();
    connection.type_ = libc::SOCK_DGRAM;
    connection.listening = &raw mut datagram_listener;
    {
        let connection_view =
            unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
        assert_eq!(connection_view.socket_type(), Ok(SocketType::Datagram));
        assert_eq!(connection_view.listener().unwrap().socket_type(), Ok(SocketType::Datagram));
    }

    let mut connection = zeroed_connection();
    connection.type_ = -1;
    {
        let connection_view =
            unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
        assert_eq!(connection_view.socket_type(), Err(ConnectionError::UnsupportedSocketType(-1)));
    }

    let mut connection = zeroed_connection();
    let connection_view =
        unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    assert_eq!(connection_view.listener(), Err(ConnectionError::MissingListener));
}

#[test]
fn read_and_write_event_views_are_checked_and_exclusive() {
    let mut read: ngx_event_t = unsafe { mem::zeroed() };
    let mut write: ngx_event_t = unsafe { mem::zeroed() };
    let mut connection = zeroed_connection();
    connection.read = &raw mut read;
    connection.write = &raw mut write;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();

    {
        let event = connection_view.read_event().unwrap();
        assert_eq!(event.as_ptr(), &raw mut read);
    }
    {
        let event = connection_view.write_event().unwrap();
        assert_eq!(event.as_ptr(), &raw mut write);
    }

    let mut connection = zeroed_connection();
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    assert!(matches!(
        connection_view.read_event(),
        Err(ConnectionError::Event(crate::event::EventError::NullEvent))
    ));
}

#[cfg(feature = "test-link")]
struct TestPool {
    raw: *mut ngx_pool_t,
    _log: Box<ngx_log_t>,
}

#[cfg(feature = "test-link")]
impl TestPool {
    fn new() -> Self {
        let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
        let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!raw.is_null());
        Self { raw, _log: log }
    }

    fn handle(&self) -> Pool<'_> {
        unsafe { Pool::from_raw(self.raw) }.unwrap()
    }
}

#[cfg(feature = "test-link")]
impl Drop for TestPool {
    fn drop(&mut self) {
        unsafe { ngx_destroy_pool(self.raw) };
    }
}

#[cfg(feature = "test-link")]
#[test]
fn permanent_replacement_requires_the_connection_pool() {
    let owner = TestPool::new();
    let other = TestPool::new();
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    let replacement = connection_view
        .pool()
        .unwrap()
        .copy_buffer(b"replacement", BufferFlags::default())
        .unwrap();
    let replacement_ptr = replacement.as_ptr();

    connection_view.replace_buffer(replacement).unwrap();
    assert_eq!(connection.buffer, replacement_ptr);

    let foreign = other.handle().copy_buffer(b"foreign", BufferFlags::default()).unwrap();
    assert_eq!(connection_view.replace_buffer(foreign), Err(ConnectionError::ForeignPool));
    assert_eq!(connection.buffer, replacement_ptr);
}

#[cfg(feature = "test-link")]
#[test]
fn proxy_protocol_builder_attaches_ipv4_and_ipv6_stream_and_datagram_metadata() {
    let cases = [
        (
            ProxyProtocolAddress::Ipv4 {
                octets: [192, 0, 2, 10],
                port: SocketPort::from_host_order(0),
            },
            ProxyProtocolAddress::Ipv4 {
                octets: [198, 51, 100, 20],
                port: SocketPort::from_host_order(u16::MAX),
            },
            SocketType::Stream,
            libc::SOCK_STREAM,
            b"192.0.2.10".as_slice(),
            b"198.51.100.20".as_slice(),
        ),
        (
            ProxyProtocolAddress::Ipv4 {
                octets: [192, 0, 2, 30],
                port: SocketPort::from_host_order(12345),
            },
            ProxyProtocolAddress::Ipv4 {
                octets: [198, 51, 100, 40],
                port: SocketPort::from_host_order(443),
            },
            SocketType::Datagram,
            libc::SOCK_DGRAM,
            b"192.0.2.30".as_slice(),
            b"198.51.100.40".as_slice(),
        ),
        (
            ProxyProtocolAddress::Ipv6 {
                octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: SocketPort::from_host_order(12345),
            },
            ProxyProtocolAddress::Ipv6 {
                octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                port: SocketPort::from_host_order(443),
            },
            SocketType::Stream,
            libc::SOCK_STREAM,
            b"2001:db8::1".as_slice(),
            b"2001:db8::2".as_slice(),
        ),
        (
            ProxyProtocolAddress::Ipv6 {
                octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
                port: SocketPort::from_host_order(5353),
            },
            ProxyProtocolAddress::Ipv6 {
                octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
                port: SocketPort::from_host_order(53),
            },
            SocketType::Datagram,
            libc::SOCK_DGRAM,
            b"2001:db8::3".as_slice(),
            b"2001:db8::4".as_slice(),
        ),
    ];

    for (source, destination, transport, carrier, source_text, destination_text) in cases {
        let owner = TestPool::new();
        let mut old: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
        let old = &raw mut old;
        let mut connection = zeroed_connection();
        connection.pool = owner.raw;
        connection.type_ = carrier;
        connection.proxy_protocol = old;
        let mut connection_view =
            unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
        let metadata = ProxyProtocolBuilder::new(source, destination, transport).unwrap();

        connection_view.attach_proxy_protocol(metadata).unwrap();
        assert_ne!(connection.proxy_protocol, old);
        let metadata = connection_view.proxy_protocol().unwrap().unwrap();
        assert_eq!(metadata.source(), source);
        assert_eq!(metadata.destination(), destination);
        assert_eq!(metadata.source().port().network_order(), source.port().network_order());
        assert_eq!(
            metadata.destination().port().network_order(),
            destination.port().network_order()
        );
        assert_eq!(metadata.transport(), transport);
        assert_eq!(metadata.source_text(), source_text);
        assert_eq!(metadata.destination_text(), destination_text);
        assert!(metadata.tlvs().is_empty());
    }
}

#[cfg(feature = "test-link")]
#[test]
fn proxy_protocol_builder_rejects_mismatched_endpoints_and_carriers_without_replacement() {
    let source = ProxyProtocolAddress::Ipv4 {
        octets: [192, 0, 2, 1],
        port: SocketPort::from_host_order(12345),
    };
    let destination = ProxyProtocolAddress::Ipv6 {
        octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port: SocketPort::from_host_order(443),
    };
    assert_eq!(
        ProxyProtocolBuilder::new(source, destination, SocketType::Stream),
        Err(ProxyProtocolError::EndpointFamilyMismatch)
    );

    let owner = TestPool::new();
    let mut old: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
    let old = &raw mut old;
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.type_ = libc::SOCK_STREAM;
    connection.proxy_protocol = old;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    let destination = ProxyProtocolAddress::Ipv4 {
        octets: [198, 51, 100, 1],
        port: SocketPort::from_host_order(443),
    };
    let metadata = ProxyProtocolBuilder::new(source, destination, SocketType::Datagram).unwrap();

    assert_eq!(
        connection_view.attach_proxy_protocol(metadata),
        Err(ProxyProtocolError::TransportMismatch {
            connection: SocketType::Stream,
            metadata: SocketType::Datagram,
        })
    );
    assert_eq!(connection.proxy_protocol, old);
}

#[cfg(all(feature = "test-link", unix))]
#[test]
fn proxy_protocol_builder_rejects_datagram_metadata_on_a_unix_stream_carrier() {
    let owner = TestPool::new();
    let mut listener_address: sockaddr_un = unsafe { mem::zeroed() };
    listener_address.sun_family = libc::AF_UNIX as _;
    let mut listener: ngx_listening_t = unsafe { mem::zeroed() };
    listener.type_ = libc::SOCK_STREAM;
    listener.sockaddr = (&raw mut listener_address).cast();
    listener.socklen = size_of::<sockaddr_un>() as _;
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.type_ = libc::SOCK_STREAM;
    connection.listening = &raw mut listener;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    let source = ProxyProtocolAddress::Ipv6 {
        octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port: SocketPort::from_host_order(12345),
    };
    let destination = ProxyProtocolAddress::Ipv6 {
        octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        port: SocketPort::from_host_order(443),
    };
    let metadata = ProxyProtocolBuilder::new(source, destination, SocketType::Datagram).unwrap();

    assert_eq!(
        connection_view.attach_proxy_protocol(metadata),
        Err(ProxyProtocolError::TransportMismatch {
            connection: SocketType::Stream,
            metadata: SocketType::Datagram,
        })
    );
}

#[cfg(feature = "test-link")]
#[test]
fn proxy_protocol_tlv_lookup_preserves_parser_results() {
    let source = ProxyProtocolAddress::Ipv4 {
        octets: [192, 0, 2, 10],
        port: SocketPort::from_host_order(12345),
    };
    let destination = ProxyProtocolAddress::Ipv4 {
        octets: [198, 51, 100, 20],
        port: SocketPort::from_host_order(443),
    };
    let tlvs = [0x05, 0, 2, 0xaa, 0xbb, 0x06, 0, 0];
    let mut owner = TestPool::new();
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.log = &raw mut *owner._log;
    connection.type_ = libc::SOCK_STREAM;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    let metadata = ProxyProtocolBuilder::new(source, destination, SocketType::Stream)
        .unwrap()
        .tlvs(&tlvs)
        .unwrap();

    connection_view.attach_proxy_protocol(metadata).unwrap();
    let metadata = connection_view.proxy_protocol().unwrap().unwrap();
    assert_eq!(metadata.tlvs(), tlvs);
    assert_eq!(metadata.lookup_tlv(0x05), Ok(ProxyProtocolTlvLookup::Ok(&[0xaa, 0xbb])));
    assert_eq!(metadata.lookup_tlv(0x06), Ok(ProxyProtocolTlvLookup::Ok(&[])));
    assert_eq!(metadata.lookup_tlv(0x07), Ok(ProxyProtocolTlvLookup::Declined));

    let malformed = [0x05, 0, 2, 0xaa];
    let mut owner = TestPool::new();
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.log = &raw mut *owner._log;
    connection.type_ = libc::SOCK_STREAM;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    let metadata = ProxyProtocolBuilder::new(source, destination, SocketType::Stream)
        .unwrap()
        .tlvs(&malformed)
        .unwrap();

    connection_view.attach_proxy_protocol(metadata).unwrap();
    assert_eq!(
        connection_view.proxy_protocol().unwrap().unwrap().lookup_tlv(0x05),
        Ok(ProxyProtocolTlvLookup::Error)
    );
}

#[cfg(feature = "test-link")]
#[test]
fn proxy_protocol_tlv_lookup_does_not_require_a_connection_log() {
    let source = ProxyProtocolAddress::Ipv4 {
        octets: [192, 0, 2, 10],
        port: SocketPort::from_host_order(12345),
    };
    let destination = ProxyProtocolAddress::Ipv4 {
        octets: [198, 51, 100, 20],
        port: SocketPort::from_host_order(443),
    };
    let tlvs = [0x05, 0, 1, 0x42];
    let owner = TestPool::new();
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.type_ = libc::SOCK_STREAM;
    {
        let mut connection_view =
            unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
        connection_view
            .attach_proxy_protocol(
                ProxyProtocolBuilder::new(source, destination, SocketType::Stream)
                    .unwrap()
                    .tlvs(&tlvs)
                    .unwrap(),
            )
            .unwrap();
        let metadata = connection_view.proxy_protocol().unwrap().unwrap();
        assert_eq!(metadata.lookup_tlv(0x05), Ok(ProxyProtocolTlvLookup::Ok(&[0x42])));
    }

    connection.log = ptr::without_provenance_mut::<ngx_log_t>(1);
    let connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    let metadata = connection_view.proxy_protocol().unwrap().unwrap();
    assert_eq!(metadata.lookup_tlv(0x05), Ok(ProxyProtocolTlvLookup::Ok(&[0x42])));
}

#[cfg(feature = "test-link")]
#[test]
fn proxy_protocol_builder_keeps_tcp_and_datagram_tlv_limits_separate() {
    let source = ProxyProtocolAddress::Ipv6 {
        octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port: SocketPort::from_host_order(12345),
    };
    let destination = ProxyProtocolAddress::Ipv6 {
        octets: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        port: SocketPort::from_host_order(443),
    };
    let stream_maximum = crate::ffi::NGX_PROXY_PROTOCOL_MAX_HEADER as usize - 16 - 36;
    let stream_tlvs = vec![0_u8; stream_maximum];
    let stream_too_large = vec![0_u8; stream_maximum + 1];
    assert!(
        ProxyProtocolBuilder::new(source, destination, SocketType::Stream)
            .unwrap()
            .tlvs(&stream_tlvs)
            .is_ok()
    );
    assert_eq!(
        ProxyProtocolBuilder::new(source, destination, SocketType::Stream)
            .unwrap()
            .tlvs(&stream_too_large),
        Err(ProxyProtocolError::TlvsTooLong)
    );

    let datagram_maximum = usize::from(u16::MAX) - 36;
    let datagram_tlvs = vec![0_u8; datagram_maximum];
    let datagram_too_large = vec![0_u8; datagram_maximum + 1];
    assert_eq!(
        ProxyProtocolBuilder::new(source, destination, SocketType::Datagram)
            .unwrap()
            .tlvs(&datagram_too_large),
        Err(ProxyProtocolError::TlvsTooLong)
    );

    let owner = TestPool::new();
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.type_ = libc::SOCK_DGRAM;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();
    let metadata = ProxyProtocolBuilder::new(source, destination, SocketType::Datagram)
        .unwrap()
        .tlvs(&datagram_tlvs)
        .unwrap();

    connection_view.attach_proxy_protocol(metadata).unwrap();
    assert_eq!(connection_view.proxy_protocol().unwrap().unwrap().tlvs(), datagram_tlvs);
}

#[cfg(feature = "test-link")]
#[test]
fn proxy_protocol_builder_keeps_existing_metadata_when_each_copy_fails() {
    let source = ProxyProtocolAddress::Ipv4 {
        octets: [192, 0, 2, 10],
        port: SocketPort::from_host_order(12345),
    };
    let destination = ProxyProtocolAddress::Ipv4 {
        octets: [198, 51, 100, 20],
        port: SocketPort::from_host_order(443),
    };
    let tlvs = [0x05, 0, 1, 0x42];
    let metadata = ProxyProtocolBuilder::new(source, destination, SocketType::Stream)
        .unwrap()
        .tlvs(&tlvs)
        .unwrap();

    for successful_allocations in 0..4 {
        let owner = TestPool::new();
        let mut old: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
        let old = &raw mut old;
        let mut connection = zeroed_connection();
        connection.pool = owner.raw;
        connection.type_ = libc::SOCK_STREAM;
        connection.proxy_protocol = old;
        unsafe {
            (*owner.raw).max = 0;
            ngx_rs_test_fail_allocations_after(successful_allocations);
        }
        let mut connection_view =
            unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();

        assert_eq!(
            connection_view.attach_proxy_protocol(metadata),
            Err(ProxyProtocolError::Allocation)
        );
        unsafe { ngx_rs_test_reset_allocation_failures() };
        assert_eq!(connection.proxy_protocol, old);
    }

    let owner = TestPool::new();
    let mut old: ngx_proxy_protocol_t = unsafe { mem::zeroed() };
    let old = &raw mut old;
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.type_ = libc::SOCK_STREAM;
    connection.proxy_protocol = old;
    let mut connection_view =
        unsafe { ConnectionRefMut::from_raw(raw_connection(&mut connection)) }.unwrap();

    connection_view.attach_proxy_protocol(metadata).unwrap();
    assert_ne!(connection.proxy_protocol, old);
}

#[test]
fn synchronous_buffer_swap_restores_the_original_on_success_error_and_unwind() {
    fn return_error(
        connection: &mut ConnectionRefMut<'_>,
        scratch: &mut ngx_buf_t,
    ) -> Result<(), ()> {
        let _swap = connection.swap_buffer(scratch).unwrap();
        Err(())
    }

    let mut original: ngx_buf_t = unsafe { mem::zeroed() };
    let original_ptr = &raw mut original;
    let mut scratch: ngx_buf_t = unsafe { mem::zeroed() };
    let scratch_ptr = &raw mut scratch;
    let mut connection = zeroed_connection();
    connection.buffer = original_ptr;
    let connection_ptr = raw_connection(&mut connection);
    let mut connection_view = unsafe { ConnectionRefMut::from_raw(connection_ptr) }.unwrap();

    {
        let mut swap = connection_view.swap_buffer(&mut scratch).unwrap();
        assert_eq!(unsafe { (*connection_ptr).buffer }, scratch_ptr);
        swap.buffer_mut().unwrap().set_flags(BufferFlags { flush: true, ..Default::default() });
    }
    assert_eq!(unsafe { (*connection_ptr).buffer }, original_ptr);
    assert_ne!(scratch.flush(), 0);

    assert_eq!(return_error(&mut connection_view, &mut scratch), Err(()));
    assert_eq!(unsafe { (*connection_ptr).buffer }, original_ptr);

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _swap = connection_view.swap_buffer(&mut scratch).unwrap();
        panic!("test unwind");
    }));
    assert!(result.is_err());
    assert_eq!(unsafe { (*connection_ptr).buffer }, original_ptr);
}

#[cfg(feature = "test-link")]
#[test]
fn buffer_swap_can_copy_a_pool_owned_final_descriptor_before_restoring() {
    let owner = TestPool::new();
    let mut original: ngx_buf_t = unsafe { mem::zeroed() };
    let original_ptr = &raw mut original;
    let mut scratch: ngx_buf_t = unsafe { mem::zeroed() };
    let mut connection = zeroed_connection();
    connection.pool = owner.raw;
    connection.buffer = original_ptr;
    let connection_ptr = raw_connection(&mut connection);
    let mut connection_view = unsafe { ConnectionRefMut::from_raw(connection_ptr) }.unwrap();
    let replacement =
        connection_view.pool().unwrap().copy_buffer(b"final", BufferFlags::default()).unwrap();
    let replacement_ptr = replacement.as_ptr();

    {
        let mut swap = connection_view.swap_buffer(&mut scratch).unwrap();
        swap.replace_buffer(replacement).unwrap();
        assert_eq!(unsafe { (*connection_ptr).buffer }, replacement_ptr);
        swap.copy_current_to_scratch().unwrap();
    }

    assert_eq!(unsafe { (*connection_ptr).buffer }, original_ptr);
    assert_eq!(scratch.pos, unsafe { (*replacement_ptr).pos });
    assert_eq!(scratch.last, unsafe { (*replacement_ptr).last });
    assert_eq!(scratch.end, unsafe { (*replacement_ptr).end });
}
