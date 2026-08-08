extern crate alloc;
extern crate std;

use alloc::boxed::Box;
use core::mem::{self, size_of};
use core::panic::AssertUnwindSafe;
use core::ptr;

use super::{ConnectionError, ConnectionRef, ConnectionRefMut, SocketAddressError, SocketType};
use crate::core::{BufferError, BufferFlags, Pool};
#[cfg(unix)]
use crate::ffi::sockaddr_un;
use crate::ffi::{
    in6_addr__bindgen_ty_1, ngx_buf_t, ngx_connection_t, ngx_create_pool, ngx_destroy_pool,
    ngx_event_t, ngx_listening_t, ngx_log_t, ngx_pool_t, sockaddr, sockaddr_in, sockaddr_in6,
};

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
    let connection_view =
        unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();
    assert!(connection_view.buffer().unwrap().is_none());

    let bytes = *b"abc";
    let mut invalid = memory_buffer(&bytes);
    invalid.pos = unsafe { invalid.pos.add(2) };
    invalid.last = bytes.as_ptr().cast_mut();
    connection.buffer = &raw mut invalid;
    let buffer = connection_view.buffer().unwrap().unwrap();
    assert_eq!(buffer.bytes(), Err(BufferError::InvalidMemoryRange));

    let mut control: ngx_buf_t = unsafe { mem::zeroed() };
    control.set_flush(1);
    connection.buffer = &raw mut control;
    let buffer = connection_view.buffer().unwrap().unwrap();
    assert_eq!(buffer.bytes(), Ok(None));
    assert_eq!(buffer.has_space(), Ok(false));

    let mut reversed_end = memory_buffer(&bytes);
    reversed_end.last = unsafe { reversed_end.pos.add(2) };
    reversed_end.end = unsafe { reversed_end.pos.add(1) };
    connection.buffer = &raw mut reversed_end;
    let buffer = connection_view.buffer().unwrap().unwrap();
    assert_eq!(buffer.has_space(), Err(BufferError::InvalidMemoryRange));
}

#[test]
fn buffer_swap_rejects_invalid_scratch_without_changing_the_connection() {
    let bytes = *b"abc";
    let mut original = memory_buffer(&bytes);
    let original_ptr = &raw mut original;
    let mut scratch = memory_buffer(&bytes);
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
    let mut listener: ngx_listening_t = unsafe { mem::zeroed() };
    listener.type_ = libc::SOCK_STREAM;
    let mut connection = zeroed_connection();
    connection.type_ = libc::SOCK_STREAM;
    connection.listening = &raw mut listener;
    let connection_view =
        unsafe { ConnectionRef::from_raw(raw_connection(&mut connection)) }.unwrap();

    assert_eq!(connection_view.socket_type(), Ok(SocketType::Stream));
    assert_eq!(connection_view.listener().unwrap().socket_type(), Ok(SocketType::Stream));

    connection.type_ = libc::SOCK_DGRAM;
    listener.type_ = libc::SOCK_DGRAM;
    assert_eq!(connection_view.socket_type(), Ok(SocketType::Datagram));
    assert_eq!(connection_view.listener().unwrap().socket_type(), Ok(SocketType::Datagram));

    connection.type_ = -1;
    assert_eq!(connection_view.socket_type(), Err(ConnectionError::UnsupportedSocketType(-1)));
    connection.listening = ptr::null_mut();
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
    connection.read = ptr::null_mut();
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
    let connection_ptr = raw_connection(&mut connection);
    connection.buffer = original_ptr;
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
    let connection_ptr = raw_connection(&mut connection);
    connection.pool = owner.raw;
    connection.buffer = original_ptr;
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
