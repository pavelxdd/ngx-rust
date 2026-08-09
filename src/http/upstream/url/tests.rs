use core::marker::PhantomData;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

use super::super::test_support::TestPool;
use super::{ConfiguredUpstreamUrl, UpstreamPort, UpstreamUrlParseError, UpstreamUrlViewError};
use crate::core::{SocketAddressError, SocketPort};
use crate::ffi::{ngx_addr_t, ngx_str_t, ngx_url_t};

fn raw_url(raw: &mut ngx_url_t) -> ConfiguredUpstreamUrl<'_> {
    ConfiguredUpstreamUrl {
        raw: NonNull::from(raw),
        _pool: PhantomData,
        _not_thread_safe: PhantomData,
    }
}

#[test]
fn configured_url_keeps_copied_input_and_default_port() {
    let owner = TestPool::new();
    let mut input = *b"127.0.0.1";
    let url = ConfiguredUpstreamUrl::parse(owner.pool(), &input, 8080).unwrap();
    input.fill(b'!');

    assert_eq!(url.input().unwrap(), b"127.0.0.1");
    assert_eq!(url.host().unwrap().as_bytes(), b"127.0.0.1");
    assert_eq!(url.port(), Some(UpstreamPort::Default(SocketPort::from_host_order(8080))));

    let addresses = url.addresses().unwrap();
    let address = addresses.get(0).unwrap();
    let address = address.socket_address().unwrap();
    assert_eq!(address.ipv4_octets(), Some([127, 0, 0, 1]));
    assert_eq!(address.port(), Some(SocketPort::from_host_order(8080)));

    let addresses = url.addresses().unwrap();
    let selected = addresses.get(0).unwrap();
    let address = selected.event_peer_address().unwrap();
    assert_eq!(address.name().unwrap().as_bytes(), b"127.0.0.1:8080");
}

#[test]
fn configured_url_preserves_explicit_ports_and_native_address_forms() {
    let owner = TestPool::new();
    let ipv4 = ConfiguredUpstreamUrl::parse(owner.pool(), b"127.0.0.1:65535", 80).unwrap();
    assert_eq!(ipv4.port(), Some(UpstreamPort::Explicit(SocketPort::from_host_order(65535))));

    let ipv6 = ConfiguredUpstreamUrl::parse(owner.pool(), b"[::1]:8443", 80).unwrap();
    let ipv6_addresses = ipv6.addresses().unwrap();
    let ipv6_selected = ipv6_addresses.get(0).unwrap();
    let ipv6_address = ipv6_selected.socket_address().unwrap();
    assert_eq!(ipv6_address.ipv6_octets(), Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    assert_eq!(ipv6_address.port(), Some(SocketPort::from_host_order(8443)));

    #[cfg(unix)]
    {
        let unix =
            ConfiguredUpstreamUrl::parse(owner.pool(), b"unix:/tmp/ngx-rust-upstream.sock", 80)
                .unwrap();
        assert_eq!(unix.port(), None);
        let addresses = unix.addresses().unwrap();
        let selected = addresses.get(0).unwrap();
        let address = selected.socket_address().unwrap();
        let path = address.unix_path().unwrap();
        assert!(path.starts_with(b"/tmp/ngx-rust-upstream.sock"));
        assert!(path[b"/tmp/ngx-rust-upstream.sock".len()..].iter().all(|byte| *byte == 0));
    }

    let hostname = ConfiguredUpstreamUrl::parse(owner.pool(), b"localhost", 0).unwrap();
    assert_eq!(hostname.port(), Some(UpstreamPort::Default(SocketPort::from_host_order(0))));
    assert!(!hostname.addresses().unwrap().is_empty());
}

#[test]
fn configured_url_copies_native_parser_errors() {
    let owner = TestPool::new();

    assert!(matches!(
        ConfiguredUpstreamUrl::parse(owner.pool(), b"", 80),
        Err(UpstreamUrlParseError::EmptyInput)
    ));
    assert!(matches!(
        ConfiguredUpstreamUrl::parse(owner.pool(), b"127.0.0.1:0", 80),
        Err(UpstreamUrlParseError::Invalid(message)) if !message.as_bytes().is_empty()
    ));
    assert!(matches!(
        ConfiguredUpstreamUrl::parse(owner.pool(), b"[::1", 80),
        Err(UpstreamUrlParseError::Invalid(message)) if !message.as_bytes().is_empty()
    ));
}

#[test]
fn configured_url_validates_selected_address_storage() {
    {
        let mut raw = unsafe { MaybeUninit::<ngx_url_t>::zeroed().assume_init() };
        raw.naddrs = 1;
        let url = raw_url(&mut raw);
        assert!(matches!(url.addresses(), Err(UpstreamUrlViewError::MissingAddresses)));
    }

    {
        let mut raw = unsafe { MaybeUninit::<ngx_url_t>::zeroed().assume_init() };
        raw.naddrs = 1;
        raw.addrs = ptr::without_provenance_mut::<ngx_addr_t>(1);
        let url = raw_url(&mut raw);
        assert!(matches!(url.addresses(), Err(UpstreamUrlViewError::MisalignedAddresses)));
    }

    let mut address = ngx_addr_t {
        sockaddr: ptr::null_mut(),
        socklen: 0,
        name: ngx_str_t { len: 1, data: ptr::null_mut() },
    };
    let mut raw = unsafe { MaybeUninit::<ngx_url_t>::zeroed().assume_init() };
    raw.naddrs = 1;
    raw.addrs = &raw mut address;
    raw.host = ngx_str_t { len: 1, data: ptr::null_mut() };
    let url = raw_url(&mut raw);
    let addresses = url.addresses().unwrap();
    let selected = addresses.get(0).unwrap();
    assert!(matches!(
        selected.socket_address(),
        Err(UpstreamUrlViewError::SocketAddress(SocketAddressError::NullAddress))
    ));
    assert!(matches!(selected.name(), Err(UpstreamUrlViewError::MissingStringData)));
    assert!(matches!(url.host(), Err(UpstreamUrlViewError::MissingStringData)));

    let mut sockaddr = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
    sockaddr.sin_family = libc::AF_INET as _;
    address.sockaddr = (&raw mut sockaddr).cast();
    address.socklen = 1;
    assert!(matches!(
        selected.socket_address(),
        Err(UpstreamUrlViewError::SocketAddress(SocketAddressError::TruncatedAddress))
    ));
}

#[test]
fn configured_url_iterates_multiple_selected_addresses_in_order() {
    let mut first = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
    first.sin_family = libc::AF_INET as _;
    first.sin_port = 8080_u16.to_be();
    first.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let mut second = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
    second.sin_family = libc::AF_INET as _;
    second.sin_port = 8081_u16.to_be();
    second.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 2]);
    let mut first_name = *b"127.0.0.1:8080";
    let mut second_name = *b"127.0.0.2:8081";
    let mut selected = [
        ngx_addr_t {
            sockaddr: (&raw mut first).cast(),
            socklen: size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t { len: first_name.len(), data: first_name.as_mut_ptr() },
        },
        ngx_addr_t {
            sockaddr: (&raw mut second).cast(),
            socklen: size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t { len: second_name.len(), data: second_name.as_mut_ptr() },
        },
    ];
    let mut raw = unsafe { MaybeUninit::<ngx_url_t>::zeroed().assume_init() };
    raw.naddrs = selected.len() as _;
    raw.addrs = selected.as_mut_ptr();
    let url = raw_url(&mut raw);
    let addresses = url.addresses().unwrap();

    assert_eq!(addresses.len(), 2);
    let first_selected = addresses.iter().next().unwrap();
    let first = first_selected.socket_address().unwrap();
    let second_selected = addresses.get(1).unwrap();
    let second = second_selected.socket_address().unwrap();
    assert_eq!(first.ipv4_octets(), Some([127, 0, 0, 1]));
    assert_eq!(first.port(), Some(SocketPort::from_host_order(8080)));
    assert_eq!(second.ipv4_octets(), Some([127, 0, 0, 2]));
    assert_eq!(second.port(), Some(SocketPort::from_host_order(8081)));
}
