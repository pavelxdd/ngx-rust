extern crate alloc;
extern crate std;

use alloc::boxed::Box;
use core::ffi::{c_int, c_void};
use core::mem::{self, offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::io::Write;
use std::net::TcpListener;
use std::sync::MutexGuard;

use super::{
    EVENT_PEER_MIN_POOL_SIZE, EventPeer, EventPeerAddress, EventPeerAddressError,
    EventPeerAttachError, EventPeerBuildError, EventPeerBuilder, EventPeerCallbacks,
    EventPeerConnectError, EventPeerConnectResult, EventPeerConnectStatus, EventPeerConnection,
    EventPeerConnectionError, EventPeerHandlers, EventPeerKeepalive,
    EventPeerKeepaliveIntoConnectionError, EventPeerKeepaliveState,
    EventPeerKeepaliveTransferError, EventPeerLogError, EventPeerPendingConnection,
    EventPeerPreparation, EventPeerReleaseState, inert_event_handler,
};
use crate::core::{ConnectionError, SocketAddressError, SocketType};
use crate::event::EventError;
#[cfg(unix)]
use crate::ffi::sockaddr_un;
use crate::ffi::{
    NGX_AGAIN, NGX_BUSY, NGX_DECLINED, NGX_DONE, NGX_ERROR, NGX_OK, NGX_USE_CLEAR_EVENT,
    ngx_addr_t, ngx_atomic_t, ngx_close_connection, ngx_connection_counter, ngx_connection_t,
    ngx_current_msec, ngx_cycle, ngx_cycle_t, ngx_event_actions, ngx_event_actions_t,
    ngx_event_connect_peer, ngx_event_flags, ngx_event_handler_pt, ngx_event_process_posted,
    ngx_event_t, ngx_event_timer_init, ngx_int_t, ngx_log_t, ngx_peer_connection_t, ngx_pool_t,
    ngx_post_event, ngx_posted_events, ngx_queue_init, ngx_str_t, ngx_uint_t, sockaddr_in,
    sockaddr_in6,
};
use crate::log::LogRef;

static EVENT_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
static EVENT_ADD_CALLS: AtomicUsize = AtomicUsize::new(0);
static IDLE_PEEK_RESULT: AtomicIsize = AtomicIsize::new(-2);

type EventAdd = unsafe extern "C" fn(*mut ngx_event_t, ngx_int_t, ngx_uint_t) -> ngx_int_t;
type PeerGet = unsafe extern "C" fn(*mut ngx_peer_connection_t, *mut c_void) -> ngx_int_t;

struct PeerGlobals {
    _guard: MutexGuard<'static, ()>,
    cycle: Box<ngx_cycle_t>,
    _connection: Box<ngx_connection_t>,
    _read: Box<ngx_event_t>,
    _write: Box<ngx_event_t>,
    _log: Box<ngx_log_t>,
    _counter: Box<ngx_atomic_t>,
    previous_cycle: *mut ngx_cycle_t,
    previous_actions: ngx_event_actions_t,
    previous_event_flags: ngx_uint_t,
    previous_connection_counter: *mut ngx_atomic_t,
}

impl PeerGlobals {
    fn new(connection_available: bool, add: EventAdd) -> Self {
        let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let mut cycle = Box::new(unsafe { mem::zeroed::<ngx_cycle_t>() });
        let mut connection = Box::new(unsafe { mem::zeroed::<ngx_connection_t>() });
        let mut read = Box::new(unsafe { mem::zeroed::<ngx_event_t>() });
        let mut write = Box::new(unsafe { mem::zeroed::<ngx_event_t>() });
        let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
        let mut counter = Box::new(unsafe { mem::zeroed::<ngx_atomic_t>() });

        connection.read = &raw mut *read;
        connection.write = &raw mut *write;
        cycle.log = &raw mut *log;
        cycle.connection_n = 1;
        if connection_available {
            cycle.free_connections = &raw mut *connection;
            cycle.free_connection_n = 1;
        }

        let previous_cycle = unsafe { ngx_cycle };
        let previous_actions = unsafe { ngx_event_actions };
        let previous_event_flags = unsafe { ngx_event_flags };
        let previous_connection_counter = unsafe { ngx_connection_counter };
        unsafe {
            ngx_cycle = &raw mut *cycle;
            ngx_event_actions = mem::zeroed();
            ngx_event_actions.add = Some(add);
            ngx_event_actions.del = Some(delete_event_ok);
            ngx_event_flags = NGX_USE_CLEAR_EVENT as _;
            ngx_connection_counter = &raw mut *counter;
        }

        Self {
            _guard: guard,
            cycle,
            _connection: connection,
            _read: read,
            _write: write,
            _log: log,
            _counter: counter,
            previous_cycle,
            previous_actions,
            previous_event_flags,
            previous_connection_counter,
        }
    }

    fn free_connection_n(&self) -> ngx_uint_t {
        self.cycle.free_connection_n
    }
}

impl Drop for PeerGlobals {
    fn drop(&mut self) {
        unsafe {
            ngx_cycle = self.previous_cycle;
            ngx_event_actions = self.previous_actions;
            ngx_event_flags = self.previous_event_flags;
            ngx_connection_counter = self.previous_connection_counter;
        }
    }
}

struct TestAddress {
    socket: sockaddr_in,
    name: [u8; 4],
    raw: ngx_addr_t,
}

impl TestAddress {
    fn ipv4(octets: [u8; 4], port: u16) -> Box<Self> {
        let mut value = Box::new(Self {
            socket: unsafe { mem::zeroed() },
            name: *b"peer",
            raw: unsafe { mem::zeroed() },
        });
        value.socket.sin_family = libc::AF_INET as _;
        value.socket.sin_port = port.to_be();
        value.socket.sin_addr.s_addr = u32::from_ne_bytes(octets);
        value.raw.sockaddr = (&raw mut value.socket).cast();
        value.raw.socklen = size_of::<sockaddr_in>() as _;
        value.raw.name = ngx_str_t { len: value.name.len(), data: value.name.as_mut_ptr() };
        value
    }

    fn peer_address(&self) -> EventPeerAddress<'_> {
        unsafe { EventPeerAddress::from_raw(&raw const self.raw) }.unwrap()
    }
}

#[cfg(unix)]
struct TestUnixAddress {
    socket: sockaddr_un,
    name: [u8; 4],
    raw: ngx_addr_t,
}

#[cfg(unix)]
impl TestUnixAddress {
    fn invalid_path() -> Box<Self> {
        let path = b"/dev/null/ngx-rust-peer";
        let mut value = Box::new(Self {
            socket: unsafe { mem::zeroed() },
            name: *b"unix",
            raw: unsafe { mem::zeroed() },
        });
        value.socket.sun_family = libc::AF_UNIX as _;
        for (target, source) in value.socket.sun_path.iter_mut().zip(path) {
            *target = *source as _;
        }
        value.raw.sockaddr = (&raw mut value.socket).cast();
        value.raw.socklen = (offset_of!(sockaddr_un, sun_path) + path.len() + 1) as _;
        value.raw.name = ngx_str_t { len: value.name.len(), data: value.name.as_mut_ptr() };
        value
    }

    fn peer_address(&self) -> EventPeerAddress<'_> {
        unsafe { EventPeerAddress::from_raw(&raw const self.raw) }.unwrap()
    }
}

unsafe extern "C" fn busy_get(_peer: *mut ngx_peer_connection_t, _data: *mut c_void) -> ngx_int_t {
    NGX_BUSY as _
}

unsafe extern "C" fn declined_get(
    _peer: *mut ngx_peer_connection_t,
    _data: *mut c_void,
) -> ngx_int_t {
    NGX_DECLINED as _
}

unsafe extern "C" fn error_get(_peer: *mut ngx_peer_connection_t, _data: *mut c_void) -> ngx_int_t {
    NGX_ERROR as _
}

unsafe extern "C" fn done_get(peer: *mut ngx_peer_connection_t, data: *mut c_void) -> ngx_int_t {
    let state = unsafe { &mut *data.cast::<CallbackState>() };
    unsafe { (*peer).connection = state.connection };
    NGX_DONE as _
}

unsafe extern "C" fn again_get(_peer: *mut ngx_peer_connection_t, _data: *mut c_void) -> ngx_int_t {
    NGX_AGAIN as _
}

unsafe extern "C" fn selected_get(
    _peer: *mut ngx_peer_connection_t,
    _data: *mut c_void,
) -> ngx_int_t {
    NGX_OK as _
}

#[derive(Default)]
struct CallbackState {
    connection: *mut ngx_connection_t,
    free_count: usize,
    free_state: ngx_uint_t,
    notify_count: usize,
    notify_type: ngx_uint_t,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    set_session_count: usize,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    save_session_count: usize,
}

unsafe extern "C" fn record_free(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
    state: ngx_uint_t,
) {
    let callback = unsafe { &mut *data.cast::<CallbackState>() };
    callback.free_count += 1;
    callback.free_state = state;
    unsafe { (*peer).connection = ptr::null_mut() };
}

unsafe extern "C" fn record_notify(
    _peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
    type_: ngx_uint_t,
) {
    let callback = unsafe { &mut *data.cast::<CallbackState>() };
    callback.notify_count += 1;
    callback.notify_type = type_;
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
unsafe extern "C" fn record_set_session(
    _peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
) -> ngx_int_t {
    let callback = unsafe { &mut *data.cast::<CallbackState>() };
    callback.set_session_count += 1;
    NGX_OK as _
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
unsafe extern "C" fn record_save_session(_peer: *mut ngx_peer_connection_t, data: *mut c_void) {
    let callback = unsafe { &mut *data.cast::<CallbackState>() };
    callback.save_session_count += 1;
}

unsafe extern "C" fn add_event_ok(
    event: *mut ngx_event_t,
    _kind: ngx_int_t,
    _flags: ngx_uint_t,
) -> ngx_int_t {
    unsafe { (*event).set_active(1) };
    EVENT_ADD_CALLS.fetch_add(1, Ordering::Relaxed);
    NGX_OK as _
}

unsafe extern "C" fn add_event_error(
    _event: *mut ngx_event_t,
    _kind: ngx_int_t,
    _flags: ngx_uint_t,
) -> ngx_int_t {
    NGX_ERROR as _
}

unsafe extern "C" fn delete_event_ok(
    event: *mut ngx_event_t,
    _kind: ngx_int_t,
    _flags: ngx_uint_t,
) -> ngx_int_t {
    unsafe { (*event).set_active(0) };
    NGX_OK as _
}

unsafe extern "C" fn active_read_handler(_event: *mut ngx_event_t) {
    EVENT_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn active_write_handler(_event: *mut ngx_event_t) {
    EVENT_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn idle_read_handler(_event: *mut ngx_event_t) {
    EVENT_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn idle_write_handler(_event: *mut ngx_event_t) {
    EVENT_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn idle_peek_handler(event: *mut ngx_event_t) {
    let connection = unsafe { (*event).data.cast::<ngx_connection_t>().as_ref() }.unwrap();
    let mut byte = 0_u8;
    let result = unsafe {
        libc::recv(connection.fd, (&raw mut byte).cast(), 1, libc::MSG_DONTWAIT | libc::MSG_PEEK)
    };
    IDLE_PEEK_RESULT.store(result as _, Ordering::Relaxed);
}

fn test_event_handlers(
    read: unsafe extern "C" fn(*mut ngx_event_t),
    write: unsafe extern "C" fn(*mut ngx_event_t),
) -> EventPeerHandlers {
    // SAFETY: test handlers accept every fixture event, ignore event data, and do not unwind or
    // invalidate their fixture owner.
    unsafe { EventPeerHandlers::new(read, write) }
}

fn test_keepalive_preparation<'log>(log: LogRef<'log>) -> EventPeerPreparation<'log> {
    EventPeerPreparation::new(
        log,
        test_event_handlers(idle_read_handler, idle_write_handler),
        EVENT_PEER_MIN_POOL_SIZE,
    )
}

fn same_event_handler(
    actual: ngx_event_handler_pt,
    expected: unsafe extern "C" fn(*mut ngx_event_t),
) -> bool {
    matches!(actual, Some(actual) if core::ptr::fn_addr_eq(actual, expected))
}

fn wait_for_writable_socket(fd: c_int) {
    let mut descriptor = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    assert_eq!(unsafe { libc::poll(&raw mut descriptor, 1, 1_000) }, 1);
}

fn wait_for_readable_socket(fd: c_int) {
    let mut descriptor = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    assert_eq!(unsafe { libc::poll(&raw mut descriptor, 1, 1_000) }, 1);
}

fn reject_keepalive_reuse<'address, 'log>(
    keepalive: EventPeerKeepalive<'address, 'log>,
    expected: EventPeerConnectionError,
) -> EventPeerKeepalive<'address, 'log> {
    let log: LogRef<'log> =
        unsafe { LogRef::from_raw(keepalive.peer.raw.log) }.expect("keepalive logger");
    match keepalive.into_connection(log) {
        Err(EventPeerKeepaliveIntoConnectionError::Connection { error, keepalive }) => {
            assert_eq!(error, expected);
            keepalive
        }
        Ok(connection) => panic!("reused a terminal keepalive connection: {connection:?}"),
    }
}

fn build_peer<'peer>(
    address: EventPeerAddress<'peer>,
    log: *mut ngx_log_t,
    callbacks: EventPeerCallbacks,
) -> EventPeer<'peer, 'peer> {
    let log = unsafe { LogRef::from_raw(log) }.unwrap();
    EventPeerBuilder::new(address).log(log).callbacks(callbacks).build().unwrap()
}

fn build_datagram_peer<'peer>(
    address: EventPeerAddress<'peer>,
    log: *mut ngx_log_t,
    callbacks: EventPeerCallbacks,
) -> EventPeer<'peer, 'peer> {
    let log = unsafe { LogRef::from_raw(log) }.unwrap();
    EventPeerBuilder::new(address)
        .log(log)
        .callbacks(callbacks)
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap()
}

fn connected_peer<'address, 'log>(
    result: EventPeerConnectResult<'address, 'log>,
) -> EventPeerConnection<'address, 'log> {
    match result {
        EventPeerConnectResult::Connected(connection)
        | EventPeerConnectResult::Reused(connection) => connection,
        result => panic!("expected connected peer, got {result:?}"),
    }
}

fn pending_peer<'address, 'log>(
    result: EventPeerConnectResult<'address, 'log>,
) -> EventPeerPendingConnection<'address, 'log> {
    match result {
        EventPeerConnectResult::Pending(connection) => connection,
        result => panic!("expected pending peer, got {result:?}"),
    }
}

fn ready_peer<'address, 'log>(
    result: EventPeerConnectResult<'address, 'log>,
) -> EventPeerConnection<'address, 'log> {
    match result {
        EventPeerConnectResult::Connected(connection)
        | EventPeerConnectResult::Reused(connection) => connection,
        EventPeerConnectResult::Pending(connection) => {
            let raw = connection.peer.raw.connection;
            let fd = unsafe { (*raw).fd };
            wait_for_writable_socket(fd);
            unsafe { (*raw).write.as_mut().unwrap().set_ready(1) };
            connection.connect_ready().unwrap().complete().unwrap()
        }
        result => panic!("expected live peer, got {result:?}"),
    }
}

fn detached_peer<'address, 'log>(
    result: EventPeerConnectResult<'address, 'log>,
) -> EventPeer<'address, 'log> {
    match result {
        EventPeerConnectResult::SelectionPending(peer)
        | EventPeerConnectResult::Busy(peer)
        | EventPeerConnectResult::Declined(peer)
        | EventPeerConnectResult::Error(peer) => peer,
        result => panic!("expected detached peer, got {result:?}"),
    }
}

#[test]
fn builder_requires_valid_address_and_log() {
    let mut socket: sockaddr_in = unsafe { mem::zeroed() };
    socket.sin_family = libc::AF_INET as _;
    socket.sin_port = 8443_u16.to_be();
    socket.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 10]);
    let address = ngx_addr_t {
        sockaddr: (&raw mut socket).cast(),
        socklen: size_of::<sockaddr_in>() as _,
        name: ngx_str_t { len: 4, data: c"peer".as_ptr().cast_mut() },
    };
    let address = unsafe { EventPeerAddress::from_raw(&raw const address) }.unwrap();
    let mut log: ngx_log_t = unsafe { mem::zeroed() };
    let log = unsafe { LogRef::from_raw(&raw mut log) }.unwrap();

    assert!(matches!(EventPeerBuilder::new(address).build(), Err(EventPeerBuildError::MissingLog)));
    assert!(matches!(
        EventPeerBuilder::new(address).log(log).build(),
        Err(EventPeerBuildError::MissingGetCallback)
    ));

    assert!(matches!(
        unsafe { EventPeerBuilder::new(address).log_from_raw(ptr::null_mut()) },
        Err(EventPeerBuildError::MissingLog)
    ));
    assert!(matches!(
        unsafe {
            EventPeerBuilder::new(address).log_from_raw(ptr::without_provenance_mut::<ngx_log_t>(1))
        },
        Err(EventPeerBuildError::MisalignedLog)
    ));
}

#[test]
fn peer_address_rejects_invalid_native_storage() {
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(ptr::null()) },
        Err(EventPeerAddressError::NullAddress)
    );
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(ptr::without_provenance(1)) },
        Err(EventPeerAddressError::MisalignedAddress)
    );

    let mut address: ngx_addr_t = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(&raw const address) },
        Err(EventPeerAddressError::SocketAddress(SocketAddressError::NullAddress))
    );

    let mut socket: sockaddr_in = unsafe { mem::zeroed() };
    socket.sin_family = libc::AF_INET as _;
    address.sockaddr = (&raw mut socket).cast();
    address.socklen = size_of::<sockaddr_in>() as _;
    address.name = ngx_str_t { len: 1, data: ptr::null_mut() };
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(&raw const address) },
        Err(EventPeerAddressError::MissingName)
    );

    address.name.len = isize::MAX as usize + 1;
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(&raw const address) },
        Err(EventPeerAddressError::NameTooLong)
    );
}

#[test]
fn builder_initializes_every_configured_peer_field() {
    let remote = TestAddress::ipv4([192, 0, 2, 10], 8443);
    let local = TestAddress::ipv4([198, 51, 100, 20], 443);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut state = CallbackState::default();
    let callbacks = unsafe {
        EventPeerCallbacks::default().get(busy_get).free(record_free).notify(record_notify)
    };
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    let callbacks =
        unsafe { callbacks.set_session(record_set_session).save_session(record_save_session) };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(callbacks)
        .local_address(local.peer_address())
        .tries(ngx_uint_t::MAX)
        .start_time(37)
        .socket_type(SocketType::Datagram)
        .receive_buffer(1024)
        .unwrap()
        .cached(true)
        .transparent(true)
        .keepalive(true)
        .down(true)
        .log_error(EventPeerLogError::Info);
    let mut peer = unsafe { peer.data((&raw mut state).cast()) }.build().unwrap();
    let raw = &mut peer.raw;

    assert!(raw.connection.is_null());
    assert_eq!(raw.sockaddr, remote.raw.sockaddr);
    assert_eq!(raw.socklen, remote.raw.socklen);
    assert_eq!(raw.name, core::ptr::addr_of!(remote.raw.name).cast_mut());
    assert_eq!(raw.tries, ngx_uint_t::MAX);
    assert_eq!(raw.start_time, 37);
    assert!(raw.get.is_some());
    assert!(raw.free.is_some());
    assert!(raw.notify.is_some());
    assert_eq!(raw.data, (&raw mut state).cast());
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    {
        assert!(raw.set_session.is_some());
        assert!(raw.save_session.is_some());
    }
    assert_eq!(raw.local, (&raw const local.raw).cast_mut());
    assert_eq!(raw.type_, libc::SOCK_DGRAM);
    assert_eq!(raw.rcvbuf, 1024);
    assert_eq!(raw.log, (&raw const log).cast_mut());
    #[cfg(any(ngx_feature = "http_upstream_sid", ngx_feature = "compat"))]
    {
        assert!(raw.hint.is_null());
        assert!(raw.sid.is_null());
    }
    #[cfg(ngx_feature = "have_bindtodevice")]
    assert!(raw.device.is_null());
    #[cfg(ngx_feature = "have_so_mark")]
    assert_eq!(raw.so_mark, 0);
    assert_eq!(raw.cached(), 1);
    assert_eq!(raw.transparent(), 1);
    assert_eq!(raw.so_keepalive(), 1);
    assert_eq!(raw.down(), 1);
    assert_eq!(raw.log_error(), EventPeerLogError::Info.raw());
}

#[test]
fn peer_address_accepts_ipv4_ipv6_and_unix_storage() {
    let ipv4 = TestAddress::ipv4([192, 0, 2, 10], 8443);
    let peer_address = ipv4.peer_address();
    let address = peer_address.socket_address().unwrap();
    assert_eq!(address.ipv4_octets(), Some([192, 0, 2, 10]));

    let mut ipv6: sockaddr_in6 = unsafe { mem::zeroed() };
    ipv6.sin6_family = libc::AF_INET6 as _;
    ipv6.sin6_addr.__in6_u.__u6_addr8 =
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut name = *b"ipv6";
    let ipv6 = ngx_addr_t {
        sockaddr: (&raw mut ipv6).cast(),
        socklen: size_of::<sockaddr_in6>() as _,
        name: ngx_str_t { len: name.len(), data: name.as_mut_ptr() },
    };
    let peer_address = unsafe { EventPeerAddress::from_raw(&raw const ipv6) }.unwrap();
    let address = peer_address.socket_address().unwrap();
    assert_eq!(
        address.ipv6_octets(),
        Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );

    #[cfg(unix)]
    {
        let unix = TestUnixAddress::invalid_path();
        let peer_address = unix.peer_address();
        let address = peer_address.socket_address().unwrap();
        assert_eq!(address.unix_path().unwrap(), b"/dev/null/ngx-rust-peer\0");
    }

    let mut socket: sockaddr_in = unsafe { mem::zeroed() };
    socket.sin_family = libc::AF_INET as _;
    let empty_name = ngx_addr_t {
        sockaddr: (&raw mut socket).cast(),
        socklen: size_of::<sockaddr_in>() as _,
        name: ngx_str_t { len: 0, data: ptr::null_mut() },
    };
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(&raw const empty_name) }
            .unwrap()
            .name()
            .unwrap()
            .as_bytes(),
        b""
    );
}

#[test]
fn peer_address_rejects_socket_length_and_family_mismatches() {
    let mut ipv4: sockaddr_in = unsafe { mem::zeroed() };
    ipv4.sin_family = libc::AF_INET as _;
    let address = ngx_addr_t {
        sockaddr: (&raw mut ipv4).cast(),
        socklen: (size_of::<sockaddr_in>() - 1) as _,
        name: ngx_str_t { len: 4, data: c"peer".as_ptr().cast_mut() },
    };
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(&raw const address) },
        Err(EventPeerAddressError::SocketAddress(SocketAddressError::InvalidLength))
    );

    let mut ipv6: sockaddr_in6 = unsafe { mem::zeroed() };
    ipv6.sin6_family = libc::AF_INET6 as _;
    let address = ngx_addr_t {
        sockaddr: (&raw mut ipv6).cast(),
        socklen: size_of::<sockaddr_in>() as _,
        name: ngx_str_t { len: 4, data: c"peer".as_ptr().cast_mut() },
    };
    assert_eq!(
        unsafe { EventPeerAddress::from_raw(&raw const address) },
        Err(EventPeerAddressError::SocketAddress(SocketAddressError::InvalidLength))
    );
}

#[test]
fn builder_defaults_to_a_fresh_stream_peer() {
    let remote = TestAddress::ipv4([192, 0, 2, 10], 8443);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    let raw = &peer.raw;

    assert!(raw.connection.is_null());
    assert_eq!(raw.tries, 0);
    assert_eq!(raw.start_time, 0);
    assert!(raw.free.is_none());
    assert!(raw.notify.is_none());
    assert!(raw.data.is_null());
    assert!(raw.local.is_null());
    assert_eq!(raw.type_, libc::SOCK_STREAM);
    assert_eq!(raw.rcvbuf, 0);
    assert_eq!(raw.cached(), 0);
    assert_eq!(raw.transparent(), 0);
    assert_eq!(raw.so_keepalive(), 0);
    assert_eq!(raw.down(), 0);
    assert_eq!(raw.log_error(), EventPeerLogError::Alert.raw());
    #[cfg(any(ngx_feature = "http_upstream_sid", ngx_feature = "compat"))]
    {
        assert!(raw.hint.is_null());
        assert!(raw.sid.is_null());
    }
    #[cfg(ngx_feature = "have_bindtodevice")]
    assert!(raw.device.is_null());
    #[cfg(ngx_feature = "have_so_mark")]
    assert_eq!(raw.so_mark, 0);
}

#[test]
fn cached_selection_dispatches_callbacks_and_releases_once() {
    let remote = TestAddress::ipv4([192, 0, 2, 10], 8443);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut read: ngx_event_t = unsafe { mem::zeroed() };
    let mut write: ngx_event_t = unsafe { mem::zeroed() };
    let mut connection: ngx_connection_t = unsafe { mem::zeroed() };
    connection.read = &raw mut read;
    connection.write = &raw mut write;
    let mut state = CallbackState { connection: &raw mut connection, ..Default::default() };
    let callbacks = unsafe {
        EventPeerCallbacks::default().get(done_get).free(record_free).notify(record_notify)
    };
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    let callbacks =
        unsafe { callbacks.set_session(record_set_session).save_session(record_save_session) };
    let peer = unsafe {
        EventPeerBuilder::new(remote.peer_address())
            .log(LogRef::from_raw((&raw const log).cast_mut()).unwrap())
            .callbacks(callbacks)
            .data((&raw mut state).cast())
            .build()
            .unwrap()
    };

    let mut connection = match peer.connect().unwrap() {
        EventPeerConnectResult::Reused(connection) => connection,
        result => panic!("unexpected connect result: {result:?}"),
    };
    assert!(connection.notify(17));
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    {
        assert_eq!(connection.set_session(), Some(NGX_OK as _));
        assert!(connection.save_session());
    }
    connection.release(EventPeerReleaseState::NEXT.union(EventPeerReleaseState::FAILED));

    assert_eq!(state.free_count, 1);
    assert_eq!(state.free_state, 6);
    assert_eq!(state.notify_count, 1);
    assert_eq!(state.notify_type, 17);
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    {
        assert_eq!(state.set_session_count, 1);
        assert_eq!(state.save_session_count, 1);
    }
}

#[test]
fn selected_peer_drop_releases_with_failed_state_once() {
    let globals = PeerGlobals::new(false, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut state = CallbackState::default();
    let peer = unsafe {
        EventPeerBuilder::new(remote.peer_address())
            .log(LogRef::from_raw((&raw const log).cast_mut()).unwrap())
            .callbacks(EventPeerCallbacks::default().get(selected_get).free(record_free))
            .data((&raw mut state).cast())
            .build()
            .unwrap()
    };

    let result = peer.connect().unwrap();
    assert_eq!(result.status(), EventPeerConnectStatus::Error);
    drop(result);

    assert_eq!(state.free_count, 1);
    assert_eq!(state.free_state, EventPeerReleaseState::FAILED.0);
    assert_eq!(globals.free_connection_n(), 0);
}

#[test]
fn unselected_callback_statuses_do_not_release_peer() {
    let globals = PeerGlobals::new(false, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };

    for (get, expected) in [
        (busy_get as PeerGet, EventPeerConnectStatus::Busy),
        (again_get as PeerGet, EventPeerConnectStatus::SelectionPending),
    ] {
        let mut state = CallbackState::default();
        let peer = unsafe {
            EventPeerBuilder::new(remote.peer_address())
                .log(LogRef::from_raw((&raw const log).cast_mut()).unwrap())
                .callbacks(EventPeerCallbacks::default().get(get).free(record_free))
                .data((&raw mut state).cast())
                .build()
                .unwrap()
        };
        let result = peer.connect().unwrap();
        assert_eq!(result.status(), expected);
        drop(result);
        assert_eq!(state.free_count, 0);
    }

    assert_eq!(globals.free_connection_n(), 0);
}

#[test]
fn builder_rejects_a_negative_receive_buffer() {
    let remote = TestAddress::ipv4([192, 0, 2, 10], 8443);
    assert!(matches!(
        EventPeerBuilder::new(remote.peer_address()).receive_buffer(-1),
        Err(EventPeerBuildError::NegativeReceiveBuffer)
    ));
}

#[test]
fn connect_preserves_unselected_callback_statuses() {
    let remote = TestAddress::ipv4([192, 0, 2, 10], 8443);
    let log: ngx_log_t = unsafe { mem::zeroed() };

    for (get, status) in [
        (busy_get as PeerGet, EventPeerConnectStatus::Busy),
        (declined_get as PeerGet, EventPeerConnectStatus::Declined),
        (error_get as PeerGet, EventPeerConnectStatus::Error),
    ] {
        let peer = build_peer(remote.peer_address(), (&raw const log).cast_mut(), unsafe {
            EventPeerCallbacks::default().get(get)
        });
        let result = peer.connect().unwrap();
        assert_eq!(result.status(), status);
        assert!(detached_peer(result).raw.connection.is_null());
    }
}

#[test]
fn connect_rejects_unknown_or_empty_success_results() {
    let remote = TestAddress::ipv4([192, 0, 2, 10], 8443);
    let log: ngx_log_t = unsafe { mem::zeroed() };

    for (native_status, expected_status) in [
        (NGX_OK as ngx_int_t, EventPeerConnectStatus::Connected),
        (NGX_AGAIN as ngx_int_t, EventPeerConnectStatus::Pending),
    ] {
        let peer = build_peer(
            remote.peer_address(),
            (&raw const log).cast_mut(),
            EventPeerCallbacks::direct(),
        );
        match peer.classify_connect(native_status) {
            Err(EventPeerConnectError::MissingConnection { status, peer }) => {
                assert_eq!(status, expected_status);
                assert!(peer.raw.connection.is_null());
            }
            result => panic!("unexpected connect result: {result:?}"),
        }
    }

    let mut peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    peer.raw.connection = ptr::without_provenance_mut::<ngx_connection_t>(1);
    match peer.classify_connect(NGX_OK as _) {
        Err(EventPeerConnectError::MisalignedConnection { status, peer }) => {
            assert_eq!(status, EventPeerConnectStatus::Connected);
            assert!(peer.raw.connection.is_null());
        }
        result => panic!("unexpected connect result: {result:?}"),
    }

    let mut invalid_connection = unsafe { mem::zeroed::<ngx_connection_t>() };
    let mut peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    peer.raw.connection = &raw mut invalid_connection;
    match peer.classify_connect(NGX_OK as _) {
        Err(EventPeerConnectError::InvalidConnection { status, error, peer }) => {
            assert_eq!(status, EventPeerConnectStatus::Connected);
            assert!(matches!(error, EventPeerConnectionError::Event(EventError::NullEvent)));
            assert!(peer.raw.connection.is_null());
        }
        result => panic!("unexpected connect result: {result:?}"),
    }
}

#[test]
fn native_datagram_connect_transfers_and_releases_connection() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let result = peer.connect().unwrap();
    assert_eq!(result.status(), EventPeerConnectStatus::Connected);

    let mut connection = match result {
        EventPeerConnectResult::Connected(connection) => connection,
        result => panic!("expected connected peer, got {result:?}"),
    };
    connection
        .with_connection(|mut connection| {
            assert!(same_event_handler(
                unsafe { connection.read_event().unwrap().as_ptr().as_ref().unwrap().handler },
                inert_event_handler,
            ));
            assert!(same_event_handler(
                unsafe { connection.write_event().unwrap().as_ptr().as_ref().unwrap().handler },
                inert_event_handler,
            ));
        })
        .unwrap();
    drop(connection);
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn native_stream_connect_returns_pending_connection() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let remote = TestAddress::ipv4([127, 0, 0, 1], port);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let result = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    )
    .connect()
    .unwrap();
    assert_eq!(result.status(), EventPeerConnectStatus::Pending);

    let peer = pending_peer(result);
    let connection = unsafe { peer.peer.raw.connection.as_ref() }.unwrap();
    assert!(same_event_handler(unsafe { (*connection.read).handler }, inert_event_handler));
    assert!(same_event_handler(unsafe { (*connection.write).handler }, inert_event_handler));
    drop(peer);
    assert_eq!(globals.free_connection_n(), 1);
    drop(listener);
}

#[test]
fn native_connect_allocation_failure_keeps_peer_detached() {
    let globals = PeerGlobals::new(false, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let result = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    )
    .connect()
    .unwrap();
    assert_eq!(result.status(), EventPeerConnectStatus::Error);
    assert!(detached_peer(result).raw.connection.is_null());
    assert_eq!(globals.free_connection_n(), 0);
}

#[test]
fn native_connect_event_registration_failure_closes_connection() {
    let globals = PeerGlobals::new(true, add_event_error);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let result = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    )
    .connect()
    .unwrap();
    assert_eq!(result.status(), EventPeerConnectStatus::Error);
    assert!(detached_peer(result).raw.connection.is_null());
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn invalid_failure_status_detaches_a_native_connection() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    assert_eq!(unsafe { ngx_event_connect_peer(&raw mut peer.raw) }, NGX_OK as _);
    assert!(!peer.raw.connection.is_null());
    let connection = peer.raw.connection;

    match peer.classify_connect(NGX_ERROR as _) {
        Err(EventPeerConnectError::ConnectionOnFailure { status, peer }) => {
            assert_eq!(status, EventPeerConnectStatus::Error);
            assert!(peer.raw.connection.is_null());
        }
        result => panic!("unexpected connect result: {result:?}"),
    }
    assert_eq!(globals.free_connection_n(), 0);
    unsafe { ngx_close_connection(connection) };
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn done_status_reuses_the_selected_native_connection() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    assert_eq!(unsafe { ngx_event_connect_peer(&raw mut peer.raw) }, NGX_OK as _);
    assert!(!peer.raw.connection.is_null());
    let connection = peer.raw.connection;

    let peer = match peer.classify_connect(NGX_DONE as _).unwrap() {
        EventPeerConnectResult::Reused(peer) => peer,
        result => panic!("unexpected connect result: {result:?}"),
    };
    assert_eq!(peer.peer.raw.connection, connection);
    drop(peer);
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn connected_peer_prepares_transfers_and_closes_socket_pool_and_events() {
    let mut globals = PeerGlobals::new(true, add_event_ok);
    unsafe {
        assert_eq!(ngx_event_timer_init(ptr::null_mut()), NGX_OK as _);
        ngx_current_msec = 0;
    }
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let request_log: ngx_log_t = unsafe { mem::zeroed() };
    let idle_log: ngx_log_t = unsafe { mem::zeroed() };
    let next_log: ngx_log_t = unsafe { mem::zeroed() };
    let mut request_data = 1_u8;
    let mut idle_data = 2_u8;
    EVENT_HANDLER_CALLS.store(0, Ordering::Relaxed);

    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const request_log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let mut connection = connected_peer(peer.connect().unwrap());
    let request_preparation = unsafe {
        EventPeerPreparation::new(
            LogRef::from_raw((&raw const request_log).cast_mut()).unwrap(),
            test_event_handlers(active_read_handler, active_write_handler),
            128,
        )
        .data((&raw mut request_data).cast())
    };
    connection.prepare(request_preparation).unwrap();

    let raw = connection.peer.raw.connection;
    let raw = unsafe { raw.as_mut() }.unwrap();
    assert!(!raw.pool.is_null());
    assert_eq!(raw.log, (&raw const request_log).cast_mut());
    assert_eq!(unsafe { (*raw.pool).log }, (&raw const request_log).cast_mut());
    assert_eq!(raw.data, (&raw mut request_data).cast());
    assert_eq!(raw.idle(), 0);
    assert!(same_event_handler(unsafe { raw.read.as_ref().unwrap().handler }, active_read_handler));
    assert!(same_event_handler(
        unsafe { raw.write.as_ref().unwrap().handler },
        active_write_handler
    ));

    connection
        .with_connection(|mut connection| unsafe {
            // SAFETY: EventPeer owns this live native connection and cancels both timers before
            // transitioning or closing it.
            connection.read_event().unwrap().add_timer(7);
            connection.write_event().unwrap().add_timer(11);
        })
        .unwrap();
    assert!(unsafe { raw.read.as_ref().unwrap().timer_set() != 0 });
    assert!(unsafe { raw.write.as_ref().unwrap().timer_set() != 0 });

    unsafe {
        raw.read.as_mut().unwrap().set_active(0);
        raw.read.as_mut().unwrap().set_ready(0);
    }
    let add_calls = EVENT_ADD_CALLS.load(Ordering::Relaxed);
    let idle_preparation = unsafe {
        EventPeerPreparation::new(
            LogRef::from_raw((&raw const idle_log).cast_mut()).unwrap(),
            test_event_handlers(idle_read_handler, idle_write_handler),
            0,
        )
        .data((&raw mut idle_data).cast())
    };
    let keepalive = connection.into_keepalive(idle_preparation).unwrap();
    assert_eq!(EVENT_ADD_CALLS.load(Ordering::Relaxed), add_calls + 1);
    assert!(unsafe { raw.read.as_ref().unwrap().timer_set() == 0 });
    assert!(unsafe { raw.write.as_ref().unwrap().timer_set() == 0 });
    assert!(unsafe { raw.read.as_ref().unwrap().active() != 0 });
    assert_eq!(raw.log, (&raw const idle_log).cast_mut());
    assert_eq!(keepalive.peer.raw.log, (&raw const idle_log).cast_mut());
    assert_eq!(unsafe { (*raw.pool).log }, (&raw const idle_log).cast_mut());
    assert_eq!(raw.data, (&raw mut idle_data).cast());
    assert_eq!(raw.idle(), 1);
    assert!(same_event_handler(unsafe { raw.read.as_ref().unwrap().handler }, idle_read_handler));
    assert!(same_event_handler(unsafe { raw.write.as_ref().unwrap().handler }, idle_write_handler));
    keepalive.validate().unwrap();
    unsafe { crate::ffi::ngx_add_timer(raw.read, 13) };
    assert!(unsafe { raw.read.as_ref().unwrap().timer_set() != 0 });

    let borrowed = keepalive
        .into_connection(unsafe { LogRef::from_raw((&raw const next_log).cast_mut()).unwrap() })
        .unwrap();
    assert_eq!(raw.idle(), 0);
    assert!(raw.data.is_null());
    assert_eq!(borrowed.peer.raw.log, (&raw const next_log).cast_mut());
    #[cfg(feature = "async")]
    assert_eq!(borrowed.readiness_log().as_ptr(), (&raw const next_log).cast_mut());
    assert_eq!(raw.log, (&raw const next_log).cast_mut());
    assert_eq!(unsafe { (*raw.read).log }, (&raw const next_log).cast_mut());
    assert_eq!(unsafe { (*raw.write).log }, (&raw const next_log).cast_mut());
    assert_eq!(unsafe { (*raw.pool).log }, (&raw const next_log).cast_mut());
    unsafe { globals._read.handler.unwrap()(&raw mut *globals._read) };
    unsafe { globals._write.handler.unwrap()(&raw mut *globals._write) };
    assert_eq!(EVENT_HANDLER_CALLS.load(Ordering::Relaxed), 0);
    drop(borrowed);

    assert_eq!(globals.free_connection_n(), 1);
    assert!(globals._connection.pool.is_null());
    assert!(globals._read.timer_set() == 0);
    unsafe { globals._read.handler.unwrap()(&raw mut *globals._read) };
    unsafe { globals._write.handler.unwrap()(&raw mut *globals._write) };
    assert_eq!(EVENT_HANDLER_CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn keepalive_validation_rejects_error_eof_and_readable_connections() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let keepalive = connected_peer(peer.connect().unwrap())
        .into_keepalive(test_keepalive_preparation(unsafe {
            LogRef::from_raw((&raw const log).cast_mut()).unwrap()
        }))
        .unwrap();
    let raw = keepalive.peer.raw.connection;
    let raw = unsafe { raw.as_mut() }.unwrap();

    raw.set_error(1);
    assert_eq!(keepalive.validate(), Err(EventPeerConnectionError::StaleConnectionError));
    raw.set_error(0);

    unsafe { raw.read.as_mut().unwrap().set_eof(1) };
    assert_eq!(keepalive.validate(), Err(EventPeerConnectionError::StaleReadEndOfFile));
    unsafe { raw.read.as_mut().unwrap().set_eof(0) };

    unsafe { raw.read.as_mut().unwrap().set_ready(1) };
    assert_eq!(keepalive.validate(), Err(EventPeerConnectionError::StaleReadReady));
    unsafe { raw.read.as_mut().unwrap().set_ready(0) };
    keepalive.validate().unwrap();
}

#[test]
fn keepalive_reuse_rejects_every_terminal_flag_without_advisory_validation() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let mut keepalive = connected_peer(peer.connect().unwrap())
        .into_keepalive(test_keepalive_preparation(unsafe {
            LogRef::from_raw((&raw const log).cast_mut()).unwrap()
        }))
        .unwrap();
    let raw = keepalive.peer.raw.connection;

    unsafe { (*raw).set_error(1) };
    keepalive = reject_keepalive_reuse(keepalive, EventPeerConnectionError::StaleConnectionError);
    unsafe { (*raw).set_error(0) };

    unsafe { (*raw).read.as_mut().unwrap().set_eof(1) };
    keepalive = reject_keepalive_reuse(keepalive, EventPeerConnectionError::StaleReadEndOfFile);
    unsafe { (*raw).read.as_mut().unwrap().set_eof(0) };

    unsafe { (*raw).read.as_mut().unwrap().set_error(1) };
    keepalive = reject_keepalive_reuse(keepalive, EventPeerConnectionError::StaleReadError);
    unsafe { (*raw).read.as_mut().unwrap().set_error(0) };

    unsafe { (*raw).read.as_mut().unwrap().set_timedout(1) };
    keepalive = reject_keepalive_reuse(keepalive, EventPeerConnectionError::StaleReadTimedOut);
    unsafe { (*raw).read.as_mut().unwrap().set_timedout(0) };

    unsafe { (*raw).write.as_mut().unwrap().set_error(1) };
    keepalive = reject_keepalive_reuse(keepalive, EventPeerConnectionError::StaleWriteError);
    unsafe { (*raw).write.as_mut().unwrap().set_error(0) };

    unsafe { (*raw).write.as_mut().unwrap().set_timedout(1) };
    keepalive = reject_keepalive_reuse(keepalive, EventPeerConnectionError::StaleWriteTimedOut);
    unsafe { (*raw).write.as_mut().unwrap().set_timedout(0) };

    unsafe { (*raw).read.as_mut().unwrap().set_ready(1) };
    keepalive = reject_keepalive_reuse(keepalive, EventPeerConnectionError::StaleReadReady);
    unsafe { (*raw).read.as_mut().unwrap().set_ready(0) };

    keepalive
        .into_connection(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .unwrap();
}

#[test]
fn keepalive_stale_state_reports_all_native_bits() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let keepalive = connected_peer(peer.connect().unwrap())
        .into_keepalive(test_keepalive_preparation(unsafe {
            LogRef::from_raw((&raw const log).cast_mut()).unwrap()
        }))
        .unwrap();
    let raw = keepalive.peer.raw.connection;
    let raw = unsafe { raw.as_mut() }.unwrap();

    raw.set_error(1);
    unsafe {
        raw.read.as_mut().unwrap().set_eof(1);
        raw.read.as_mut().unwrap().set_error(1);
        raw.read.as_mut().unwrap().set_timedout(1);
        raw.read.as_mut().unwrap().set_ready(1);
        raw.write.as_mut().unwrap().set_error(1);
        raw.write.as_mut().unwrap().set_timedout(1);
    }

    assert_eq!(
        keepalive.stale_state(),
        Ok(EventPeerKeepaliveState {
            connection_error: true,
            read_eof: true,
            read_error: true,
            read_timed_out: true,
            write_error: true,
            write_timed_out: true,
            read_ready: true,
        })
    );
    assert_eq!(keepalive.validate(), Err(EventPeerConnectionError::StaleConnectionError));
}

#[test]
fn keepalive_storage_rejects_terminal_state_before_publication() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let connection = connected_peer(peer.connect().unwrap());
    let raw = connection.peer.raw.connection;
    unsafe { (*raw).write.as_mut().unwrap().set_timedout(1) };

    match connection.into_keepalive(test_keepalive_preparation(unsafe {
        LogRef::from_raw((&raw const log).cast_mut()).unwrap()
    })) {
        Err(EventPeerKeepaliveTransferError::Connection { error, connection: _ }) => {
            assert_eq!(error, EventPeerConnectionError::StaleWriteTimedOut);
            assert_eq!(unsafe { (*raw).idle() }, 0);
        }
        result => panic!("unexpected keepalive storage result: {result:?}"),
    }
}

#[test]
fn keepalive_read_registration_failure_rolls_back_to_active_owner() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let idle_log: ngx_log_t = unsafe { mem::zeroed() };
    let mut idle_data = 1_u8;
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let connection = connected_peer(peer.connect().unwrap());
    let raw = connection.peer.raw.connection;
    unsafe {
        (*raw).read.as_mut().unwrap().set_active(0);
        (*raw).read.as_mut().unwrap().set_ready(0);
        ngx_event_actions.add = Some(add_event_error);
    }
    let preparation = unsafe {
        test_keepalive_preparation(LogRef::from_raw((&raw const idle_log).cast_mut()).unwrap())
            .data((&raw mut idle_data).cast())
    };

    match connection.into_keepalive(preparation) {
        Err(EventPeerKeepaliveTransferError::Connection { error, connection }) => {
            assert_eq!(error, EventPeerConnectionError::ReadEventRegistration);
            assert_eq!(unsafe { (*raw).idle() }, 0);
            assert!(unsafe { (*raw).data.is_null() });
            assert_eq!(connection.peer.raw.log, (&raw const log).cast_mut());
            assert_eq!(unsafe { (*raw).log }, (&raw const log).cast_mut());
            assert_eq!(unsafe { (*(*raw).read).log }, (&raw const log).cast_mut());
            assert_eq!(unsafe { (*(*raw).write).log }, (&raw const log).cast_mut());
            assert_eq!(unsafe { (*(*raw).pool).log }, (&raw const log).cast_mut());
            assert!(same_event_handler(unsafe { (*(*raw).read).handler }, inert_event_handler,));
            assert!(same_event_handler(unsafe { (*(*raw).write).handler }, inert_event_handler,));
        }
        result => panic!("unexpected keepalive registration result: {result:?}"),
    }
}

#[test]
fn registered_idle_handler_observes_real_unread_data_and_eof() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    let connection = ready_peer(peer.connect().unwrap());
    let fd = unsafe { (*connection.peer.raw.connection).fd };
    let (mut server, _) = listener.accept().unwrap();
    let preparation = EventPeerPreparation::new(
        unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() },
        test_event_handlers(idle_peek_handler, idle_write_handler),
        EVENT_PEER_MIN_POOL_SIZE,
    );
    IDLE_PEEK_RESULT.store(-2, Ordering::Relaxed);
    let keepalive = connection.into_keepalive(preparation).unwrap();
    let read = unsafe { (*keepalive.peer.raw.connection).read };
    assert_ne!(unsafe { (*read).active() }, 0);

    server.write_all(b"x").unwrap();
    wait_for_readable_socket(fd);
    unsafe { (*read).handler.unwrap()(read) };
    assert_eq!(IDLE_PEEK_RESULT.load(Ordering::Relaxed), 1);

    let mut byte = 0_u8;
    assert_eq!(unsafe { libc::recv(fd, (&raw mut byte).cast(), 1, 0) }, 1);
    drop(server);
    wait_for_readable_socket(fd);
    unsafe { (*read).handler.unwrap()(read) };
    assert_eq!(IDLE_PEEK_RESULT.load(Ordering::Relaxed), 0);
}

#[test]
fn pending_peer_rejects_completion_before_native_readiness() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    let connection = pending_peer(peer.connect().unwrap());
    let error = connection.connect_ready().unwrap_err();
    assert_eq!(error.error(), EventPeerConnectionError::NotReady);
    drop(error.into_connection());
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn pending_peer_checks_connect_completion() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    let connection = pending_peer(peer.connect().unwrap());
    let raw = connection.peer.raw.connection;
    let fd = unsafe { raw.as_ref().unwrap().fd };
    wait_for_writable_socket(fd);
    unsafe { raw.as_ref().unwrap().write.as_mut().unwrap().set_ready(1) };
    let connection = connection.connect_ready().unwrap().complete().unwrap();

    drop(connection);
    assert_eq!(globals.free_connection_n(), 1);
    drop(listener);
}

#[test]
fn pending_peer_reports_refused_and_invalid_socket_completion() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    drop(listener);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    let connection = pending_peer(peer.connect().unwrap());

    let raw = connection.peer.raw.connection;
    let fd = unsafe { raw.as_ref().unwrap().fd };
    wait_for_writable_socket(fd);
    unsafe { raw.as_ref().unwrap().write.as_mut().unwrap().set_ready(1) };
    assert!(matches!(
        connection.connect_ready().unwrap().complete(),
        Err(EventPeerConnectionError::Connect(_))
    ));
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn pending_peer_stays_owned_until_completed_or_closed() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    );
    let connection = pending_peer(peer.connect().unwrap());
    drop(connection);
    assert_eq!(globals.free_connection_n(), 1);
    drop(listener);
}

#[test]
fn peer_preparation_reuses_existing_pool_and_reports_allocation_failure() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let mut connection = connected_peer(peer.connect().unwrap());
    let handlers = test_event_handlers(active_read_handler, active_write_handler);

    for pool_size in [0, mem::size_of::<ngx_pool_t>() - 1, EVENT_PEER_MIN_POOL_SIZE - 1] {
        assert_eq!(
            connection.prepare(EventPeerPreparation::new(
                unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() },
                handlers,
                pool_size,
            )),
            Err(EventPeerConnectionError::PoolTooSmall {
                requested: pool_size,
                minimum: EVENT_PEER_MIN_POOL_SIZE,
            })
        );
    }
    let raw = connection.peer.raw.connection;
    assert!(unsafe { raw.as_ref().unwrap().pool.is_null() });

    assert_eq!(
        connection.prepare(EventPeerPreparation::new(
            unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() },
            handlers,
            usize::MAX
        )),
        Err(EventPeerConnectionError::PoolAllocation)
    );
    assert!(unsafe { raw.as_ref().unwrap().pool.is_null() });

    connection
        .prepare(EventPeerPreparation::new(
            unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() },
            handlers,
            EVENT_PEER_MIN_POOL_SIZE,
        ))
        .unwrap();
    let pool = unsafe { raw.as_ref().unwrap().pool };
    connection
        .prepare(EventPeerPreparation::new(
            unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() },
            handlers,
            0,
        ))
        .unwrap();
    assert_eq!(unsafe { raw.as_ref().unwrap().pool }, pool);

    drop(connection);
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn keepalive_attach_transfers_external_socket_and_rejects_invalid_connection() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut source = connected_peer(
        EventPeerBuilder::new(remote.peer_address())
            .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
            .callbacks(EventPeerCallbacks::direct())
            .socket_type(SocketType::Datagram)
            .build()
            .unwrap()
            .connect()
            .unwrap(),
    );
    let raw = source.peer.raw.connection;
    source.peer.raw.connection = ptr::null_mut();
    drop(source);

    let attached = unsafe {
        EventPeerBuilder::new(remote.peer_address())
            .log(LogRef::from_raw((&raw const log).cast_mut()).unwrap())
            .callbacks(EventPeerCallbacks::direct())
            .build()
            .unwrap()
            .attach_keepalive(raw)
    }
    .unwrap();
    let borrowed = attached
        .into_connection(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .unwrap();
    drop(borrowed);
    assert_eq!(globals.free_connection_n(), 1);

    let detached = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .build()
        .unwrap();
    assert!(matches!(
        unsafe { detached.attach_keepalive(ptr::null_mut()) },
        Err(EventPeerAttachError::Connection {
            error: EventPeerConnectionError::Connection(ConnectionError::NullConnection),
            ..
        })
    ));
}

#[test]
fn keepalive_attach_quiesces_previous_handlers_data_and_timers() {
    let mut globals = PeerGlobals::new(true, add_event_ok);
    unsafe {
        assert_eq!(ngx_event_timer_init(ptr::null_mut()), NGX_OK as _);
        ngx_current_msec = 0;
        ngx_queue_init(&raw mut ngx_posted_events);
    }
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut source_data = 1_u8;
    EVENT_HANDLER_CALLS.store(0, Ordering::Relaxed);

    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let mut source = connected_peer(peer.connect().unwrap());
    source
        .prepare(unsafe {
            EventPeerPreparation::new(
                LogRef::from_raw((&raw const log).cast_mut()).unwrap(),
                test_event_handlers(active_read_handler, active_write_handler),
                EVENT_PEER_MIN_POOL_SIZE,
            )
            .data((&raw mut source_data).cast())
        })
        .unwrap();
    source
        .with_connection(|mut connection| unsafe {
            connection.read_event().unwrap().add_timer(7);
            connection.write_event().unwrap().add_timer(11);
        })
        .unwrap();
    let raw = source.peer.raw.connection;
    unsafe {
        (*(*raw).read).set_active(1);
        (*(*raw).write).set_active(1);
        ngx_post_event((*raw).read, &raw mut ngx_posted_events);
    }
    source.peer.raw.connection = ptr::null_mut();
    drop(source);

    let attached = unsafe {
        EventPeerBuilder::new(remote.peer_address())
            .log(LogRef::from_raw((&raw const log).cast_mut()).unwrap())
            .callbacks(EventPeerCallbacks::direct())
            .build()
            .unwrap()
            .attach_keepalive(raw)
    }
    .unwrap();

    assert!(unsafe { (*raw).data.is_null() });
    assert_eq!(unsafe { (*raw).idle() }, 1);
    assert_eq!(unsafe { (*(*raw).read).active() }, 1);
    assert_eq!(unsafe { (*(*raw).write).active() }, 1);
    assert_eq!(unsafe { (*(*raw).read).timer_set() }, 0);
    assert_eq!(unsafe { (*(*raw).write).timer_set() }, 0);
    assert_ne!(unsafe { (*(*raw).read).posted() }, 0);
    unsafe {
        ngx_event_process_posted(&raw mut *globals.cycle, &raw mut ngx_posted_events);
    }
    assert_eq!(unsafe { (*(*raw).read).posted() }, 0);
    unsafe { (*(*raw).read).handler.unwrap()((*raw).read) };
    unsafe { (*(*raw).write).handler.unwrap()((*raw).write) };
    assert_eq!(EVENT_HANDLER_CALLS.load(Ordering::Relaxed), 0);

    drop(attached);
    assert_eq!(globals.free_connection_n(), 1);
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
#[test]
fn keepalive_attach_rejects_ssl_connection_without_taking_ownership() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let mut source_data = 1_u8;
    let mut source = connected_peer(
        EventPeerBuilder::new(remote.peer_address())
            .log(unsafe { LogRef::from_raw((&raw const log).cast_mut()).unwrap() })
            .callbacks(EventPeerCallbacks::direct())
            .socket_type(SocketType::Datagram)
            .build()
            .unwrap()
            .connect()
            .unwrap(),
    );
    let raw = source.peer.raw.connection;
    source.peer.raw.connection = ptr::null_mut();
    drop(source);
    unsafe {
        (*raw).data = (&raw mut source_data).cast();
        (*(*raw).read).handler = Some(active_read_handler);
        (*(*raw).write).handler = Some(active_write_handler);
        (*raw).ssl = core::ptr::NonNull::<u8>::dangling().as_ptr().cast();
    }

    let result = unsafe {
        EventPeerBuilder::new(remote.peer_address())
            .log(LogRef::from_raw((&raw const log).cast_mut()).unwrap())
            .callbacks(EventPeerCallbacks::direct())
            .build()
            .unwrap()
            .attach_keepalive(raw)
    };
    match result {
        Err(EventPeerAttachError::Connection {
            error: EventPeerConnectionError::SslConnection,
            peer,
        }) => {
            assert_eq!(unsafe { (*raw).data }, (&raw mut source_data).cast());
            assert!(same_event_handler(unsafe { (*(*raw).read).handler }, active_read_handler));
            assert!(same_event_handler(unsafe { (*(*raw).write).handler }, active_write_handler));
            drop(peer);
            unsafe {
                (*raw).ssl = ptr::null_mut();
                crate::ffi::ngx_close_connection(raw);
            }
        }
        Ok(attached) => {
            unsafe { (*raw).ssl = ptr::null_mut() };
            drop(attached);
            panic!("SSL connection ownership must be rejected");
        }
        Err(error) => panic!("unexpected SSL connection result: {error:?}"),
    }
    assert_eq!(globals.free_connection_n(), 1);
}

#[cfg(unix)]
#[test]
fn native_connect_decline_closes_connection() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestUnixAddress::invalid_path();
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let result = build_peer(
        remote.peer_address(),
        (&raw const log).cast_mut(),
        EventPeerCallbacks::direct(),
    )
    .connect()
    .unwrap();
    assert_eq!(result.status(), EventPeerConnectStatus::Declined);
    assert!(detached_peer(result).raw.connection.is_null());
    assert_eq!(globals.free_connection_n(), 1);
}

#[cfg(feature = "async")]
#[path = "readiness_tests.rs"]
mod readiness_tests;
