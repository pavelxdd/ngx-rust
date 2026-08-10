use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::ffi::c_int;
use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::io::Write;
use std::net::TcpListener;

use super::*;
use crate::async_::{Readiness, ReadinessError};
use crate::event::EventError;
use crate::ffi::{
    NGX_OK, NGX_USE_CLEAR_EVENT, ngx_add_timer, ngx_current_msec, ngx_del_timer,
    ngx_event_expire_timers, ngx_event_timer_init, ngx_msec_int_t, ngx_msec_t,
};

#[derive(Default)]
struct WakeState {
    wakes: AtomicUsize,
}

struct RecordingWake {
    state: Arc<WakeState>,
}

impl Wake for RecordingWake {
    fn wake(self: Arc<Self>) {
        self.state.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.state.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

fn recording_waker() -> (Waker, Arc<WakeState>) {
    let state = Arc::new(WakeState::default());
    let waker = Waker::from(Arc::new(RecordingWake { state: Arc::clone(&state) }));
    (waker, state)
}

fn wait_for_socket(fd: c_int, events: i16) {
    let mut descriptor = libc::pollfd { fd, events, revents: 0 };
    assert_eq!(unsafe { libc::poll(&raw mut descriptor, 1, 1_000) }, 1);
    assert_ne!(descriptor.revents & events, 0);
}

fn invoke_event_handler(event: *mut ngx_event_t) {
    unsafe { (*event).handler.expect("readiness wait must install an event handler")(event) };
}

fn reset_timer_tree() {
    unsafe {
        assert_eq!(ngx_event_timer_init(ptr::null_mut()), NGX_OK as _);
        ngx_current_msec = 0;
    }
}

fn advance_to(msec: ngx_msec_t) {
    unsafe {
        ngx_current_msec = msec;
        ngx_event_expire_timers();
    }
}

#[test]
fn readiness_returns_immediately_for_a_ready_read_event() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().read.as_mut().unwrap().set_ready(1) };

    let mut readiness = Box::pin(connection.wait_read(None));
    let mut context = Context::from_waker(Waker::noop());

    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Ready(Ok(Readiness::Read)));
}

#[test]
fn readiness_returns_immediately_for_a_ready_write_event() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().write.as_mut().unwrap().set_ready(1) };

    let mut readiness = Box::pin(connection.wait_write(None));
    let mut context = Context::from_waker(Waker::noop());

    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Ready(Ok(Readiness::Write)));
}

#[test]
fn readiness_returns_immediately_for_a_connected_peer() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(&log)
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().write.as_mut().unwrap().set_ready(0) };
    let mut readiness = Box::pin(connection.wait_connect(None));
    let mut context = Context::from_waker(Waker::noop());

    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Ready(Ok(Readiness::Connect)));
}

#[test]
fn readiness_returns_ready_before_zero_timeout() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().read.as_mut().unwrap().set_ready(1) };

    let mut readiness = Box::pin(connection.wait_read(Some(Duration::ZERO)));
    let mut context = Context::from_waker(Waker::noop());

    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Ready(Ok(Readiness::Read)));
}

#[test]
fn readiness_reports_native_error_before_connected_state() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(&log)
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().write.as_mut().unwrap().set_error(1) };

    let mut readiness = Box::pin(connection.wait_connect(None));
    let mut context = Context::from_waker(Waker::noop());

    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Connection))
    );
}

#[test]
fn readiness_reports_an_invalid_selected_event() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    unsafe { raw.as_mut().unwrap().read = ptr::null_mut() };

    let mut readiness = Box::pin(connection.wait_read(None));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Peer(EventPeerConnectionError::Event(
            EventError::NullEvent,
        ))))
    );
    drop(readiness);

    unsafe { raw.as_mut().unwrap().read = read };
}

#[test]
fn readiness_reports_an_invalid_socket_while_completing_connect() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    assert_eq!(connection.state(), EventPeerConnectionState::Pending);
    let raw = connection.peer.raw.connection;
    let fd = unsafe { raw.as_ref().unwrap().fd };
    unsafe {
        raw.as_ref().unwrap().write.as_mut().unwrap().set_ready(1);
        raw.as_mut().unwrap().fd = -1;
    }

    let mut readiness = Box::pin(connection.wait_connect(None));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Peer(EventPeerConnectionError::SocketOption(_))))
    ));
    drop(readiness);

    unsafe { raw.as_mut().unwrap().fd = fd };
}

#[test]
fn readiness_wakes_for_delayed_read_and_restores_handler() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    let fd = unsafe { raw.as_ref().unwrap().fd };
    wait_for_writable_socket(fd);
    connection.complete_connect().unwrap();
    let (mut server, _) = listener.accept().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let read = unsafe { raw.as_ref().unwrap().read };
    let data = unsafe { (*read).data };
    unsafe { (*read).set_ready(0) };

    let (waker, state) = recording_waker();
    let mut readiness = Box::pin(connection.wait_read(None));
    let mut context = Context::from_waker(&waker);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Pending);
    assert!(!same_event_handler(unsafe { (*read).handler }, active_read_handler));
    assert_eq!(unsafe { (*read).data }, data);

    server.write_all(b"r").unwrap();
    wait_for_socket(fd, libc::POLLIN);
    unsafe { (*read).set_ready(1) };
    invoke_event_handler(read);

    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Ready(Ok(Readiness::Read)));
    assert!(same_event_handler(unsafe { (*read).handler }, active_read_handler));
    assert_eq!(unsafe { (*read).data }, data);
}

#[test]
fn readiness_rearms_after_a_partial_write_cycle() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    let fd = unsafe { raw.as_ref().unwrap().fd };
    wait_for_writable_socket(fd);
    connection.complete_connect().unwrap();
    let _server = listener.accept().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let write = unsafe { raw.as_ref().unwrap().write };
    unsafe { (*write).set_ready(0) };

    let (first_waker, first_state) = recording_waker();
    let mut first = Box::pin(connection.wait_write(None));
    let mut first_context = Context::from_waker(&first_waker);
    assert_eq!(Pin::as_mut(&mut first).poll(&mut first_context), Poll::Pending);
    wait_for_socket(fd, libc::POLLOUT);
    unsafe { (*write).set_ready(1) };
    invoke_event_handler(write);
    assert_eq!(first_state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(Pin::as_mut(&mut first).poll(&mut first_context), Poll::Ready(Ok(Readiness::Write)));
    drop(first);

    unsafe { (*write).set_ready(0) };
    let (second_waker, second_state) = recording_waker();
    let mut second = Box::pin(connection.wait_write(None));
    let mut second_context = Context::from_waker(&second_waker);
    assert_eq!(Pin::as_mut(&mut second).poll(&mut second_context), Poll::Pending);
    unsafe { (*write).set_ready(1) };
    invoke_event_handler(write);
    assert_eq!(second_state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(
        Pin::as_mut(&mut second).poll(&mut second_context),
        Poll::Ready(Ok(Readiness::Write))
    );
    assert!(same_event_handler(unsafe { (*write).handler }, active_write_handler));
}

#[test]
fn readiness_completes_pending_connect_after_so_error_check() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    assert_eq!(connection.state(), EventPeerConnectionState::Pending);
    let raw = connection.peer.raw.connection;
    let fd = unsafe { raw.as_ref().unwrap().fd };
    let write = unsafe { raw.as_ref().unwrap().write };
    unsafe { (*write).set_ready(0) };

    let (waker, state) = recording_waker();
    let mut readiness = Box::pin(connection.wait_connect(None));
    let mut context = Context::from_waker(&waker);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Pending);
    wait_for_writable_socket(fd);
    unsafe { (*write).set_ready(1) };
    invoke_event_handler(write);

    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Ready(Ok(Readiness::Connect)));
    drop(readiness);
    assert_eq!(connection.state(), EventPeerConnectionState::Connected);
}

#[test]
fn readiness_reports_refused_pending_connect_from_so_error() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = TestAddress::ipv4([127, 0, 0, 1], listener.local_addr().unwrap().port());
    drop(listener);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    assert_eq!(connection.state(), EventPeerConnectionState::Pending);
    let raw = connection.peer.raw.connection;
    let fd = unsafe { raw.as_ref().unwrap().fd };
    let write = unsafe { raw.as_ref().unwrap().write };
    unsafe { (*write).set_ready(0) };

    let (waker, state) = recording_waker();
    let mut readiness = Box::pin(connection.wait_connect(None));
    let mut context = Context::from_waker(&waker);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Pending);
    wait_for_writable_socket(fd);
    unsafe { (*write).set_ready(1) };
    invoke_event_handler(write);

    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    assert!(matches!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Peer(EventPeerConnectionError::Connect(_))))
    ));
}

#[test]
fn readiness_reports_eof_and_connection_error() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().read.as_mut().unwrap().set_eof(1) };

    let mut eof = Box::pin(connection.wait_read(None));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        Pin::as_mut(&mut eof).poll(&mut context),
        Poll::Ready(Err(ReadinessError::EndOfFile))
    );
    drop(eof);

    unsafe {
        raw.as_ref().unwrap().read.as_mut().unwrap().set_eof(0);
        raw.as_mut().unwrap().set_error(1);
    }
    let mut error = Box::pin(connection.wait_write(None));
    assert_eq!(
        Pin::as_mut(&mut error).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Connection))
    );
}

#[test]
fn readiness_times_out_without_installing_for_zero_duration() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    unsafe { (*read).set_ready(0) };

    let mut readiness = Box::pin(connection.wait_read(Some(Duration::ZERO)));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Timeout))
    );
    assert!(same_event_handler(unsafe { (*read).handler }, active_read_handler));
}

#[test]
fn readiness_rounds_a_submillisecond_timeout_up_to_one_millisecond() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    reset_timer_tree();
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    unsafe { (*read).set_ready(0) };

    let (waker, state) = recording_waker();
    let mut readiness = Box::pin(connection.wait_read(Some(Duration::from_nanos(1))));
    let mut context = Context::from_waker(&waker);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Pending);
    advance_to(0);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
    advance_to(1);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Timeout))
    );
    assert!(same_event_handler(unsafe { (*read).handler }, active_read_handler));
}

#[test]
fn readiness_chunks_a_timeout_larger_than_one_nginx_timer_step() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    reset_timer_tree();
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().read.as_mut().unwrap().set_ready(0) };
    let maximum = ngx_msec_int_t::MAX as u64;

    let (waker, state) = recording_waker();
    let mut readiness = Box::pin(
        connection.wait_read(Some(Duration::from_millis(maximum.checked_add(1).unwrap()))),
    );
    let mut context = Context::from_waker(&waker);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Pending);
    advance_to(maximum as ngx_msec_t);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Pending);
    advance_to(maximum.checked_add(1).unwrap() as ngx_msec_t);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 2);
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Timeout))
    );
}

#[test]
fn readiness_rejects_an_event_timer_owned_by_another_handler() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    reset_timer_tree();
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    unsafe {
        (*read).set_ready(0);
        ngx_add_timer(read, 5);
    }

    let mut readiness = Box::pin(connection.wait_read(None));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::TimerActive))
    );
    assert!(same_event_handler(unsafe { (*read).handler }, active_read_handler));
    assert_ne!(unsafe { (*read).timer_set() }, 0);
    unsafe { ngx_del_timer(read) };
}

#[test]
fn readiness_restores_the_handler_when_native_registration_fails() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    unsafe {
        (*read).set_active(0);
        (*read).set_ready(0);
        ngx_event_actions.add = Some(add_event_error);
        ngx_event_flags = NGX_USE_CLEAR_EVENT as _;
    }

    let mut readiness = Box::pin(connection.wait_read(None));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::EventRegistration))
    );
    assert!(same_event_handler(unsafe { (*read).handler }, active_read_handler));
}

#[test]
fn readiness_drop_cancels_timeout_and_leaves_no_late_waker() {
    let globals = PeerGlobals::new(true, add_event_ok);
    reset_timer_tree();
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    unsafe { (*read).set_ready(0) };
    EVENT_HANDLER_CALLS.store(0, Ordering::Relaxed);

    let (waker, state) = recording_waker();
    let mut readiness = Box::pin(connection.wait_read(Some(Duration::from_millis(5))));
    let mut context = Context::from_waker(&waker);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Pending);
    invoke_event_handler(read);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    drop(readiness);

    assert!(same_event_handler(unsafe { (*read).handler }, active_read_handler));
    advance_to(5);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    unsafe { (*read).set_ready(1) };
    invoke_event_handler(read);
    assert_eq!(EVENT_HANDLER_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(globals.free_connection_n(), 0);

    connection.close();
    invoke_event_handler(read);
    assert_eq!(state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn readiness_keeps_a_borrowed_peer_open_and_transferable_after_drop() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = EventPeerBuilder::new(remote.peer_address())
        .log(&log)
        .callbacks(EventPeerCallbacks::direct())
        .socket_type(SocketType::Datagram)
        .build()
        .unwrap();
    let connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let keepalive = connection.into_keepalive().unwrap();
    let mut borrowed = keepalive.into_connection().unwrap();
    assert_eq!(borrowed.state(), EventPeerConnectionState::Borrowed);
    let raw = borrowed.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().read.as_mut().unwrap().set_ready(1) };

    let mut readiness = Box::pin(borrowed.wait_read(None));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut context), Poll::Ready(Ok(Readiness::Read)));
    drop(readiness);

    let keepalive = borrowed.into_keepalive().unwrap();
    assert_eq!(globals.free_connection_n(), 0);
    drop(keepalive);
    assert_eq!(globals.free_connection_n(), 1);
}

#[test]
fn readiness_uses_the_latest_waker_for_event_and_finite_timeout() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    reset_timer_tree();
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    unsafe { (*read).set_ready(0) };

    let (first_waker, first_state) = recording_waker();
    let (second_waker, second_state) = recording_waker();
    let mut readiness = Box::pin(connection.wait_read(Some(Duration::from_millis(5))));
    let mut first_context = Context::from_waker(&first_waker);
    let mut second_context = Context::from_waker(&second_waker);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut first_context), Poll::Pending);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut second_context), Poll::Pending);

    invoke_event_handler(read);
    assert_eq!(first_state.wakes.load(Ordering::Relaxed), 0);
    assert_eq!(second_state.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(Pin::as_mut(&mut readiness).poll(&mut second_context), Poll::Pending);

    advance_to(5);
    assert_eq!(first_state.wakes.load(Ordering::Relaxed), 0);
    assert_eq!(second_state.wakes.load(Ordering::Relaxed), 2);
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut second_context),
        Poll::Ready(Err(ReadinessError::Timeout))
    );
}

#[test]
fn readiness_returns_timeout_for_a_native_timedout_event() {
    let _globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    let raw = connection.peer.raw.connection;
    unsafe { raw.as_ref().unwrap().read.as_mut().unwrap().set_timedout(1) };

    let mut readiness = Box::pin(connection.wait_read(None));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        Pin::as_mut(&mut readiness).poll(&mut context),
        Poll::Ready(Err(ReadinessError::Timeout))
    );
}

#[test]
fn dropping_an_unpolled_readiness_future_does_not_change_peer_ownership() {
    let globals = PeerGlobals::new(true, add_event_ok);
    let remote = TestAddress::ipv4([127, 0, 0, 1], 9);
    let log: ngx_log_t = unsafe { mem::zeroed() };
    let peer = build_peer(remote.peer_address(), &log, EventPeerCallbacks::direct());
    let mut connection = peer.connect().unwrap().into_peer().into_connection().unwrap();
    connection
        .prepare(EventPeerPreparation::new(
            &log,
            EventPeerHandlers::new(active_read_handler, active_write_handler),
            128,
        ))
        .unwrap();
    let raw = connection.peer.raw.connection;
    let read = unsafe { raw.as_ref().unwrap().read };
    let readiness = connection.wait_read(Some(Duration::from_millis(5)));
    drop(readiness);

    assert!(same_event_handler(unsafe { (*read).handler }, active_read_handler));
    assert_eq!(globals.free_connection_n(), 0);
    connection.close();
    assert_eq!(globals.free_connection_n(), 1);
}
