//! Private scheduler notification channel lifecycle and datagram protocol.

use core::ptr::NonNull;

use crate::ffi::{
    NGX_OK, ngx_close_connection, ngx_connection_t, ngx_get_connection, ngx_handle_read_event,
    ngx_nonblocking,
};
use crate::log::LogRef;

/// Opens the worker-local receiver and the cross-thread sender.
///
/// # Safety
///
/// The current worker must have an initialized nginx cycle and event backend. `log` and the
/// cycle connection array must remain live until worker shutdown closes the returned connection.
pub(super) unsafe fn open_notification_channel(
    log: LogRef<'_>,
    handler: unsafe extern "C" fn(*mut crate::ffi::ngx_event_t),
) -> Option<(NonNull<ngx_connection_t>, libc::c_int)> {
    let mut sockets = [-1; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sockets.as_mut_ptr()) } != 0 {
        return None;
    }

    let close_sockets = |sockets: [libc::c_int; 2]| unsafe {
        libc::close(sockets[0]);
        libc::close(sockets[1]);
    };
    for socket in sockets {
        if unsafe { ngx_nonblocking(socket) } != 0
            || unsafe { libc::fcntl(socket, libc::F_SETFD, libc::FD_CLOEXEC) } == -1
        {
            close_sockets(sockets);
            return None;
        }
    }

    let Some(connection) = NonNull::new(unsafe { ngx_get_connection(sockets[0], log.as_ptr()) })
    else {
        close_sockets(sockets);
        return None;
    };
    unsafe {
        (*connection.as_ptr()).read.as_mut().unwrap().handler = Some(handler);
        (*connection.as_ptr()).read.as_mut().unwrap().log = log.as_ptr();
        (*connection.as_ptr()).write.as_mut().unwrap().log = log.as_ptr();
    }
    if unsafe { ngx_handle_read_event((*connection.as_ptr()).read, 0) } != NGX_OK as _ {
        unsafe { ngx_close_connection(connection.as_ptr()) };
        unsafe { libc::close(sockets[1]) };
        return None;
    }

    Some((connection, sockets[1]))
}

pub(super) fn send_notification(socket: libc::c_int) -> bool {
    let byte = 1_u8;
    loop {
        let written = unsafe { libc::send(socket, (&raw const byte).cast(), 1, 0) };
        if written == 1 {
            return true;
        }
        if written == -1 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return true,
                _ => {}
            }
        }
        return false;
    }
}

pub(super) fn drain_notification(connection: NonNull<ngx_connection_t>) -> bool {
    let socket = unsafe { connection.as_ref().fd };
    let mut bytes = [0_u8; 64];

    loop {
        let received = unsafe { libc::recv(socket, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        if received > 0 {
            continue;
        }
        if received == -1 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(error) if error == libc::EAGAIN || error == libc::EWOULDBLOCK => break,
                _ => return false,
            }
        }
        return false;
    }

    let event = unsafe { connection.as_ref().read };
    let Some(mut event) = NonNull::new(event) else {
        return false;
    };
    unsafe { event.as_mut().set_ready(0) };
    true
}

pub(super) fn close_notification(socket: libc::c_int) {
    unsafe { libc::close(socket) };
}
