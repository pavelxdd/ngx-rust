use crate::core::NgxStr;
use crate::ffi::{ngx_http_upstream_state_t, ngx_msec_t, off_t};

/// State recorded for one upstream connection attempt.
#[repr(transparent)]
pub struct UpstreamState(ngx_http_upstream_state_t);

impl UpstreamState {
    /// Address of the attempted peer, when nginx selected one.
    pub fn peer(&self) -> Option<&NgxStr> {
        let peer = unsafe { self.0.peer.as_ref()? };

        // SAFETY: nginx owns the string in the request pool for at least as long as this state.
        Some(unsafe { NgxStr::from_ngx_str(*peer) })
    }

    /// HTTP status received from the peer, or zero before a response status is available.
    pub fn status(&self) -> u16 {
        self.0.status as u16
    }

    /// Milliseconds spent on the attempt.
    ///
    /// The value is `ngx_msec_t::MAX` while the attempt is still in progress.
    pub fn response_time(&self) -> ngx_msec_t {
        self.0.response_time
    }

    /// Milliseconds spent establishing the upstream connection.
    ///
    /// The value is `ngx_msec_t::MAX` until nginx records the connection result.
    pub fn connect_time(&self) -> ngx_msec_t {
        self.0.connect_time
    }

    /// Milliseconds until nginx received the upstream response headers.
    ///
    /// The value is `ngx_msec_t::MAX` until nginx receives the headers.
    pub fn header_time(&self) -> ngx_msec_t {
        self.0.header_time
    }

    /// Milliseconds the request spent waiting in an upstream queue.
    pub fn queue_time(&self) -> ngx_msec_t {
        self.0.queue_time
    }

    /// Bytes written to the upstream connection.
    pub fn bytes_sent(&self) -> off_t {
        self.0.bytes_sent
    }

    /// Bytes read from the upstream connection.
    pub fn bytes_received(&self) -> off_t {
        self.0.bytes_received
    }

    /// Response body bytes received from the upstream connection.
    pub fn response_length(&self) -> off_t {
        self.0.response_length
    }
}

/// Define a static upstream peer initializer
///
/// Initializes the upstream 'get', 'free', and 'session' callbacks and gives the module writer an
/// opportunity to set custom data.
///
/// This macro will define the NGINX callback type:
/// `typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
/// ngx_http_upstream_srv_conf_t *us)`, we keep this macro name in-sync with its underlying NGINX
/// type, this callback is required to initialize your peer.
///
/// Load Balancing: <https://nginx.org/en/docs/dev/development_guide.html#http_load_balancing>
#[macro_export]
macro_rules! http_upstream_init_peer_pt {
    ( $name: ident, $handler: expr ) => {
        extern "C" fn $name(
            r: *mut $crate::ffi::ngx_http_request_t,
            us: *mut $crate::ffi::ngx_http_upstream_srv_conf_t,
        ) -> $crate::ffi::ngx_int_t {
            let request = unsafe { $crate::http::Request::from_ngx_http_request(r) };
            let status: $crate::core::Status = $handler(request, us);
            status.0
        }
    };
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use super::*;
    use crate::ffi::{ngx_http_upstream_state_t, ngx_str_t};

    fn zeroed_state() -> UpstreamState {
        UpstreamState(unsafe { MaybeUninit::zeroed().assume_init() })
    }

    #[test]
    fn peer_is_none_for_a_null_pointer() {
        assert!(zeroed_state().peer().is_none());
    }

    #[test]
    fn peer_borrows_the_nginx_string() {
        let bytes = b"10.0.0.1:8080";
        let mut peer = ngx_str_t { len: bytes.len(), data: bytes.as_ptr().cast_mut() };
        let mut state = zeroed_state();
        state.0.peer = &raw mut peer;

        assert_eq!(state.peer().map(NgxStr::as_bytes), Some(bytes.as_slice()));
    }

    #[test]
    fn accessors_read_the_upstream_attempt() {
        let mut state = zeroed_state();
        state.0.status = 502;
        state.0.response_time = 75;
        state.0.connect_time = 5;
        state.0.header_time = 10;
        state.0.queue_time = 1;
        state.0.bytes_sent = 1024;
        state.0.bytes_received = 4096;
        state.0.response_length = 2048;

        assert_eq!(state.status(), 502);
        assert_eq!(state.response_time(), 75);
        assert_eq!(state.connect_time(), 5);
        assert_eq!(state.header_time(), 10);
        assert_eq!(state.queue_time(), 1);
        assert_eq!(state.bytes_sent(), 1024);
        assert_eq!(state.bytes_received(), 4096);
        assert_eq!(state.response_length(), 2048);
    }

    #[test]
    fn wrapper_preserves_the_ffi_layout() {
        assert_eq!(
            core::mem::size_of::<UpstreamState>(),
            core::mem::size_of::<ngx_http_upstream_state_t>()
        );
        assert_eq!(
            core::mem::align_of::<UpstreamState>(),
            core::mem::align_of::<ngx_http_upstream_state_t>()
        );
    }
}
