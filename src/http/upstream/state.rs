use core::error;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::slice;

use crate::collections::NgxArray;
use crate::core::NgxStr;
use crate::ffi::{ngx_array_t, ngx_http_upstream_state_t, ngx_msec_t, off_t};

/// Failure while reading request-scoped upstream attempt state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamStateError {
    /// The request state-array pointer is misaligned.
    MisalignedArray,
    /// The nginx state array has incompatible element size, capacity, or storage alignment.
    InvalidArray,
    /// A state has a nonempty peer string without backing bytes.
    MissingPeerData,
    /// A state peer string does not satisfy `ngx_str_t` alignment.
    MisalignedPeer,
}

impl fmt::Display for UpstreamStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MisalignedArray => formatter.write_str("upstream state array is misaligned"),
            Self::InvalidArray => formatter.write_str("upstream state array is invalid"),
            Self::MissingPeerData => formatter.write_str("upstream state peer has no data"),
            Self::MisalignedPeer => formatter.write_str("upstream state peer is misaligned"),
        }
    }
}

impl error::Error for UpstreamStateError {}

/// State recorded for one upstream connection attempt.
#[repr(transparent)]
pub struct UpstreamState(ngx_http_upstream_state_t);

impl UpstreamState {
    /// Address of the attempted peer, when nginx selected one.
    pub fn peer(&self) -> Result<Option<&NgxStr>, UpstreamStateError> {
        let Some(peer) = NonNull::new(self.0.peer) else {
            return Ok(None);
        };
        if !peer.as_ptr().is_aligned() {
            return Err(UpstreamStateError::MisalignedPeer);
        }
        let peer = unsafe { peer.as_ref() };
        if peer.len == 0 {
            return Ok(Some(NgxStr::from_bytes(&[])));
        }

        let data = NonNull::new(peer.data).ok_or(UpstreamStateError::MissingPeerData)?;
        let bytes = unsafe { slice::from_raw_parts(data.as_ptr(), peer.len) };
        Ok(Some(NgxStr::from_bytes(bytes)))
    }

    /// HTTP status received from the peer, or `None` before a response status is available.
    pub fn status(&self) -> Option<u16> {
        let status = u16::try_from(self.0.status).ok()?;
        (status != 0).then_some(status)
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

/// Checked request-scoped upstream attempt states.
#[derive(Clone, Copy)]
pub struct UpstreamStates<'request> {
    raw: &'request NgxArray<UpstreamState>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'request> UpstreamStates<'request> {
    pub(crate) unsafe fn from_raw(
        array: *mut ngx_array_t,
    ) -> Result<Option<Self>, UpstreamStateError> {
        let Some(array) = NonNull::new(array) else {
            return Ok(None);
        };
        if !array.as_ptr().is_aligned() {
            return Err(UpstreamStateError::MisalignedArray);
        }

        let array = unsafe { NgxArray::from_ngx_array(array.as_ref()) }
            .ok_or(UpstreamStateError::InvalidArray)?;
        Ok(Some(Self { raw: array, _not_thread_safe: PhantomData }))
    }

    /// Returns the number of upstream attempts nginx recorded.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Returns whether nginx recorded no upstream attempts.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Returns one upstream attempt by index.
    pub fn get(&self, index: usize) -> Option<&UpstreamState> {
        self.raw.as_slice().get(index)
    }

    /// Iterates over upstream attempts in nginx's recorded order.
    pub fn iter(&self) -> slice::Iter<'_, UpstreamState> {
        self.raw.as_slice().iter()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{MaybeUninit, size_of};
    use core::ptr;

    use super::*;
    use crate::ffi::{ngx_array_t, ngx_http_upstream_state_t, ngx_str_t, ngx_uint_t};

    fn zeroed_state() -> UpstreamState {
        UpstreamState(unsafe { MaybeUninit::zeroed().assume_init() })
    }

    #[test]
    fn peer_is_none_for_a_null_pointer() {
        assert!(zeroed_state().peer().unwrap().is_none());
    }

    #[test]
    fn peer_borrows_the_nginx_string() {
        let bytes = b"10.0.0.1:8080";
        let mut peer = ngx_str_t { len: bytes.len(), data: bytes.as_ptr().cast_mut() };
        let mut state = zeroed_state();
        state.0.peer = &raw mut peer;

        assert_eq!(state.peer().unwrap().map(NgxStr::as_bytes), Some(bytes.as_slice()));
    }

    #[test]
    fn peer_rejects_missing_or_misaligned_string_storage() {
        let mut missing = ngx_str_t { len: 1, data: ptr::null_mut() };
        let mut state = zeroed_state();
        state.0.peer = &raw mut missing;
        assert!(matches!(state.peer(), Err(UpstreamStateError::MissingPeerData)));

        state.0.peer = ptr::without_provenance_mut::<ngx_str_t>(1);
        assert!(matches!(state.peer(), Err(UpstreamStateError::MisalignedPeer)));
    }

    #[test]
    fn accessors_read_the_upstream_attempt() {
        let mut state = zeroed_state();
        assert_eq!(state.status(), None);
        state.0.status = 502;
        state.0.response_time = 75;
        state.0.connect_time = 5;
        state.0.header_time = 10;
        state.0.queue_time = 1;
        state.0.bytes_sent = 1024;
        state.0.bytes_received = 4096;
        state.0.response_length = 2048;

        assert_eq!(state.status(), Some(502));
        assert_eq!(state.response_time(), 75);
        assert_eq!(state.connect_time(), 5);
        assert_eq!(state.header_time(), 10);
        assert_eq!(state.queue_time(), 1);
        assert_eq!(state.bytes_sent(), 1024);
        assert_eq!(state.bytes_received(), 4096);
        assert_eq!(state.response_length(), 2048);

        state.0.status = ngx_uint_t::from(u16::MAX) + 1;
        assert_eq!(state.status(), None);

        state.0.response_time = ngx_msec_t::MAX;
        state.0.connect_time = ngx_msec_t::MAX;
        state.0.header_time = ngx_msec_t::MAX;
        state.0.queue_time = ngx_msec_t::MAX;
        state.0.bytes_sent = -1;
        state.0.bytes_received = -1;
        state.0.response_length = -1;
        assert_eq!(state.response_time(), ngx_msec_t::MAX);
        assert_eq!(state.connect_time(), ngx_msec_t::MAX);
        assert_eq!(state.header_time(), ngx_msec_t::MAX);
        assert_eq!(state.queue_time(), ngx_msec_t::MAX);
        assert_eq!(state.bytes_sent(), -1);
        assert_eq!(state.bytes_received(), -1);
        assert_eq!(state.response_length(), -1);
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

    #[test]
    fn upstream_states_distinguish_absent_empty_and_multiple_attempts() {
        assert!(unsafe { UpstreamStates::from_raw(ptr::null_mut()) }.unwrap().is_none());

        let mut empty = ngx_array_t {
            elts: ptr::null_mut(),
            nelts: 0,
            size: size_of::<ngx_http_upstream_state_t>(),
            nalloc: 0,
            pool: ptr::null_mut(),
        };
        let states = unsafe { UpstreamStates::from_raw(&raw mut empty) }.unwrap().unwrap();
        assert!(states.is_empty());

        let mut attempts =
            [unsafe { MaybeUninit::<ngx_http_upstream_state_t>::zeroed().assume_init() }, unsafe {
                MaybeUninit::<ngx_http_upstream_state_t>::zeroed().assume_init()
            }];
        attempts[0].status = 502;
        attempts[1].status = 503;
        let mut raw = ngx_array_t {
            elts: attempts.as_mut_ptr().cast(),
            nelts: attempts.len(),
            size: size_of::<ngx_http_upstream_state_t>(),
            nalloc: attempts.len(),
            pool: ptr::null_mut(),
        };
        let states = unsafe { UpstreamStates::from_raw(&raw mut raw) }.unwrap().unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states.get(0).unwrap().status(), Some(502));
        assert_eq!(states.iter().nth(1).unwrap().status(), Some(503));
    }

    #[test]
    fn upstream_states_reject_misaligned_or_malformed_arrays() {
        assert!(matches!(
            unsafe { UpstreamStates::from_raw(ptr::without_provenance_mut::<ngx_array_t>(1)) },
            Err(UpstreamStateError::MisalignedArray)
        ));

        let mut wrong_size = ngx_array_t {
            elts: ptr::null_mut(),
            nelts: 0,
            size: 1,
            nalloc: 0,
            pool: ptr::null_mut(),
        };
        assert!(matches!(
            unsafe { UpstreamStates::from_raw(&raw mut wrong_size) },
            Err(UpstreamStateError::InvalidArray)
        ));

        let mut invalid_capacity = ngx_array_t {
            elts: ptr::null_mut(),
            nelts: 1,
            size: size_of::<ngx_http_upstream_state_t>(),
            nalloc: 0,
            pool: ptr::null_mut(),
        };
        assert!(matches!(
            unsafe { UpstreamStates::from_raw(&raw mut invalid_capacity) },
            Err(UpstreamStateError::InvalidArray)
        ));
    }
}
