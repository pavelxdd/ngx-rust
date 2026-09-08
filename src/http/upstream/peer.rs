use core::any::TypeId;
use core::cell::Cell;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::core::{Pool, Status};
use crate::ffi::{
    NGX_LOG_ERR, ngx_event_free_peer_pt, ngx_event_get_peer_pt, ngx_event_notify_peer_pt,
    ngx_int_t, ngx_peer_connection_t, ngx_uint_t,
};
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
use crate::ffi::{ngx_event_save_peer_session_pt, ngx_event_set_peer_session_pt};
use crate::log::LogRef;

use super::callback::{HttpUpstreamPeerHandler, UpstreamCallbackError};
use super::peer_init::RequestUpstream;

const PEER_DATA_MAGIC: u64 = 0x7d5a_1bc8_9e34_f602;

/// Opaque proof that a native callback populated the fields required for a selected peer.
///
/// ```compile_fail
/// use core::marker::PhantomData;
/// use ngx::http::SelectedUpstreamPeer;
///
/// fn forge<'a>() -> SelectedUpstreamPeer<'a> {
///     SelectedUpstreamPeer { status: 0, _callback: PhantomData }
/// }
/// ```
pub struct SelectedUpstreamPeer<'callback> {
    status: ngx_int_t,
    pub(super) generation: u64,
    _callback: PhantomData<&'callback mut ngx_peer_connection_t>,
}

/// Safe result of an upstream peer selection callback.
///
/// ```compile_fail
/// use ngx::http::UpstreamPeerSelection;
///
/// fn escape<'a>(selection: UpstreamPeerSelection<'a>) -> UpstreamPeerSelection<'static> {
///     selection
/// }
/// ```
pub enum UpstreamPeerSelection<'callback> {
    /// Peer selection failed.
    Error,
    /// No live peer is currently available.
    Busy,
    /// This peer selection attempt was declined.
    Declined,
    /// A new, pending, or reused peer has all native fields required by nginx.
    Selected(SelectedUpstreamPeer<'callback>),
}

impl UpstreamPeerSelection<'_> {
    fn into_returned(self) -> ReturnedPeerSelection {
        match self {
            Self::Error => ReturnedPeerSelection::Unselected(Status::NGX_ERROR.0),
            Self::Busy => ReturnedPeerSelection::Unselected(Status::NGX_BUSY.0),
            Self::Declined => ReturnedPeerSelection::Unselected(Status::NGX_DECLINED.0),
            Self::Selected(selected) => ReturnedPeerSelection::Selected {
                status: selected.status,
                generation: selected.generation,
            },
        }
    }

    #[cfg(test)]
    pub(super) fn status(&self) -> ngx_int_t {
        match self {
            Self::Error => Status::NGX_ERROR.0,
            Self::Busy => Status::NGX_BUSY.0,
            Self::Declined => Status::NGX_DECLINED.0,
            Self::Selected(selected) => selected.status,
        }
    }
}

#[derive(Clone, Copy)]
enum ReturnedPeerSelection {
    Unselected(ngx_int_t),
    Selected { status: ngx_int_t, generation: u64 },
}

/// Checked peer-connection callback view.
pub struct UpstreamPeerConnection<'callback> {
    pub(super) raw: NonNull<ngx_peer_connection_t>,
    _callback: PhantomData<&'callback mut ngx_peer_connection_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl UpstreamPeerConnection<'_> {
    pub(super) unsafe fn from_raw(
        peer: *mut ngx_peer_connection_t,
    ) -> Result<Self, UpstreamCallbackError> {
        let raw = NonNull::new(peer).ok_or(UpstreamCallbackError::NullPeer)?;
        if !peer.is_aligned() {
            return Err(UpstreamCallbackError::MisalignedPeer);
        }

        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Returns the number of remaining peer attempts nginx recorded.
    pub fn tries(&self) -> ngx_uint_t {
        unsafe { self.raw.as_ref().tries }
    }

    fn selected(
        &mut self,
        status: ngx_int_t,
        generation: u64,
    ) -> Result<SelectedUpstreamPeer<'_>, UpstreamCallbackError> {
        let peer = unsafe { self.raw.as_ref() };
        if peer.name.is_null() {
            return Err(UpstreamCallbackError::MissingSelectedPeerName);
        }
        if !peer.name.is_aligned() {
            return Err(UpstreamCallbackError::MisalignedSelectedPeerName);
        }

        if status == Status::NGX_OK.0 {
            if peer.sockaddr.is_null() {
                return Err(UpstreamCallbackError::MissingSelectedPeerAddress);
            }
            if !peer.sockaddr.is_aligned() {
                return Err(UpstreamCallbackError::MisalignedSelectedPeerAddress);
            }
        } else {
            if peer.connection.is_null() {
                return Err(UpstreamCallbackError::MissingSelectedPeerConnection);
            }
            if !peer.connection.is_aligned() {
                return Err(UpstreamCallbackError::MisalignedSelectedPeerConnection);
            }
        }

        Ok(SelectedUpstreamPeer { status, generation, _callback: PhantomData })
    }

    fn log_failure(&self, action: &str, error: &UpstreamCallbackError) {
        let log = unsafe { self.raw.as_ref().log };
        let Some(log) = (unsafe { LogRef::from_raw(log) }) else {
            return;
        };
        crate::ngx_log_error!(NGX_LOG_ERR, log, "HTTP upstream {action} failed: {error}");
    }
}

/// Exact nginx peer release-state bits passed to a `free_peer` callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamPeerState(ngx_uint_t);

impl UpstreamPeerState {
    /// Returns the unchanged native state bits.
    pub fn bits(self) -> ngx_uint_t {
        self.0
    }
}

#[derive(Clone, Copy)]
pub(super) struct OriginalPeerCallbacks {
    pub(super) get: ngx_event_get_peer_pt,
    pub(super) free: ngx_event_free_peer_pt,
    pub(super) notify: ngx_event_notify_peer_pt,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub(super) set_session: ngx_event_set_peer_session_pt,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    pub(super) save_session: ngx_event_save_peer_session_pt,
    pub(super) data: *mut c_void,
}

/// One callback-local capability to invoke the saved original peer selector.
///
/// ```compile_fail
/// use ngx::http::{OriginalPeerGet, UpstreamPeerConnection};
///
/// fn duplicate(original: OriginalPeerGet<'_>, peer: &mut UpstreamPeerConnection<'_>) {
///     original.call(peer).unwrap();
///     original.call(peer).unwrap();
/// }
/// ```
pub struct OriginalPeerGet<'callback> {
    pub(super) original: OriginalPeerCallbacks,
    pub(super) generation: u64,
    pub(super) outcome: &'callback Cell<OriginalPeerGetOutcome>,
    pub(super) _callback: PhantomData<&'callback mut ngx_peer_connection_t>,
}

impl<'callback> OriginalPeerGet<'callback> {
    /// Consumes this capability and invokes the original peer selector once.
    pub fn call(
        self,
        peer: &'callback mut UpstreamPeerConnection<'_>,
    ) -> Result<UpstreamPeerSelection<'callback>, UpstreamCallbackError> {
        let callback = self.original.get.ok_or(UpstreamCallbackError::MissingOriginalGetPeer)?;
        let status =
            call_original(self.original, peer, |peer, data| unsafe { callback(peer, data) });
        match status {
            status if status == Status::NGX_ERROR.0 => {
                self.outcome.set(OriginalPeerGetOutcome::Unselected);
                Ok(UpstreamPeerSelection::Error)
            }
            status if status == Status::NGX_BUSY.0 => {
                self.outcome.set(OriginalPeerGetOutcome::Unselected);
                Ok(UpstreamPeerSelection::Busy)
            }
            status if status == Status::NGX_DECLINED.0 => {
                self.outcome.set(OriginalPeerGetOutcome::Unselected);
                Ok(UpstreamPeerSelection::Declined)
            }
            status
                if status == Status::NGX_OK.0
                    || status == Status::NGX_AGAIN.0
                    || status == Status::NGX_DONE.0 =>
            {
                self.outcome.set(OriginalPeerGetOutcome::Selected);
                Ok(UpstreamPeerSelection::Selected(peer.selected(status, self.generation)?))
            }
            status => {
                self.outcome.set(OriginalPeerGetOutcome::Unselected);
                Err(UpstreamCallbackError::InvalidOriginalGetStatus(status))
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum OriginalPeerGetOutcome {
    NotCalled,
    Unselected,
    Selected,
}

#[derive(Default)]
struct PeerSelectionState {
    generation: u64,
    active_generation: Option<u64>,
}

impl PeerSelectionState {
    fn begin(&mut self) -> Result<u64, UpstreamCallbackError> {
        if self.active_generation.is_some() {
            return Err(UpstreamCallbackError::PeerSelectionPendingRelease);
        }
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }
        Ok(self.generation)
    }

    fn select(&mut self, generation: u64) {
        self.active_generation = Some(generation);
    }

    fn release(&mut self) -> Result<(), UpstreamCallbackError> {
        self.active_generation
            .take()
            .map(|_| ())
            .ok_or(UpstreamCallbackError::PeerReleaseWithoutSelection)
    }
}

struct HttpUpstreamPeerData<T> {
    magic: u64,
    handler: TypeId,
    peer: NonNull<ngx_peer_connection_t>,
    value: T,
    original: OriginalPeerCallbacks,
    selection: PeerSelectionState,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<T> HttpUpstreamPeerData<T> {
    fn new<H>(
        peer: NonNull<ngx_peer_connection_t>,
        value: T,
        original: OriginalPeerCallbacks,
    ) -> Self
    where
        H: HttpUpstreamPeerHandler,
    {
        Self {
            magic: PEER_DATA_MAGIC,
            handler: TypeId::of::<H>(),
            peer,
            value,
            original,
            selection: PeerSelectionState::default(),
            _not_thread_safe: PhantomData,
        }
    }
}

fn call_original<R>(
    original: OriginalPeerCallbacks,
    peer: &mut UpstreamPeerConnection<'_>,
    callback: impl FnOnce(*mut ngx_peer_connection_t, *mut c_void) -> R,
) -> R {
    callback(peer.raw.as_ptr(), original.data)
}

fn release_original_peer(
    original: OriginalPeerCallbacks,
    peer: &mut UpstreamPeerConnection<'_>,
    state: UpstreamPeerState,
) {
    if let Some(callback) = original.free {
        call_original(original, peer, |peer, data| unsafe { callback(peer, data, state.bits()) });
    }
}

impl RequestUpstream {
    pub(super) fn install<H>(
        &mut self,
        pool: &Pool<'_>,
        value: H::Data,
    ) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        let peer = unsafe { &mut self.raw.as_mut().peer };
        let original = OriginalPeerCallbacks {
            get: peer.get,
            free: peer.free,
            notify: peer.notify,
            #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
            set_session: peer.set_session,
            #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
            save_session: peer.save_session,
            data: peer.data,
        };
        let owner = NonNull::from(&mut *peer);
        let data = pool
            .allocate_with_cleanup(|| HttpUpstreamPeerData::new::<H>(owner, value, original))
            .map_err(|_| UpstreamCallbackError::Allocation)?
            .into_non_null();

        peer.data = data.as_ptr().cast();
        peer.get = Some(raw_get_peer::<H>);
        peer.free = Some(raw_free_peer::<H>);
        if original.notify.is_some() {
            peer.notify = Some(raw_notify_peer::<H>);
        }
        #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
        {
            if original.set_session.is_some() {
                peer.set_session = Some(raw_set_session::<H>);
            }
            if original.save_session.is_some() {
                peer.save_session = Some(raw_save_session::<H>);
            }
        }
        Ok(())
    }
}

fn peer_data<H>(
    peer: &UpstreamPeerConnection<'_>,
    data: *mut c_void,
) -> Result<NonNull<HttpUpstreamPeerData<H::Data>>, UpstreamCallbackError>
where
    H: HttpUpstreamPeerHandler,
{
    let data = NonNull::new(data.cast::<HttpUpstreamPeerData<H::Data>>())
        .ok_or(UpstreamCallbackError::NullPeerData)?;
    if !data.as_ptr().is_aligned() {
        return Err(UpstreamCallbackError::MisalignedPeerData);
    }
    let value = unsafe { data.as_ref() };
    if value.magic != PEER_DATA_MAGIC
        || value.handler != TypeId::of::<H>()
        || value.peer != peer.raw
    {
        return Err(UpstreamCallbackError::ForeignPeerData);
    }

    Ok(data)
}

pub(super) unsafe extern "C" fn raw_get_peer<H>(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
) -> ngx_int_t
where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return Status::NGX_ERROR.0;
    };
    match (|| {
        let mut data = peer_data::<H>(&peer, data)?;
        let data = unsafe { data.as_mut() };
        let generation = data.selection.begin()?;
        let outcome = Cell::new(OriginalPeerGetOutcome::NotCalled);
        let returned = H::get(
            &mut peer,
            &mut data.value,
            OriginalPeerGet {
                original: data.original,
                generation,
                outcome: &outcome,
                _callback: PhantomData,
            },
        )
        .map(UpstreamPeerSelection::into_returned);

        match (outcome.get(), returned) {
            (
                OriginalPeerGetOutcome::Selected,
                Ok(ReturnedPeerSelection::Selected { status, generation: selected_generation }),
            ) if selected_generation == generation => {
                data.selection.select(generation);
                Ok(status)
            }
            (OriginalPeerGetOutcome::Selected, Ok(ReturnedPeerSelection::Selected { .. })) => {
                release_original_peer(data.original, &mut peer, UpstreamPeerState(0));
                Err(UpstreamCallbackError::ForeignSelectedPeer)
            }
            (OriginalPeerGetOutcome::Selected, Ok(ReturnedPeerSelection::Unselected(_))) => {
                release_original_peer(data.original, &mut peer, UpstreamPeerState(0));
                Err(UpstreamCallbackError::DiscardedOriginalPeerSelection)
            }
            (OriginalPeerGetOutcome::Selected, Err(error)) => {
                release_original_peer(data.original, &mut peer, UpstreamPeerState(0));
                Err(error)
            }
            (_, Ok(ReturnedPeerSelection::Selected { .. })) => {
                Err(UpstreamCallbackError::ForeignSelectedPeer)
            }
            (_, Ok(ReturnedPeerSelection::Unselected(status))) => Ok(status),
            (_, Err(error)) => Err(error),
        }
    })() {
        Ok(status) => status,
        Err(error) => {
            peer.log_failure("peer selection", &error);
            Status::NGX_ERROR.0
        }
    }
}

pub(super) unsafe extern "C" fn raw_free_peer<H>(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
    state: ngx_uint_t,
) where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return;
    };
    let result = (|| {
        let mut data = peer_data::<H>(&peer, data)?;
        let data = unsafe { data.as_mut() };
        data.selection.release()?;
        let state = UpstreamPeerState(state);
        release_original_peer(data.original, &mut peer, state);
        H::free(&mut peer, &mut data.value, state)
    })();
    if let Err(error) = result {
        peer.log_failure("peer release", &error);
    }
}

pub(super) unsafe extern "C" fn raw_notify_peer<H>(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
    type_: ngx_uint_t,
) where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return;
    };
    let data = match peer_data::<H>(&peer, data) {
        Ok(data) => unsafe { data.as_ref() },
        Err(error) => {
            peer.log_failure("peer notification", &error);
            return;
        }
    };
    let Some(callback) = data.original.notify else {
        return;
    };
    call_original(data.original, &mut peer, |peer, data| unsafe { callback(peer, data, type_) });
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
pub(super) unsafe extern "C" fn raw_set_session<H>(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
) -> ngx_int_t
where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return Status::NGX_ERROR.0;
    };
    let data = match peer_data::<H>(&peer, data) {
        Ok(data) => unsafe { data.as_ref() },
        Err(error) => {
            peer.log_failure("peer session lookup", &error);
            return Status::NGX_ERROR.0;
        }
    };
    let Some(callback) = data.original.set_session else {
        return Status::NGX_ERROR.0;
    };
    call_original(data.original, &mut peer, |peer, data| unsafe { callback(peer, data) })
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
pub(super) unsafe extern "C" fn raw_save_session<H>(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
) where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return;
    };
    let data = match peer_data::<H>(&peer, data) {
        Ok(data) => unsafe { data.as_ref() },
        Err(error) => {
            peer.log_failure("peer session save", &error);
            return;
        }
    };
    let Some(callback) = data.original.save_session else {
        return;
    };
    call_original(data.original, &mut peer, |peer, data| unsafe { callback(peer, data) });
}
