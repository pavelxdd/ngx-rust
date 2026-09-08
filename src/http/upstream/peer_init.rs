use core::any::TypeId;
use core::cell::Cell;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::core::{Pool, Status};
use crate::ffi::{
    NGX_LOG_ERR, ngx_http_request_t, ngx_http_upstream_init_peer_pt, ngx_http_upstream_srv_conf_t,
    ngx_http_upstream_t, ngx_int_t, ngx_pool_cleanup_add, ngx_pool_cleanup_t,
};
use crate::http::RequestRefMut;
use crate::log::LogRef;

use super::callback::{HttpUpstreamPeerHandler, UpstreamCallbackError, UpstreamCallbackSlot};
use super::init::UpstreamServerConf;

/// Checked result returned by a saved native request peer initializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamPeerInitStatus {
    /// The native initializer succeeded and installed a peer getter.
    Initialized,
    /// The native initializer returned a non-success status.
    Unavailable,
}

/// Owner-typed capability to invoke one saved request peer initializer.
///
/// The installation slot constructs this capability only for its handler and upstream generation.
/// Calling it consumes the capability, so one handler invocation cannot delegate twice.
///
/// ```compile_fail
/// use ngx::http::OriginalPeerInit;
///
/// fn forge<H>() -> OriginalPeerInit<H> {
///     OriginalPeerInit { callback: None, _handler: core::marker::PhantomData }
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::{OriginalPeerInit, UpstreamPeerInitRequest, UpstreamServerConf};
///
/// fn call_twice<H>(
///     original: OriginalPeerInit<H>,
///     request: &mut UpstreamPeerInitRequest<'_>,
///     upstream: &mut UpstreamServerConf<'_>,
/// ) {
///     let _ = original.call(request, upstream);
///     let _ = original.call(request, upstream);
/// }
/// ```
pub struct OriginalPeerInit<H> {
    pub(super) callback: ngx_http_upstream_init_peer_pt,
    pub(super) _handler: PhantomData<fn() -> H>,
}

impl<H> OriginalPeerInit<H> {
    /// Delegates to the saved request peer initializer with its original nginx arguments.
    pub fn call(
        self,
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInitStatus, UpstreamCallbackError> {
        let callback = self.callback.ok_or(UpstreamCallbackError::MissingOriginalInitPeer)?;
        let status = unsafe { callback(request.request.as_ptr(), upstream.raw.as_ptr()) };
        request.ensure_live()?;
        if status != Status::NGX_OK.0 {
            return Ok(UpstreamPeerInitStatus::Unavailable);
        }
        let request_upstream = RequestUpstream::from_request(request)?;
        if unsafe { request_upstream.raw.as_ref().peer.get.is_none() } {
            return Err(UpstreamCallbackError::MissingPeerGetter);
        }
        Ok(UpstreamPeerInitStatus::Initialized)
    }
}

/// Request peer-initialization capability without terminal request authority.
///
/// Only callback-safe logging is exposed. The saved native peer initializer can mutate the
/// request only through [`OriginalPeerInit::call`]:
///
/// ```compile_fail
/// use ngx::http::{HTTPStatus, UpstreamPeerInitRequest};
///
/// fn cannot_finalize(request: &mut UpstreamPeerInitRequest<'_>) {
///     request.finalize(HTTPStatus::BAD_REQUEST).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::UpstreamPeerInitRequest;
///
/// fn cannot_borrow_main(request: &UpstreamPeerInitRequest<'_>) {
///     let _main = request.main().unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::UpstreamPeerInitRequest;
///
/// fn cannot_access_raw_request(request: &UpstreamPeerInitRequest<'_>) {
///     let _raw = request.as_ptr();
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::UpstreamPeerInitRequest;
///
/// fn cannot_redirect(request: &mut UpstreamPeerInitRequest<'_>) {
///     request.internal_redirect("/other").unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::PoolChain;
/// use ngx::http::UpstreamPeerInitRequest;
///
/// fn cannot_send_output(request: &mut UpstreamPeerInitRequest<'_>, chain: PoolChain<'_>) {
///     request.output_filter(chain).unwrap();
/// }
/// ```
pub struct UpstreamPeerInitRequest<'callback> {
    request: RequestRefMut<'callback>,
    live: &'callback Cell<bool>,
}

impl UpstreamPeerInitRequest<'_> {
    fn ensure_live(&self) -> Result<(), UpstreamCallbackError> {
        if !self.live.get() {
            return Err(UpstreamCallbackError::RequestDestroyedDuringPeerInitialization);
        }
        Ok(())
    }

    /// Returns the live request's connection logger.
    pub fn log(&self) -> Result<Option<LogRef<'_>>, UpstreamCallbackError> {
        self.ensure_live()?;
        self.request.log().map_err(Into::into)
    }
}

struct PeerInitLiveness<'callback> {
    live: &'callback Cell<bool>,
    cleanup: NonNull<ngx_pool_cleanup_t>,
}

impl<'callback> PeerInitLiveness<'callback> {
    fn register(
        pool: &Pool<'_>,
        live: &'callback Cell<bool>,
    ) -> Result<Self, UpstreamCallbackError> {
        let cleanup = NonNull::new(unsafe { ngx_pool_cleanup_add(pool.as_ptr(), 0) })
            .ok_or(UpstreamCallbackError::Allocation)?;
        // The cleanup is disabled before `live` leaves this stack frame. If native code destroys
        // the pool during initialization, the cleanup only marks the request inaccessible.
        unsafe {
            (*cleanup.as_ptr()).data = ptr::from_ref(live).cast_mut().cast();
            (*cleanup.as_ptr()).handler = Some(mark_peer_init_request_destroyed);
        }
        Ok(Self { live, cleanup })
    }
}

impl Drop for PeerInitLiveness<'_> {
    fn drop(&mut self) {
        if !self.live.get() {
            return;
        }
        unsafe {
            (*self.cleanup.as_ptr()).handler = None;
            (*self.cleanup.as_ptr()).data = ptr::null_mut();
        }
    }
}

unsafe extern "C" fn mark_peer_init_request_destroyed(data: *mut c_void) {
    if let Some(live) = NonNull::new(data.cast::<Cell<bool>>()) {
        unsafe { live.as_ref() }.set(false);
    }
}

/// Result of initializing a request's typed upstream peer callbacks.
///
/// ```compile_fail
/// use ngx::http::UpstreamPeerInit;
///
/// fn forge() -> UpstreamPeerInit<()> {
///     UpstreamPeerInit::Return(0)
/// }
/// ```
pub enum UpstreamPeerInit<T> {
    /// Install the typed peer data and callback adapters around the original peer callbacks.
    Install(T),
    /// Return a non-success status without installing typed peer data or callbacks.
    Unavailable,
}

pub(super) struct RequestUpstream {
    pub(super) raw: NonNull<ngx_http_upstream_t>,
}

impl RequestUpstream {
    fn from_request(request: &UpstreamPeerInitRequest<'_>) -> Result<Self, UpstreamCallbackError> {
        request.ensure_live()?;
        let request = unsafe { request.request.as_ptr() };
        let raw = NonNull::new(unsafe { (*request).upstream })
            .ok_or(UpstreamCallbackError::MissingRequestUpstream)?;
        if !raw.as_ptr().is_aligned() {
            return Err(UpstreamCallbackError::MisalignedRequestUpstream);
        }

        Ok(Self { raw })
    }
}

pub(super) unsafe extern "C" fn raw_init_peer<H>(
    request: *mut ngx_http_request_t,
    upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t
where
    H: HttpUpstreamPeerHandler,
{
    unsafe {
        RequestRefMut::with_raw(request, |request| {
            let pool = match request.pool() {
                Ok(pool) => pool.as_ptr(),
                Err(error) => {
                    let error = UpstreamCallbackError::Request(error);
                    log_request_failure(&request, "peer initialization", &error);
                    return Status::NGX_ERROR.0;
                }
            };
            let pool = Pool::from_raw(pool).expect("checked request pool");
            let live = Cell::new(true);
            let liveness = match PeerInitLiveness::register(&pool, &live) {
                Ok(liveness) => liveness,
                Err(error) => {
                    log_request_failure(&request, "peer initialization", &error);
                    return Status::NGX_ERROR.0;
                }
            };
            let mut request = UpstreamPeerInitRequest { request, live: &live };
            let result = (|| {
                let mut request_upstream = RequestUpstream::from_request(&request)?;
                let mut upstream = UpstreamServerConf::from_raw(upstream)?;
                let original = upstream.original_peer::<H>()?;
                let initialized = H::init(&mut request, &mut upstream, original)?;
                request.ensure_live()?;
                let current_upstream = RequestUpstream::from_request(&request)?;
                if current_upstream.raw != request_upstream.raw {
                    return Err(UpstreamCallbackError::ReplacedRequestUpstream);
                }
                match initialized {
                    UpstreamPeerInit::Install(value) => {
                        request_upstream.install::<H>(&pool, value)?;
                        Ok(Status::NGX_OK.0)
                    }
                    UpstreamPeerInit::Unavailable => Ok(Status::NGX_ERROR.0),
                }
            })();
            let request_live = request.ensure_live().is_ok();
            drop(liveness);
            match result {
                Ok(status) => status,
                Err(error) => {
                    if request_live {
                        log_request_failure(&request.request, "peer initialization", &error);
                    }
                    Status::NGX_ERROR.0
                }
            }
        })
    }
    .unwrap_or(Status::NGX_ERROR.0)
}

impl UpstreamCallbackSlot {
    pub(super) fn install_peer<H>(
        &mut self,
        upstream: NonNull<ngx_http_upstream_srv_conf_t>,
        original: ngx_http_upstream_init_peer_pt,
    ) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        if self.peer.is_some() {
            return Err(UpstreamCallbackError::DuplicatePeerInitializer);
        }
        self.peer = Some(upstream);
        self.peer_handler = Some(TypeId::of::<H>());
        self.original_peer = original;
        Ok(())
    }

    pub(super) fn original_peer<H>(
        &self,
        upstream: NonNull<ngx_http_upstream_srv_conf_t>,
    ) -> Result<OriginalPeerInit<H>, UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        if self.peer != Some(upstream) || self.peer_handler != Some(TypeId::of::<H>()) {
            return Err(UpstreamCallbackError::ForeignPeerInitializer);
        }
        Ok(OriginalPeerInit { callback: self.original_peer, _handler: PhantomData })
    }
}

impl<'callback> UpstreamServerConf<'callback> {
    fn peer_slot<H>(&mut self) -> Result<NonNull<UpstreamCallbackSlot>, UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        self.callback_slot::<H::Module>(H::callback_slot)
    }

    pub(super) fn original_peer<H>(&mut self) -> Result<OriginalPeerInit<H>, UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        let owner = self.raw;
        let slot = self.peer_slot::<H>()?;
        unsafe { slot.as_ref().original_peer::<H>(owner) }
    }

    /// Installs this handler's request peer initializer for the current upstream configuration.
    pub fn install_peer_initializer<H>(&mut self) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        let mut owner = self.raw;
        let original = unsafe { owner.as_ref().peer.init };
        let mut slot = self.peer_slot::<H>()?;
        unsafe { slot.as_mut().install_peer::<H>(owner, original)? };
        unsafe { owner.as_mut().peer.init = Some(raw_init_peer::<H>) };
        Ok(())
    }
}

fn log_request_failure(request: &RequestRefMut<'_>, action: &str, error: &UpstreamCallbackError) {
    let Ok(Some(log)) = request.log() else {
        return;
    };
    crate::ngx_log_error!(NGX_LOG_ERR, log, "HTTP upstream {action} failed: {error}");
}
