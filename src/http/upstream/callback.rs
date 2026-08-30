use core::any::TypeId;
use core::error;
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::{self, NonNull};

use crate::core::{Pool, Status};
use crate::ffi::{
    NGX_LOG_EMERG, NGX_LOG_ERR, ngx_conf_t, ngx_event_free_peer_pt, ngx_event_get_peer_pt,
    ngx_event_notify_peer_pt, ngx_http_request_t, ngx_http_upstream_init_peer_pt,
    ngx_http_upstream_init_pt, ngx_http_upstream_srv_conf_t, ngx_http_upstream_t, ngx_int_t,
    ngx_peer_connection_t, ngx_uint_t,
};
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
use crate::ffi::{ngx_event_save_peer_session_pt, ngx_event_set_peer_session_pt};
use crate::http::{HttpConfigError, HttpModuleServerConf, RequestError, RequestRefMut};
use crate::log::LogRef;

const PEER_DATA_MAGIC: u64 = 0x7d5a_1bc8_9e34_f602;

/// Failure while entering or delegating an HTTP upstream callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamCallbackError {
    /// nginx supplied no configuration parser pointer.
    NullConfiguration,
    /// The configuration parser pointer is misaligned.
    MisalignedConfiguration,
    /// The configuration parser has no usable nginx pool.
    MissingConfigurationPool,
    /// nginx supplied no upstream server-configuration pointer.
    NullUpstream,
    /// The upstream server-configuration pointer is misaligned.
    MisalignedUpstream,
    /// The request has no active upstream object.
    MissingRequestUpstream,
    /// The request upstream pointer is misaligned.
    MisalignedRequestUpstream,
    /// nginx supplied no peer-connection pointer.
    NullPeer,
    /// The peer-connection pointer is misaligned.
    MisalignedPeer,
    /// nginx supplied no peer callback data pointer.
    NullPeerData,
    /// The peer callback data pointer is misaligned.
    MisalignedPeerData,
    /// The peer callback data does not belong to this typed handler.
    ForeignPeerData,
    /// nginx invoked a peer callback with data different from `pc->data`.
    PeerDataMismatch,
    /// The saved original upstream initializer is absent.
    MissingOriginalInitUpstream,
    /// The saved original request peer initializer is absent.
    MissingOriginalInitPeer,
    /// The saved original peer getter is absent.
    MissingOriginalGetPeer,
    /// The saved original peer releaser is absent.
    MissingOriginalFreePeer,
    /// nginx could not retain handler data in the request pool.
    Allocation,
    /// Resolving a typed module configuration failed.
    Configuration(HttpConfigError),
    /// Resolving the active request pool failed.
    Request(RequestError),
    /// A Rust upstream callback panicked.
    CallbackPanicked,
}

impl fmt::Display for UpstreamCallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullConfiguration => formatter.write_str("upstream configuration is null"),
            Self::MisalignedConfiguration => {
                formatter.write_str("upstream configuration is misaligned")
            }
            Self::MissingConfigurationPool => {
                formatter.write_str("upstream configuration has no usable pool")
            }
            Self::NullUpstream => formatter.write_str("upstream server configuration is null"),
            Self::MisalignedUpstream => {
                formatter.write_str("upstream server configuration is misaligned")
            }
            Self::MissingRequestUpstream => formatter.write_str("request has no upstream"),
            Self::MisalignedRequestUpstream => {
                formatter.write_str("request upstream is misaligned")
            }
            Self::NullPeer => formatter.write_str("upstream peer is null"),
            Self::MisalignedPeer => formatter.write_str("upstream peer is misaligned"),
            Self::NullPeerData => formatter.write_str("upstream peer data is null"),
            Self::MisalignedPeerData => formatter.write_str("upstream peer data is misaligned"),
            Self::ForeignPeerData => {
                formatter.write_str("upstream peer data belongs to another handler")
            }
            Self::PeerDataMismatch => {
                formatter.write_str("upstream peer callback data does not match the peer")
            }
            Self::MissingOriginalInitUpstream => {
                formatter.write_str("upstream has no original initializer")
            }
            Self::MissingOriginalInitPeer => {
                formatter.write_str("upstream has no original peer initializer")
            }
            Self::MissingOriginalGetPeer => {
                formatter.write_str("upstream has no original peer getter")
            }
            Self::MissingOriginalFreePeer => {
                formatter.write_str("upstream has no original peer releaser")
            }
            Self::Allocation => formatter.write_str("failed to allocate upstream peer data"),
            Self::Configuration(_) => {
                formatter.write_str("failed to resolve upstream configuration")
            }
            Self::Request(_) => formatter.write_str("failed to resolve upstream request state"),
            Self::CallbackPanicked => formatter.write_str("upstream callback panicked"),
        }
    }
}

impl error::Error for UpstreamCallbackError {}

impl From<HttpConfigError> for UpstreamCallbackError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<RequestError> for UpstreamCallbackError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Checked configuration callback view supplied to an upstream initializer.
///
/// ```compile_fail
/// use ngx::http::UpstreamConfiguration;
///
/// fn escape<'a>(
///     configuration: &'a mut UpstreamConfiguration<'_>,
/// ) -> &'static mut UpstreamConfiguration<'static> {
///     configuration
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::UpstreamConfiguration;
///
/// fn duplicate(configuration: UpstreamConfiguration<'_>) {
///     let first = configuration;
///     let second = configuration;
/// }
/// ```
pub struct UpstreamConfiguration<'callback> {
    raw: NonNull<ngx_conf_t>,
    _callback: PhantomData<&'callback mut ngx_conf_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl UpstreamConfiguration<'_> {
    /// # Safety
    ///
    /// `configuration` must point to the live nginx parser state for the callback. Its
    /// configuration pool must not be reset before that pool is destroyed.
    unsafe fn from_raw(configuration: *mut ngx_conf_t) -> Result<Self, UpstreamCallbackError> {
        let raw = NonNull::new(configuration).ok_or(UpstreamCallbackError::NullConfiguration)?;
        if !configuration.is_aligned() {
            return Err(UpstreamCallbackError::MisalignedConfiguration);
        }

        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Returns the nginx configuration pool for copied URL and module data.
    pub fn pool(&self) -> Result<Pool<'_>, UpstreamCallbackError> {
        unsafe { Pool::from_raw(self.raw.as_ref().pool) }
            .ok_or(UpstreamCallbackError::MissingConfigurationPool)
    }

    fn log_failure(&mut self, action: &str, error: &UpstreamCallbackError) {
        if unsafe { self.raw.as_ref().log.is_null() } {
            return;
        }
        crate::ngx_conf_log_error!(
            NGX_LOG_EMERG,
            self.raw.as_ptr(),
            "HTTP upstream {action} failed: {error}"
        );
    }
}

/// Checked upstream server-configuration callback view.
pub struct UpstreamServerConf<'callback> {
    raw: NonNull<ngx_http_upstream_srv_conf_t>,
    _callback: PhantomData<&'callback mut ngx_http_upstream_srv_conf_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> UpstreamServerConf<'callback> {
    fn from_mut(upstream: &'callback mut ngx_http_upstream_srv_conf_t) -> Self {
        Self { raw: NonNull::from(upstream), _callback: PhantomData, _not_thread_safe: PhantomData }
    }

    unsafe fn from_raw(
        upstream: *mut ngx_http_upstream_srv_conf_t,
    ) -> Result<Self, UpstreamCallbackError> {
        let raw = NonNull::new(upstream).ok_or(UpstreamCallbackError::NullUpstream)?;
        if !upstream.is_aligned() {
            return Err(UpstreamCallbackError::MisalignedUpstream);
        }

        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Resolves one typed module server configuration from this upstream configuration.
    pub fn module_conf<M>(&self) -> Result<Option<&M::ServerConf>, HttpConfigError>
    where
        M: HttpModuleServerConf,
    {
        Ok(crate::http::conf::upstream_server_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Resolves one mutable typed module server configuration from this upstream configuration.
    pub fn module_conf_mut<M>(&mut self) -> Result<Option<&mut M::ServerConf>, HttpConfigError>
    where
        M: HttpModuleServerConf,
    {
        Ok(crate::http::conf::upstream_server_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|mut value| unsafe { value.as_mut() }))
    }

    /// Returns the current upstream initializer, including an absent initializer.
    ///
    /// During [`HttpUpstreamInitializer::init`], this is the installed typed adapter. Delegate
    /// through the callback returned by [`install_upstream_initializer`] and retained in module
    /// configuration instead.
    pub fn init_upstream(&self) -> UpstreamInitCallback {
        UpstreamInitCallback(unsafe { self.raw.as_ref().peer.init_upstream })
    }

    /// Replaces the upstream initializer with a typed callback and returns the previous one.
    pub fn replace_init_upstream<H>(&mut self) -> UpstreamInitCallback
    where
        H: HttpUpstreamInitializer,
    {
        let previous = self.init_upstream();
        unsafe { self.raw.as_mut().peer.init_upstream = Some(raw_init_upstream::<H>) };
        previous
    }

    /// Returns the current request peer initializer, including an absent initializer.
    ///
    /// During [`HttpUpstreamPeerHandler::init`], this is the installed typed adapter. Delegate
    /// through the callback returned by [`Self::replace_init_peer`] and retained in module
    /// configuration instead.
    pub fn init_peer(&self) -> UpstreamPeerInitCallback {
        UpstreamPeerInitCallback(unsafe { self.raw.as_ref().peer.init })
    }

    /// Replaces the request peer initializer with a typed callback and returns the previous one.
    pub fn replace_init_peer<H>(&mut self) -> UpstreamPeerInitCallback
    where
        H: HttpUpstreamPeerHandler,
    {
        let previous = self.init_peer();
        unsafe { self.raw.as_mut().peer.init = Some(raw_init_peer::<H>) };
        previous
    }
}

/// Saved HTTP upstream initializer that can be called through checked callback views.
#[derive(Clone, Copy, Default)]
pub struct UpstreamInitCallback(ngx_http_upstream_init_pt);

impl UpstreamInitCallback {
    /// Returns whether nginx provided an original initializer.
    pub fn is_present(self) -> bool {
        self.0.is_some()
    }

    /// Delegates to the saved initializer with its original nginx arguments.
    pub fn call(
        self,
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        let callback = self.0.ok_or(UpstreamCallbackError::MissingOriginalInitUpstream)?;
        Ok(unsafe { callback(configuration.raw.as_ptr(), upstream.raw.as_ptr()) })
    }
}

/// Saved HTTP request peer initializer that can be called through checked callback views.
#[derive(Clone, Copy, Default)]
pub struct UpstreamPeerInitCallback(ngx_http_upstream_init_peer_pt);

impl UpstreamPeerInitCallback {
    /// Returns whether nginx provided an original request peer initializer.
    pub fn is_present(self) -> bool {
        self.0.is_some()
    }

    /// Delegates to the saved request peer initializer with its original nginx arguments.
    pub fn call(
        self,
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        let callback = self.0.ok_or(UpstreamCallbackError::MissingOriginalInitPeer)?;
        Ok(unsafe { callback(request.request.as_ptr(), upstream.raw.as_ptr()) })
    }
}

/// Request peer-initialization capability without terminal request authority.
///
/// Shared request operations remain available through dereferencing. The saved native peer
/// initializer can mutate the request only through [`UpstreamPeerInitCallback::call`]:
///
/// ```compile_fail
/// use ngx::http::{HTTPStatus, UpstreamPeerInitRequest};
///
/// fn cannot_finalize(request: &mut UpstreamPeerInitRequest<'_>) {
///     request.finalize(HTTPStatus::BAD_REQUEST).unwrap();
/// }
/// ```
pub struct UpstreamPeerInitRequest<'callback> {
    request: RequestRefMut<'callback>,
}

impl<'callback> Deref for UpstreamPeerInitRequest<'callback> {
    type Target = RequestRefMut<'callback>;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

/// Installs a typed HTTP upstream initializer and returns the original callback.
///
/// Call this from the upstream directive setup after resolving nginx's upstream server
/// configuration. The returned callback can be retained in the module's server configuration.
pub fn install_upstream_initializer<H>(
    upstream: &mut ngx_http_upstream_srv_conf_t,
) -> UpstreamInitCallback
where
    H: HttpUpstreamInitializer,
{
    let mut upstream = UpstreamServerConf::from_mut(upstream);
    upstream.replace_init_upstream::<H>()
}

/// Typed HTTP upstream initializer.
pub trait HttpUpstreamInitializer: 'static {
    /// Initializes one configured upstream and returns the exact nginx status to propagate.
    fn init(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError>;
}

/// Result of initializing a request's typed upstream peer callbacks.
pub enum UpstreamPeerInit<T> {
    /// Install the typed peer data and callback adapters around the original peer callbacks.
    Install(T),
    /// Return this nginx status without installing typed peer data or callbacks.
    Return(ngx_int_t),
}

/// Typed request peer initializer, getter, and releaser for one upstream implementation.
pub trait HttpUpstreamPeerHandler: 'static {
    /// Request-pool data retained while nginx uses this peer callback family.
    type Data: 'static;

    /// Initializes custom request peer data after any needed original initialization.
    ///
    /// Return [`UpstreamPeerInit::Return`] to preserve an original initializer's non-OK status
    /// without replacing the native peer callbacks.
    fn init(
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError>;

    /// Selects a peer or delegates selection to the saved original callback.
    fn get(
        peer: &mut UpstreamPeerConnection<'_>,
        data: &mut Self::Data,
        original: OriginalPeerGet,
    ) -> Result<ngx_int_t, UpstreamCallbackError>;

    /// Releases a peer or delegates release to the saved original callback.
    fn free(
        peer: &mut UpstreamPeerConnection<'_>,
        data: &mut Self::Data,
        state: UpstreamPeerState,
        original: OriginalPeerFree,
    ) -> Result<(), UpstreamCallbackError>;
}

/// Checked peer-connection callback view.
pub struct UpstreamPeerConnection<'callback> {
    raw: NonNull<ngx_peer_connection_t>,
    _callback: PhantomData<&'callback mut ngx_peer_connection_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl UpstreamPeerConnection<'_> {
    unsafe fn from_raw(peer: *mut ngx_peer_connection_t) -> Result<Self, UpstreamCallbackError> {
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

    fn data(&self) -> *mut c_void {
        unsafe { self.raw.as_ref().data }
    }

    fn set_data(&mut self, data: *mut c_void) {
        unsafe { self.raw.as_mut().data = data };
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
struct OriginalPeerCallbacks {
    get: ngx_event_get_peer_pt,
    free: ngx_event_free_peer_pt,
    notify: ngx_event_notify_peer_pt,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    set_session: ngx_event_set_peer_session_pt,
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    save_session: ngx_event_save_peer_session_pt,
    data: *mut c_void,
}

/// One callback-local capability to invoke the saved original peer selector.
///
/// ```compile_fail
/// use ngx::http::{OriginalPeerGet, UpstreamPeerConnection};
///
/// fn duplicate(original: OriginalPeerGet, peer: &mut UpstreamPeerConnection<'_>) {
///     original.call(peer).unwrap();
///     original.call(peer).unwrap();
/// }
/// ```
pub struct OriginalPeerGet {
    original: OriginalPeerCallbacks,
}

impl OriginalPeerGet {
    /// Consumes this capability and invokes the original peer selector once.
    pub fn call(
        self,
        peer: &mut UpstreamPeerConnection<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        let callback = self.original.get.ok_or(UpstreamCallbackError::MissingOriginalGetPeer)?;
        Ok(with_original_data(self.original, peer, |peer, data| unsafe { callback(peer, data) }))
    }
}

/// One callback-local capability to invoke the saved original peer releaser.
///
/// ```compile_fail
/// use ngx::http::{OriginalPeerFree, UpstreamPeerConnection};
///
/// fn duplicate(original: OriginalPeerFree, peer: &mut UpstreamPeerConnection<'_>) {
///     original.call(peer).unwrap();
///     original.call(peer).unwrap();
/// }
/// ```
pub struct OriginalPeerFree {
    original: OriginalPeerCallbacks,
    state: UpstreamPeerState,
}

impl OriginalPeerFree {
    /// Consumes this capability and invokes the original peer releaser once.
    pub fn call(self, peer: &mut UpstreamPeerConnection<'_>) -> Result<(), UpstreamCallbackError> {
        let callback = self.original.free.ok_or(UpstreamCallbackError::MissingOriginalFreePeer)?;
        with_original_data(self.original, peer, |peer, data| unsafe {
            callback(peer, data, self.state.bits())
        });
        Ok(())
    }
}

struct HttpUpstreamPeerData<T> {
    magic: u64,
    handler: TypeId,
    value: T,
    original: OriginalPeerCallbacks,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<T> HttpUpstreamPeerData<T> {
    fn new<H>(value: T, original: OriginalPeerCallbacks) -> Self
    where
        H: HttpUpstreamPeerHandler,
    {
        Self {
            magic: PEER_DATA_MAGIC,
            handler: TypeId::of::<H>(),
            value,
            original,
            _not_thread_safe: PhantomData,
        }
    }
}

fn with_original_data<R>(
    original: OriginalPeerCallbacks,
    peer: &mut UpstreamPeerConnection<'_>,
    callback: impl FnOnce(*mut ngx_peer_connection_t, *mut c_void) -> R,
) -> R {
    let previous = peer.data();
    peer.set_data(original.data);
    let result = callback(peer.raw.as_ptr(), original.data);
    peer.set_data(previous);
    result
}

struct RequestUpstream {
    raw: NonNull<ngx_http_upstream_t>,
}

impl RequestUpstream {
    fn from_request(request: &UpstreamPeerInitRequest<'_>) -> Result<Self, UpstreamCallbackError> {
        let request = unsafe { request.request.as_ptr() };
        let raw = NonNull::new(unsafe { (*request).upstream })
            .ok_or(UpstreamCallbackError::MissingRequestUpstream)?;
        if !raw.as_ptr().is_aligned() {
            return Err(UpstreamCallbackError::MisalignedRequestUpstream);
        }

        Ok(Self { raw })
    }

    fn install<H>(&mut self, pool: &Pool<'_>, value: H::Data) -> Result<(), UpstreamCallbackError>
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
        let data = pool
            .allocate_with_cleanup(|| HttpUpstreamPeerData::new::<H>(value, original))
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
    if !ptr::eq(peer.data(), data.as_ptr().cast()) {
        return Err(UpstreamCallbackError::PeerDataMismatch);
    }

    let value = unsafe { data.as_ref() };
    if value.magic != PEER_DATA_MAGIC || value.handler != TypeId::of::<H>() {
        return Err(UpstreamCallbackError::ForeignPeerData);
    }

    Ok(data)
}

fn catch_upstream_callback<T>(
    callback: impl FnOnce() -> Result<T, UpstreamCallbackError>,
) -> Result<T, UpstreamCallbackError> {
    #[cfg(feature = "std")]
    {
        std::panic::catch_unwind(core::panic::AssertUnwindSafe(callback))
            .unwrap_or(Err(UpstreamCallbackError::CallbackPanicked))
    }

    #[cfg(not(feature = "std"))]
    {
        callback()
    }
}

fn log_request_failure(request: &RequestRefMut<'_>, action: &str, error: &UpstreamCallbackError) {
    let Ok(Some(log)) = request.log() else {
        return;
    };
    crate::ngx_log_error!(NGX_LOG_ERR, log, "HTTP upstream {action} failed: {error}");
}

unsafe extern "C" fn raw_init_upstream<H>(
    configuration: *mut ngx_conf_t,
    upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t
where
    H: HttpUpstreamInitializer,
{
    // SAFETY: nginx invokes this initializer with its stable configuration pool.
    let Ok(mut configuration) = (unsafe { UpstreamConfiguration::from_raw(configuration) }) else {
        return Status::NGX_ERROR.0;
    };
    match catch_upstream_callback(|| {
        let mut upstream = unsafe { UpstreamServerConf::from_raw(upstream) }?;
        H::init(&mut configuration, &mut upstream)
    }) {
        Ok(status) => status,
        Err(error) => {
            configuration.log_failure("initialization", &error);
            Status::NGX_ERROR.0
        }
    }
}

unsafe extern "C" fn raw_init_peer<H>(
    request: *mut ngx_http_request_t,
    upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t
where
    H: HttpUpstreamPeerHandler,
{
    unsafe {
        RequestRefMut::with_raw(request, |request| {
            let mut request = UpstreamPeerInitRequest { request };
            let result = catch_upstream_callback(|| {
                let mut request_upstream = RequestUpstream::from_request(&request)?;
                let mut upstream = UpstreamServerConf::from_raw(upstream)?;
                match H::init(&mut request, &mut upstream)? {
                    UpstreamPeerInit::Install(value) => {
                        let pool = request.pool()?;
                        request_upstream.install::<H>(&pool, value)?;
                        Ok(Status::NGX_OK.0)
                    }
                    UpstreamPeerInit::Return(status) => Ok(status),
                }
            });
            match result {
                Ok(status) => status,
                Err(error) => {
                    log_request_failure(&request, "peer initialization", &error);
                    Status::NGX_ERROR.0
                }
            }
        })
    }
    .unwrap_or(Status::NGX_ERROR.0)
}

unsafe extern "C" fn raw_get_peer<H>(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
) -> ngx_int_t
where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return Status::NGX_ERROR.0;
    };
    match catch_upstream_callback(|| {
        let mut data = peer_data::<H>(&peer, data)?;
        let data = unsafe { data.as_mut() };
        H::get(&mut peer, &mut data.value, OriginalPeerGet { original: data.original })
    }) {
        Ok(status) => status,
        Err(error) => {
            peer.log_failure("peer selection", &error);
            Status::NGX_ERROR.0
        }
    }
}

unsafe extern "C" fn raw_free_peer<H>(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
    state: ngx_uint_t,
) where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return;
    };
    let result = catch_upstream_callback(|| {
        let mut data = peer_data::<H>(&peer, data)?;
        let data = unsafe { data.as_mut() };
        let state = UpstreamPeerState(state);
        H::free(
            &mut peer,
            &mut data.value,
            state,
            OriginalPeerFree { original: data.original, state },
        )
    });
    if let Err(error) = result {
        peer.log_failure("peer release", &error);
    }
}

unsafe extern "C" fn raw_notify_peer<H>(
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
    with_original_data(data.original, &mut peer, |peer, data| unsafe {
        callback(peer, data, type_)
    });
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
unsafe extern "C" fn raw_set_session<H>(
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
    with_original_data(data.original, &mut peer, |peer, data| unsafe { callback(peer, data) })
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
unsafe extern "C" fn raw_save_session<H>(peer: *mut ngx_peer_connection_t, data: *mut c_void)
where
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
    with_original_data(data.original, &mut peer, |peer, data| unsafe { callback(peer, data) });
}

#[cfg(all(test, feature = "test-link"))]
#[path = "callback/tests.rs"]
mod tests;
