use core::any::TypeId;
use core::error;
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::NonNull;

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
    /// The initializer owner has no module server configuration for this upstream.
    MissingInitializerConfiguration,
    /// This module slot already owns an upstream initializer for the current configuration.
    DuplicateUpstreamInitializer,
    /// This module slot already owns a peer initializer for the current configuration.
    DuplicatePeerInitializer,
    /// The upstream initializer slot does not own this callback invocation.
    ForeignUpstreamInitializer,
    /// The peer initializer slot does not own this callback invocation.
    ForeignPeerInitializer,
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
    /// The saved original upstream initializer is absent.
    MissingOriginalInitUpstream,
    /// The saved original request peer initializer is absent.
    MissingOriginalInitPeer,
    /// The saved original peer getter is absent.
    MissingOriginalGetPeer,
    /// The saved original peer releaser is absent.
    MissingOriginalFreePeer,
    /// A successful upstream initializer left the request peer initializer absent.
    MissingPeerInitializer,
    /// A successful original request peer initializer left the peer getter absent.
    MissingPeerGetter,
    /// The original peer getter returned a status outside nginx's supported set.
    InvalidOriginalGetStatus(ngx_int_t),
    /// A newly selected peer has no socket address.
    MissingSelectedPeerAddress,
    /// A newly selected peer has a misaligned socket address.
    MisalignedSelectedPeerAddress,
    /// A selected peer has no display name.
    MissingSelectedPeerName,
    /// A selected peer has a misaligned display name.
    MisalignedSelectedPeerName,
    /// A reused or pending selected peer has no connection.
    MissingSelectedPeerConnection,
    /// A reused or pending selected peer has a misaligned connection.
    MisalignedSelectedPeerConnection,
    /// nginx could not retain handler data in the request pool.
    Allocation,
    /// Resolving a typed module configuration failed.
    Configuration(HttpConfigError),
    /// Resolving the active request pool failed.
    Request(RequestError),
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
            Self::MissingInitializerConfiguration => {
                formatter.write_str("upstream initializer owner has no server configuration")
            }
            Self::DuplicateUpstreamInitializer => {
                formatter.write_str("upstream initializer is already installed")
            }
            Self::DuplicatePeerInitializer => {
                formatter.write_str("upstream peer initializer is already installed")
            }
            Self::ForeignUpstreamInitializer => {
                formatter.write_str("upstream initializer belongs to another configuration")
            }
            Self::ForeignPeerInitializer => {
                formatter.write_str("upstream peer initializer belongs to another configuration")
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
            Self::MissingPeerInitializer => {
                formatter.write_str("upstream initialization installed no peer initializer")
            }
            Self::MissingPeerGetter => {
                formatter.write_str("peer initialization installed no peer getter")
            }
            Self::InvalidOriginalGetStatus(status) => {
                write!(formatter, "original peer getter returned unsupported status {status}")
            }
            Self::MissingSelectedPeerAddress => {
                formatter.write_str("selected upstream peer has no socket address")
            }
            Self::MisalignedSelectedPeerAddress => {
                formatter.write_str("selected upstream peer socket address is misaligned")
            }
            Self::MissingSelectedPeerName => {
                formatter.write_str("selected upstream peer has no name")
            }
            Self::MisalignedSelectedPeerName => {
                formatter.write_str("selected upstream peer name is misaligned")
            }
            Self::MissingSelectedPeerConnection => {
                formatter.write_str("selected upstream peer has no connection")
            }
            Self::MisalignedSelectedPeerConnection => {
                formatter.write_str("selected upstream peer connection is misaligned")
            }
            Self::Allocation => formatter.write_str("failed to allocate upstream peer data"),
            Self::Configuration(_) => {
                formatter.write_str("failed to resolve upstream configuration")
            }
            Self::Request(_) => formatter.write_str("failed to resolve upstream request state"),
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

/// Module-owned installation state for one upstream and peer initializer pair.
///
/// Embed one slot in the module's per-upstream server configuration and return it from the
/// initializer traits. A fresh server configuration is also the generation boundary: successful
/// installation records the owning upstream before publishing the native adapter.
pub struct UpstreamCallbackSlot {
    upstream: Option<NonNull<ngx_http_upstream_srv_conf_t>>,
    upstream_handler: Option<TypeId>,
    original_upstream: ngx_http_upstream_init_pt,
    peer: Option<NonNull<ngx_http_upstream_srv_conf_t>>,
    peer_handler: Option<TypeId>,
    original_peer: ngx_http_upstream_init_peer_pt,
}

impl UpstreamCallbackSlot {
    /// Creates an uninstalled callback slot.
    pub const fn new() -> Self {
        Self {
            upstream: None,
            upstream_handler: None,
            original_upstream: None,
            peer: None,
            peer_handler: None,
            original_peer: None,
        }
    }

    fn install_upstream<H>(
        &mut self,
        upstream: NonNull<ngx_http_upstream_srv_conf_t>,
        original: ngx_http_upstream_init_pt,
    ) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        if self.upstream.is_some() {
            return Err(UpstreamCallbackError::DuplicateUpstreamInitializer);
        }
        self.upstream = Some(upstream);
        self.upstream_handler = Some(TypeId::of::<H>());
        self.original_upstream = original;
        Ok(())
    }

    fn install_peer<H>(
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

    fn original_upstream<H>(
        &self,
        upstream: NonNull<ngx_http_upstream_srv_conf_t>,
    ) -> Result<OriginalUpstreamInit<H>, UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        if self.upstream != Some(upstream) || self.upstream_handler != Some(TypeId::of::<H>()) {
            return Err(UpstreamCallbackError::ForeignUpstreamInitializer);
        }
        Ok(OriginalUpstreamInit { callback: self.original_upstream, _handler: PhantomData })
    }

    fn original_peer<H>(
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

impl Default for UpstreamCallbackSlot {
    fn default() -> Self {
        Self::new()
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

    fn callback_slot<M>(
        &mut self,
        slot: impl FnOnce(&mut M::ServerConf) -> &mut UpstreamCallbackSlot,
    ) -> Result<NonNull<UpstreamCallbackSlot>, UpstreamCallbackError>
    where
        M: HttpModuleServerConf,
    {
        let configuration = self
            .module_conf_mut::<M>()?
            .ok_or(UpstreamCallbackError::MissingInitializerConfiguration)?;
        Ok(NonNull::from(slot(configuration)))
    }

    fn upstream_slot<H>(&mut self) -> Result<NonNull<UpstreamCallbackSlot>, UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        self.callback_slot::<H::Module>(H::callback_slot)
    }

    fn peer_slot<H>(&mut self) -> Result<NonNull<UpstreamCallbackSlot>, UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        self.callback_slot::<H::Module>(H::callback_slot)
    }

    fn original_upstream<H>(&mut self) -> Result<OriginalUpstreamInit<H>, UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        let owner = self.raw;
        let slot = self.upstream_slot::<H>()?;
        unsafe { slot.as_ref().original_upstream::<H>(owner) }
    }

    fn original_peer<H>(&mut self) -> Result<OriginalPeerInit<H>, UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        let owner = self.raw;
        let slot = self.peer_slot::<H>()?;
        unsafe { slot.as_ref().original_peer::<H>(owner) }
    }

    fn install_upstream<H>(&mut self) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        let mut owner = self.raw;
        let original = unsafe { owner.as_ref().peer.init_upstream };
        let mut slot = self.upstream_slot::<H>()?;
        unsafe { slot.as_mut().install_upstream::<H>(owner, original)? };
        unsafe { owner.as_mut().peer.init_upstream = Some(raw_init_upstream::<H>) };
        Ok(())
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

    /// Proves that this configured upstream has a request peer initializer.
    pub fn initialized(&self) -> Result<UpstreamInitialized<'_>, UpstreamCallbackError> {
        if unsafe { self.raw.as_ref().peer.init.is_none() } {
            return Err(UpstreamCallbackError::MissingPeerInitializer);
        }
        Ok(UpstreamInitialized { _upstream: PhantomData })
    }
}

/// Proof that a configured upstream has its mandatory request peer initializer.
///
/// ```compile_fail
/// use core::marker::PhantomData;
/// use ngx::http::UpstreamInitialized;
///
/// fn forge<'a>() -> UpstreamInitialized<'a> {
///     UpstreamInitialized { _upstream: PhantomData }
/// }
/// ```
pub struct UpstreamInitialized<'upstream> {
    _upstream: PhantomData<&'upstream ngx_http_upstream_srv_conf_t>,
}

/// Checked result returned by a saved native upstream initializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamInitStatus {
    /// The native initializer succeeded and installed a request peer initializer.
    Initialized,
    /// The native initializer returned a non-success status.
    Unavailable,
}

/// Result of typed upstream configuration initialization.
pub enum UpstreamInitialization<'upstream> {
    /// The mandatory request peer initializer is installed.
    Initialized(UpstreamInitialized<'upstream>),
    /// Configuration initialization did not succeed.
    Unavailable,
}

/// Owner-typed capability to invoke one saved upstream initializer.
///
/// The installation slot constructs this capability only for its handler and upstream generation.
/// Calling it consumes the capability, so one handler invocation cannot delegate twice.
///
/// ```compile_fail
/// use ngx::http::OriginalUpstreamInit;
///
/// fn forge<H>() -> OriginalUpstreamInit<H> {
///     OriginalUpstreamInit { callback: None, _handler: core::marker::PhantomData }
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::{OriginalUpstreamInit, UpstreamConfiguration, UpstreamServerConf};
///
/// fn call_twice<H>(
///     original: OriginalUpstreamInit<H>,
///     configuration: &mut UpstreamConfiguration<'_>,
///     upstream: &mut UpstreamServerConf<'_>,
/// ) {
///     let _ = original.call(configuration, upstream);
///     let _ = original.call(configuration, upstream);
/// }
/// ```
pub struct OriginalUpstreamInit<H> {
    callback: ngx_http_upstream_init_pt,
    _handler: PhantomData<fn() -> H>,
}

impl<H> OriginalUpstreamInit<H> {
    /// Delegates to the saved initializer with its original nginx arguments.
    pub fn call(
        self,
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamInitStatus, UpstreamCallbackError> {
        let callback = self.callback.ok_or(UpstreamCallbackError::MissingOriginalInitUpstream)?;
        let status = unsafe { callback(configuration.raw.as_ptr(), upstream.raw.as_ptr()) };
        if status != Status::NGX_OK.0 {
            return Ok(UpstreamInitStatus::Unavailable);
        }
        let _ = upstream.initialized()?;
        Ok(UpstreamInitStatus::Initialized)
    }
}

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
    callback: ngx_http_upstream_init_peer_pt,
    _handler: PhantomData<fn() -> H>,
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
/// Shared request operations remain available through dereferencing. The saved native peer
/// initializer can mutate the request only through [`OriginalPeerInit::call`]:
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

/// Installs a typed HTTP upstream initializer in its module-owned configuration slot.
///
/// Call this from the upstream directive setup after resolving nginx's upstream server
/// configuration. Repeated installation in the same module configuration is rejected before the
/// native callback changes.
pub fn install_upstream_initializer<H>(
    upstream: &mut ngx_http_upstream_srv_conf_t,
) -> Result<(), UpstreamCallbackError>
where
    H: HttpUpstreamInitializer,
{
    UpstreamServerConf::from_mut(upstream).install_upstream::<H>()
}

/// Typed HTTP upstream initializer.
///
/// An initializer must not panic; panics terminate the worker process.
pub trait HttpUpstreamInitializer: Sized + 'static {
    /// Module that owns this initializer's per-upstream installation slot.
    type Module: HttpModuleServerConf;

    /// Selects this initializer's unique slot from its module server configuration.
    ///
    /// Every call for one server configuration must return the same field. Installed slot state
    /// must not be inherited or copied into another server configuration.
    fn callback_slot(
        configuration: &mut <Self::Module as HttpModuleServerConf>::ServerConf,
    ) -> &mut UpstreamCallbackSlot;

    /// Initializes one configured upstream without exposing a forgeable success status.
    fn init<'upstream>(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &'upstream mut UpstreamServerConf<'_>,
        original: OriginalUpstreamInit<Self>,
    ) -> Result<UpstreamInitialization<'upstream>, UpstreamCallbackError>;
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

/// Typed request peer initializer, getter, and releaser for one upstream implementation.
///
/// Peer callbacks must not panic; panics terminate the worker process.
pub trait HttpUpstreamPeerHandler: Sized + 'static {
    /// Module that owns this handler's per-upstream installation slot.
    type Module: HttpModuleServerConf;

    /// Request-pool data retained while nginx uses this peer callback family.
    type Data: 'static;

    /// Selects this handler's unique slot from its module server configuration.
    ///
    /// Every call for one server configuration must return the same field. Installed slot state
    /// must not be inherited or copied into another server configuration.
    fn callback_slot(
        configuration: &mut <Self::Module as HttpModuleServerConf>::ServerConf,
    ) -> &mut UpstreamCallbackSlot;

    /// Initializes custom request peer data after any needed original initialization.
    ///
    /// Return [`UpstreamPeerInit::Unavailable`] when an original initializer does not succeed,
    /// without replacing the native peer callbacks.
    fn init(
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
        original: OriginalPeerInit<Self>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError>;

    /// Selects a peer or delegates selection to the saved original callback.
    fn get<'callback>(
        peer: &'callback mut UpstreamPeerConnection<'_>,
        data: &mut Self::Data,
        original: OriginalPeerGet<'callback>,
    ) -> Result<UpstreamPeerSelection<'callback>, UpstreamCallbackError>;

    /// Releases a peer or delegates release to the saved original callback.
    fn free<'callback>(
        peer: &'callback mut UpstreamPeerConnection<'_>,
        data: &mut Self::Data,
        state: UpstreamPeerState,
        original: OriginalPeerFree<'callback>,
    ) -> Result<(), UpstreamCallbackError>;
}

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
    fn status(self) -> ngx_int_t {
        match self {
            Self::Error => Status::NGX_ERROR.0,
            Self::Busy => Status::NGX_BUSY.0,
            Self::Declined => Status::NGX_DECLINED.0,
            Self::Selected(selected) => selected.status,
        }
    }
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

    fn selected(
        &mut self,
        status: ngx_int_t,
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

        Ok(SelectedUpstreamPeer { status, _callback: PhantomData })
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
/// fn duplicate(original: OriginalPeerGet<'_>, peer: &mut UpstreamPeerConnection<'_>) {
///     original.call(peer).unwrap();
///     original.call(peer).unwrap();
/// }
/// ```
pub struct OriginalPeerGet<'callback> {
    original: OriginalPeerCallbacks,
    _callback: PhantomData<&'callback mut ngx_peer_connection_t>,
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
            status if status == Status::NGX_ERROR.0 => Ok(UpstreamPeerSelection::Error),
            status if status == Status::NGX_BUSY.0 => Ok(UpstreamPeerSelection::Busy),
            status if status == Status::NGX_DECLINED.0 => Ok(UpstreamPeerSelection::Declined),
            status
                if status == Status::NGX_OK.0
                    || status == Status::NGX_AGAIN.0
                    || status == Status::NGX_DONE.0 =>
            {
                Ok(UpstreamPeerSelection::Selected(peer.selected(status)?))
            }
            status => Err(UpstreamCallbackError::InvalidOriginalGetStatus(status)),
        }
    }
}

/// One callback-local capability to invoke the saved original peer releaser.
///
/// ```compile_fail
/// use ngx::http::{OriginalPeerFree, UpstreamPeerConnection};
///
/// fn duplicate(original: OriginalPeerFree<'_>, peer: &mut UpstreamPeerConnection<'_>) {
///     original.call(peer).unwrap();
///     original.call(peer).unwrap();
/// }
/// ```
pub struct OriginalPeerFree<'callback> {
    original: OriginalPeerCallbacks,
    state: UpstreamPeerState,
    _callback: PhantomData<&'callback mut ngx_peer_connection_t>,
}

impl<'callback> OriginalPeerFree<'callback> {
    /// Consumes this capability and invokes the original peer releaser once.
    pub fn call(
        self,
        peer: &'callback mut UpstreamPeerConnection<'_>,
    ) -> Result<(), UpstreamCallbackError> {
        let callback = self.original.free.ok_or(UpstreamCallbackError::MissingOriginalFreePeer)?;
        call_original(self.original, peer, |peer, data| unsafe {
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

fn call_original<R>(
    original: OriginalPeerCallbacks,
    peer: &mut UpstreamPeerConnection<'_>,
    callback: impl FnOnce(*mut ngx_peer_connection_t, *mut c_void) -> R,
) -> R {
    callback(peer.raw.as_ptr(), original.data)
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
    if value.magic != PEER_DATA_MAGIC || value.handler != TypeId::of::<H>() {
        return Err(UpstreamCallbackError::ForeignPeerData);
    }

    Ok(data)
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
    match (|| {
        let mut upstream = unsafe { UpstreamServerConf::from_raw(upstream) }?;
        let original = upstream.original_upstream::<H>()?;
        match H::init(&mut configuration, &mut upstream, original)? {
            UpstreamInitialization::Initialized(_) => Ok(Status::NGX_OK.0),
            UpstreamInitialization::Unavailable => Ok(Status::NGX_ERROR.0),
        }
    })() {
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
            let result = (|| {
                let mut request_upstream = RequestUpstream::from_request(&request)?;
                let mut upstream = UpstreamServerConf::from_raw(upstream)?;
                let original = upstream.original_peer::<H>()?;
                match H::init(&mut request, &mut upstream, original)? {
                    UpstreamPeerInit::Install(value) => {
                        let pool = request.pool()?;
                        request_upstream.install::<H>(&pool, value)?;
                        Ok(Status::NGX_OK.0)
                    }
                    UpstreamPeerInit::Unavailable => Ok(Status::NGX_ERROR.0),
                }
            })();
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
    match (|| {
        let mut data = peer_data::<H>(data)?;
        let data = unsafe { data.as_mut() };
        let selection = H::get(
            &mut peer,
            &mut data.value,
            OriginalPeerGet { original: data.original, _callback: PhantomData },
        )?;
        Ok(selection.status())
    })() {
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
    let result = (|| {
        let mut data = peer_data::<H>(data)?;
        let data = unsafe { data.as_mut() };
        let state = UpstreamPeerState(state);
        H::free(
            &mut peer,
            &mut data.value,
            state,
            OriginalPeerFree { original: data.original, state, _callback: PhantomData },
        )
    })();
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
    let data = match peer_data::<H>(data) {
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
    let data = match peer_data::<H>(data) {
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
unsafe extern "C" fn raw_save_session<H>(peer: *mut ngx_peer_connection_t, data: *mut c_void)
where
    H: HttpUpstreamPeerHandler,
{
    let Ok(mut peer) = (unsafe { UpstreamPeerConnection::from_raw(peer) }) else {
        return;
    };
    let data = match peer_data::<H>(data) {
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

#[cfg(all(test, feature = "test-link"))]
#[path = "callback/tests.rs"]
mod tests;
