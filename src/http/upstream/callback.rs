use core::any::TypeId;
use core::error;
use core::fmt;
use core::ptr::NonNull;

use crate::ffi::{
    ngx_http_upstream_init_peer_pt, ngx_http_upstream_init_pt, ngx_http_upstream_srv_conf_t,
    ngx_int_t,
};
use crate::http::{HttpConfigError, HttpModuleServerConf, RequestError};

use super::init::{
    OriginalUpstreamInit, UpstreamConfiguration, UpstreamInitialization, UpstreamServerConf,
};
use super::peer::{
    OriginalPeerGet, UpstreamPeerConnection, UpstreamPeerSelection, UpstreamPeerState,
};
use super::peer_init::{OriginalPeerInit, UpstreamPeerInit, UpstreamPeerInitRequest};

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
    /// The request pool was destroyed during peer initialization.
    RequestDestroyedDuringPeerInitialization,
    /// The request changed to a different upstream owner during peer initialization.
    ReplacedRequestUpstream,
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
    /// A selected peer has not yet been released.
    PeerSelectionPendingRelease,
    /// nginx tried to release a peer without a matching successful selection.
    PeerReleaseWithoutSelection,
    /// A handler discarded a peer selected by the original getter.
    DiscardedOriginalPeerSelection,
    /// A handler returned a selected-peer proof from another selection generation.
    ForeignSelectedPeer,
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
            Self::RequestDestroyedDuringPeerInitialization => {
                formatter.write_str("request was destroyed during peer initialization")
            }
            Self::ReplacedRequestUpstream => {
                formatter.write_str("request changed upstream owner during peer initialization")
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
            Self::PeerSelectionPendingRelease => {
                formatter.write_str("selected upstream peer has not been released")
            }
            Self::PeerReleaseWithoutSelection => {
                formatter.write_str("upstream peer release has no matching selection")
            }
            Self::DiscardedOriginalPeerSelection => {
                formatter.write_str("handler discarded the original selected peer")
            }
            Self::ForeignSelectedPeer => {
                formatter.write_str("selected upstream peer belongs to another generation")
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

/// Module-owned installation state for one upstream and peer initializer pair.
///
/// Embed one slot in the module's per-upstream server configuration and return it from the
/// initializer traits. A fresh server configuration is also the generation boundary: successful
/// installation records the owning upstream before publishing the native adapter.
pub struct UpstreamCallbackSlot {
    pub(super) upstream: Option<NonNull<ngx_http_upstream_srv_conf_t>>,
    pub(super) upstream_handler: Option<TypeId>,
    pub(super) original_upstream: ngx_http_upstream_init_pt,
    pub(super) peer: Option<NonNull<ngx_http_upstream_srv_conf_t>>,
    pub(super) peer_handler: Option<TypeId>,
    pub(super) original_peer: ngx_http_upstream_init_peer_pt,
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
}

impl Default for UpstreamCallbackSlot {
    fn default() -> Self {
        Self::new()
    }
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

    /// Observes a peer release after the framework has released the saved original peer.
    ///
    /// Original release accounting is complete before this hook runs, including when the hook
    /// returns an error or terminates the worker by panicking.
    fn free(
        peer: &mut UpstreamPeerConnection<'_>,
        data: &mut Self::Data,
        state: UpstreamPeerState,
    ) -> Result<(), UpstreamCallbackError>;
}
