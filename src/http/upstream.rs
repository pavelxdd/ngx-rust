mod callback;
mod init;
mod peer;
mod peer_init;
mod state;
mod url;

pub use callback::{
    HttpUpstreamInitializer, HttpUpstreamPeerHandler, UpstreamCallbackError, UpstreamCallbackSlot,
};
pub use init::{
    OriginalUpstreamInit, UpstreamConfiguration, UpstreamInitStatus, UpstreamInitialization,
    UpstreamInitialized, UpstreamServerConf, install_upstream_initializer,
};
pub use peer::{
    OriginalPeerGet, SelectedUpstreamPeer, UpstreamPeerConnection, UpstreamPeerSelection,
    UpstreamPeerState,
};
pub use peer_init::{
    OriginalPeerInit, UpstreamPeerInit, UpstreamPeerInitRequest, UpstreamPeerInitStatus,
};
pub use state::{UpstreamState, UpstreamStateError, UpstreamStates};
pub use url::{
    ConfiguredUpstreamUrl, UpstreamAddress, UpstreamAddressIter, UpstreamAddresses, UpstreamPort,
    UpstreamUrlMessage, UpstreamUrlParseError, UpstreamUrlViewError,
};

#[cfg(all(test, feature = "test-link"))]
#[path = "upstream/test_support.rs"]
mod test_support;

#[cfg(all(test, feature = "test-link"))]
#[path = "upstream/tests.rs"]
mod tests;
