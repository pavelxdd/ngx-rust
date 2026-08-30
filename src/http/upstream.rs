mod callback;
mod state;
mod url;

pub use callback::{
    HttpUpstreamInitializer, HttpUpstreamPeerHandler, OriginalPeerFree, OriginalPeerGet,
    SelectedUpstreamPeer, UpstreamCallbackError, UpstreamConfiguration, UpstreamInitCallback,
    UpstreamInitStatus, UpstreamInitialization, UpstreamInitialized, UpstreamPeerConnection,
    UpstreamPeerInit, UpstreamPeerInitCallback, UpstreamPeerInitRequest, UpstreamPeerInitStatus,
    UpstreamPeerSelection, UpstreamPeerState, UpstreamServerConf, install_upstream_initializer,
};
pub use state::{UpstreamState, UpstreamStateError, UpstreamStates};
pub use url::{
    ConfiguredUpstreamUrl, UpstreamAddress, UpstreamAddressIter, UpstreamAddresses, UpstreamPort,
    UpstreamUrlMessage, UpstreamUrlParseError, UpstreamUrlViewError,
};

#[cfg(all(test, feature = "test-link"))]
#[path = "upstream/test_support.rs"]
mod test_support;
