mod callback;
mod state;
mod url;

pub use callback::{
    HttpUpstreamInitializer, HttpUpstreamPeerData, HttpUpstreamPeerHandler, UpstreamCallbackError,
    UpstreamConfiguration, UpstreamInitCallback, UpstreamPeerConnection, UpstreamPeerInit,
    UpstreamPeerInitCallback, UpstreamPeerState, UpstreamServerConf, install_upstream_initializer,
};
pub use state::{UpstreamState, UpstreamStateError, UpstreamStates};
pub use url::{
    ConfiguredUpstreamUrl, UpstreamAddress, UpstreamAddressIter, UpstreamAddresses, UpstreamPort,
    UpstreamUrlMessage, UpstreamUrlParseError, UpstreamUrlViewError,
};

#[cfg(all(test, feature = "test-link"))]
#[path = "upstream/test_support.rs"]
mod test_support;
