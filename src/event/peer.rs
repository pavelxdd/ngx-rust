//! Outbound nginx event-peer ownership.

mod builder;
pub use builder::{
    EventPeerAddress, EventPeerAddressError, EventPeerBuildError, EventPeerBuilder,
    EventPeerCallbacks, EventPeerLogError,
};
mod connection;
use connection::{EVENT_PEER_MIN_POOL_SIZE, inert_event_handler};
pub use connection::{
    EventPeer, EventPeerConnectError, EventPeerConnectReady, EventPeerConnectReadyError,
    EventPeerConnectResult, EventPeerConnectStatus, EventPeerConnection, EventPeerConnectionError,
    EventPeerHandlers, EventPeerPendingConnection, EventPeerPreparation, EventPeerReleaseState,
};
mod keepalive;
pub use keepalive::{
    EventPeerAttachError, EventPeerKeepalive, EventPeerKeepaliveIntoConnectionError,
    EventPeerKeepaliveState, EventPeerKeepaliveTransferError,
};

#[cfg(all(test, feature = "test-link"))]
#[path = "peer/tests.rs"]
mod tests;
