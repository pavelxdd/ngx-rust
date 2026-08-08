//! Collection types.
//!
//! This module provides common collection types, mostly implemented as wrappers over the
//! corresponding NGINX types.

#[cfg(feature = "alloc")]
pub use allocator_api2::{
    collections::{TryReserveError, TryReserveErrorKind},
    vec, // reexport both the module and the macro
    vec::Vec,
};
pub use array::NgxArray;
pub use hash::{NgxHash, NgxHashKey};
pub use list::NgxList;
pub use queue::Queue;
pub use rbtree::RbTreeMap;
pub use slab_queue::{
    SlabQueue, SlabQueueEntry, SlabQueueEntryMut, SlabQueueEntryRef, SlabQueueError, SlabQueueIter,
};
pub use slab_rbtree::{
    SlabRbTree, SlabRbTreeEntry, SlabRbTreeEntryMut, SlabRbTreeEntryRef, SlabRbTreeError,
    SlabRbTreeIter,
};

pub mod array;
pub mod hash;
pub mod list;
pub mod queue;
pub mod rbtree;
pub mod slab_queue;
pub mod slab_rbtree;
