//! Guard-scoped intrusive red-black trees in nginx shared slab memory.

use core::cmp::Ordering;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use nginx_sys::{
    ngx_rbtree_delete, ngx_rbtree_init, ngx_rbtree_insert, ngx_rbtree_insert_pt, ngx_rbtree_key_t,
    ngx_rbtree_node_t, ngx_rbtree_t,
};

use crate::core::{SlabError, SlabGuard};

/// Failure while validating or traversing a shared intrusive red-black tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabRbTreeError {
    /// A shared-memory pointer failed the slab guard's range or alignment checks.
    Slab(SlabError),
    /// The tree does not have an nginx insertion callback.
    MissingInsertCallback,
    /// The tree root pointer is null.
    NullRoot,
    /// The tree sentinel pointer is null.
    NullSentinel,
    /// The tree's sentinel changed after the adapter was created.
    SentinelChanged,
    /// A normal tree operation reached the sentinel as an entry node.
    SentinelNode,
    /// An inserted node still has intrusive links from another tree.
    AlreadyLinked,
    /// A non-sentinel child pointer is null.
    NullChild,
    /// A non-root node has a null parent pointer.
    NullParent,
    /// Parent and child links do not point back to each other.
    BrokenParent,
    /// The entry conversion does not round-trip through its rbtree node.
    EntryNodeMismatch,
    /// Traversal exceeded its caller-provided bound.
    TraversalLimit,
    /// A direct or duplicated child link repeats a node.
    Cycle,
}

impl From<SlabError> for SlabRbTreeError {
    fn from(error: SlabError) -> Self {
        Self::Slab(error)
    }
}

/// Conversion contract for a shared record linked through an nginx rbtree node.
///
/// # Safety
///
/// `Self` must have a stable `repr(C)` layout whose `ngx_rbtree_node_t` conversion is reversible.
/// Every converted entry and payload pointer must identify initialized values in the active slab
/// mapping. `payload` must identify a disjoint field whose safe mutation cannot change tree links,
/// the nginx key, or any field used by the insertion callback. The insertion callback and each
/// `find_by` comparator must implement the same strict total ordering, including secondary keys.
pub unsafe trait SlabRbTreeEntry: Sized {
    /// The part of a record that safe callers may mutate while the node stays linked.
    type Payload: Sized;

    /// Converts a checked nginx rbtree node to its containing shared record.
    ///
    /// # Safety
    ///
    /// `node` identifies a checked, initialized node for this entry layout.
    unsafe fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self>;

    /// Returns the nginx rbtree node embedded in a checked shared record.
    ///
    /// # Safety
    ///
    /// `entry` identifies a checked, initialized record for this entry layout.
    unsafe fn rbtree_node(entry: NonNull<Self>) -> NonNull<ngx_rbtree_node_t>;

    /// Returns the safely mutable payload embedded in a checked shared record.
    ///
    /// # Safety
    ///
    /// `entry` identifies a checked, initialized record for this entry layout.
    unsafe fn payload(entry: NonNull<Self>) -> NonNull<Self::Payload>;
}

/// An intrusive nginx red-black tree borrowed under a live [`SlabGuard`].
///
/// The adapter neither owns nor drops the tree, sentinel, or entries. Its safe views stay bounded
/// by the native mutex guard, while insertion and removal remain explicit unsafe operations.
pub struct SlabRbTree<'guard, 'zone, 'lock, T> {
    guard: &'guard mut SlabGuard<'zone, 'lock>,
    tree: NonNull<ngx_rbtree_t>,
    sentinel: NonNull<ngx_rbtree_node_t>,
    _entry: PhantomData<T>,
}

/// Immutable access to one checked shared rbtree record.
///
/// The handle cannot escape the tree borrow:
///
/// ```compile_fail
/// # use core::cmp::Ordering;
/// # use ngx::collections::{SlabRbTree, SlabRbTreeEntry, SlabRbTreeEntryRef};
/// fn escape<T: SlabRbTreeEntry>(
///     tree: &SlabRbTree<'_, '_, '_, T>,
/// ) -> SlabRbTreeEntryRef<'static, T> {
///     unsafe { tree.find_by(0, 1, |_| Ordering::Equal) }.unwrap().unwrap()
/// }
/// ```
pub struct SlabRbTreeEntryRef<'tree, T: SlabRbTreeEntry> {
    entry: NonNull<T>,
    payload: NonNull<T::Payload>,
    _borrow: PhantomData<(&'tree T, *mut ())>,
}

impl<T: SlabRbTreeEntry> SlabRbTreeEntryRef<'_, T> {
    /// Returns the checked record without granting mutable access to its tree state.
    pub fn entry(&self) -> &T {
        unsafe { self.entry.as_ref() }
    }

    /// Returns the checked immutable payload.
    pub fn payload(&self) -> &T::Payload {
        unsafe { self.payload.as_ref() }
    }
}

/// Mutable payload access to one checked shared rbtree record.
///
/// The adapter intentionally has no mutable-record accessor, so tree links and ordering fields
/// cannot be changed through safe code:
///
/// ```compile_fail
/// # use ngx::collections::{SlabRbTreeEntry, SlabRbTreeEntryMut};
/// fn mutate<T: SlabRbTreeEntry>(entry: &mut SlabRbTreeEntryMut<'_, T>) {
///     entry.entry_mut();
/// }
/// ```
pub struct SlabRbTreeEntryMut<'tree, T: SlabRbTreeEntry> {
    entry: NonNull<T>,
    payload: NonNull<T::Payload>,
    _borrow: PhantomData<(&'tree mut T, *mut ())>,
}

impl<T: SlabRbTreeEntry> SlabRbTreeEntryMut<'_, T> {
    /// Returns the checked record without granting mutable access to its tree state.
    pub fn entry(&self) -> &T {
        unsafe { self.entry.as_ref() }
    }

    /// Returns the checked immutable payload.
    pub fn payload(&self) -> &T::Payload {
        unsafe { self.payload.as_ref() }
    }

    /// Returns the checked payload as the record's only safe mutable view.
    pub fn payload_mut(&mut self) -> &mut T::Payload {
        unsafe { self.payload.as_mut() }
    }
}

#[derive(Clone, Copy)]
struct TreeParts {
    root: NonNull<ngx_rbtree_node_t>,
    sentinel: NonNull<ngx_rbtree_node_t>,
}

#[derive(Clone, Copy)]
struct NodeLinks {
    key: ngx_rbtree_key_t,
    left: Option<NonNull<ngx_rbtree_node_t>>,
    right: Option<NonNull<ngx_rbtree_node_t>>,
    parent: Option<NonNull<ngx_rbtree_node_t>>,
}

impl<'guard, 'zone, 'lock, T> SlabRbTree<'guard, 'zone, 'lock, T>
where
    T: SlabRbTreeEntry,
{
    /// Initializes an existing shared tree and sentinel with an nginx insertion callback.
    ///
    /// # Safety
    ///
    /// `tree` and `sentinel` must be exclusive, properly allocated shared slab storage that stays
    /// live for this guard. `insert` must only traverse entries satisfying `T`'s layout and
    /// ordering contract.
    pub unsafe fn init(
        guard: &'guard mut SlabGuard<'zone, 'lock>,
        tree: NonNull<ngx_rbtree_t>,
        sentinel: NonNull<ngx_rbtree_node_t>,
        insert: ngx_rbtree_insert_pt,
    ) -> Result<Self, SlabRbTreeError> {
        let insert = insert.ok_or(SlabRbTreeError::MissingInsertCallback)?;
        guard.check_typed(tree)?;
        guard.check_typed(sentinel)?;
        unsafe { ngx_rbtree_init(tree.as_ptr(), sentinel.as_ptr(), Some(insert)) };

        Ok(Self { guard, tree, sentinel, _entry: PhantomData })
    }

    /// Borrows an initialized shared rbtree that already has a configured sentinel and callback.
    ///
    /// # Safety
    ///
    /// `tree` must identify one initialized nginx rbtree in the active slab mapping. Every linked
    /// node must satisfy `T`'s conversion and ordering contract and remain valid under this guard.
    pub unsafe fn from_raw(
        guard: &'guard mut SlabGuard<'zone, 'lock>,
        tree: NonNull<ngx_rbtree_t>,
    ) -> Result<Self, SlabRbTreeError> {
        guard.check_typed(tree)?;
        let raw = unsafe { tree.as_ref() };
        let sentinel = NonNull::new(raw.sentinel).ok_or(SlabRbTreeError::NullSentinel)?;
        let this = Self { guard, tree, sentinel, _entry: PhantomData };
        this.tree_parts()?;
        Ok(this)
    }

    /// Returns the locked slab guard for allocating or releasing detached shared records.
    pub fn guard_mut(&mut self) -> &mut SlabGuard<'zone, 'lock> {
        self.guard
    }

    /// Returns whether the tree currently has no entries after validating its root links.
    pub fn is_empty(&self) -> Result<bool, SlabRbTreeError> {
        let parts = self.tree_parts()?;
        if parts.root == parts.sentinel {
            return Ok(true);
        }

        self.node_links(parts.root, parts)?;
        Ok(false)
    }

    /// Inserts one detached shared record through the configured nginx callback.
    ///
    /// # Safety
    ///
    /// `entry` must identify an initialized, detached record that satisfies `T`'s conversion and
    /// ordering contract. The current tree must be well formed for the configured native callback,
    /// and no entry handle may exist while the tree is mutated.
    pub unsafe fn insert(&mut self, entry: NonNull<T>) -> Result<(), SlabRbTreeError> {
        let parts = self.tree_parts()?;
        let node = self.node_from_entry(entry)?;
        if node == parts.sentinel {
            return Err(SlabRbTreeError::SentinelNode);
        }

        let (left, right, parent) = unsafe {
            let node = node.as_ref();
            (node.left, node.right, node.parent)
        };
        if !left.is_null() || !right.is_null() || !parent.is_null() {
            return Err(SlabRbTreeError::AlreadyLinked);
        }

        unsafe { ngx_rbtree_insert(self.tree.as_ptr(), node.as_ptr()) };
        Ok(())
    }

    /// Removes a linked shared record and leaves its rbtree links detached.
    ///
    /// # Safety
    ///
    /// `entry` must currently belong to this well-formed tree at this address. No entry handle may
    /// exist while the tree is mutated. After success, the record can be released through
    /// [`SlabGuard::free`](crate::core::SlabGuard::free).
    pub unsafe fn remove(&mut self, entry: NonNull<T>) -> Result<(), SlabRbTreeError> {
        let parts = self.tree_parts()?;
        let mut node = self.node_from_entry(entry)?;
        if node == parts.sentinel {
            return Err(SlabRbTreeError::SentinelNode);
        }
        self.node_links(node, parts)?;

        unsafe { ngx_rbtree_delete(self.tree.as_ptr(), node.as_ptr()) };
        unsafe {
            let node = node.as_mut();
            node.left = ptr::null_mut();
            node.right = ptr::null_mut();
            node.parent = ptr::null_mut();
        }
        Ok(())
    }

    /// Looks up a record with a primary nginx key and caller-defined secondary ordering.
    ///
    /// # Safety
    ///
    /// `compare` must compare the requested secondary key with an entry using exactly the same
    /// ordering as this tree's insertion callback. The tree must not be mutated for the returned
    /// handle's lifetime.
    pub unsafe fn find_by<F>(
        &self,
        key: ngx_rbtree_key_t,
        max_steps: usize,
        mut compare: F,
    ) -> Result<Option<SlabRbTreeEntryRef<'_, T>>, SlabRbTreeError>
    where
        F: FnMut(&T) -> Ordering,
    {
        let parts = self.tree_parts()?;
        if parts.root == parts.sentinel {
            return Ok(None);
        }

        let mut node = parts.root;
        let mut steps = 0;
        loop {
            if steps == max_steps {
                return Err(SlabRbTreeError::TraversalLimit);
            }
            steps += 1;

            let links = self.node_links(node, parts)?;
            let next = match key.cmp(&links.key) {
                Ordering::Less => links.left,
                Ordering::Greater => links.right,
                Ordering::Equal => {
                    let entry = self.entry_ref_from_node(node)?;
                    match compare(entry.entry()) {
                        Ordering::Less => links.left,
                        Ordering::Greater => links.right,
                        Ordering::Equal => return Ok(Some(entry)),
                    }
                }
            };

            match next {
                Some(next) => node = next,
                None => return Ok(None),
            }
        }
    }

    /// Looks up one record and grants mutable access only to its declared payload.
    ///
    /// # Safety
    ///
    /// `compare` must compare the requested secondary key with an entry using exactly the same
    /// ordering as this tree's insertion callback. The tree must not be structurally mutated while
    /// the returned payload handle exists.
    pub unsafe fn find_by_mut<F>(
        &mut self,
        key: ngx_rbtree_key_t,
        max_steps: usize,
        mut compare: F,
    ) -> Result<Option<SlabRbTreeEntryMut<'_, T>>, SlabRbTreeError>
    where
        F: FnMut(&T) -> Ordering,
    {
        let parts = self.tree_parts()?;
        if parts.root == parts.sentinel {
            return Ok(None);
        }

        let mut node = parts.root;
        let mut steps = 0;
        loop {
            if steps == max_steps {
                return Err(SlabRbTreeError::TraversalLimit);
            }
            steps += 1;

            let links = self.node_links(node, parts)?;
            let next = match key.cmp(&links.key) {
                Ordering::Less => links.left,
                Ordering::Greater => links.right,
                Ordering::Equal => {
                    let (entry, payload) = self.entry_parts_from_node(node)?;
                    match compare(unsafe { entry.as_ref() }) {
                        Ordering::Less => links.left,
                        Ordering::Greater => links.right,
                        Ordering::Equal => {
                            return Ok(Some(SlabRbTreeEntryMut {
                                entry,
                                payload,
                                _borrow: PhantomData,
                            }));
                        }
                    }
                }
            };

            match next {
                Some(next) => node = next,
                None => return Ok(None),
            }
        }
    }

    /// Iterates in nginx rbtree order without traversing more than `max_entries` records.
    ///
    /// The iterator yields [`SlabRbTreeError::TraversalLimit`] if the tree has another record
    /// after the requested bound or if malformed links exhaust its finite traversal budget.
    pub fn iter(&self, max_entries: usize) -> SlabRbTreeIter<'_, 'guard, 'zone, 'lock, T> {
        SlabRbTreeIter {
            tree: self,
            next: None,
            started: false,
            yielded: 0,
            max_entries,
            steps: 0,
            done: false,
        }
    }

    fn tree_parts(&self) -> Result<TreeParts, SlabRbTreeError> {
        self.guard.check_typed(self.tree)?;
        let tree = unsafe { self.tree.as_ref() };
        let sentinel = NonNull::new(tree.sentinel).ok_or(SlabRbTreeError::NullSentinel)?;
        if sentinel != self.sentinel {
            return Err(SlabRbTreeError::SentinelChanged);
        }
        self.check_node(sentinel)?;
        if tree.insert.is_none() {
            return Err(SlabRbTreeError::MissingInsertCallback);
        }

        let root = NonNull::new(tree.root).ok_or(SlabRbTreeError::NullRoot)?;
        self.check_node(root)?;
        Ok(TreeParts { root, sentinel })
    }

    fn check_node(&self, node: NonNull<ngx_rbtree_node_t>) -> Result<(), SlabRbTreeError> {
        self.guard.check_typed(node)?;
        Ok(())
    }

    fn node_links(
        &self,
        node: NonNull<ngx_rbtree_node_t>,
        parts: TreeParts,
    ) -> Result<NodeLinks, SlabRbTreeError> {
        if node == parts.sentinel {
            return Err(SlabRbTreeError::SentinelNode);
        }
        self.check_node(node)?;
        let raw = unsafe { node.as_ref() };
        let left = self.child(node, raw.left, parts.sentinel)?;
        let right = self.child(node, raw.right, parts.sentinel)?;
        if left.is_some() && left == right {
            return Err(SlabRbTreeError::Cycle);
        }

        let parent = if node == parts.root {
            if !raw.parent.is_null() {
                return Err(SlabRbTreeError::BrokenParent);
            }
            None
        } else {
            let parent = NonNull::new(raw.parent).ok_or(SlabRbTreeError::NullParent)?;
            if parent == parts.sentinel {
                return Err(SlabRbTreeError::BrokenParent);
            }
            self.check_node(parent)?;
            let parent_node = unsafe { parent.as_ref() };
            let points_left = ptr::addr_eq(parent_node.left, node.as_ptr());
            let points_right = ptr::addr_eq(parent_node.right, node.as_ptr());
            if !points_left && !points_right {
                return Err(SlabRbTreeError::BrokenParent);
            }
            if points_left && points_right {
                return Err(SlabRbTreeError::Cycle);
            }
            Some(parent)
        };

        Ok(NodeLinks { key: raw.key, left, right, parent })
    }

    fn child(
        &self,
        node: NonNull<ngx_rbtree_node_t>,
        child: *mut ngx_rbtree_node_t,
        sentinel: NonNull<ngx_rbtree_node_t>,
    ) -> Result<Option<NonNull<ngx_rbtree_node_t>>, SlabRbTreeError> {
        let child = NonNull::new(child).ok_or(SlabRbTreeError::NullChild)?;
        if child == sentinel {
            return Ok(None);
        }
        if child == node {
            return Err(SlabRbTreeError::Cycle);
        }
        self.check_node(child)?;

        let parent = unsafe { child.as_ref() }.parent;
        let parent = NonNull::new(parent).ok_or(SlabRbTreeError::NullParent)?;
        self.check_node(parent)?;
        if parent != node {
            return Err(SlabRbTreeError::BrokenParent);
        }
        Ok(Some(child))
    }

    fn entry_parts_from_node(
        &self,
        node: NonNull<ngx_rbtree_node_t>,
    ) -> Result<(NonNull<T>, NonNull<T::Payload>), SlabRbTreeError> {
        self.check_node(node)?;
        let entry = unsafe { T::from_rbtree_node(node) };
        self.guard.check_typed(entry)?;

        let entry_node = unsafe { T::rbtree_node(entry) };
        self.check_node(entry_node)?;
        if entry_node != node {
            return Err(SlabRbTreeError::EntryNodeMismatch);
        }

        let payload = unsafe { T::payload(entry) };
        self.guard.check_typed(payload)?;
        Ok((entry, payload))
    }

    fn node_from_entry(
        &self,
        entry: NonNull<T>,
    ) -> Result<NonNull<ngx_rbtree_node_t>, SlabRbTreeError> {
        self.guard.check_typed(entry)?;
        let node = unsafe { T::rbtree_node(entry) };
        let (round_trip, _) = self.entry_parts_from_node(node)?;
        if round_trip != entry {
            return Err(SlabRbTreeError::EntryNodeMismatch);
        }
        Ok(node)
    }

    fn entry_ref_from_node(
        &self,
        node: NonNull<ngx_rbtree_node_t>,
    ) -> Result<SlabRbTreeEntryRef<'_, T>, SlabRbTreeError> {
        let (entry, payload) = self.entry_parts_from_node(node)?;
        Ok(SlabRbTreeEntryRef { entry, payload, _borrow: PhantomData })
    }
}

/// A bounded in-order traversal over a [`SlabRbTree`].
pub struct SlabRbTreeIter<'tree, 'guard, 'zone, 'lock, T: SlabRbTreeEntry> {
    tree: &'tree SlabRbTree<'guard, 'zone, 'lock, T>,
    next: Option<NonNull<ngx_rbtree_node_t>>,
    started: bool,
    yielded: usize,
    max_entries: usize,
    steps: usize,
    done: bool,
}

impl<'tree, T> SlabRbTreeIter<'tree, '_, '_, '_, T>
where
    T: SlabRbTreeEntry,
{
    fn next_entry(&mut self) -> Result<Option<SlabRbTreeEntryRef<'tree, T>>, SlabRbTreeError> {
        self.initialize()?;
        let node = match self.next {
            Some(node) => node,
            None => return Ok(None),
        };
        if self.yielded == self.max_entries {
            return Err(SlabRbTreeError::TraversalLimit);
        }

        let parts = self.tree.tree_parts()?;
        let next = self.successor(node, parts)?;
        let entry = self.tree.entry_ref_from_node(node)?;
        self.next = next;
        self.yielded += 1;
        Ok(Some(entry))
    }

    fn initialize(&mut self) -> Result<(), SlabRbTreeError> {
        if self.started {
            return Ok(());
        }
        self.started = true;

        let parts = self.tree.tree_parts()?;
        if parts.root == parts.sentinel {
            return Ok(());
        }
        if self.max_entries == 0 {
            self.next = Some(parts.root);
            return Ok(());
        }

        self.next = Some(self.leftmost(parts.root, parts)?);
        Ok(())
    }

    fn leftmost(
        &mut self,
        mut node: NonNull<ngx_rbtree_node_t>,
        parts: TreeParts,
    ) -> Result<NonNull<ngx_rbtree_node_t>, SlabRbTreeError> {
        loop {
            let links = self.tree.node_links(node, parts)?;
            match links.left {
                Some(left) => {
                    self.consume_step()?;
                    node = left;
                }
                None => return Ok(node),
            }
        }
    }

    fn successor(
        &mut self,
        node: NonNull<ngx_rbtree_node_t>,
        parts: TreeParts,
    ) -> Result<Option<NonNull<ngx_rbtree_node_t>>, SlabRbTreeError> {
        let links = self.tree.node_links(node, parts)?;
        if let Some(right) = links.right {
            self.consume_step()?;
            return Ok(Some(self.leftmost(right, parts)?));
        }

        let mut child = node;
        let mut parent = links.parent;
        while let Some(current) = parent {
            self.consume_step()?;
            let parent_links = self.tree.node_links(current, parts)?;
            if parent_links.left == Some(child) {
                return Ok(Some(current));
            }
            if parent_links.right != Some(child) {
                return Err(SlabRbTreeError::BrokenParent);
            }
            child = current;
            parent = parent_links.parent;
        }

        Ok(None)
    }

    fn consume_step(&mut self) -> Result<(), SlabRbTreeError> {
        let limit = self.max_entries.saturating_mul(4).saturating_add(1);
        if self.steps == limit {
            return Err(SlabRbTreeError::TraversalLimit);
        }
        self.steps += 1;
        Ok(())
    }
}

impl<'tree, T> Iterator for SlabRbTreeIter<'tree, '_, '_, '_, T>
where
    T: SlabRbTreeEntry,
{
    type Item = Result<SlabRbTreeEntryRef<'tree, T>, SlabRbTreeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match self.next_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

#[cfg(all(test, feature = "test-link"))]
#[path = "slab_rbtree_tests.rs"]
mod tests;
