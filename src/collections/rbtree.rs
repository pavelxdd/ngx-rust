//! Types and utilities for working with [ngx_rbtree_t].
//!
//! This module provides both the tools for interaction with the existing `ngx_rbtree_t` objects in
//! the NGINX, and useful high-level types built on top of the `ngx_rbtree_t`.
//!
//! See <https://nginx.org/en/docs/dev/development_guide.html#red_black_tree>.

use core::alloc::Layout;
use core::cmp::Ordering;
use core::hash::{self, BuildHasher, Hash};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use core::{borrow, mem};

use nginx_sys::{
    ngx_rbt_red, ngx_rbtree_data, ngx_rbtree_delete, ngx_rbtree_init, ngx_rbtree_insert,
    ngx_rbtree_key_t, ngx_rbtree_min, ngx_rbtree_next, ngx_rbtree_node_t, ngx_rbtree_t,
};

use crate::allocator::{self, AllocError, Allocator};

/// Trait for pointer conversions between the tree entry and its container.
///
/// # Safety
///
/// This trait must only be implemented on types that contain a tree node or wrappers with
/// compatible layout. The type then can be used to access elements of a raw rbtree type
/// [NgxRbTree] linked via specified field.
///
/// If the struct can belong to several trees through multiple embedded `ngx_rbtree_node_t` fields,
/// a separate [NgxRbTreeEntry] implementation via wrapper type should be used for each tree.
pub unsafe trait NgxRbTreeEntry {
    /// Gets a container pointer from tree node.
    fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self>;
    /// Gets an rbtree node from a container reference.
    fn to_rbtree_node(&mut self) -> &mut ngx_rbtree_node_t;
}

unsafe impl NgxRbTreeEntry for ngx_rbtree_node_t {
    fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self> {
        node
    }

    fn to_rbtree_node(&mut self) -> &mut ngx_rbtree_node_t {
        self
    }
}

/// A wrapper over a raw `ngx_rbtree_t`, a red-black tree implementation.
///
/// This wrapper is defined in terms of type `T` that embeds and can be converted from or to the
/// tree nodes.
///
/// See <https://nginx.org/en/docs/dev/development_guide.html#red_black_tree>.
#[derive(Debug)]
#[repr(transparent)]
pub struct NgxRbTree<T> {
    inner: ngx_rbtree_t,
    _type: PhantomData<T>,
}

impl<T> NgxRbTree<T>
where
    T: NgxRbTreeEntry,
{
    /// Creates a tree reference from a pointer to [ngx_rbtree_t].
    ///
    /// # Safety
    ///
    /// `tree` is a valid pointer to [ngx_rbtree_t], and `T::from_rbtree_node` on the tree nodes
    /// results in valid pointers to `T`.
    pub unsafe fn from_ptr<'a>(tree: *const ngx_rbtree_t) -> &'a Self {
        unsafe { &*tree.cast() }
    }

    /// Creates a mutable tree reference from a pointer to [ngx_rbtree_t].
    ///
    /// # Safety
    ///
    /// `tree` is a valid pointer to [ngx_rbtree_t], and `T::from_rbtree_node` on the tree nodes
    /// results in valid pointers to `T`.
    pub unsafe fn from_ptr_mut<'a>(tree: *mut ngx_rbtree_t) -> &'a mut Self {
        unsafe { &mut *tree.cast() }
    }

    /// Returns `true` if the tree contains no elements.
    pub fn is_empty(&self) -> bool {
        ptr::addr_eq(self.inner.root, self.inner.sentinel)
    }

    /// Appends a node to the tree.
    ///
    /// # Safety
    ///
    /// `node` must not belong to another tree and must remain valid at the same address until it is
    /// removed. Its ordering fields must satisfy this tree's insertion callback. No references
    /// obtained through this tree may exist while the node is inserted.
    pub unsafe fn insert(&mut self, node: &mut T) {
        unsafe { ngx_rbtree_insert(&raw mut self.inner, node.to_rbtree_node()) };
    }

    /// Removes the specified node from the tree.
    ///
    /// # Safety
    ///
    /// `node` must currently belong to this tree at the address used for insertion. No references
    /// obtained through this tree may exist while the node is removed.
    pub unsafe fn remove(&mut self, node: &mut T) {
        unsafe { ngx_rbtree_delete(&raw mut self.inner, node.to_rbtree_node()) };
    }

    /// Returns an iterator over the nodes of the tree.
    pub fn iter(&self) -> NgxRbTreeEntryIter<'_, T> {
        NgxRbTreeEntryIter::new(self)
    }

    /// Returns a mutable iterator over the nodes of the tree.
    ///
    /// # Safety
    ///
    /// The caller must not modify tree links or any fields used to order the entries.
    pub unsafe fn iter_mut(&mut self) -> NgxRbTreeEntryIterMut<'_, T> {
        unsafe { NgxRbTreeEntryIterMut::new(self) }
    }
}

/// Raw iterator over the `ngx_rbtree_t` nodes.
///
/// This iterator type can be used to access elements of any correctly initialized `ngx_rbtree_t`
/// instance, including those already embedded in the nginx structures.  The iterator stores pointer
/// to the next node and thus remains valid and usable even if the last returned item is removed
/// from the tree.
pub struct NgxRbTreeIter<'a> {
    tree: NonNull<ngx_rbtree_t>,
    node: *mut ngx_rbtree_node_t,
    _lifetime: PhantomData<&'a ()>,
}

impl NgxRbTreeIter<'_> {
    /// Creates an iterator for the `ngx_rbtree_t`.
    ///
    /// # Safety
    ///
    /// The tree must outlive the iterator.
    pub unsafe fn new(tree: NonNull<ngx_rbtree_t>) -> Self {
        let t = unsafe { tree.as_ref() };
        let node = if ptr::addr_eq(t.root, t.sentinel) {
            // empty tree
            ptr::null_mut()
        } else {
            unsafe { ngx_rbtree_min(t.root, t.sentinel) }
        };

        Self { tree, node, _lifetime: PhantomData }
    }
}

impl Iterator for NgxRbTreeIter<'_> {
    type Item = NonNull<ngx_rbtree_node_t>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = NonNull::new(self.node)?;
        // ngx_rbtree_next does not mutate the tree
        self.node = unsafe { ngx_rbtree_next(self.tree.as_mut(), self.node) };
        Some(item)
    }
}

/// An iterator over typed entries of an nginx red-black tree.
pub struct NgxRbTreeEntryIter<'a, T>(NgxRbTreeIter<'a>, PhantomData<&'a T>);

impl<'a, T> NgxRbTreeEntryIter<'a, T>
where
    T: NgxRbTreeEntry,
{
    fn new(tree: &'a NgxRbTree<T>) -> Self {
        let raw = NonNull::from(&tree.inner);
        Self(unsafe { NgxRbTreeIter::new(raw) }, PhantomData)
    }
}

impl<'a, T> Iterator for NgxRbTreeEntryIter<'a, T>
where
    T: NgxRbTreeEntry,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = T::from_rbtree_node(self.0.next()?);
        Some(unsafe { entry.as_ref() })
    }
}

/// A mutable iterator over typed entries of an nginx red-black tree.
pub struct NgxRbTreeEntryIterMut<'a, T>(NgxRbTreeIter<'a>, PhantomData<&'a mut T>);

impl<'a, T> NgxRbTreeEntryIterMut<'a, T>
where
    T: NgxRbTreeEntry,
{
    unsafe fn new(tree: &'a mut NgxRbTree<T>) -> Self {
        let raw = NonNull::from(&mut tree.inner);
        Self(unsafe { NgxRbTreeIter::new(raw) }, PhantomData)
    }
}

impl<'a, T> Iterator for NgxRbTreeEntryIterMut<'a, T>
where
    T: NgxRbTreeEntry,
{
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = T::from_rbtree_node(self.0.next()?);
        Some(unsafe { entry.as_mut() })
    }
}

#[allow(deprecated)]
type BuildMapHasher = core::hash::BuildHasherDefault<hash::SipHasher>;

/// A map type based on the `ngx_rbtree_t`.
///
/// This map implementation owns the stored keys and values and ensures that the data is dropped.
/// The order of the elements is an undocumented implementation detail.
///
/// This is a `ngx`-specific high-level type with no direct counterpart in the NGINX code.
#[derive(Debug)]
pub struct RbTreeMap<K, V, A>
where
    A: Allocator,
{
    tree: NgxRbTree<MapEntry<K, V>>,
    sentinel: NonNull<ngx_rbtree_node_t>,
    alloc: A,
}

/// Entry type for the [RbTreeMap].
///
/// The struct is used from the Rust code only and thus does not need to be compatible with C.
#[derive(Debug)]
struct MapEntry<K, V> {
    node: ngx_rbtree_node_t,
    key: K,
    value: V,
}

impl<K, V> MapEntry<K, V>
where
    K: Hash,
{
    fn new(key: K, value: V) -> Self {
        let mut node: ngx_rbtree_node_t = unsafe { mem::zeroed() };
        node.key = BuildMapHasher::default().hash_one(&key) as ngx_rbtree_key_t;

        Self { node, key, value }
    }

    fn into_kv(self) -> (K, V) {
        (self.key, self.value)
    }
}

unsafe impl<K, V> NgxRbTreeEntry for MapEntry<K, V> {
    fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self> {
        unsafe { ngx_rbtree_data!(node, Self, node) }
    }

    fn to_rbtree_node(&mut self) -> &mut ngx_rbtree_node_t {
        &mut self.node
    }
}

/// An iterator for the [RbTreeMap].
pub struct MapIter<'a, K: 'a, V: 'a>(NgxRbTreeEntryIter<'a, MapEntry<K, V>>);

impl<'a, K: 'a, V: 'a> MapIter<'a, K, V> {
    /// Creates an iterator for the [RbTreeMap].
    pub fn new<A: Allocator>(tree: &'a RbTreeMap<K, V, A>) -> Self {
        Self(tree.tree.iter())
    }
}

impl<'a, K: 'a, V: 'a> Iterator for MapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next()?;
        Some((&item.key, &item.value))
    }
}

/// A mutable iterator for the [RbTreeMap].
pub struct MapIterMut<'a, K: 'a, V: 'a>(NgxRbTreeEntryIterMut<'a, MapEntry<K, V>>);

impl<'a, K: 'a, V: 'a> MapIterMut<'a, K, V> {
    /// Creates an iterator for the [RbTreeMap].
    pub fn new<A: Allocator>(tree: &'a mut RbTreeMap<K, V, A>) -> Self {
        Self(unsafe { tree.tree.iter_mut() })
    }
}

impl<'a, K: 'a, V: 'a> Iterator for MapIterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next()?;
        Some((&item.key, &mut item.value))
    }
}

impl<K, V, A> RbTreeMap<K, V, A>
where
    A: Allocator,
{
    /// Returns a reference to the underlying allocator.
    pub fn allocator(&self) -> &A {
        &self.alloc
    }

    /// Clears the tree, removing all elements.
    pub fn clear(&mut self) {
        // SAFETY: the iter lives until the end of the scope
        let iter = unsafe { NgxRbTreeIter::new(NonNull::from(&self.tree.inner)) };
        let layout = Layout::new::<MapEntry<K, V>>();

        for node in iter {
            unsafe {
                let mut data = MapEntry::<K, V>::from_rbtree_node(node);

                ngx_rbtree_delete(&raw mut self.tree.inner, &raw mut data.as_mut().node);
                ptr::drop_in_place(data.as_mut());
                self.allocator().deallocate(data.cast(), layout)
            }
        }
    }

    /// Returns true if the tree contains no entries.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Returns an iterator over the entries of the tree.
    #[inline]
    pub fn iter(&self) -> MapIter<'_, K, V> {
        MapIter::new(self)
    }

    /// Returns a mutable iterator over the entries of the tree.
    #[inline]
    pub fn iter_mut(&mut self) -> MapIterMut<'_, K, V> {
        MapIterMut::new(self)
    }
}

impl<K, V, A> RbTreeMap<K, V, A>
where
    A: Allocator,
    K: Hash + Ord,
{
    /// Attempts to create and initialize a new RbTreeMap with specified allocator.
    pub fn try_new_in(alloc: A) -> Result<Self, AllocError> {
        let layout = Layout::new::<ngx_rbtree_node_t>();
        let sentinel: NonNull<ngx_rbtree_node_t> = alloc.allocate_zeroed(layout)?.cast();

        let tree = NgxRbTree { inner: unsafe { mem::zeroed() }, _type: PhantomData };

        let mut this = RbTreeMap { tree, sentinel, alloc };

        unsafe {
            ngx_rbtree_init(&raw mut this.tree.inner, this.sentinel.as_ptr(), Some(Self::insert))
        };

        Ok(this)
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: borrow::Borrow<Q>,
        Q: Hash + Ord + ?Sized,
    {
        self.lookup(key).map(|x| unsafe { &x.as_ref().value })
    }

    /// Returns a mutable reference to the value corresponding to the key.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: borrow::Borrow<Q>,
        Q: Hash + Ord + ?Sized,
    {
        self.lookup(key).map(|mut x| unsafe { &mut x.as_mut().value })
    }

    /// Removes a key from the tree, returning the value at the key if the key was previously in the
    /// tree.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: borrow::Borrow<Q>,
        Q: Hash + Ord + ?Sized,
    {
        self.remove_entry(key).map(|(_, v)| v)
    }

    /// Removes a key from the tree, returning the stored key and value if the key was previously in
    /// the tree.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: borrow::Borrow<Q>,
        Q: Hash + Ord + ?Sized,
    {
        let mut node = self.lookup(key)?;
        unsafe {
            self.tree.remove(node.as_mut());

            let layout = Layout::for_value(node.as_ref());
            // SAFETY: we make a bitwise copy of the node and dispose of the original value without
            // dropping it.
            let copy = node.as_ptr().read();
            self.allocator().deallocate(node.cast(), layout);
            Some(copy.into_kv())
        }
    }

    /// Attempts to insert a new element into the tree.
    pub fn try_insert(&mut self, key: K, value: V) -> Result<&mut V, AllocError> {
        let mut node = if let Some(mut node) = self.lookup(&key) {
            unsafe { node.as_mut().value = value };
            node
        } else {
            let node = MapEntry::new(key, value);
            let mut node = allocator::allocate(node, self.allocator())?;
            unsafe { self.tree.insert(node.as_mut()) };
            node
        };

        Ok(unsafe { &mut node.as_mut().value })
    }

    extern "C" fn insert(
        mut temp: *mut ngx_rbtree_node_t,
        node: *mut ngx_rbtree_node_t,
        sentinel: *mut ngx_rbtree_node_t,
    ) {
        let n = unsafe { &mut *ngx_rbtree_data!(node, MapEntry<K, V>, node) };

        loop {
            let t = unsafe { &mut *ngx_rbtree_data!(temp, MapEntry<K, V>, node) };
            let p = match Ord::cmp(&n.node.key, &t.node.key) {
                Ordering::Less => &mut t.node.left,
                Ordering::Greater => &mut t.node.right,
                Ordering::Equal => match Ord::cmp(&n.key, &t.key) {
                    Ordering::Less => &mut t.node.left,
                    Ordering::Greater => &mut t.node.right,
                    // should be handled in try_insert
                    Ordering::Equal => &mut t.node.right,
                },
            };

            if ptr::addr_eq(*p, sentinel) {
                *p = node;
                break;
            }

            temp = *p;
        }

        n.node.parent = temp;
        n.node.left = sentinel;
        n.node.right = sentinel;
        unsafe { ngx_rbt_red(node) };
    }

    fn lookup<Q>(&self, key: &Q) -> Option<NonNull<MapEntry<K, V>>>
    where
        K: borrow::Borrow<Q>,
        Q: Hash + Ord + ?Sized,
    {
        let mut node = self.tree.inner.root;
        let hash = BuildMapHasher::default().hash_one(key) as ngx_rbtree_key_t;

        while !ptr::addr_eq(node, self.tree.inner.sentinel) {
            let n = unsafe { NonNull::new_unchecked(ngx_rbtree_data!(node, MapEntry<K, V>, node)) };
            let nr = unsafe { n.as_ref() };

            node = match Ord::cmp(&hash, &nr.node.key) {
                Ordering::Less => nr.node.left,
                Ordering::Greater => nr.node.right,
                Ordering::Equal => match Ord::cmp(key, nr.key.borrow()) {
                    Ordering::Less => nr.node.left,
                    Ordering::Greater => nr.node.right,
                    Ordering::Equal => return Some(n),
                },
            }
        }

        None
    }
}

impl<K, V, A> Drop for RbTreeMap<K, V, A>
where
    A: Allocator,
{
    fn drop(&mut self) {
        self.clear();

        unsafe {
            self.allocator()
                .deallocate(self.sentinel.cast(), Layout::for_value(self.sentinel.as_ref()))
        };
    }
}

unsafe impl<K, V, A> Send for RbTreeMap<K, V, A>
where
    A: Send + Allocator,
    K: Send,
    V: Send,
{
}

unsafe impl<K, V, A> Sync for RbTreeMap<K, V, A>
where
    A: Sync + Allocator,
    K: Sync,
    V: Sync,
{
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    use crate::allocator::Global;

    use super::*;

    #[repr(C)]
    struct Entry {
        node: ngx_rbtree_node_t,
        value: i32,
    }

    unsafe impl NgxRbTreeEntry for Entry {
        fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self> {
            unsafe { ngx_rbtree_data!(node, Self, node) }
        }

        fn to_rbtree_node(&mut self) -> &mut ngx_rbtree_node_t {
            &mut self.node
        }
    }

    #[test]
    fn intrusive_tree_iterators_return_typed_entries() {
        let mut sentinel: ngx_rbtree_node_t = unsafe { mem::zeroed() };
        let mut entry = Entry { node: unsafe { mem::zeroed() }, value: 10 };
        entry.node.left = &raw mut sentinel;
        entry.node.right = &raw mut sentinel;

        let mut raw: ngx_rbtree_t = unsafe { mem::zeroed() };
        raw.root = &raw mut entry.node;
        raw.sentinel = &raw mut sentinel;
        let tree = unsafe { NgxRbTree::<Entry>::from_ptr_mut(&raw mut raw) };

        assert_eq!(tree.iter().map(|entry| entry.value).collect::<alloc::vec::Vec<_>>(), [10]);

        for entry in unsafe { tree.iter_mut() } {
            entry.value = 20;
        }

        assert_eq!(tree.iter().map(|entry| entry.value).collect::<alloc::vec::Vec<_>>(), [20]);
    }

    #[test]
    fn owned_map_supports_lookup_iteration_and_mutation() {
        let mut map = RbTreeMap::try_new_in(Global).unwrap();
        map.try_insert(2_i32, 20_i32).unwrap();
        map.try_insert(1, 10).unwrap();
        map.try_insert(3, 30).unwrap();

        assert_eq!(map.get(&2), Some(&20));
        assert_eq!(map.get(&4), None);
        *map.get_mut(&2).unwrap() = 21;
        for (_, value) in map.iter_mut() {
            *value += 1;
        }

        let mut entries =
            map.iter().map(|(key, value)| (*key, *value)).collect::<alloc::vec::Vec<_>>();
        entries.sort_unstable();
        assert_eq!(entries, [(1, 11), (2, 22), (3, 31)]);
        assert_eq!(map.remove(&2), Some(22));
        assert_eq!(map.get(&2), None);
    }
}
