use alloc::vec::Vec;
use core::alloc::Layout;
use core::cmp::Ordering;
use core::mem;
use core::ptr::{self, NonNull};

use nginx_sys::{
    ngx_rbt_red, ngx_rbtree_insert_pt, ngx_rbtree_key_t, ngx_rbtree_node_t, ngx_rbtree_t,
};

use crate::core::slab::tests::TestZone;
use crate::core::{SlabError, SlabGuard};

use super::{SlabRbTree, SlabRbTreeEntry, SlabRbTreeError};

#[repr(C)]
struct Entry {
    node: ngx_rbtree_node_t,
    secondary: u32,
    value: i32,
}

unsafe impl SlabRbTreeEntry for Entry {
    type Payload = i32;

    unsafe fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self> {
        node.cast()
    }

    unsafe fn rbtree_node(entry: NonNull<Self>) -> NonNull<ngx_rbtree_node_t> {
        entry.cast()
    }

    unsafe fn payload(entry: NonNull<Self>) -> NonNull<Self::Payload> {
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*entry.as_ptr()).value)) }
    }
}

unsafe extern "C" fn insert_entry(
    mut current: *mut ngx_rbtree_node_t,
    node: *mut ngx_rbtree_node_t,
    sentinel: *mut ngx_rbtree_node_t,
) {
    let entry = unsafe { &mut *node.cast::<Entry>() };

    loop {
        let current_entry = unsafe { &mut *current.cast::<Entry>() };
        let link = match entry.node.key.cmp(&current_entry.node.key) {
            Ordering::Less => &mut current_entry.node.left,
            Ordering::Greater => &mut current_entry.node.right,
            Ordering::Equal => match entry.secondary.cmp(&current_entry.secondary) {
                Ordering::Less => &mut current_entry.node.left,
                Ordering::Greater | Ordering::Equal => &mut current_entry.node.right,
            },
        };
        if ptr::addr_eq(*link, sentinel) {
            *link = node;
            break;
        }
        current = *link;
    }

    entry.node.parent = current;
    entry.node.left = sentinel;
    entry.node.right = sentinel;
    unsafe { ngx_rbt_red(node) };
}

fn init_tree<'guard, 'zone, 'lock>(
    guard: &'guard mut SlabGuard<'zone, 'lock>,
) -> (SlabRbTree<'guard, 'zone, 'lock, Entry>, NonNull<ngx_rbtree_t>, NonNull<ngx_rbtree_node_t>) {
    let raw_tree = guard.calloc(Layout::new::<ngx_rbtree_t>()).unwrap().cast();
    let sentinel = guard.calloc(Layout::new::<ngx_rbtree_node_t>()).unwrap().cast();
    let callback: ngx_rbtree_insert_pt = Some(insert_entry);
    let tree = unsafe { SlabRbTree::init(guard, raw_tree, sentinel, callback) }.unwrap();

    (tree, raw_tree, sentinel)
}

fn allocate_entry(
    tree: &mut SlabRbTree<'_, '_, '_, Entry>,
    key: ngx_rbtree_key_t,
    secondary: u32,
    value: i32,
) -> NonNull<Entry> {
    let entry: NonNull<Entry> = tree.guard_mut().calloc(Layout::new::<Entry>()).unwrap().cast();
    let node = unsafe { mem::zeroed() };
    unsafe { entry.as_ptr().write(Entry { node, secondary, value }) };
    unsafe { (*entry.as_ptr()).node.key = key };
    entry
}

fn insert(
    tree: &mut SlabRbTree<'_, '_, '_, Entry>,
    key: ngx_rbtree_key_t,
    secondary: u32,
    value: i32,
) -> NonNull<Entry> {
    let entry = allocate_entry(tree, key, secondary, value);
    unsafe { tree.insert(entry) }.unwrap();
    entry
}

fn lookup(
    tree: &SlabRbTree<'_, '_, '_, Entry>,
    key: ngx_rbtree_key_t,
    secondary: u32,
) -> Result<Option<i32>, SlabRbTreeError> {
    let entry = unsafe { tree.find_by(key, 32, |entry| secondary.cmp(&entry.secondary)) };
    Ok(entry?.map(|entry| *entry.payload()))
}

fn child_count(entry: NonNull<Entry>, sentinel: NonNull<ngx_rbtree_node_t>) -> usize {
    let node = unsafe { entry.cast::<ngx_rbtree_node_t>().as_ref() };
    usize::from(!ptr::addr_eq(node.left, sentinel.as_ptr()))
        + usize::from(!ptr::addr_eq(node.right, sentinel.as_ptr()))
}

fn assert_detached(entry: NonNull<Entry>) {
    let node = unsafe { entry.cast::<ngx_rbtree_node_t>().as_ref() };
    assert!(node.left.is_null());
    assert!(node.right.is_null());
    assert!(node.parent.is_null());
}

fn free_detached(tree: &mut SlabRbTree<'_, '_, '_, Entry>, entry: NonNull<Entry>) {
    unsafe { tree.guard_mut().free(entry.cast(), Layout::new::<Entry>()) }.unwrap();
}

fn insert_four(tree: &mut SlabRbTree<'_, '_, '_, Entry>) -> [NonNull<Entry>; 4] {
    [insert(tree, 1, 0, 10), insert(tree, 2, 0, 20), insert(tree, 3, 0, 30), insert(tree, 4, 0, 40)]
}

fn single_tree<'guard, 'zone, 'lock>(
    guard: &'guard mut SlabGuard<'zone, 'lock>,
) -> (
    SlabRbTree<'guard, 'zone, 'lock, Entry>,
    NonNull<ngx_rbtree_t>,
    NonNull<ngx_rbtree_node_t>,
    NonNull<Entry>,
) {
    let (mut tree, raw_tree, sentinel) = init_tree(guard);
    let entry = insert(&mut tree, 1, 0, 10);
    (tree, raw_tree, sentinel, entry)
}

#[test]
fn initializes_and_finds_empty() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (tree, _, _) = init_tree(&mut guard);

    assert_eq!(tree.is_empty(), Ok(true));
    assert_eq!(lookup(&tree, 1, 0), Ok(None));
}

#[test]
fn reopens_initialized_tree_under_the_same_guard() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let raw_tree = {
        let (_, raw_tree, _) = init_tree(&mut guard);
        raw_tree
    };

    let tree = unsafe { SlabRbTree::<Entry>::from_raw(&mut guard, raw_tree) }.unwrap();
    assert_eq!(tree.is_empty(), Ok(true));
}

#[test]
fn finds_primary_and_secondary_ordering_paths() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut tree, _, _) = init_tree(&mut guard);
    insert(&mut tree, 5, 10, 100);
    insert(&mut tree, 3, 0, 30);
    insert(&mut tree, 7, 0, 70);
    insert(&mut tree, 5, 5, 50);
    insert(&mut tree, 5, 15, 150);

    assert_eq!(lookup(&tree, 2, 0), Ok(None));
    assert_eq!(lookup(&tree, 5, 5), Ok(Some(50)));
    assert_eq!(lookup(&tree, 5, 10), Ok(Some(100)));
    assert_eq!(lookup(&tree, 5, 12), Ok(None));
    assert_eq!(lookup(&tree, 5, 15), Ok(Some(150)));
    assert_eq!(lookup(&tree, 8, 0), Ok(None));

    {
        let mut entry = unsafe { tree.find_by_mut(5, 32, |entry| 10_u32.cmp(&entry.secondary)) }
            .unwrap()
            .unwrap();
        assert_eq!(entry.entry().node.key, 5);
        assert_eq!(*entry.payload(), 100);
        *entry.payload_mut() = 101;
    }

    assert_eq!(lookup(&tree, 5, 10), Ok(Some(101)));
}

#[test]
fn iterates_in_order_and_reports_the_bound() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut tree, _, _) = init_tree(&mut guard);
    insert(&mut tree, 5, 10, 100);
    insert(&mut tree, 3, 0, 30);
    insert(&mut tree, 7, 0, 70);
    insert(&mut tree, 5, 5, 50);
    insert(&mut tree, 5, 15, 150);

    let entries = tree
        .iter(8)
        .map(|entry| {
            entry.map(|entry| (entry.entry().node.key, entry.entry().secondary, *entry.payload()))
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries, [(3, 0, 30), (5, 5, 50), (5, 10, 100), (5, 15, 150), (7, 0, 70)]);

    let mut limited = tree.iter(2);
    assert_eq!(limited.next().unwrap().unwrap().entry().node.key, 3);
    assert_eq!(limited.next().unwrap().unwrap().entry().node.key, 5);
    assert!(matches!(limited.next(), Some(Err(SlabRbTreeError::TraversalLimit))));
}

#[test]
fn removes_a_root_with_two_children_before_freeing_it() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut tree, _, sentinel) = init_tree(&mut guard);
    let [one, two, three, four] = insert_four(&mut tree);

    assert!(unsafe { two.cast::<ngx_rbtree_node_t>().as_ref() }.parent.is_null());
    assert_eq!(child_count(two, sentinel), 2);
    unsafe { tree.remove(two) }.unwrap();
    assert_detached(two);
    assert_eq!(lookup(&tree, 2, 0), Ok(None));
    assert_eq!(lookup(&tree, 1, 0), Ok(Some(10)));
    assert_eq!(lookup(&tree, 3, 0), Ok(Some(30)));
    assert_eq!(lookup(&tree, 4, 0), Ok(Some(40)));
    free_detached(&mut tree, two);

    let _ = (one, three, four);
}

#[test]
fn removes_a_root_with_one_child_and_normalizes_the_new_root() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut tree, _, _) = init_tree(&mut guard);
    let root = insert(&mut tree, 2, 0, 20);
    let child = insert(&mut tree, 1, 0, 10);

    unsafe { tree.remove(root) }.unwrap();

    assert!(unsafe { child.cast::<ngx_rbtree_node_t>().as_ref() }.parent.is_null());
    assert_eq!(lookup(&tree, 1, 0), Ok(Some(10)));
    free_detached(&mut tree, root);
}

#[test]
fn removes_a_leaf_before_freeing_it() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut tree, _, sentinel) = init_tree(&mut guard);
    let [one, _, _, _] = insert_four(&mut tree);

    assert_eq!(child_count(one, sentinel), 0);
    unsafe { tree.remove(one) }.unwrap();
    assert_detached(one);
    assert_eq!(lookup(&tree, 1, 0), Ok(None));
    free_detached(&mut tree, one);
}

#[test]
fn removes_a_one_child_entry_before_freeing_it() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut tree, _, sentinel) = init_tree(&mut guard);
    let [_, _, three, _] = insert_four(&mut tree);

    assert_eq!(child_count(three, sentinel), 1);
    unsafe { tree.remove(three) }.unwrap();
    assert_detached(three);
    assert_eq!(lookup(&tree, 3, 0), Ok(None));
    free_detached(&mut tree, three);
}

#[test]
fn rejects_a_null_root() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (tree, raw_tree, _, _) = single_tree(&mut guard);

    unsafe { (*raw_tree.as_ptr()).root = ptr::null_mut() };
    assert_eq!(tree.is_empty(), Err(SlabRbTreeError::NullRoot));
}

#[test]
fn rejects_an_out_of_range_root() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (tree, raw_tree, _, _) = single_tree(&mut guard);
    let outside = unsafe { zone.mapping().add(zone.mapping_len()) }.cast();

    unsafe { (*raw_tree.as_ptr()).root = outside };
    assert_eq!(tree.is_empty(), Err(SlabRbTreeError::Slab(SlabError::OutOfRange)));
}

#[test]
fn rejects_a_misaligned_root() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (tree, raw_tree, _, _) = single_tree(&mut guard);
    let misaligned = unsafe { zone.mapping().add(1) }.cast();

    unsafe { (*raw_tree.as_ptr()).root = misaligned };
    assert_eq!(tree.is_empty(), Err(SlabRbTreeError::Slab(SlabError::MisalignedPointer)));
}

#[test]
fn rejects_a_changed_sentinel() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut tree, raw_tree, _, _) = single_tree(&mut guard);
    let replacement = tree.guard_mut().calloc(Layout::new::<ngx_rbtree_node_t>()).unwrap().cast();

    unsafe { (*raw_tree.as_ptr()).sentinel = replacement.as_ptr() };
    assert_eq!(tree.is_empty(), Err(SlabRbTreeError::SentinelChanged));
}

#[test]
fn rejects_a_broken_parent_link() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (tree, _, sentinel, entry) = single_tree(&mut guard);

    unsafe { (*entry.cast::<ngx_rbtree_node_t>().as_ptr()).parent = sentinel.as_ptr() };
    assert_eq!(tree.is_empty(), Err(SlabRbTreeError::BrokenParent));
}

#[test]
fn rejects_a_null_child_link() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (tree, _, _, entry) = single_tree(&mut guard);

    unsafe { (*entry.cast::<ngx_rbtree_node_t>().as_ptr()).left = ptr::null_mut() };
    assert_eq!(tree.is_empty(), Err(SlabRbTreeError::NullChild));
}

#[test]
fn rejects_a_cycle_during_bounded_iteration() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (tree, _, _, entry) = single_tree(&mut guard);
    let node = entry.cast::<ngx_rbtree_node_t>();

    unsafe { (*node.as_ptr()).left = node.as_ptr() };
    let mut iter = tree.iter(4);
    assert!(matches!(iter.next(), Some(Err(SlabRbTreeError::Cycle))));
}
