use alloc::{vec, vec::Vec};
use core::alloc::Layout;
use core::mem;
use core::ptr::{self, NonNull};

use nginx_sys::{ngx_queue_t, ngx_rbt_red, ngx_rbtree_node_t, ngx_rbtree_t};

use crate::collections::{SlabRbTree, SlabRbTreeEntry};
use crate::core::slab::tests::TestZone;
use crate::core::{SlabError, SlabGuard};

use super::{SlabQueue, SlabQueueEntry, SlabQueueError};

#[repr(C)]
struct Entry {
    queue: ngx_queue_t,
    tree: ngx_rbtree_node_t,
    value: i32,
}

unsafe impl SlabQueueEntry for Entry {
    type Payload = i32;

    unsafe fn from_queue(queue: NonNull<ngx_queue_t>) -> NonNull<Self> {
        queue.cast()
    }

    unsafe fn queue_node(entry: NonNull<Self>) -> NonNull<ngx_queue_t> {
        entry.cast()
    }

    unsafe fn payload(entry: NonNull<Self>) -> NonNull<Self::Payload> {
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*entry.as_ptr()).value)) }
    }
}

unsafe impl SlabRbTreeEntry for Entry {
    type Payload = i32;

    unsafe fn from_rbtree_node(node: NonNull<ngx_rbtree_node_t>) -> NonNull<Self> {
        let entry = unsafe { node.as_ptr().byte_sub(mem::offset_of!(Self, tree)).cast() };
        unsafe { NonNull::new_unchecked(entry) }
    }

    unsafe fn rbtree_node(entry: NonNull<Self>) -> NonNull<ngx_rbtree_node_t> {
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*entry.as_ptr()).tree)) }
    }

    unsafe fn payload(entry: NonNull<Self>) -> NonNull<Self::Payload> {
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*entry.as_ptr()).value)) }
    }
}

unsafe extern "C" fn insert_by_key(
    mut current: *mut ngx_rbtree_node_t,
    node: *mut ngx_rbtree_node_t,
    sentinel: *mut ngx_rbtree_node_t,
) {
    loop {
        let link = unsafe {
            if (*node).key < (*current).key { &mut (*current).left } else { &mut (*current).right }
        };
        if ptr::addr_eq(*link, sentinel) {
            *link = node;
            break;
        }
        current = *link;
    }

    unsafe {
        (*node).parent = current;
        (*node).left = sentinel;
        (*node).right = sentinel;
        ngx_rbt_red(node);
    }
}

fn init_queue<'guard, 'zone, 'lock>(
    guard: &'guard mut SlabGuard<'zone, 'lock>,
) -> (SlabQueue<'guard, 'zone, 'lock, Entry>, NonNull<ngx_queue_t>) {
    let head = guard.calloc(Layout::new::<ngx_queue_t>()).unwrap().cast();
    let queue = unsafe { SlabQueue::init(guard, head) }.unwrap();

    (queue, head)
}

fn allocate_entry(
    queue: &mut SlabQueue<'_, '_, '_, Entry>,
    key: usize,
    value: i32,
) -> NonNull<Entry> {
    let entry: NonNull<Entry> = queue.guard_mut().calloc(Layout::new::<Entry>()).unwrap().cast();
    let queue_node = unsafe { mem::zeroed() };
    let tree_node = unsafe { mem::zeroed() };
    unsafe {
        entry.as_ptr().write(Entry { queue: queue_node, tree: tree_node, value });
        (*entry.as_ptr()).tree.key = key;
    }
    entry
}

fn push_back(queue: &mut SlabQueue<'_, '_, '_, Entry>, key: usize, value: i32) -> NonNull<Entry> {
    let entry = allocate_entry(queue, key, value);
    unsafe { queue.push_back(entry) }.unwrap();
    entry
}

fn values(queue: &SlabQueue<'_, '_, '_, Entry>) -> Result<Vec<i32>, SlabQueueError> {
    queue.iter(16).map(|entry| entry.map(|entry| *entry.payload())).collect()
}

fn assert_queue_detached(entry: NonNull<Entry>) {
    let queue = unsafe { entry.cast::<ngx_queue_t>().as_ref() };
    assert!(queue.prev.is_null());
    assert!(queue.next.is_null());
}

fn assert_tree_detached(entry: NonNull<Entry>) {
    let tree =
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*entry.as_ptr()).tree)).as_ref() };
    assert!(tree.left.is_null());
    assert!(tree.right.is_null());
    assert!(tree.parent.is_null());
}

#[test]
fn initializes_an_empty_queue() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (queue, _) = init_queue(&mut guard);

    assert_eq!(queue.is_empty(), Ok(true));
    assert!(queue.front().unwrap().is_none());
    assert!(queue.back().unwrap().is_none());
}

#[test]
fn inserts_at_both_ends_and_exposes_head_and_tail() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut queue, _) = init_queue(&mut guard);
    let one = push_back(&mut queue, 1, 10);
    let two = push_back(&mut queue, 2, 20);
    let three = allocate_entry(&mut queue, 3, 30);
    unsafe { queue.push_front(three) }.unwrap();

    assert_eq!(*queue.front().unwrap().unwrap().payload(), 30);
    assert_eq!(*queue.back().unwrap().unwrap().payload(), 20);
    {
        let mut front = queue.front_mut().unwrap().unwrap();
        *front.payload_mut() = 31;
    }
    assert_eq!(values(&queue), Ok(vec![31, 10, 20]));

    let _ = (one, two);
}

#[test]
fn unlinks_a_record_before_freeing_it() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut queue, _) = init_queue(&mut guard);
    let one = push_back(&mut queue, 1, 10);
    push_back(&mut queue, 2, 20);

    unsafe { queue.remove(one) }.unwrap();
    assert_queue_detached(one);
    assert_eq!(values(&queue), Ok(vec![20]));
    unsafe { queue.guard_mut().free(one.cast(), Layout::new::<Entry>()) }.unwrap();
}

#[test]
fn moves_records_to_the_front_in_mru_order() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut queue, _) = init_queue(&mut guard);
    let one = push_back(&mut queue, 1, 10);
    let two = push_back(&mut queue, 2, 20);
    let three = push_back(&mut queue, 3, 30);

    unsafe { queue.move_to_front(two) }.unwrap();
    assert_eq!(values(&queue), Ok(vec![20, 10, 30]));
    unsafe { queue.move_to_front(three) }.unwrap();
    assert_eq!(values(&queue), Ok(vec![30, 20, 10]));

    let _ = one;
}

#[test]
fn reports_a_bounded_traversal() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut queue, _) = init_queue(&mut guard);
    push_back(&mut queue, 1, 10);
    push_back(&mut queue, 2, 20);
    push_back(&mut queue, 3, 30);

    let mut iter = queue.iter(2);
    assert_eq!(*iter.next().unwrap().unwrap().payload(), 10);
    assert_eq!(*iter.next().unwrap().unwrap().payload(), 20);
    assert!(matches!(iter.next(), Some(Err(SlabQueueError::TraversalLimit))));
}

#[test]
fn rejects_a_null_head_link() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (queue, head) = init_queue(&mut guard);

    unsafe { (*head.as_ptr()).next = ptr::null_mut() };
    assert_eq!(queue.is_empty(), Err(SlabQueueError::NullNext));
}

#[test]
fn rejects_an_out_of_range_head_link() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (queue, head) = init_queue(&mut guard);
    let outside = unsafe { zone.mapping().add(zone.mapping_len()) }.cast();

    unsafe { (*head.as_ptr()).next = outside };
    assert_eq!(queue.is_empty(), Err(SlabQueueError::Slab(SlabError::OutOfRange)));
}

#[test]
fn rejects_a_broken_backlink() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut queue, _) = init_queue(&mut guard);
    let entry = push_back(&mut queue, 1, 10);

    unsafe { (*entry.cast::<ngx_queue_t>().as_ptr()).prev = entry.cast().as_ptr() };
    assert!(matches!(queue.front(), Err(SlabQueueError::BrokenLink)));
}

#[test]
fn rejects_a_cycle() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut queue, _) = init_queue(&mut guard);
    let first = push_back(&mut queue, 1, 10);
    push_back(&mut queue, 2, 20);

    unsafe { (*first.cast::<ngx_queue_t>().as_ptr()).next = first.cast().as_ptr() };
    assert!(matches!(queue.front(), Err(SlabQueueError::Cycle)));
}

#[test]
fn rejects_double_link_membership() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let (mut queue, _) = init_queue(&mut guard);
    let entry = push_back(&mut queue, 1, 10);

    assert_eq!(unsafe { queue.push_front(entry) }, Err(SlabQueueError::AlreadyLinked));
}

#[test]
fn detaches_queue_and_tree_links_before_freeing_a_record() {
    let zone = TestZone::new();
    let mut pool = zone.pool();
    let mut guard = pool.lock();
    let raw_tree = guard.calloc(Layout::new::<ngx_rbtree_t>()).unwrap().cast();
    let sentinel = guard.calloc(Layout::new::<ngx_rbtree_node_t>()).unwrap().cast();
    let head = guard.calloc(Layout::new::<ngx_queue_t>()).unwrap().cast();
    let entry: NonNull<Entry> = guard.calloc(Layout::new::<Entry>()).unwrap().cast();
    let queue_node = unsafe { mem::zeroed() };
    let tree_node = unsafe { mem::zeroed() };
    unsafe {
        entry.as_ptr().write(Entry { queue: queue_node, tree: tree_node, value: 10 });
        (*entry.as_ptr()).tree.key = 1;
    }

    {
        let mut tree =
            unsafe { SlabRbTree::init(&mut guard, raw_tree, sentinel, Some(insert_by_key)) }
                .unwrap();
        unsafe { tree.insert(entry) }.unwrap();
    }
    {
        let mut queue = unsafe { SlabQueue::init(&mut guard, head) }.unwrap();
        unsafe { queue.push_back(entry) }.unwrap();
    }
    {
        let mut queue = unsafe { SlabQueue::from_raw(&mut guard, head) }.unwrap();
        unsafe { queue.remove(entry) }.unwrap();
    }
    {
        let mut tree = unsafe { SlabRbTree::from_raw(&mut guard, raw_tree) }.unwrap();
        unsafe { tree.remove(entry) }.unwrap();
    }

    assert_queue_detached(entry);
    assert_tree_detached(entry);
    unsafe { guard.free(entry.cast(), Layout::new::<Entry>()) }.unwrap();
}
