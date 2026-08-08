//! Guard-scoped intrusive queues in nginx shared slab memory.

use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use nginx_sys::{
    ngx_queue_init, ngx_queue_insert_after, ngx_queue_insert_before, ngx_queue_remove, ngx_queue_t,
};

use crate::core::{SlabError, SlabGuard};

/// Failure while validating or traversing a shared intrusive queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabQueueError {
    /// A shared-memory pointer failed the slab guard's range or alignment checks.
    Slab(SlabError),
    /// A queue node has a null next link.
    NullNext,
    /// A queue node has a null previous link.
    NullPrev,
    /// A queue operation reached the sentinel as an entry node.
    HeadNode,
    /// An inserted node still has intrusive links from another queue.
    AlreadyLinked,
    /// Adjacent queue links do not point back to each other.
    BrokenLink,
    /// The entry conversion does not round-trip through its queue node.
    EntryNodeMismatch,
    /// Traversal exceeded its caller-provided bound.
    TraversalLimit,
    /// A direct or duplicated link repeats a node.
    Cycle,
}

impl From<SlabError> for SlabQueueError {
    fn from(error: SlabError) -> Self {
        Self::Slab(error)
    }
}

/// Conversion contract for a shared record linked through an nginx queue node.
///
/// # Safety
///
/// `Self` must have a stable `repr(C)` layout whose `ngx_queue_t` conversion is reversible.
/// Every converted entry and payload pointer must identify initialized values in the active slab
/// mapping. `payload` must identify a disjoint field whose safe mutation cannot change queue links.
pub unsafe trait SlabQueueEntry: Sized {
    /// The part of a record that safe callers may mutate while the node stays linked.
    type Payload: Sized;

    /// Converts a checked nginx queue node to its containing shared record.
    ///
    /// # Safety
    ///
    /// `queue` identifies a checked, initialized node for this entry layout.
    unsafe fn from_queue(queue: NonNull<ngx_queue_t>) -> NonNull<Self>;

    /// Returns the nginx queue node embedded in a checked shared record.
    ///
    /// # Safety
    ///
    /// `entry` identifies a checked, initialized record for this entry layout.
    unsafe fn queue_node(entry: NonNull<Self>) -> NonNull<ngx_queue_t>;

    /// Returns the safely mutable payload embedded in a checked shared record.
    ///
    /// # Safety
    ///
    /// `entry` identifies a checked, initialized record for this entry layout.
    unsafe fn payload(entry: NonNull<Self>) -> NonNull<Self::Payload>;
}

/// An intrusive nginx queue borrowed under a live [`SlabGuard`].
///
/// The adapter neither owns nor drops the sentinel or entries. Its safe views stay bounded by the
/// native mutex guard, while insertion, removal, and movement remain explicit unsafe operations.
pub struct SlabQueue<'guard, 'zone, 'lock, T> {
    guard: &'guard mut SlabGuard<'zone, 'lock>,
    head: NonNull<ngx_queue_t>,
    _entry: PhantomData<T>,
}

/// Immutable access to one checked shared queue record.
///
/// The handle cannot escape the queue borrow:
///
/// ```compile_fail
/// # use ngx::collections::{SlabQueue, SlabQueueEntry, SlabQueueEntryRef};
/// fn escape<T: SlabQueueEntry>(
///     queue: &SlabQueue<'_, '_, '_, T>,
/// ) -> SlabQueueEntryRef<'static, T> {
///     queue.front().unwrap().unwrap()
/// }
/// ```
pub struct SlabQueueEntryRef<'queue, T: SlabQueueEntry> {
    entry: NonNull<T>,
    payload: NonNull<T::Payload>,
    _borrow: PhantomData<(&'queue T, *mut ())>,
}

impl<T: SlabQueueEntry> SlabQueueEntryRef<'_, T> {
    /// Returns the checked record without granting mutable access to its queue state.
    pub fn entry(&self) -> &T {
        unsafe { self.entry.as_ref() }
    }

    /// Returns the checked immutable payload.
    pub fn payload(&self) -> &T::Payload {
        unsafe { self.payload.as_ref() }
    }
}

/// Mutable payload access to one checked shared queue record.
///
/// The adapter intentionally has no mutable-record accessor, so queue links cannot be changed
/// through safe code:
///
/// ```compile_fail
/// # use ngx::collections::{SlabQueueEntry, SlabQueueEntryMut};
/// fn mutate<T: SlabQueueEntry>(entry: &mut SlabQueueEntryMut<'_, T>) {
///     entry.entry_mut();
/// }
/// ```
pub struct SlabQueueEntryMut<'queue, T: SlabQueueEntry> {
    entry: NonNull<T>,
    payload: NonNull<T::Payload>,
    _borrow: PhantomData<(&'queue mut T, *mut ())>,
}

impl<T: SlabQueueEntry> SlabQueueEntryMut<'_, T> {
    /// Returns the checked record without granting mutable access to its queue state.
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
struct QueueParts {
    next: NonNull<ngx_queue_t>,
    prev: NonNull<ngx_queue_t>,
}

#[derive(Clone, Copy)]
struct QueueNodeLinks {
    next: NonNull<ngx_queue_t>,
}

impl<'guard, 'zone, 'lock, T> SlabQueue<'guard, 'zone, 'lock, T>
where
    T: SlabQueueEntry,
{
    /// Initializes an existing shared queue sentinel.
    ///
    /// # Safety
    ///
    /// `head` must be exclusive, properly allocated shared slab storage that stays live for this
    /// guard.
    pub unsafe fn init(
        guard: &'guard mut SlabGuard<'zone, 'lock>,
        head: NonNull<ngx_queue_t>,
    ) -> Result<Self, SlabQueueError> {
        guard.check_typed(head)?;
        unsafe { ngx_queue_init(head.as_ptr()) };
        Ok(Self { guard, head, _entry: PhantomData })
    }

    /// Borrows an initialized shared queue sentinel.
    ///
    /// # Safety
    ///
    /// `head` must identify one initialized nginx queue in the active slab mapping. Every linked
    /// node must satisfy `T`'s conversion contract and remain valid under this guard.
    pub unsafe fn from_raw(
        guard: &'guard mut SlabGuard<'zone, 'lock>,
        head: NonNull<ngx_queue_t>,
    ) -> Result<Self, SlabQueueError> {
        guard.check_typed(head)?;
        let this = Self { guard, head, _entry: PhantomData };
        this.queue_parts()?;
        Ok(this)
    }

    /// Returns the locked slab guard for allocating or releasing detached shared records.
    pub fn guard_mut(&mut self) -> &mut SlabGuard<'zone, 'lock> {
        self.guard
    }

    /// Returns whether the queue currently has no entries after validating its sentinel links.
    pub fn is_empty(&self) -> Result<bool, SlabQueueError> {
        let parts = self.queue_parts()?;
        if parts.next == self.head {
            return Ok(true);
        }

        self.node_links(parts.next)?;
        Ok(false)
    }

    /// Returns the first queue record, if any.
    pub fn front(&self) -> Result<Option<SlabQueueEntryRef<'_, T>>, SlabQueueError> {
        let parts = self.queue_parts()?;
        if parts.next == self.head {
            return Ok(None);
        }

        self.node_links(parts.next)?;
        Ok(Some(self.entry_ref_from_node(parts.next)?))
    }

    /// Returns the last queue record, if any.
    pub fn back(&self) -> Result<Option<SlabQueueEntryRef<'_, T>>, SlabQueueError> {
        let parts = self.queue_parts()?;
        if parts.prev == self.head {
            return Ok(None);
        }

        self.node_links(parts.prev)?;
        Ok(Some(self.entry_ref_from_node(parts.prev)?))
    }

    /// Returns the first queue record with mutable access only to its payload.
    pub fn front_mut(&mut self) -> Result<Option<SlabQueueEntryMut<'_, T>>, SlabQueueError> {
        let parts = self.queue_parts()?;
        if parts.next == self.head {
            return Ok(None);
        }

        self.node_links(parts.next)?;
        let (entry, payload) = self.entry_parts_from_node(parts.next)?;
        Ok(Some(SlabQueueEntryMut { entry, payload, _borrow: PhantomData }))
    }

    /// Returns the last queue record with mutable access only to its payload.
    pub fn back_mut(&mut self) -> Result<Option<SlabQueueEntryMut<'_, T>>, SlabQueueError> {
        let parts = self.queue_parts()?;
        if parts.prev == self.head {
            return Ok(None);
        }

        self.node_links(parts.prev)?;
        let (entry, payload) = self.entry_parts_from_node(parts.prev)?;
        Ok(Some(SlabQueueEntryMut { entry, payload, _borrow: PhantomData }))
    }

    /// Inserts one detached shared record at the front of the queue.
    ///
    /// # Safety
    ///
    /// `entry` must identify an initialized, detached record that satisfies `T`'s conversion
    /// contract. The current queue must be well formed, and no entry handle may exist while the
    /// queue is mutated.
    pub unsafe fn push_front(&mut self, entry: NonNull<T>) -> Result<(), SlabQueueError> {
        self.queue_parts()?;
        let node = self.node_from_entry(entry)?;
        self.require_detached(node)?;

        unsafe { ngx_queue_insert_after(self.head.as_ptr(), node.as_ptr()) };
        Ok(())
    }

    /// Inserts one detached shared record at the back of the queue.
    ///
    /// # Safety
    ///
    /// `entry` must identify an initialized, detached record that satisfies `T`'s conversion
    /// contract. The current queue must be well formed, and no entry handle may exist while the
    /// queue is mutated.
    pub unsafe fn push_back(&mut self, entry: NonNull<T>) -> Result<(), SlabQueueError> {
        self.queue_parts()?;
        let node = self.node_from_entry(entry)?;
        self.require_detached(node)?;

        unsafe { ngx_queue_insert_before(self.head.as_ptr(), node.as_ptr()) };
        Ok(())
    }

    /// Unlinks one queue record and leaves its queue links detached.
    ///
    /// # Safety
    ///
    /// `entry` must currently belong to this well-formed queue at this address. No entry handle may
    /// exist while the queue is mutated. After success, the record can be released through
    /// [`SlabGuard::free`](crate::core::SlabGuard::free).
    pub unsafe fn remove(&mut self, entry: NonNull<T>) -> Result<(), SlabQueueError> {
        self.queue_parts()?;
        let mut node = self.node_from_entry(entry)?;
        self.node_links(node)?;

        unsafe { ngx_queue_remove(node.as_ptr()) };
        unsafe {
            let node = node.as_mut();
            node.prev = ptr::null_mut();
            node.next = ptr::null_mut();
        }
        Ok(())
    }

    /// Moves one linked queue record to the front of the queue.
    ///
    /// # Safety
    ///
    /// `entry` must currently belong to this well-formed queue at this address. No entry handle may
    /// exist while the queue is mutated.
    pub unsafe fn move_to_front(&mut self, entry: NonNull<T>) -> Result<(), SlabQueueError> {
        self.queue_parts()?;
        let node = self.node_from_entry(entry)?;
        self.node_links(node)?;

        unsafe {
            ngx_queue_remove(node.as_ptr());
            ngx_queue_insert_after(self.head.as_ptr(), node.as_ptr());
        }
        Ok(())
    }

    /// Iterates from front to back without returning more than `max_entries` records.
    ///
    /// The iterator yields [`SlabQueueError::TraversalLimit`] if the queue has another record after
    /// the requested bound or malformed links exhaust that finite traversal.
    pub fn iter(&self, max_entries: usize) -> SlabQueueIter<'_, 'guard, 'zone, 'lock, T> {
        SlabQueueIter { queue: self, current: self.head, yielded: 0, max_entries, done: false }
    }

    fn queue_parts(&self) -> Result<QueueParts, SlabQueueError> {
        self.check_node(self.head)?;
        let head = unsafe { self.head.as_ref() };
        let next = NonNull::new(head.next).ok_or(SlabQueueError::NullNext)?;
        let prev = NonNull::new(head.prev).ok_or(SlabQueueError::NullPrev)?;
        self.check_node(next)?;
        self.check_node(prev)?;

        if next == self.head {
            if prev != self.head {
                return Err(SlabQueueError::BrokenLink);
            }
        } else {
            let next_node = unsafe { next.as_ref() };
            if !ptr::addr_eq(next_node.prev, self.head.as_ptr()) {
                return Err(SlabQueueError::BrokenLink);
            }
        }

        if prev == self.head {
            if next != self.head {
                return Err(SlabQueueError::BrokenLink);
            }
        } else {
            let prev_node = unsafe { prev.as_ref() };
            if !ptr::addr_eq(prev_node.next, self.head.as_ptr()) {
                return Err(SlabQueueError::BrokenLink);
            }
        }

        Ok(QueueParts { next, prev })
    }

    fn check_node(&self, node: NonNull<ngx_queue_t>) -> Result<(), SlabQueueError> {
        self.guard.check_typed(node)?;
        Ok(())
    }

    fn node_links(&self, node: NonNull<ngx_queue_t>) -> Result<QueueNodeLinks, SlabQueueError> {
        if node == self.head {
            return Err(SlabQueueError::HeadNode);
        }
        self.check_node(node)?;
        let raw = unsafe { node.as_ref() };
        let prev = NonNull::new(raw.prev).ok_or(SlabQueueError::NullPrev)?;
        let next = NonNull::new(raw.next).ok_or(SlabQueueError::NullNext)?;
        if prev == node || next == node {
            return Err(SlabQueueError::Cycle);
        }
        self.check_node(prev)?;
        self.check_node(next)?;

        let prev_node = unsafe { prev.as_ref() };
        let next_node = unsafe { next.as_ref() };
        if !ptr::addr_eq(prev_node.next, node.as_ptr())
            || !ptr::addr_eq(next_node.prev, node.as_ptr())
        {
            return Err(SlabQueueError::BrokenLink);
        }
        if prev == next && prev != self.head {
            return Err(SlabQueueError::Cycle);
        }

        Ok(QueueNodeLinks { next })
    }

    fn require_detached(&self, node: NonNull<ngx_queue_t>) -> Result<(), SlabQueueError> {
        self.check_node(node)?;
        let node = unsafe { node.as_ref() };
        if !node.prev.is_null() || !node.next.is_null() {
            return Err(SlabQueueError::AlreadyLinked);
        }
        Ok(())
    }

    fn entry_parts_from_node(
        &self,
        node: NonNull<ngx_queue_t>,
    ) -> Result<(NonNull<T>, NonNull<T::Payload>), SlabQueueError> {
        self.check_node(node)?;
        let entry = unsafe { T::from_queue(node) };
        self.guard.check_typed(entry)?;

        let entry_node = unsafe { T::queue_node(entry) };
        self.check_node(entry_node)?;
        if entry_node != node {
            return Err(SlabQueueError::EntryNodeMismatch);
        }

        let payload = unsafe { T::payload(entry) };
        self.guard.check_typed(payload)?;
        Ok((entry, payload))
    }

    fn node_from_entry(&self, entry: NonNull<T>) -> Result<NonNull<ngx_queue_t>, SlabQueueError> {
        self.guard.check_typed(entry)?;
        let node = unsafe { T::queue_node(entry) };
        self.check_node(node)?;
        if node == self.head {
            return Err(SlabQueueError::HeadNode);
        }
        let (round_trip, _) = self.entry_parts_from_node(node)?;
        if round_trip != entry {
            return Err(SlabQueueError::EntryNodeMismatch);
        }
        Ok(node)
    }

    fn entry_ref_from_node(
        &self,
        node: NonNull<ngx_queue_t>,
    ) -> Result<SlabQueueEntryRef<'_, T>, SlabQueueError> {
        let (entry, payload) = self.entry_parts_from_node(node)?;
        Ok(SlabQueueEntryRef { entry, payload, _borrow: PhantomData })
    }
}

/// A bounded front-to-back traversal over a [`SlabQueue`].
pub struct SlabQueueIter<'queue, 'guard, 'zone, 'lock, T: SlabQueueEntry> {
    queue: &'queue SlabQueue<'guard, 'zone, 'lock, T>,
    current: NonNull<ngx_queue_t>,
    yielded: usize,
    max_entries: usize,
    done: bool,
}

impl<'queue, T> SlabQueueIter<'queue, '_, '_, '_, T>
where
    T: SlabQueueEntry,
{
    fn next_entry(&mut self) -> Result<Option<SlabQueueEntryRef<'queue, T>>, SlabQueueError> {
        let parts = self.queue.queue_parts()?;
        let next = if self.current == self.queue.head {
            parts.next
        } else {
            self.queue.node_links(self.current)?.next
        };
        if next == self.queue.head {
            return Ok(None);
        }
        if self.yielded == self.max_entries {
            return Err(SlabQueueError::TraversalLimit);
        }

        self.queue.node_links(next)?;
        let entry = self.queue.entry_ref_from_node(next)?;
        self.current = next;
        self.yielded += 1;
        Ok(Some(entry))
    }
}

impl<'queue, T> Iterator for SlabQueueIter<'queue, '_, '_, '_, T>
where
    T: SlabQueueEntry,
{
    type Item = Result<SlabQueueEntryRef<'queue, T>, SlabQueueError>;

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
#[path = "slab_queue_tests.rs"]
mod tests;
