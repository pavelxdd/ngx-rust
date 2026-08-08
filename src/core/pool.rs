use core::alloc::Layout;
use core::convert::Infallible;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::ptr::{self, NonNull};

use nginx_sys::{
    NGX_ALIGNMENT, ngx_palloc, ngx_pcalloc, ngx_pfree, ngx_pmemalign, ngx_pnalloc,
    ngx_pool_cleanup_add, ngx_pool_cleanup_t, ngx_pool_t,
};

use crate::allocator::{AllocError, Allocator, dangling_for_layout};

/// Non-owning wrapper for an [`ngx_pool_t`] pointer, providing methods for working with memory
/// pools.
///
/// See <https://nginx.org/en/docs/dev/development_guide.html#pool>
///
/// The native pool remains opaque to safe Rust:
///
/// ```compile_fail
/// # use ngx::core::Pool;
/// # use ngx::ffi::ngx_pool_t;
/// # fn native_reference(pool: &Pool<'_>) {
/// let _: &ngx_pool_t = pool.as_ref();
/// # }
/// ```
///
/// ```compile_fail
/// # use ngx::core::Pool;
/// # use ngx::ffi::ngx_pool_t;
/// # fn native_reference(pool: &mut Pool<'_>) {
/// let _: &mut ngx_pool_t = pool.as_mut();
/// # }
/// ```
///
/// A raw pointer can be passed to nginx, but dereferencing it is explicitly unsafe:
///
/// ```compile_fail
/// # use ngx::core::Pool;
/// # fn native_reference(pool: &Pool<'_>) {
/// let _native = &*pool.as_ptr();
/// # }
/// ```
///
/// Pool handles cannot be detached from their proven lifetime or moved to another thread:
///
/// ```compile_fail
/// # use ngx::core::Pool;
/// fn erase_lifetime(pool: Pool<'_>) -> Pool<'static> {
///     pool
/// }
/// ```
///
/// ```compile_fail
/// # use ngx::core::Pool;
/// # fn require_send<T: Send>(_: T) {}
/// # fn send_pool(pool: Pool<'_>) {
/// require_send(pool);
/// # }
/// ```
///
/// ```compile_fail
/// # use ngx::core::Pool;
/// # fn require_sync<T: Sync>(_: &T) {}
/// # fn share_pool(pool: &Pool<'_>) {
/// require_sync(pool);
/// # }
/// ```
///
/// Cleanup values cannot borrow shorter-lived storage because nginx may retain them until the
/// pool is destroyed:
///
/// ```compile_fail
/// # use core::cell::Cell;
/// # use ngx::core::Pool;
/// # fn register_borrowed(pool: &Pool<'_>, counter: &Cell<usize>) {
/// struct Borrowed<'a>(&'a Cell<usize>);
/// impl Drop for Borrowed<'_> {
///     fn drop(&mut self) {
///         self.0.set(self.0.get() + 1);
///     }
/// }
/// let _value = pool.allocate_with_cleanup(|| Borrowed(counter)).unwrap();
/// # }
/// ```
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Pool<'pool> {
    raw: NonNull<ngx_pool_t>,
    _lifetime: PhantomData<&'pool ngx_pool_t>,
}

/// Error returned when a pool cleanup value cannot be allocated or constructed.
#[derive(Debug, Eq, PartialEq)]
pub enum PoolCleanupError<E> {
    /// Nginx could not allocate the cleanup entry or value storage.
    Allocation,
    /// The value constructor returned an error.
    Construction(E),
}

/// A stable, pool-owned value registered with an nginx cleanup handler.
///
/// Moving this handle does not move the value. Dropping the handle leaves the value owned by the
/// pool; [`remove`](Self::remove) unlinks and drops it early.
#[derive(Debug)]
pub struct PoolValue<'pool, T> {
    value: NonNull<T>,
    cleanup: NonNull<ngx_pool_cleanup_t>,
    pool: Pool<'pool>,
}

impl<T> PoolValue<'_, T> {
    /// Returns the stable address of the pool-owned value.
    pub fn as_non_null(&self) -> NonNull<T> {
        self.value
    }

    /// Discards the safe handle and returns the stable address retained by the pool cleanup.
    ///
    /// Dereferencing the returned pointer remains unsafe, and the pointer must not be used after
    /// the nginx pool is destroyed or the cleanup is removed.
    pub fn into_non_null(self) -> NonNull<T> {
        self.value
    }

    /// Returns a pinned exclusive reference to the stable pool allocation.
    pub fn as_pin_mut(&mut self) -> Pin<&mut T> {
        unsafe { Pin::new_unchecked(self.value.as_mut()) }
    }

    /// Unlinks the cleanup entry and drops the value.
    ///
    /// Returns `false` only when external unsafe code has already unlinked the cleanup entry.
    pub fn remove(self) -> bool {
        if self.pool.unlink_cleanup(self.cleanup).is_none() {
            return false;
        }

        unsafe {
            (*self.cleanup.as_ptr()).handler = None;
            cleanup_type::<T>(self.value.as_ptr().cast());
        }
        true
    }
}

impl<T> Deref for PoolValue<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.value.as_ref() }
    }
}

impl<T: Unpin> DerefMut for PoolValue<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.value.as_mut() }
    }
}

fn cleanup_type_fits_pool<T>() -> bool {
    mem::align_of::<T>() <= NGX_ALIGNMENT
}

unsafe impl Allocator for Pool<'_> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // SAFETY:
        // * This wrapper should be constructed with a valid pointer to ngx_pool_t.
        // * The Pool type is !Send, thus we expect exclusive access for this call.
        // * Pointers are considered mutable unless obtained from an immutable reference.
        let ptr = if layout.size() == 0 {
            // We can guarantee alignment <= NGX_ALIGNMENT for allocations of size 0 made with
            // ngx_palloc_small. Any other cases are implementation-defined, and we can't tell which
            // one will be used internally.
            return Ok(NonNull::slice_from_raw_parts(dangling_for_layout(&layout), layout.size()));
        } else if layout.align() == 1 {
            unsafe { ngx_pnalloc(self.raw.as_ptr(), layout.size()) }
        } else if layout.align() <= NGX_ALIGNMENT {
            unsafe { ngx_palloc(self.raw.as_ptr(), layout.size()) }
        } else if cfg!(any(ngx_feature = "have_posix_memalign", ngx_feature = "have_memalign")) {
            // ngx_pmemalign is always defined, but does not guarantee the requested alignment
            // unless memalign/posix_memalign exists.
            unsafe { ngx_pmemalign(self.raw.as_ptr(), layout.size(), layout.align()) }
        } else {
            return Err(AllocError);
        };

        let ptr = NonNull::<u8>::new(ptr.cast()).ok_or(AllocError)?;
        debug_assert_eq!(ptr.as_ptr().align_offset(layout.align()), 0);
        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // ngx_pfree is noop for small allocations unless NGX_DEBUG_PALLOC is set.
        //
        // Note: there should be no cleanup handlers for the allocations made using this API.
        // Violating that could result in the following issues:
        //  - use-after-free on large allocation
        //  - multiple cleanup handlers attached to a dangling ptr (these are not unique)
        if layout.size() > 0 // 0 is dangling ptr
            && (layout.size() > unsafe { (*self.raw.as_ptr()).max }
                || layout.align() > NGX_ALIGNMENT)
        {
            unsafe { ngx_pfree(self.raw.as_ptr(), ptr.as_ptr().cast()) };
        }
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(
            new_layout.size() >= old_layout.size(),
            "`new_layout.size()` must be greater than or equal to `old_layout.size()`"
        );
        unsafe { self.resize(ptr, old_layout, new_layout) }
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(
            new_layout.size() >= old_layout.size(),
            "`new_layout.size()` must be greater than or equal to `old_layout.size()`"
        );
        unsafe {
            #[allow(clippy::manual_inspect)]
            self.resize(ptr, old_layout, new_layout).map(|new_ptr| {
                new_ptr
                    .cast::<u8>()
                    .byte_add(old_layout.size())
                    .write_bytes(0, new_layout.size() - old_layout.size());
                new_ptr
            })
        }
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(
            new_layout.size() <= old_layout.size(),
            "`new_layout.size()` must be smaller than or equal to `old_layout.size()`"
        );
        unsafe { self.resize(ptr, old_layout, new_layout) }
    }
}

impl<'pool> Pool<'pool> {
    /// Creates a non-owning pool handle from an [`ngx_pool_t`] pointer.
    ///
    /// # Safety
    /// The pointer must identify a live nginx pool for all of `'pool`. The caller must also ensure
    /// nginx pool operations remain confined to the owning worker thread. Null and misaligned
    /// pointers are rejected.
    ///
    /// ```compile_fail
    /// # use ngx::core::Pool;
    /// # use ngx::ffi::ngx_pool_t;
    /// # fn construct(raw: *mut ngx_pool_t) {
    /// let _pool = Pool::from_raw(raw);
    /// # }
    /// ```
    pub unsafe fn from_raw(pool: *mut ngx_pool_t) -> Option<Self> {
        let raw = NonNull::new(pool)?;
        if !pool.is_aligned() {
            return None;
        }

        Some(Self { raw, _lifetime: PhantomData })
    }

    /// Invokes a closure with a pool handle that cannot escape the closure through a safe value.
    ///
    /// # Safety
    /// The pointer must identify a live nginx pool for the complete closure call. Nginx pool
    /// operations must remain confined to the owning worker thread.
    ///
    /// ```compile_fail
    /// # use ngx::core::Pool;
    /// # use ngx::ffi::ngx_pool_t;
    /// # fn escape(raw: *mut ngx_pool_t) {
    /// let _value = unsafe {
    ///     Pool::with_raw(raw, |pool| pool.allocate_with_cleanup(|| 42_u32).unwrap())
    /// };
    /// # }
    /// ```
    pub unsafe fn with_raw<R>(
        pool: *mut ngx_pool_t,
        f: impl for<'scope> FnOnce(Pool<'scope>) -> R,
    ) -> Option<R> {
        let pool = unsafe { Pool::from_raw(pool) }?;
        Some(f(pool))
    }

    /// Expose the underlying `ngx_pool_t` pointer, for use with `ngx::ffi`
    /// functions.
    pub fn as_ptr(&self) -> *mut ngx_pool_t {
        self.raw.as_ptr()
    }

    /// Allocates a value and registers its destructor with the pool.
    ///
    /// The constructor is called only after nginx allocates storage for the value. The destructor
    /// runs when the pool is destroyed or when [`PoolValue::remove`] removes the value.
    pub fn allocate_with_cleanup<T: 'static>(
        &self,
        constructor: impl FnOnce() -> T,
    ) -> Result<PoolValue<'pool, T>, AllocError> {
        match self.try_allocate_with_cleanup(|| Ok::<T, Infallible>(constructor())) {
            Ok(value) => Ok(value),
            Err(PoolCleanupError::Allocation) => Err(AllocError),
            Err(PoolCleanupError::Construction(error)) => match error {},
        }
    }

    /// Allocates a value with a cleanup handler using a fallible constructor.
    ///
    /// The cleanup handler is published only after construction succeeds. A failed constructor
    /// leaves no cleanup entry linked into the pool.
    pub fn try_allocate_with_cleanup<T: 'static, E>(
        &self,
        constructor: impl FnOnce() -> Result<T, E>,
    ) -> Result<PoolValue<'pool, T>, PoolCleanupError<E>> {
        if !cleanup_type_fits_pool::<T>() {
            return Err(PoolCleanupError::Allocation);
        }

        let cleanup =
            NonNull::new(unsafe { ngx_pool_cleanup_add(self.raw.as_ptr(), mem::size_of::<T>()) })
                .ok_or(PoolCleanupError::Allocation)?;

        let data: NonNull<T> = if mem::size_of::<T>() == 0 {
            cleanup.cast()
        } else {
            NonNull::new(unsafe { (*cleanup.as_ptr()).data.cast() })
                .ok_or(PoolCleanupError::Allocation)?
        };
        debug_assert_eq!(data.as_ptr().align_offset(mem::align_of::<T>()), 0);

        let value = match constructor() {
            Ok(value) => value,
            Err(error) => {
                let removed = self.unlink_cleanup(cleanup);
                debug_assert!(removed.is_some());
                return Err(PoolCleanupError::Construction(error));
            }
        };
        unsafe {
            data.as_ptr().write(value);
            (*cleanup.as_ptr()).data = data.as_ptr().cast();
            (*cleanup.as_ptr()).handler = Some(cleanup_type::<T>);
        }

        Ok(PoolValue { value: data, cleanup, pool: self.clone() })
    }

    /// Allocates memory from the pool of the specified size.
    /// The resulting pointer is aligned to a platform word size.
    ///
    /// Returns a raw pointer to the allocated memory.
    pub fn alloc(&self, size: usize) -> *mut c_void {
        unsafe { ngx_palloc(self.raw.as_ptr(), size) }
    }

    /// Allocates memory for a type from the pool.
    /// The resulting pointer is aligned to a platform word size.
    ///
    /// Returns a typed pointer to the allocated memory.
    pub fn alloc_type<T: Copy>(&self) -> *mut T {
        self.alloc(mem::size_of::<T>()) as *mut T
    }

    /// Allocates zeroed memory from the pool of the specified size.
    /// The resulting pointer is aligned to a platform word size.
    ///
    /// Returns a raw pointer to the allocated memory.
    pub fn calloc(&self, size: usize) -> *mut c_void {
        unsafe { ngx_pcalloc(self.raw.as_ptr(), size) }
    }

    /// Allocates zeroed memory for a type from the pool.
    /// The resulting pointer is aligned to a platform word size.
    ///
    /// Returns a typed pointer to the allocated memory.
    pub fn calloc_type<T: Copy>(&self) -> *mut T {
        self.calloc(mem::size_of::<T>()) as *mut T
    }

    /// Allocates unaligned memory from the pool of the specified size.
    ///
    /// Returns a raw pointer to the allocated memory.
    pub fn alloc_unaligned(&self, size: usize) -> *mut c_void {
        unsafe { ngx_pnalloc(self.raw.as_ptr(), size) }
    }

    /// Allocates unaligned memory for a type from the pool.
    ///
    /// Returns a typed pointer to the allocated memory.
    pub fn alloc_type_unaligned<T: Copy>(&self) -> *mut T {
        self.alloc_unaligned(mem::size_of::<T>()) as *mut T
    }

    /// Runs the cleanup handler for a value and unlinks it from the pool.
    ///
    /// Returns `false` when the value has no matching cleanup entry.
    ///
    /// # Safety
    ///
    /// `value` must be a pointer returned by
    /// [`PoolValue::into_non_null`] for this pool. No references to the value may be live, and the
    /// pointer must not be used after this call.
    pub unsafe fn remove_cleanup<T>(&self, value: NonNull<T>) -> bool {
        let Some(cleanup) = self
            .unlink_cleanup_if(|cleanup| unsafe { ptr::addr_eq((*cleanup).data, value.as_ptr()) })
        else {
            return false;
        };
        let Some(handler) = (unsafe { (*cleanup.as_ptr()).handler }) else {
            return false;
        };

        unsafe {
            (*cleanup.as_ptr()).handler = None;
            handler((*cleanup.as_ptr()).data);
        }
        true
    }

    fn unlink_cleanup(
        &self,
        cleanup: NonNull<ngx_pool_cleanup_t>,
    ) -> Option<NonNull<ngx_pool_cleanup_t>> {
        self.unlink_cleanup_if(|candidate| ptr::eq(candidate, cleanup.as_ptr()))
    }

    fn unlink_cleanup_if(
        &self,
        mut predicate: impl FnMut(*mut ngx_pool_cleanup_t) -> bool,
    ) -> Option<NonNull<ngx_pool_cleanup_t>> {
        let mut link = unsafe { &raw mut (*self.raw.as_ptr()).cleanup };

        loop {
            let cleanup = unsafe { *link };
            let cleanup = NonNull::new(cleanup)?;
            if predicate(cleanup.as_ptr()) {
                unsafe {
                    *link = (*cleanup.as_ptr()).next;
                    (*cleanup.as_ptr()).next = ptr::null_mut();
                }
                return Some(cleanup);
            }
            link = unsafe { &raw mut (*cleanup.as_ptr()).next };
        }
    }

    /// Resizes a memory allocation in place if possible.
    ///
    /// If resizing is requested for the last allocation in the pool, it may be
    /// possible to adjust pool data and avoid any real allocations.
    ///
    /// # Safety
    /// `ptr` must point to allocated address and `old_layout` must match the current layout
    /// of the allocation.
    #[inline(always)]
    unsafe fn resize(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        if unsafe {
            ptr.byte_add(old_layout.size()).as_ptr() == (*self.raw.as_ptr()).d.last
                && ptr.byte_add(new_layout.size()).as_ptr() <= (*self.raw.as_ptr()).d.end
                && ptr.align_offset(new_layout.align()) == 0
        } {
            let pool = self.raw.as_ptr();
            unsafe { (*pool).d.last = ptr.byte_add(new_layout.size()).as_ptr() };
            Ok(NonNull::slice_from_raw_parts(ptr, new_layout.size()))
        } else {
            let size = core::cmp::min(old_layout.size(), new_layout.size());
            let new_ptr = <Self as Allocator>::allocate(self, new_layout)?;
            unsafe {
                ptr.copy_to_nonoverlapping(new_ptr.cast(), size);
                self.deallocate(ptr, old_layout);
            }
            Ok(new_ptr)
        }
    }
}

/// Drops a value registered in a pool cleanup entry.
///
/// # Safety
/// `data` must be a valid, writable, and properly aligned pointer to an initialized `T`.
unsafe extern "C" fn cleanup_type<T>(data: *mut c_void) {
    unsafe {
        ptr::drop_in_place(data as *mut T);
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use core::alloc::Layout;
    use core::cell::Cell;
    use core::mem;

    use nginx_sys::{ngx_create_pool, ngx_destroy_pool, ngx_log_t};

    use super::*;
    use crate::allocator::Allocator;

    #[repr(align(4096))]
    struct OverAligned;

    struct DropCounter(alloc::rc::Rc<Cell<usize>>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn cleanup_storage_rejects_unsupported_alignment() {
        assert!(!cleanup_type_fits_pool::<OverAligned>());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn cleanup_allocation_rejects_unsupported_alignment_without_linking_an_entry() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let head = unsafe { (*owner.raw).cleanup };

        assert!(pool.allocate_with_cleanup(|| OverAligned).is_err());
        assert_eq!(unsafe { (*owner.raw).cleanup }, head);
    }

    #[test]
    fn raw_construction_rejects_null_and_misaligned_pointers() {
        assert!(unsafe { Pool::from_raw(ptr::null_mut()) }.is_none());

        let misaligned = ptr::without_provenance_mut::<ngx_pool_t>(1);
        assert!(unsafe { Pool::from_raw(misaligned) }.is_none());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn allocator_covers_zero_small_large_and_overaligned_layouts() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let cloned = pool.clone();

        let zero = Layout::from_size_align(0, 64).unwrap();
        let zero_ptr = pool.allocate(zero).unwrap().cast::<u8>();
        assert_eq!(zero_ptr.as_ptr().align_offset(zero.align()), 0);

        let small = Layout::from_size_align(32, 8).unwrap();
        let small_ptr = pool.allocate(small).unwrap().cast::<u8>();
        assert_eq!(small_ptr.as_ptr().align_offset(small.align()), 0);

        let large = Layout::from_size_align(16 * 1024, 8).unwrap();
        let large_ptr = cloned.allocate(large).unwrap().cast::<u8>();
        assert_eq!(large_ptr.as_ptr().align_offset(large.align()), 0);

        let over_aligned = Layout::from_size_align(128, 4096).unwrap();
        let result = pool.allocate(over_aligned);
        if cfg!(any(ngx_feature = "have_posix_memalign", ngx_feature = "have_memalign")) {
            assert_eq!(result.unwrap().cast::<u8>().as_ptr().align_offset(4096), 0);
        } else {
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn resize_preserves_bytes_and_reuses_the_last_allocation() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let initial = Layout::from_size_align(16, 8).unwrap();
        let grown = Layout::from_size_align(64, 8).unwrap();
        let shrunk = Layout::from_size_align(8, 8).unwrap();
        let ptr = pool.allocate(initial).unwrap().cast::<u8>();
        unsafe { ptr.as_ptr().write_bytes(0x5a, initial.size()) };

        let grown_ptr = unsafe { pool.grow(ptr, initial, grown) }.unwrap().cast::<u8>();
        assert_eq!(grown_ptr, ptr);
        assert_eq!(
            unsafe { core::slice::from_raw_parts(grown_ptr.as_ptr(), initial.size()) },
            [0x5a; 16]
        );

        let shrunk_ptr = unsafe { pool.shrink(grown_ptr, grown, shrunk) }.unwrap().cast::<u8>();
        assert_eq!(shrunk_ptr, ptr);
        assert_eq!(
            unsafe { core::slice::from_raw_parts(shrunk_ptr.as_ptr(), shrunk.size()) },
            [0x5a; 8]
        );

        let moving_layout = Layout::from_size_align(16, 8).unwrap();
        let moved_layout = Layout::from_size_align(128, 8).unwrap();
        let moving_ptr = pool.allocate(moving_layout).unwrap().cast::<u8>();
        unsafe { moving_ptr.as_ptr().write_bytes(0xa5, moving_layout.size()) };
        let _blocker = pool.allocate(moving_layout).unwrap();

        let moved_ptr =
            unsafe { pool.grow(moving_ptr, moving_layout, moved_layout) }.unwrap().cast::<u8>();
        assert_ne!(moved_ptr, moving_ptr);
        assert_eq!(
            unsafe { core::slice::from_raw_parts(moved_ptr.as_ptr(), moving_layout.size()) },
            [0xa5; 16]
        );

        let zeroed_initial = Layout::from_size_align(8, 8).unwrap();
        let zeroed_grown = Layout::from_size_align(32, 8).unwrap();
        let zeroed_ptr = pool.allocate(zeroed_initial).unwrap().cast::<u8>();
        unsafe { zeroed_ptr.as_ptr().write_bytes(0x3c, zeroed_initial.size()) };

        let zeroed_ptr = unsafe { pool.grow_zeroed(zeroed_ptr, zeroed_initial, zeroed_grown) }
            .unwrap()
            .cast::<u8>();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(zeroed_ptr.as_ptr(), zeroed_initial.size()) },
            [0x3c; 8]
        );
        assert!(
            unsafe {
                core::slice::from_raw_parts(
                    zeroed_ptr.as_ptr().add(zeroed_initial.size()),
                    zeroed_grown.size() - zeroed_initial.size(),
                )
            }
            .iter()
            .all(|byte| *byte == 0)
        );
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn failed_constructor_is_never_published_as_cleanup() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let head = unsafe { (*owner.raw).cleanup };

        let result = pool.try_allocate_with_cleanup(|| {
            let pending = unsafe { (*owner.raw).cleanup };
            assert_ne!(pending, head);
            assert!(unsafe { (*pending).handler }.is_none());
            Err::<DropCounter, _>("rejected")
        });

        assert!(matches!(result, Err(PoolCleanupError::Construction("rejected"))));
        assert_eq!(unsafe { (*owner.raw).cleanup }, head);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn removal_and_pool_destruction_drop_each_value_once() {
        let drops = alloc::rc::Rc::new(Cell::new(0));
        let owner = TestPool::new();
        let pool = owner.handle();
        let removed = pool.allocate_with_cleanup(|| DropCounter(drops.clone())).unwrap();
        let raw_removed = pool.allocate_with_cleanup(|| DropCounter(drops.clone())).unwrap();
        let retained = pool.allocate_with_cleanup(|| DropCounter(drops.clone())).unwrap();
        let raw_removed = raw_removed.into_non_null();
        let _ = retained.into_non_null();

        assert!(removed.remove());
        assert_eq!(drops.get(), 1);
        assert!(unsafe { pool.remove_cleanup(raw_removed) });
        assert_eq!(drops.get(), 2);

        drop(owner);
        assert_eq!(drops.get(), 3);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn cleanup_value_keeps_a_stable_address_when_its_handle_moves() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let value = pool.allocate_with_cleanup(|| 41_u64).unwrap();
        let address = value.as_non_null();

        let mut moved = value;
        *moved = 42;

        assert_eq!(moved.as_non_null(), address);
        assert_eq!(*moved, 42);
        assert!(moved.remove());
    }

    #[cfg(feature = "test-link")]
    struct TestPool {
        raw: *mut ngx_pool_t,
        _log: Box<ngx_log_t>,
    }

    #[cfg(feature = "test-link")]
    impl TestPool {
        fn new() -> Self {
            let mut log = Box::new(unsafe { mem::zeroed() });
            let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!raw.is_null());
            Self { raw, _log: log }
        }

        fn handle(&self) -> Pool<'_> {
            unsafe { Pool::from_raw(self.raw) }.unwrap()
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }
}
