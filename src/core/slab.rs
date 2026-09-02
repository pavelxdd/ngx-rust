use core::alloc::Layout;
use core::cmp;
use core::marker::PhantomData;
use core::mem;
use core::ptr::NonNull;
use core::slice;

use nginx_sys::{
    ngx_shm_zone_t, ngx_shmtx_lock, ngx_shmtx_unlock, ngx_slab_alloc_locked,
    ngx_slab_calloc_locked, ngx_slab_free_locked, ngx_slab_pool_t,
};

use crate::allocator::dangling_for_layout;

/// Failure while constructing or accessing a shared slab zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabError {
    /// The shared-memory mapping pointer is null.
    NullMapping,
    /// The shared-memory mapping cannot contain an aligned slab-pool header.
    MisalignedMapping,
    /// The shared-memory mapping is smaller than an `ngx_slab_pool_t` header.
    MappingTooSmall,
    /// Shared-memory address arithmetic overflowed.
    Overflow,
    /// A requested byte or typed region lies outside the shared-memory mapping.
    OutOfRange,
    /// A requested typed region does not meet its type alignment.
    MisalignedPointer,
    /// Nginx cannot satisfy the requested allocation alignment.
    UnsupportedAlignment,
    /// Nginx could not allocate shared slab memory.
    Allocation,
}

/// A persistent, untyped allocation in an nginx shared slab pool.
///
/// A region stores only its address and layout. It does not own a Rust value and has no `Drop`
/// implementation: the ABI owner initializes, validates, detaches, and explicitly frees its
/// record through a live [`SlabGuard`].
pub struct SlabRegion<'zone> {
    ptr: NonNull<u8>,
    layout: Layout,
    _zone: PhantomData<&'zone ngx_shm_zone_t>,
}

impl<'zone> SlabRegion<'zone> {
    /// Returns the layout of a header followed by `tail_len` raw bytes.
    ///
    /// The header and tail contents stay opaque here; their ABI owner defines and validates them.
    pub fn flexible_layout<Header>(tail_len: usize) -> Result<Layout, SlabError> {
        let tail = Layout::array::<u8>(tail_len).map_err(|_| SlabError::Overflow)?;
        let (layout, _) = Layout::new::<Header>().extend(tail).map_err(|_| SlabError::Overflow)?;
        Ok(layout)
    }

    /// Returns the allocation address without allowing dereference outside a slab guard.
    pub fn as_ptr(&self) -> NonNull<u8> {
        self.ptr
    }

    /// Returns the allocation layout used for checked access and eventual freeing.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Transfers this token into raw allocation identity.
    ///
    /// The allocation remains live. Reconstruct it with
    /// [`SlabGuard::region_from_raw`] before checked access or freeing.
    pub fn into_raw_parts(self) -> (NonNull<u8>, Layout) {
        (self.ptr, self.layout)
    }

    /// Returns checked initialized bytes while `guard` holds the native slab mutex.
    ///
    /// # Safety
    ///
    /// The region must still identify one live allocation whose bytes are initialized. Its lifetime
    /// is bounded by the guard and cannot escape after unlock:
    ///
    /// ```compile_fail
    /// # use ngx::core::{SlabPool, SlabRegion};
    /// fn escape<'zone>(pool: &mut SlabPool<'zone>, region: &SlabRegion<'zone>) -> &'static [u8] {
    ///     let guard = pool.lock();
    ///     unsafe { region.bytes(&guard) }.unwrap()
    /// }
    /// ```
    pub unsafe fn bytes<'guard>(
        &self,
        guard: &'guard SlabGuard<'zone, '_>,
    ) -> Result<&'guard [u8], SlabError> {
        if self.layout.size() == 0 {
            return Ok(unsafe { slice::from_raw_parts(self.ptr.as_ptr(), 0) });
        }

        unsafe { guard.bytes(self.ptr, self.layout.size()) }
    }

    /// Returns checked initialized bytes with exclusive access while `guard` holds the mutex.
    ///
    /// # Safety
    ///
    /// The region must still identify one live allocation whose bytes are initialized, and the
    /// guard must provide its only mutable access for the returned borrow.
    pub unsafe fn bytes_mut<'guard>(
        &self,
        guard: &'guard mut SlabGuard<'zone, '_>,
    ) -> Result<&'guard mut [u8], SlabError> {
        if self.layout.size() == 0 {
            return Ok(unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), 0) });
        }

        unsafe { guard.bytes_mut(self.ptr, self.layout.size()) }
    }
}

/// Failure while allocating or initializing a [`SlabRegion`].
#[derive(Debug, Eq, PartialEq)]
pub enum SlabRegionInitError<E> {
    /// The native slab allocation or checked region access failed.
    Slab(SlabError),
    /// The caller rejected the zeroed region during initialization.
    Init(E),
}

struct SlabRegionRollback<'guard, 'zone, 'lock> {
    guard: &'guard mut SlabGuard<'zone, 'lock>,
    allocation: Option<NonNull<u8>>,
}

impl SlabRegionRollback<'_, '_, '_> {
    fn disarm(&mut self) {
        self.allocation = None;
    }
}

impl Drop for SlabRegionRollback<'_, '_, '_> {
    fn drop(&mut self) {
        if let Some(ptr) = self.allocation {
            unsafe { self.guard.free_raw(ptr) };
        }
    }
}

/// Non-owning, zone-lifetime handle for an initialized nginx slab pool.
///
/// The handle is neither cloneable nor transferable across threads. It records the complete
/// shared-memory mapping, but exposes no safe native reference or allocator implementation. A
/// caller must borrow it exclusively through [`lock`](Self::lock) before accessing the zone.
///
/// Constructing another handle for the same zone is explicit unsafe code:
///
/// ```compile_fail
/// # use ngx::core::SlabPool;
/// # use ngx::ffi::ngx_shm_zone_t;
/// # fn duplicate(zone: &ngx_shm_zone_t) {
/// let _pool = SlabPool::from_shm_zone(zone);
/// # }
/// ```
///
/// Slab handles cannot be cloned, sent, or shared:
///
/// ```compile_fail
/// # use ngx::core::SlabPool;
/// # fn require_send<T: Send>(_: T) {}
/// # fn reject(pool: SlabPool<'_>) {
/// require_send(pool);
/// # }
/// ```
///
/// ```compile_fail
/// # use ngx::core::SlabPool;
/// # fn reject(pool: SlabPool<'_>) {
/// let _copy = pool.clone();
/// # }
/// ```
///
/// ```compile_fail
/// # use ngx::core::SlabPool;
/// # fn require_sync<T: Sync>(_: &T) {}
/// # fn reject(pool: &SlabPool<'_>) {
/// require_sync(pool);
/// # }
/// ```
pub struct SlabPool<'zone> {
    raw: NonNull<ngx_slab_pool_t>,
    mapping_start: usize,
    mapping_end: usize,
    _zone: PhantomData<&'zone ngx_shm_zone_t>,
    _not_send_sync: PhantomData<*mut ()>,
}

impl<'zone> SlabPool<'zone> {
    /// Creates a slab-pool handle borrowing an initialized live shared-memory zone.
    ///
    /// # Safety
    ///
    /// `shm_zone` must remain live and continue to describe one initialized nginx slab pool for
    /// `'zone`. The caller must ensure that ordinary safe code owns at most one handle for the
    /// zone; constructing independent handles is only valid when their lock discipline is proven
    /// externally.
    pub unsafe fn from_shm_zone(shm_zone: &'zone ngx_shm_zone_t) -> Result<Self, SlabError> {
        let mapping = NonNull::new(shm_zone.shm.addr).ok_or(SlabError::NullMapping)?;
        if !mapping.as_ptr().cast::<ngx_slab_pool_t>().is_aligned() {
            return Err(SlabError::MisalignedMapping);
        }
        if shm_zone.shm.size < mem::size_of::<ngx_slab_pool_t>() {
            return Err(SlabError::MappingTooSmall);
        }

        let mapping_start = mapping.as_ptr() as usize;
        let mapping_end =
            mapping_start.checked_add(shm_zone.shm.size).ok_or(SlabError::Overflow)?;

        Ok(Self {
            raw: mapping.cast(),
            mapping_start,
            mapping_end,
            _zone: PhantomData,
            _not_send_sync: PhantomData,
        })
    }

    /// Locks the native nginx shared-memory mutex for this zone.
    #[inline]
    pub fn lock<'lock>(&'lock mut self) -> SlabGuard<'zone, 'lock> {
        unsafe { ngx_shmtx_lock(&raw mut (*self.raw.as_ptr()).mutex) };
        SlabGuard { pool: self }
    }
}

/// Native slab access held under an nginx shared-memory mutex.
///
/// A guard releases the native mutex when dropped, including during unwinding. Do not keep it
/// across nginx callbacks, logging that can re-enter the owner, event-loop suspension, or
/// asynchronous suspension.
///
/// A guard cannot escape its mutable pool borrow:
///
/// ```compile_fail
/// # use ngx::core::{SlabGuard, SlabPool};
/// fn escape<'zone>(pool: &mut SlabPool<'zone>) -> SlabGuard<'zone, 'static> {
///     pool.lock()
/// }
/// ```
///
/// It does not expose a safe native slab reference:
///
/// ```compile_fail
/// # use ngx::core::SlabGuard;
/// # use ngx::ffi::ngx_slab_pool_t;
/// # fn native_reference(guard: &SlabGuard<'_, '_>) {
/// let _: &ngx_slab_pool_t = guard.as_ref();
/// # }
/// ```
///
/// It cannot serve as an allocator for a container that would outlive the lock:
///
/// ```compile_fail
/// # use ngx::allocator::Box;
/// # use ngx::core::SlabGuard;
/// # fn retain<'zone, 'lock>(guard: SlabGuard<'zone, 'lock>) {
/// let _value = Box::try_new_in(1_u8, guard);
/// # }
/// ```
pub struct SlabGuard<'zone, 'lock> {
    pool: &'lock mut SlabPool<'zone>,
}

impl<'zone> SlabGuard<'zone, '_> {
    /// Allocates an uninitialized persistent region while this guard holds the native mutex.
    pub fn alloc_region(&mut self, layout: Layout) -> Result<SlabRegion<'zone>, SlabError> {
        let ptr = self.alloc(layout)?.cast();
        Ok(SlabRegion { ptr, layout, _zone: PhantomData })
    }

    /// Allocates a zeroed persistent region while this guard holds the native mutex.
    pub fn calloc_region(&mut self, layout: Layout) -> Result<SlabRegion<'zone>, SlabError> {
        let ptr = self.calloc(layout)?.cast();
        Ok(SlabRegion { ptr, layout, _zone: PhantomData })
    }

    /// Reconstructs a checked region for a live persistent slab allocation.
    ///
    /// # Safety
    ///
    /// `ptr` must identify one live allocation from this slab pool with `layout`. Its contents must
    /// remain valid according to the ABI owner until it is detached and freed.
    pub unsafe fn region_from_raw(
        &self,
        ptr: NonNull<u8>,
        layout: Layout,
    ) -> Result<SlabRegion<'zone>, SlabError> {
        self.check_region(ptr, layout)?;
        Ok(SlabRegion { ptr, layout, _zone: PhantomData })
    }

    /// Initializes a zeroed persistent region and frees it if initialization returns an error or
    /// unwinds.
    ///
    /// The callback must fully initialize the ABI-owned bytes before returning `Ok`. The region is
    /// returned only after that succeeds.
    pub fn try_calloc_region<E>(
        &mut self,
        layout: Layout,
        initialize: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<SlabRegion<'zone>, SlabRegionInitError<E>> {
        let region = self.calloc_region(layout).map_err(SlabRegionInitError::Slab)?;
        let allocation = (layout.size() != 0).then_some(region.ptr);
        let mut rollback = SlabRegionRollback { guard: self, allocation };
        let bytes =
            unsafe { region.bytes_mut(rollback.guard) }.map_err(SlabRegionInitError::Slab)?;
        initialize(bytes).map_err(SlabRegionInitError::Init)?;
        rollback.disarm();
        Ok(region)
    }

    /// Frees a detached persistent region while this guard holds the native mutex.
    ///
    /// # Safety
    ///
    /// `region` must identify a live allocation from this slab pool and must already be detached
    /// from every native intrusive structure. Its ABI owner must have completed any required
    /// destructor or cleanup before this call.
    pub unsafe fn free_region(&mut self, region: SlabRegion<'zone>) -> Result<(), SlabError> {
        unsafe { self.free(region.ptr, region.layout) }
    }

    /// Allocates uninitialized slab memory while this guard holds the native mutex.
    pub fn alloc(&mut self, layout: Layout) -> Result<NonNull<[u8]>, SlabError> {
        self.allocate(layout, false)
    }

    /// Allocates zeroed slab memory while this guard holds the native mutex.
    pub fn calloc(&mut self, layout: Layout) -> Result<NonNull<[u8]>, SlabError> {
        self.allocate(layout, true)
    }

    /// Frees a slab allocation while this guard holds the native mutex.
    ///
    /// # Safety
    ///
    /// `ptr` must identify a live allocation obtained from this slab pool with `layout`, must not
    /// have been freed already, and must be detached from every native intrusive structure.
    pub unsafe fn free(&mut self, ptr: NonNull<u8>, layout: Layout) -> Result<(), SlabError> {
        if layout.size() == 0 {
            return Ok(());
        }

        if ptr.as_ptr().align_offset(layout.align()) != 0 {
            return Err(SlabError::MisalignedPointer);
        }
        self.checked_bytes(ptr, allocation_size(layout))?;
        unsafe { self.free_raw(ptr) };
        Ok(())
    }

    /// Returns a checked immutable byte region in the shared mapping.
    ///
    /// # Safety
    ///
    /// `ptr..ptr + len` must identify initialized bytes in one live allocation in this mapping.
    /// The caller must preserve their validity for the returned borrow.
    pub unsafe fn bytes(&self, ptr: NonNull<u8>, len: usize) -> Result<&[u8], SlabError> {
        self.checked_bytes(ptr, len)?;
        Ok(unsafe { slice::from_raw_parts(ptr.as_ptr(), len) })
    }

    /// Returns a checked mutable byte region in the shared mapping.
    ///
    /// # Safety
    ///
    /// `ptr..ptr + len` must identify initialized bytes in one live allocation in this mapping,
    /// and this guard must provide their only mutable access for the returned borrow.
    pub unsafe fn bytes_mut(
        &mut self,
        ptr: NonNull<u8>,
        len: usize,
    ) -> Result<&mut [u8], SlabError> {
        self.checked_bytes(ptr, len)?;
        Ok(unsafe { slice::from_raw_parts_mut(ptr.as_ptr(), len) })
    }

    /// Returns a checked shared typed reference in the shared mapping.
    ///
    /// # Safety
    ///
    /// `ptr` must identify an initialized, valid `T` in this mapping. The caller must preserve
    /// Rust aliasing rules and the value's validity for the returned borrow.
    pub unsafe fn get<T>(&self, ptr: NonNull<T>) -> Result<&T, SlabError> {
        self.check_typed(ptr)?;
        Ok(unsafe { ptr.as_ref() })
    }

    /// Returns a checked mutable typed reference in the shared mapping.
    ///
    /// # Safety
    ///
    /// `ptr` must identify an initialized, valid `T` in this mapping, and this guard must provide
    /// its only mutable access for the returned borrow.
    pub unsafe fn get_mut<T>(&mut self, mut ptr: NonNull<T>) -> Result<&mut T, SlabError> {
        self.check_typed(ptr)?;
        Ok(unsafe { ptr.as_mut() })
    }

    /// Returns the native slab-pool pointer for ABI or intrusive-container code.
    ///
    /// # Safety
    ///
    /// The returned pointer must only be dereferenced while this guard remains live. The caller
    /// must prove native initialization, checked mapping range, alignment, and exclusive access.
    pub unsafe fn raw_pool(&self) -> NonNull<ngx_slab_pool_t> {
        self.pool.raw
    }

    fn allocate(&mut self, layout: Layout, zeroed: bool) -> Result<NonNull<[u8]>, SlabError> {
        if layout.size() == 0 {
            return Ok(NonNull::slice_from_raw_parts(dangling_for_layout(&layout), 0));
        }

        let size = allocation_size(layout);
        let raw = if zeroed {
            unsafe { ngx_slab_calloc_locked(self.pool.raw.as_ptr(), size) }
        } else {
            unsafe { ngx_slab_alloc_locked(self.pool.raw.as_ptr(), size) }
        };
        let ptr = NonNull::<u8>::new(raw.cast()).ok_or(SlabError::Allocation)?;

        if ptr.as_ptr().align_offset(layout.align()) != 0 {
            unsafe { self.free_raw(ptr) };
            return Err(SlabError::UnsupportedAlignment);
        }
        if let Err(error) = self.checked_bytes(ptr, size) {
            unsafe { self.free_raw(ptr) };
            return Err(error);
        }

        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn free_raw(&mut self, ptr: NonNull<u8>) {
        unsafe { ngx_slab_free_locked(self.pool.raw.as_ptr(), ptr.as_ptr().cast()) }
    }

    pub(crate) fn mapping_len(&self) -> usize {
        self.pool.mapping_end - self.pool.mapping_start
    }

    pub(crate) fn check_typed<T>(&self, ptr: NonNull<T>) -> Result<(), SlabError> {
        if !ptr.as_ptr().is_aligned() {
            return Err(SlabError::MisalignedPointer);
        }
        self.checked_bytes(ptr.cast(), mem::size_of::<T>())
    }

    fn check_region(&self, ptr: NonNull<u8>, layout: Layout) -> Result<(), SlabError> {
        if ptr.as_ptr().align_offset(layout.align()) != 0 {
            return Err(SlabError::MisalignedPointer);
        }
        if layout.size() == 0 {
            return Ok(());
        }

        self.checked_bytes(ptr, allocation_size(layout))
    }

    fn checked_bytes(&self, ptr: NonNull<u8>, len: usize) -> Result<(), SlabError> {
        let start = ptr.as_ptr() as usize;
        if start < self.pool.mapping_start || start > self.pool.mapping_end {
            return Err(SlabError::OutOfRange);
        }
        let end = start.checked_add(len).ok_or(SlabError::Overflow)?;
        if end > self.pool.mapping_end {
            return Err(SlabError::OutOfRange);
        }
        Ok(())
    }
}

impl Drop for SlabGuard<'_, '_> {
    fn drop(&mut self) {
        unsafe { ngx_shmtx_unlock(&raw mut (*self.pool.raw.as_ptr()).mutex) }
    }
}

fn allocation_size(layout: Layout) -> usize {
    cmp::max(layout.size(), layout.align())
}

#[cfg(all(test, feature = "test-link"))]
pub(crate) mod tests {
    use alloc::boxed::Box;
    use core::alloc::Layout;
    use core::ffi::c_int;
    use core::mem::{self, MaybeUninit};
    use core::panic::AssertUnwindSafe;
    use core::ptr::{self, NonNull};
    use std::panic::catch_unwind;
    use std::sync::{MutexGuard, Once};

    use nginx_sys::{
        ngx_cycle, ngx_cycle_t, ngx_int_t, ngx_log_t, ngx_ncpu, ngx_pagesize, ngx_pagesize_shift,
        ngx_pid, ngx_pid_t, ngx_shm_alloc, ngx_shm_free, ngx_shm_zone_t, ngx_shmtx_create,
        ngx_shmtx_destroy, ngx_shmtx_trylock, ngx_shmtx_unlock, ngx_slab_init, ngx_slab_pool_t,
        ngx_slab_sizes_init, ngx_uint_t,
    };

    use super::{SlabError, SlabPool, SlabRegion, SlabRegionInitError};

    static SLAB_SIZES: Once = Once::new();

    unsafe extern "C" {
        fn fork() -> c_int;
        fn getpagesize() -> c_int;
        fn getpid() -> c_int;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        fn _exit(status: c_int) -> !;
    }

    struct GlobalState {
        cycle: *mut ngx_cycle_t,
        ncpu: ngx_int_t,
        pagesize: ngx_uint_t,
        pagesize_shift: ngx_uint_t,
        pid: ngx_pid_t,
    }

    struct TestGlobals {
        _guard: MutexGuard<'static, ()>,
        previous: GlobalState,
        page_size: usize,
    }

    impl TestGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let page_size = usize::try_from(unsafe { getpagesize() }).expect("positive page size");
            assert!(page_size.is_power_of_two());

            let previous = unsafe {
                GlobalState {
                    cycle: ngx_cycle,
                    ncpu: ngx_ncpu,
                    pagesize: ngx_pagesize,
                    pagesize_shift: ngx_pagesize_shift,
                    pid: ngx_pid,
                }
            };

            unsafe {
                ngx_ncpu = 1;
                ngx_pagesize = page_size;
                ngx_pagesize_shift = page_size.trailing_zeros() as usize;
                ngx_pid = getpid();
            }
            SLAB_SIZES.call_once(|| unsafe { ngx_slab_sizes_init() });

            Self { _guard: guard, previous, page_size }
        }
    }

    impl Drop for TestGlobals {
        fn drop(&mut self) {
            unsafe {
                ngx_cycle = self.previous.cycle;
                ngx_ncpu = self.previous.ncpu;
                ngx_pagesize = self.previous.pagesize;
                ngx_pagesize_shift = self.previous.pagesize_shift;
                ngx_pid = self.previous.pid;
            }
        }
    }

    pub(crate) struct TestZone {
        _globals: TestGlobals,
        _log: Box<ngx_log_t>,
        _cycle: Box<ngx_cycle_t>,
        zone: Box<ngx_shm_zone_t>,
    }

    impl TestZone {
        pub(crate) fn new() -> Self {
            let globals = TestGlobals::new();
            let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
            let mut cycle = Box::new(unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() });
            cycle.log = &raw mut *log;

            unsafe { ngx_cycle = &raw mut *cycle };

            let mut zone =
                Box::new(unsafe { MaybeUninit::<ngx_shm_zone_t>::zeroed().assume_init() });
            zone.shm.size = globals.page_size.checked_mul(16).expect("test mapping size");
            zone.shm.log = &raw mut *log;
            assert_eq!(unsafe { ngx_shm_alloc(&raw mut zone.shm) }, 0);

            let pool = zone.shm.addr.cast::<ngx_slab_pool_t>();
            unsafe {
                (*pool).end = zone.shm.addr.add(zone.shm.size);
                (*pool).min_shift = 3;
                (*pool).addr = zone.shm.addr.cast();
                assert_eq!(
                    ngx_shmtx_create(
                        &raw mut (*pool).mutex,
                        &raw mut (*pool).lock,
                        ptr::null_mut()
                    ),
                    0
                );
                ngx_slab_init(pool);
            }

            Self { _globals: globals, _log: log, _cycle: cycle, zone }
        }

        pub(crate) fn pool(&self) -> SlabPool<'_> {
            unsafe { SlabPool::from_shm_zone(&self.zone) }.expect("initialized test slab")
        }

        pub(crate) fn mapping(&self) -> *mut u8 {
            self.zone.shm.addr
        }

        pub(crate) fn mapping_len(&self) -> usize {
            self.zone.shm.size
        }

        fn raw_pool(&self) -> *mut ngx_slab_pool_t {
            self.zone.shm.addr.cast()
        }

        fn assert_unlocked(&self) {
            let mutex = unsafe { &raw mut (*self.raw_pool()).mutex };
            assert_eq!(unsafe { ngx_shmtx_trylock(mutex) }, 1);
            unsafe { ngx_shmtx_unlock(mutex) };
        }
    }

    impl Drop for TestZone {
        fn drop(&mut self) {
            let pool = self.raw_pool();
            unsafe {
                ngx_shmtx_destroy(&raw mut (*pool).mutex);
                ngx_shm_free(&raw mut self.zone.shm);
            }
        }
    }

    #[test]
    fn slab_pool_rejects_null_mapping() {
        let zone = unsafe { MaybeUninit::<ngx_shm_zone_t>::zeroed().assume_init() };

        assert!(matches!(unsafe { SlabPool::from_shm_zone(&zone) }, Err(SlabError::NullMapping)));
    }

    #[test]
    fn slab_pool_rejects_invalid_mapping_layouts() {
        let mut zone = unsafe { MaybeUninit::<ngx_shm_zone_t>::zeroed().assume_init() };
        zone.shm.addr = ptr::without_provenance_mut(1);
        zone.shm.size = mem::size_of::<ngx_slab_pool_t>();
        assert!(matches!(
            unsafe { SlabPool::from_shm_zone(&zone) },
            Err(SlabError::MisalignedMapping)
        ));

        zone.shm.addr = NonNull::<ngx_slab_pool_t>::dangling().as_ptr().cast();
        zone.shm.size = mem::size_of::<ngx_slab_pool_t>() - 1;
        assert!(matches!(
            unsafe { SlabPool::from_shm_zone(&zone) },
            Err(SlabError::MappingTooSmall)
        ));

        let alignment = mem::align_of::<ngx_slab_pool_t>();
        zone.shm.addr = ptr::without_provenance_mut(usize::MAX & !(alignment - 1));
        zone.shm.size = mem::size_of::<ngx_slab_pool_t>();
        assert!(matches!(unsafe { SlabPool::from_shm_zone(&zone) }, Err(SlabError::Overflow)));
    }

    #[test]
    fn slab_guard_checks_shared_byte_and_typed_ranges() {
        let zone = TestZone::new();
        let mut pool = zone.pool();
        let guard = pool.lock();
        let mapping = zone.mapping();
        let one_past_end = NonNull::new(unsafe { mapping.add(zone.mapping_len()) }).unwrap();

        assert_eq!(unsafe { guard.bytes(one_past_end, 1) }, Err(SlabError::OutOfRange));
        assert_eq!(
            unsafe { guard.bytes(NonNull::new(mapping).unwrap(), usize::MAX) },
            Err(SlabError::Overflow)
        );

        let misaligned = NonNull::new(unsafe { mapping.add(1) }).unwrap().cast::<u64>();
        assert_eq!(unsafe { guard.get(misaligned) }, Err(SlabError::MisalignedPointer));
    }

    #[test]
    fn slab_guard_allocates_zeroes_and_frees_checked_regions() {
        let zone = TestZone::new();
        let mut pool = zone.pool();
        let mut guard = pool.lock();
        let layout = Layout::from_size_align(64, 16).unwrap();

        let allocation = guard.alloc(layout).unwrap().cast::<u8>();
        assert_eq!(unsafe { guard.free(allocation, layout) }, Ok(()));

        let zeroed = guard.calloc(layout).unwrap().cast::<u8>();
        assert!(
            unsafe { guard.bytes(zeroed, layout.size()) }.unwrap().iter().all(|byte| *byte == 0)
        );
        unsafe { guard.bytes_mut(zeroed, layout.size()).unwrap().fill(0xa5) };
        assert_eq!(unsafe { guard.bytes(zeroed, layout.size()) }.unwrap(), [0xa5; 64]);
        unsafe { guard.bytes_mut(zeroed, layout.size()).unwrap().fill(0) };
        assert!(
            unsafe { guard.bytes(zeroed, layout.size()) }.unwrap().iter().all(|byte| *byte == 0)
        );
        assert_eq!(unsafe { guard.free(zeroed, layout) }, Ok(()));

        let typed_layout = Layout::new::<u64>();
        let typed = guard.calloc(typed_layout).unwrap().cast::<u64>();
        *unsafe { guard.get_mut(typed) }.unwrap() = 42;
        assert_eq!(*unsafe { guard.get(typed) }.unwrap(), 42);
        assert_eq!(unsafe { guard.free(typed.cast(), typed_layout) }, Ok(()));

        let outside = NonNull::new(unsafe { zone.mapping().add(zone.mapping_len()) }).unwrap();
        assert_eq!(unsafe { guard.free(outside, Layout::new::<u8>()) }, Err(SlabError::OutOfRange));

        let too_large = Layout::from_size_align(zone.mapping_len() * 2, 1).unwrap();
        assert_eq!(guard.alloc(too_large), Err(SlabError::Allocation));
        assert_eq!(guard.calloc(too_large), Err(SlabError::Allocation));
    }

    #[repr(C)]
    struct FlexibleHeader {
        kind: u16,
        length: u16,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum InitError {
        Rejected,
    }

    #[test]
    fn slab_regions_initialize_flexible_storage_and_roll_back_errors() {
        let zone = TestZone::new();
        let mut pool = zone.pool();
        let mut guard = pool.lock();
        let layout = SlabRegion::flexible_layout::<FlexibleHeader>(0).unwrap();

        assert_eq!(layout.size(), mem::size_of::<FlexibleHeader>());
        assert_eq!(layout.align(), mem::align_of::<FlexibleHeader>());
        assert_eq!(
            SlabRegion::flexible_layout::<FlexibleHeader>(usize::MAX),
            Err(SlabError::Overflow)
        );

        let region = guard
            .try_calloc_region(layout, |bytes| {
                assert!(bytes.iter().all(|byte| *byte == 0));
                bytes[..mem::size_of::<u16>()].copy_from_slice(&0x1234_u16.to_ne_bytes());
                Ok::<_, InitError>(())
            })
            .unwrap();
        assert_eq!(
            unsafe { region.bytes(&guard) }.unwrap()[..mem::size_of::<u16>()],
            0x1234_u16.to_ne_bytes()
        );

        let (ptr, layout) = region.into_raw_parts();
        let region = unsafe { guard.region_from_raw(ptr, layout) }.unwrap();
        unsafe { guard.free_region(region) }.unwrap();

        let rollback_layout = Layout::from_size_align(zone.mapping_len() / 2, 1).unwrap();
        let rollback =
            guard.try_calloc_region(rollback_layout, |_| Err::<(), _>(InitError::Rejected));
        assert!(matches!(rollback, Err(SlabRegionInitError::Init(InitError::Rejected))));
        let region = guard.calloc_region(rollback_layout).unwrap();
        unsafe { guard.free_region(region) }.unwrap();

        let unwind = catch_unwind(AssertUnwindSafe(|| {
            guard
                .try_calloc_region(rollback_layout, |_| -> Result<(), InitError> {
                    panic!("reject region initialization")
                })
                .unwrap();
        }));
        assert!(unwind.is_err());
        let region = guard.calloc_region(rollback_layout).unwrap();
        unsafe { guard.free_region(region) }.unwrap();
    }

    fn return_after_lock(pool: &mut SlabPool<'_>) {
        let _guard = pool.lock();
    }

    #[test]
    fn slab_guard_unlocks_on_return_and_unwind() {
        let zone = TestZone::new();
        let mut pool = zone.pool();

        return_after_lock(&mut pool);
        zone.assert_unlocked();

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = pool.lock();
            panic!("unwind through slab guard");
        }));
        assert!(result.is_err());
        zone.assert_unlocked();
    }

    #[test]
    fn slab_pool_allows_independent_handles_only_through_unsafe_construction() {
        let zone = TestZone::new();
        let first = unsafe { SlabPool::from_shm_zone(&zone.zone) }.unwrap();
        let second = unsafe { SlabPool::from_shm_zone(&zone.zone) }.unwrap();

        assert_eq!(first.raw, second.raw);
    }

    #[test]
    fn native_shmtx_excludes_a_forked_process() {
        let zone = TestZone::new();
        let mut pool = zone.pool();
        let _guard = pool.lock();
        let child = unsafe { fork() };
        assert!(child >= 0, "fork failed");

        if child == 0 {
            let mutex = unsafe { &raw mut (*zone.raw_pool()).mutex };
            if unsafe { ngx_shmtx_trylock(mutex) } == 0 {
                unsafe { _exit(0) };
            }
            unsafe {
                ngx_shmtx_unlock(mutex);
                _exit(1);
            }
        }

        let mut status = 0;
        assert_eq!(unsafe { waitpid(child, &raw mut status, 0) }, child);
        assert_eq!(status, 0);
    }
}
