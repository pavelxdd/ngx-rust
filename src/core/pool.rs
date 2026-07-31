use core::alloc::Layout;
use core::ffi::c_void;
use core::mem;
use core::ptr::{self, NonNull};

use nginx_sys::{
    NGX_ALIGNMENT, ngx_buf_t, ngx_create_temp_buf, ngx_palloc, ngx_pcalloc, ngx_pfree,
    ngx_pmemalign, ngx_pnalloc, ngx_pool_cleanup_add, ngx_pool_cleanup_t, ngx_pool_t,
};

use crate::allocator::{AllocError, Allocator, dangling_for_layout};
use crate::core::buffer::{Buffer, MemoryBuffer, TemporaryBuffer};

/// Non-owning wrapper for an [`ngx_pool_t`] pointer, providing methods for working with memory
/// pools.
///
/// See <https://nginx.org/en/docs/dev/development_guide.html#pool>
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Pool(NonNull<ngx_pool_t>);

fn cleanup_type_fits_pool<T>() -> bool {
    mem::align_of::<T>() <= NGX_ALIGNMENT
}

unsafe impl Allocator for Pool {
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
            unsafe { ngx_pnalloc(self.0.as_ptr(), layout.size()) }
        } else if layout.align() <= NGX_ALIGNMENT {
            unsafe { ngx_palloc(self.0.as_ptr(), layout.size()) }
        } else if cfg!(any(ngx_feature = "have_posix_memalign", ngx_feature = "have_memalign")) {
            // ngx_pmemalign is always defined, but does not guarantee the requested alignment
            // unless memalign/posix_memalign exists.
            unsafe { ngx_pmemalign(self.0.as_ptr(), layout.size(), layout.align()) }
        } else {
            return Err(AllocError);
        };

        // Verify the alignment of the result
        debug_assert_eq!(ptr.align_offset(layout.align()), 0);

        let ptr = NonNull::new(ptr.cast()).ok_or(AllocError)?;
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
            && (layout.size() > self.as_ref().max || layout.align() > NGX_ALIGNMENT)
        {
            unsafe { ngx_pfree(self.0.as_ptr(), ptr.as_ptr().cast()) };
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

impl AsRef<ngx_pool_t> for Pool {
    #[inline]
    fn as_ref(&self) -> &ngx_pool_t {
        // SAFETY: this wrapper should be constructed with a valid pointer to ngx_pool_t
        unsafe { self.0.as_ref() }
    }
}

impl AsMut<ngx_pool_t> for Pool {
    #[inline]
    fn as_mut(&mut self) -> &mut ngx_pool_t {
        // SAFETY: this wrapper should be constructed with a valid pointer to ngx_pool_t
        unsafe { self.0.as_mut() }
    }
}

impl Pool {
    /// Creates a new `Pool` from an `ngx_pool_t` pointer.
    ///
    /// # Safety
    /// The caller must ensure that a valid `ngx_pool_t` pointer is provided, pointing to valid
    /// memory and non-null. A null argument will cause an assertion failure and panic.
    pub unsafe fn from_ngx_pool(pool: *mut ngx_pool_t) -> Pool {
        unsafe {
            debug_assert!(!pool.is_null());
            debug_assert!(pool.is_aligned());
            Pool(NonNull::new_unchecked(pool))
        }
    }

    /// Expose the underlying `ngx_pool_t` pointer, for use with `ngx::ffi`
    /// functions.
    pub fn as_ptr(&self) -> *mut ngx_pool_t {
        self.0.as_ptr()
    }

    /// Creates a buffer of the specified size in the memory pool.
    ///
    /// Returns `Some(TemporaryBuffer)` if the buffer is successfully created, or `None` if
    /// allocation fails.
    pub fn create_buffer(&self, size: usize) -> Option<TemporaryBuffer> {
        let buf = unsafe { ngx_create_temp_buf(self.0.as_ptr(), size) };
        if buf.is_null() {
            return None;
        }

        Some(TemporaryBuffer::from_ngx_buf(buf))
    }

    /// Creates a buffer from a string in the memory pool.
    ///
    /// Returns `Some(TemporaryBuffer)` if the buffer is successfully created, or `None` if
    /// allocation fails.
    pub fn create_buffer_from_str(&self, str: &str) -> Option<TemporaryBuffer> {
        let mut buffer = self.create_buffer(str.len())?;
        unsafe {
            let buf = buffer.as_ngx_buf_mut();
            ptr::copy_nonoverlapping(str.as_ptr(), (*buf).pos, str.len());
            (*buf).last = (*buf).pos.add(str.len());
        }
        Some(buffer)
    }

    /// Creates a buffer from a static string in the memory pool.
    ///
    /// Returns `Some(MemoryBuffer)` if the buffer is successfully created, or `None` if allocation
    /// fails.
    pub fn create_buffer_from_static_str(&self, str: &'static str) -> Option<MemoryBuffer> {
        let buf = self.calloc_type::<ngx_buf_t>();
        if buf.is_null() {
            return None;
        }

        // We cast away const, but buffers with the memory flag are read-only
        let start = str.as_ptr() as *mut u8;
        let end = unsafe { start.add(str.len()) };

        unsafe {
            (*buf).start = start;
            (*buf).pos = start;
            (*buf).last = end;
            (*buf).end = end;
            (*buf).set_memory(1);
        }

        Some(MemoryBuffer::from_ngx_buf(buf))
    }

    /// Allocates a value and registers its destructor with the pool.
    ///
    /// The constructor is called only after nginx allocates storage for the value. The destructor
    /// runs when the pool is destroyed or when [`remove`](Self::remove) removes the value.
    ///
    /// # Safety
    ///
    /// The returned pointer must not outlive the pool and must not be freed manually. The caller
    /// must not access the value after the pool is destroyed or after passing its pointer to
    /// [`remove`](Self::remove).
    pub unsafe fn allocate_with_cleanup<T>(
        &self,
        constructor: impl FnOnce() -> T,
    ) -> Result<NonNull<T>, AllocError> {
        if !cleanup_type_fits_pool::<T>() {
            return Err(AllocError);
        }

        let mut cleanup =
            NonNull::new(unsafe { ngx_pool_cleanup_add(self.0.as_ptr(), mem::size_of::<T>()) })
                .ok_or(AllocError)?;

        let data: NonNull<T> = if mem::size_of::<T>() == 0 {
            cleanup.cast()
        } else {
            NonNull::new(unsafe { cleanup.as_ref().data.cast() }).ok_or(AllocError)?
        };
        debug_assert_eq!(data.as_ptr().align_offset(mem::align_of::<T>()), 0);

        let value = constructor();
        unsafe {
            data.as_ptr().write(value);
            cleanup.as_mut().data = data.as_ptr().cast();
            cleanup.as_mut().handler = Some(cleanup_type::<T>);
        }

        Ok(data)
    }

    /// Allocates memory from the pool of the specified size.
    /// The resulting pointer is aligned to a platform word size.
    ///
    /// Returns a raw pointer to the allocated memory.
    pub fn alloc(&self, size: usize) -> *mut c_void {
        unsafe { ngx_palloc(self.0.as_ptr(), size) }
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
        unsafe { ngx_pcalloc(self.0.as_ptr(), size) }
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
        unsafe { ngx_pnalloc(self.0.as_ptr(), size) }
    }

    /// Allocates unaligned memory for a type from the pool.
    ///
    /// Returns a typed pointer to the allocated memory.
    pub fn alloc_type_unaligned<T: Copy>(&self) -> *mut T {
        self.alloc_unaligned(mem::size_of::<T>()) as *mut T
    }

    /// Runs the cleanup handler for a value and unlinks it from the pool.
    ///
    /// Returns `None` when the value has no matching cleanup entry.
    ///
    /// # Safety
    ///
    /// `value` must be a non-null pointer returned by [`allocate_with_cleanup`](Self::allocate_with_cleanup)
    /// for this pool. No references to the value may be live, the pointer must not be used after
    /// this call, and no other handle may access the pool's cleanup list during this call.
    pub unsafe fn remove<T>(&mut self, value: *const T) -> Option<()> {
        let cleanup = self.remove_cleanup_if(|cleanup| ptr::addr_eq(cleanup.data, value))?;
        let handler = cleanup.handler?;

        unsafe { handler(cleanup.data) };
        Some(())
    }

    fn remove_cleanup_if(
        &mut self,
        predicate: impl Fn(&ngx_pool_cleanup_t) -> bool,
    ) -> Option<&ngx_pool_cleanup_t> {
        let mut head = ngx_pool_cleanup_t {
            handler: None,
            data: ptr::null_mut(),
            next: self.as_ref().cleanup,
        };
        let head_ptr = &raw const head;
        let mut previous = &mut head;

        while let Some(cleanup) = unsafe { previous.next.as_mut() } {
            if predicate(cleanup) {
                if ptr::eq(previous, head_ptr) {
                    self.as_mut().cleanup = cleanup.next;
                } else {
                    previous.next = cleanup.next;
                }
                return Some(cleanup);
            }
            previous = cleanup;
        }

        None
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
            ptr.byte_add(old_layout.size()).as_ptr() == self.as_ref().d.last
                && ptr.byte_add(new_layout.size()).as_ptr() <= self.as_ref().d.end
                && ptr.align_offset(new_layout.align()) == 0
        } {
            let pool = self.0.as_ptr();
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
    use core::cell::Cell;
    use core::mem::{MaybeUninit, zeroed};

    use super::*;

    #[repr(align(4096))]
    struct OverAligned;

    struct DropCounter<'a>(&'a Cell<usize>);

    impl Drop for DropCounter<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn cleanup_storage_rejects_unsupported_alignment() {
        assert!(!cleanup_type_fits_pool::<OverAligned>());
    }

    #[test]
    fn remove_drops_value_and_unlinks_cleanup() {
        let drops = Cell::new(0);
        let mut value = MaybeUninit::new(DropCounter(&drops));
        let mut cleanup = ngx_pool_cleanup_t {
            handler: Some(cleanup_type::<DropCounter<'_>>),
            data: value.as_mut_ptr().cast(),
            next: ptr::null_mut(),
        };
        let mut raw_pool: ngx_pool_t = unsafe { zeroed() };
        raw_pool.cleanup = &raw mut cleanup;
        let mut pool = unsafe { Pool::from_ngx_pool(&raw mut raw_pool) };

        let removed = unsafe { pool.remove(value.as_ptr()) };

        assert_eq!(removed, Some(()));
        assert!(raw_pool.cleanup.is_null());
        assert_eq!(drops.get(), 1);
    }
}
