//! The allocator module.
//!
//! The module provides custom memory allocator support traits and utilities based on the unstable
//! [feature(allocator_api)].
//!
//! Currently implemented as a reexport of parts of the [allocator_api2].
//!
//! [feature(allocator_api)]: https://github.com/rust-lang/rust/issues/32838

use ::core::alloc::Layout;
use ::core::ffi::c_void;
use ::core::mem;
use ::core::ptr::{self, NonNull};
pub use allocator_api2::alloc::{AllocError, Allocator};
#[cfg(feature = "alloc")]
pub use allocator_api2::{alloc::Global, boxed::Box, unsize_box};
use nginx_sys::{NGX_ALIGNMENT, ngx_alloc, ngx_calloc, ngx_log_t};

use crate::log::LogRef;

#[cfg(all(test, feature = "test-link"))]
unsafe extern "C" {
    #[link_name = "ngx_rs_test_free"]
    fn ngx_heap_free(ptr: *mut c_void);
}

#[cfg(not(all(test, feature = "test-link")))]
unsafe extern "C" {
    #[link_name = "free"]
    fn ngx_heap_free(ptr: *mut c_void);
}

/// Allocator for nginx heap allocations that are explicitly freed before their logger expires.
///
/// `NginxAllocator` supports the alignment guaranteed by the configured nginx build. It is suited
/// to values with an independent lifetime, unlike [`crate::core::Pool`], whose allocations are
/// released with the pool.
///
/// The allocator cannot outlive the [`LogRef`] supplied to [`new`](Self::new).
///
/// A raw logger pointer is callback-scoped through [`with_raw`](Self::with_raw):
///
/// ```compile_fail
/// # use ngx::allocator::NginxAllocator;
/// # use ngx::ffi::ngx_log_t;
/// fn escape(log: *mut ngx_log_t) -> Option<NginxAllocator<'static>> {
///     unsafe { NginxAllocator::with_raw(log, |allocator| allocator) }
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct NginxAllocator<'log> {
    log: LogRef<'log>,
}

impl<'log> NginxAllocator<'log> {
    /// Creates an allocator using an opaque native logger handle.
    pub fn new(log: LogRef<'log>) -> Self {
        Self { log }
    }

    /// Creates an allocator from a live nginx logger pointer.
    ///
    /// # Safety
    ///
    /// `log` must be valid and properly aligned for all of `'log`. The caller must keep allocator
    /// operations on a thread where the logger remains usable. Null and misaligned pointers are
    /// rejected.
    pub unsafe fn from_raw(log: *mut ngx_log_t) -> Option<Self> {
        let log = unsafe { LogRef::from_raw(log) }?;
        Some(Self::new(log))
    }

    /// Invokes `f` with an allocator that cannot safely escape the raw logger's callback scope.
    ///
    /// # Safety
    ///
    /// `log` must identify a valid nginx logger for the complete closure call. Allocations that
    /// outlive the callback require a logger whose lifetime is proven by a longer-lived safe
    /// reference.
    pub unsafe fn with_raw<R>(
        log: *mut ngx_log_t,
        f: impl for<'scope> FnOnce(NginxAllocator<'scope>) -> R,
    ) -> Option<R> {
        let allocator = unsafe { Self::from_raw(log) }?;
        Some(f(allocator))
    }

    fn allocate_with(&self, layout: Layout, zeroed: bool) -> Result<NonNull<[u8]>, AllocError> {
        if layout.size() == 0 {
            return Ok(NonNull::slice_from_raw_parts(dangling_for_layout(&layout), 0));
        }
        if layout.align() > NGX_ALIGNMENT {
            return Err(AllocError);
        }

        let ptr = if zeroed {
            unsafe { ngx_calloc(layout.size(), self.log.as_ptr()) }
        } else {
            unsafe { ngx_alloc(layout.size(), self.log.as_ptr()) }
        };
        let ptr = NonNull::<u8>::new(ptr.cast()).ok_or(AllocError)?;
        debug_assert_eq!(ptr.as_ptr().align_offset(layout.align()), 0);
        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn resize(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
        zeroed: bool,
    ) -> Result<NonNull<[u8]>, AllocError> {
        if new_layout.size() == 0 {
            if old_layout.size() != 0 {
                unsafe { self.deallocate(ptr, old_layout) };
            }
            return Ok(NonNull::slice_from_raw_parts(dangling_for_layout(&new_layout), 0));
        }

        if old_layout == new_layout {
            return Ok(NonNull::slice_from_raw_parts(ptr, new_layout.size()));
        }

        let new_ptr = self.allocate_with(new_layout, zeroed)?;
        if old_layout.size() != 0 {
            let size = core::cmp::min(old_layout.size(), new_layout.size());
            unsafe {
                ptr.copy_to_nonoverlapping(new_ptr.cast(), size);
                self.deallocate(ptr, old_layout);
            }
        }
        Ok(new_ptr)
    }
}

unsafe impl Allocator for NginxAllocator<'_> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.allocate_with(layout, false)
    }

    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.allocate_with(layout, true)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if layout.size() != 0 {
            unsafe { ngx_heap_free(ptr.as_ptr().cast()) };
        }
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() >= old_layout.size());
        unsafe { self.resize(ptr, old_layout, new_layout, false) }
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() >= old_layout.size());
        unsafe { self.resize(ptr, old_layout, new_layout, true) }
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        debug_assert!(new_layout.size() <= old_layout.size());
        unsafe { self.resize(ptr, old_layout, new_layout, false) }
    }
}

/// Explicitly duplicate an object using the specified Allocator.
pub trait TryCloneIn: Sized {
    /// Target type, generic over an allocator.
    type Target<A: Allocator + Clone>;

    /// Attempts to copy the value using `alloc` as an underlying Allocator.
    fn try_clone_in<A: Allocator + Clone>(&self, alloc: A) -> Result<Self::Target<A>, AllocError>;
}

/// Moves `value` to the memory backed by `alloc` and returns a pointer.
///
/// This should be similar to `Box::into_raw(Box::try_new_in(value, alloc)?)`, except without
/// `alloc` requirement and intermediate steps.
///
/// # Note
///
/// The resulting pointer has no owner. The caller is responsible for destroying `T` and releasing
/// the memory.
pub fn allocate<T, A>(value: T, alloc: &A) -> Result<NonNull<T>, AllocError>
where
    A: Allocator,
{
    let layout = Layout::for_value(&value);
    let ptr: NonNull<T> = alloc.allocate(layout)?.cast();

    // SAFETY: the allocator succeeded and gave us a correctly aligned pointer to an uninitialized
    // data
    unsafe { ptr.cast::<mem::MaybeUninit<T>>().as_mut().write(value) };

    Ok(ptr)
}
///
/// Creates a [NonNull] that is dangling, but well-aligned for this [Layout].
///
/// See also [::core::alloc::Layout::dangling()]
#[inline(always)]
pub(crate) const fn dangling_for_layout(layout: &Layout) -> NonNull<u8> {
    unsafe { NonNull::new_unchecked(ptr::without_provenance_mut(layout.align())) }
}

#[cfg(feature = "alloc")]
mod impls {
    use allocator_api2::boxed::Box;

    use super::*;

    impl<T, OA> TryCloneIn for Box<T, OA>
    where
        T: TryCloneIn,
        OA: Allocator,
    {
        type Target<A: Allocator + Clone> = Box<<T as TryCloneIn>::Target<A>, A>;

        fn try_clone_in<A: Allocator + Clone>(
            &self,
            alloc: A,
        ) -> Result<Self::Target<A>, AllocError> {
            let x = self.as_ref().try_clone_in(alloc.clone())?;
            Box::try_new_in(x, alloc)
        }
    }
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    extern crate alloc;

    use alloc::{boxed::Box, rc::Rc};
    use core::alloc::Layout;
    use core::cell::Cell;
    use core::ffi::c_void;
    use core::mem;
    use core::pin::Pin;

    use std::sync::Mutex;

    use nginx_sys::{NGX_ALIGNMENT, ngx_log_t, ngx_uint_t};

    use super::{Allocator, LogRef, NginxAllocator};

    unsafe extern "C" {
        fn ngx_rs_test_track_free(ptr: *mut c_void);
        fn ngx_rs_test_free_count() -> ngx_uint_t;
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestLogger {
        raw: Box<ngx_log_t>,
    }

    impl TestLogger {
        fn new() -> Self {
            Self { raw: Box::new(unsafe { mem::zeroed() }) }
        }

        fn allocator(&mut self) -> NginxAllocator<'_> {
            let log = unsafe { LogRef::from_raw(&raw mut *self.raw) }.unwrap();
            NginxAllocator::new(log)
        }
    }

    #[test]
    fn allocator_covers_zeroed_and_configured_alignment() {
        let mut logger = TestLogger::new();
        let allocator = logger.allocator();
        let zero = Layout::from_size_align(0, NGX_ALIGNMENT * 2).unwrap();
        let normal = Layout::from_size_align(32, NGX_ALIGNMENT).unwrap();
        let unsupported = Layout::from_size_align(32, NGX_ALIGNMENT * 2).unwrap();

        let zero_ptr = allocator.allocate(zero).unwrap().cast::<u8>();
        assert_eq!(zero_ptr.as_ptr().align_offset(zero.align()), 0);
        unsafe { allocator.deallocate(zero_ptr, zero) };

        let normal_ptr = allocator.allocate(normal).unwrap().cast::<u8>();
        assert_eq!(normal_ptr.as_ptr().align_offset(normal.align()), 0);
        unsafe { allocator.deallocate(normal_ptr, normal) };

        let zeroed_ptr = allocator.allocate_zeroed(normal).unwrap().cast::<u8>();
        assert!(
            unsafe { core::slice::from_raw_parts(zeroed_ptr.as_ptr(), normal.size()) }
                .iter()
                .all(|byte| *byte == 0)
        );
        unsafe { allocator.deallocate(zeroed_ptr, normal) };

        assert!(allocator.allocate(unsupported).is_err());
    }

    #[test]
    fn allocator_grows_and_shrinks_without_losing_initialized_bytes() {
        let mut logger = TestLogger::new();
        let allocator = logger.allocator();
        let initial = Layout::from_size_align(16, NGX_ALIGNMENT).unwrap();
        let grown = Layout::from_size_align(64, NGX_ALIGNMENT).unwrap();
        let shrunk = Layout::from_size_align(8, NGX_ALIGNMENT).unwrap();
        let unsupported_grow = Layout::from_size_align(64, NGX_ALIGNMENT * 2).unwrap();
        let unsupported_shrink = Layout::from_size_align(8, NGX_ALIGNMENT * 2).unwrap();

        let ptr = allocator.allocate(initial).unwrap().cast::<u8>();
        unsafe { ptr.as_ptr().write_bytes(0xa5, initial.size()) };

        assert!(unsafe { allocator.grow(ptr, initial, unsupported_grow) }.is_err());
        assert_eq!(
            unsafe { core::slice::from_raw_parts(ptr.as_ptr(), initial.size()) },
            [0xa5; 16]
        );

        let grown_ptr = unsafe { allocator.grow(ptr, initial, grown) }.unwrap().cast::<u8>();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(grown_ptr.as_ptr(), initial.size()) },
            [0xa5; 16]
        );

        assert!(unsafe { allocator.shrink(grown_ptr, grown, unsupported_shrink) }.is_err());
        assert_eq!(
            unsafe { core::slice::from_raw_parts(grown_ptr.as_ptr(), initial.size()) },
            [0xa5; 16]
        );

        let shrunk_ptr =
            unsafe { allocator.shrink(grown_ptr, grown, shrunk) }.unwrap().cast::<u8>();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(shrunk_ptr.as_ptr(), shrunk.size()) },
            [0xa5; 8]
        );
        unsafe { allocator.deallocate(shrunk_ptr, shrunk) };

        let zeroed_ptr = allocator.allocate(initial).unwrap().cast::<u8>();
        unsafe { zeroed_ptr.as_ptr().write_bytes(0x3c, initial.size()) };
        let zeroed_ptr =
            unsafe { allocator.grow_zeroed(zeroed_ptr, initial, grown) }.unwrap().cast::<u8>();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(zeroed_ptr.as_ptr(), initial.size()) },
            [0x3c; 16]
        );
        assert!(
            unsafe {
                core::slice::from_raw_parts(
                    zeroed_ptr.as_ptr().add(initial.size()),
                    grown.size() - initial.size(),
                )
            }
            .iter()
            .all(|byte| *byte == 0)
        );
        unsafe { allocator.deallocate(zeroed_ptr, grown) };
    }

    #[test]
    fn allocator_backed_boxes_and_vectors_drop_and_free_once() {
        struct DropCounter(Rc<Cell<usize>>);

        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let _guard = TEST_LOCK.lock().unwrap();
        let mut logger = TestLogger::new();
        let allocator = logger.allocator();
        let drops = Rc::new(Cell::new(0));

        let boxed = super::Box::try_new_in(DropCounter(drops.clone()), allocator).unwrap();
        let address = boxed.as_ref() as *const DropCounter as *mut DropCounter;
        unsafe { ngx_rs_test_track_free(address.cast()) };
        let pinned = unsafe { Pin::new_unchecked(boxed) };
        assert_eq!(pinned.as_ref().get_ref() as *const DropCounter, address.cast_const());
        drop(pinned);
        assert_eq!(drops.get(), 1);
        assert_eq!(unsafe { ngx_rs_test_free_count() }, 1);

        let mut values = crate::collections::Vec::new_in(allocator);
        values.try_reserve_exact(2).unwrap();
        values.push(DropCounter(drops.clone()));
        values.push(DropCounter(drops.clone()));
        unsafe { ngx_rs_test_track_free(values.as_mut_ptr().cast()) };
        drop(values);
        assert_eq!(drops.get(), 3);
        assert_eq!(unsafe { ngx_rs_test_free_count() }, 1);
        unsafe { ngx_rs_test_track_free(core::ptr::null_mut()) };
    }
}
