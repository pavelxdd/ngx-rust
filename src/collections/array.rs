//! Types and utilities for working with [`ngx_array_t`].

use core::marker::PhantomData;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::slice;

use nginx_sys::{NGX_ALIGNMENT, ngx_array_push, ngx_array_t};

use crate::allocator::AllocError;

/// A typed view over an nginx array.
///
/// The array and its element storage remain owned by the nginx pool. This wrapper does not drop
/// elements when the pool releases that storage.
#[derive(Debug)]
#[repr(transparent)]
pub struct NgxArray<T> {
    inner: ngx_array_t,
    _type: PhantomData<T>,
}

impl<T> NgxArray<T> {
    /// Creates a typed shared view over an nginx array.
    ///
    /// Returns `None` when the raw array's element size, bounds, or alignment do not match `T`.
    ///
    /// # Safety
    ///
    /// The first `nelts` entries must be initialized, valid `T` values. The array and its storage
    /// must remain valid and must not be mutated for the returned borrow.
    pub unsafe fn from_ngx_array(array: &ngx_array_t) -> Option<&Self> {
        if !Self::is_compatible(array) {
            return None;
        }

        Some(unsafe { &*(array as *const ngx_array_t).cast() })
    }

    /// Creates a typed exclusive view over an nginx array.
    ///
    /// Returns `None` when the raw array's element size, bounds, or alignment do not match `T`.
    ///
    /// # Safety
    ///
    /// The first `nelts` entries must be initialized, valid `T` values. The array and its storage
    /// must remain valid and exclusively accessible for the returned borrow.
    pub unsafe fn from_ngx_array_mut(array: &mut ngx_array_t) -> Option<&mut Self> {
        if !Self::is_compatible(array) {
            return None;
        }

        Some(unsafe { &mut *(array as *mut ngx_array_t).cast() })
    }

    /// Returns the number of initialized elements.
    pub fn len(&self) -> usize {
        self.inner.nelts
    }

    /// Returns `true` when the array contains no initialized elements.
    pub fn is_empty(&self) -> bool {
        self.inner.nelts == 0
    }

    /// Returns the number of elements that fit without reallocating.
    pub fn capacity(&self) -> usize {
        self.inner.nalloc
    }

    /// Returns the initialized elements as a slice.
    pub fn as_slice(&self) -> &[T] {
        let data = if self.is_empty() {
            NonNull::<T>::dangling().as_ptr()
        } else {
            self.inner.elts.cast()
        };

        unsafe { slice::from_raw_parts(data, self.len()) }
    }

    /// Returns the initialized elements as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        let data = if self.is_empty() {
            NonNull::<T>::dangling().as_ptr()
        } else {
            self.inner.elts.cast()
        };

        unsafe { slice::from_raw_parts_mut(data, self.len()) }
    }

    /// Appends an element, growing the nginx array when necessary.
    pub fn push(&mut self, value: T) -> Result<&mut T, AllocError> {
        if self.inner.pool.is_null() || self.inner.nalloc == 0 {
            return Err(AllocError);
        }
        if self.inner.nelts == self.inner.nalloc {
            let new_capacity = self.inner.nalloc.checked_mul(2).ok_or(AllocError)?;
            let new_size = mem::size_of::<T>().checked_mul(new_capacity).ok_or(AllocError)?;
            if new_size > isize::MAX as usize {
                return Err(AllocError);
            }
        }

        let mut element = NonNull::new(unsafe { ngx_array_push(&raw mut self.inner).cast::<T>() })
            .ok_or(AllocError)?;
        debug_assert_eq!(element.as_ptr().align_offset(mem::align_of::<T>()), 0);
        unsafe {
            element.write(value);
            Ok(element.as_mut())
        }
    }

    /// Returns a pointer to the underlying nginx array.
    pub fn as_ptr(&self) -> *const ngx_array_t {
        &raw const self.inner
    }

    /// Returns a mutable pointer to the underlying nginx array.
    pub fn as_mut_ptr(&mut self) -> *mut ngx_array_t {
        &raw mut self.inner
    }

    fn is_compatible(array: &ngx_array_t) -> bool {
        let element_size = mem::size_of::<T>();
        let element_align = mem::align_of::<T>();
        if element_size == 0
            || element_align > NGX_ALIGNMENT
            || array.size != element_size
            || array.nelts > array.nalloc
        {
            return false;
        }

        let Some(storage_size) = element_size.checked_mul(array.nalloc) else {
            return false;
        };
        if storage_size > isize::MAX as usize {
            return false;
        }

        array.nalloc == 0 || (!array.elts.is_null() && array.elts.align_offset(element_align) == 0)
    }
}

impl<T> Deref for NgxArray<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T> DerefMut for NgxArray<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{self, MaybeUninit};

    use nginx_sys::{ngx_array_t, ngx_pool_t};

    use super::NgxArray;

    #[test]
    fn typed_array_exposes_initialized_elements() {
        let mut storage = [10_i32, 20, 0];
        let mut pool = MaybeUninit::<ngx_pool_t>::zeroed();
        let mut raw = ngx_array_t {
            elts: storage.as_mut_ptr().cast(),
            nelts: 2,
            size: mem::size_of::<i32>(),
            nalloc: storage.len(),
            pool: pool.as_mut_ptr(),
        };
        let array = unsafe { NgxArray::<i32>::from_ngx_array_mut(&mut raw) }.unwrap();

        assert_eq!(array.len(), 2);
        assert_eq!(array.capacity(), 3);
        assert_eq!(array.get(1), Some(&20));
        assert_eq!(array.iter().copied().sum::<i32>(), 30);

        array[1] = 25;

        assert_eq!(array.as_slice(), [10, 25]);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn typed_array_pushes_into_nginx_storage() {
        let mut storage = [10_i32, 20, 0];
        let mut pool = MaybeUninit::<ngx_pool_t>::zeroed();
        let mut raw = ngx_array_t {
            elts: storage.as_mut_ptr().cast(),
            nelts: 2,
            size: mem::size_of::<i32>(),
            nalloc: storage.len(),
            pool: pool.as_mut_ptr(),
        };
        let array = unsafe { NgxArray::<i32>::from_ngx_array_mut(&mut raw) }.unwrap();

        let inserted = array.push(30).unwrap();

        assert_eq!(*inserted, 30);
        assert_eq!(array.as_slice(), [10, 20, 30]);
    }

    #[test]
    fn typed_array_rejects_the_wrong_element_layout() {
        let mut storage = [0_u16; 2];
        let raw = ngx_array_t {
            elts: storage.as_mut_ptr().cast(),
            nelts: storage.len(),
            size: mem::size_of::<u16>(),
            nalloc: storage.len(),
            pool: core::ptr::null_mut(),
        };

        assert!(unsafe { NgxArray::<u32>::from_ngx_array(&raw) }.is_none());
    }
}
