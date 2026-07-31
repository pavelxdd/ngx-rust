//! Types and utilities for working with [`ngx_list_t`].

use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};

use nginx_sys::{NGX_ALIGNMENT, ngx_list_part_t, ngx_list_push, ngx_list_t};

use crate::allocator::AllocError;

/// A typed view over an nginx list.
///
/// The list and its element storage remain owned by the nginx pool. This wrapper does not drop
/// elements when the pool releases that storage.
#[derive(Debug)]
#[repr(transparent)]
pub struct NgxList<T> {
    inner: ngx_list_t,
    _type: PhantomData<T>,
}

impl<T> NgxList<T> {
    /// Creates a typed shared view over an nginx list.
    ///
    /// Returns `None` when the raw list's element size, part chain, bounds, or alignment do not
    /// match `T`.
    ///
    /// # Safety
    ///
    /// Every part pointer and the first `nelts` entries in each part must be valid. Those entries
    /// must contain initialized `T` values. The list and its storage must remain valid and must not
    /// be mutated for the returned borrow.
    pub unsafe fn from_ngx_list(list: &ngx_list_t) -> Option<&Self> {
        if !unsafe { Self::is_compatible(list) } {
            return None;
        }

        Some(unsafe { &*(list as *const ngx_list_t).cast() })
    }

    /// Creates a typed exclusive view over an nginx list.
    ///
    /// Returns `None` when the raw list's element size, part chain, bounds, or alignment do not
    /// match `T`.
    ///
    /// # Safety
    ///
    /// Every part pointer and the first `nelts` entries in each part must be valid. Those entries
    /// must contain initialized `T` values. The list, its parts, and its storage must remain valid
    /// and exclusively accessible for the returned borrow.
    pub unsafe fn from_ngx_list_mut(list: &mut ngx_list_t) -> Option<&mut Self> {
        if !unsafe { Self::is_compatible(list) } {
            return None;
        }

        Some(unsafe { &mut *(list as *mut ngx_list_t).cast() })
    }

    /// Returns the total number of initialized elements across all parts.
    pub fn len(&self) -> usize {
        unsafe { Self::count(&self.inner) }.expect("validated nginx list length")
    }

    /// Returns `true` when every part is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a shared reference to the element at `index`.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.iter().nth(index)
    }

    /// Returns an exclusive reference to the element at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.iter_mut().nth(index)
    }

    /// Returns an iterator over all parts in list order.
    pub fn iter(&self) -> NgxListIter<'_, T> {
        NgxListIter {
            part: &raw const self.inner.part,
            index: 0,
            remaining: self.len(),
            _lifetime: PhantomData,
        }
    }

    /// Returns a mutable iterator over all parts in list order.
    pub fn iter_mut(&mut self) -> NgxListIterMut<'_, T> {
        let remaining = self.len();
        NgxListIterMut {
            part: &raw mut self.inner.part,
            index: 0,
            remaining,
            _lifetime: PhantomData,
        }
    }

    /// Appends an element to the last part, allocating a new part when necessary.
    pub fn push(&mut self, value: T) -> Result<&mut T, AllocError> {
        if self.inner.pool.is_null() || self.inner.nalloc == 0 || self.len() == usize::MAX {
            return Err(AllocError);
        }

        let mut element = NonNull::new(unsafe { ngx_list_push(&raw mut self.inner).cast::<T>() })
            .ok_or(AllocError)?;
        debug_assert_eq!(element.as_ptr().align_offset(mem::align_of::<T>()), 0);
        unsafe {
            element.write(value);
            Ok(element.as_mut())
        }
    }

    /// Returns a pointer to the underlying nginx list.
    pub fn as_ptr(&self) -> *const ngx_list_t {
        &raw const self.inner
    }

    /// Returns a mutable pointer to the underlying nginx list.
    pub fn as_mut_ptr(&mut self) -> *mut ngx_list_t {
        &raw mut self.inner
    }

    unsafe fn is_compatible(list: &ngx_list_t) -> bool {
        let element_size = mem::size_of::<T>();
        let element_align = mem::align_of::<T>();
        if element_size == 0
            || element_align > NGX_ALIGNMENT
            || list.size != element_size
            || element_size.checked_mul(list.nalloc).is_none_or(|size| size > isize::MAX as usize)
        {
            return false;
        }

        let first = &raw const list.part;
        let mut slow = first;
        let mut fast = first;
        loop {
            slow = unsafe { Self::next_part(slow) };
            fast = unsafe { Self::next_part(fast) };
            if fast.is_null() {
                break;
            }
            fast = unsafe { Self::next_part(fast) };
            if slow.is_null() || fast.is_null() {
                break;
            }
            if ptr::eq(slow, fast) {
                return false;
            }
        }

        let mut part = first;
        let mut last = ptr::null();
        while let Some(current) = unsafe { part.as_ref() } {
            if current.nelts > list.nalloc
                || (list.nalloc != 0
                    && (current.elts.is_null() || current.elts.align_offset(element_align) != 0))
            {
                return false;
            }
            last = part;
            part = current.next;
        }

        ptr::eq(list.last.cast_const(), last) && unsafe { Self::count(list) }.is_some()
    }

    unsafe fn next_part(part: *const ngx_list_part_t) -> *const ngx_list_part_t {
        unsafe { part.as_ref() }.map_or(ptr::null(), |part| part.next)
    }

    unsafe fn count(list: &ngx_list_t) -> Option<usize> {
        let mut count = 0_usize;
        let mut part = &raw const list.part;
        while let Some(current) = unsafe { part.as_ref() } {
            count = count.checked_add(current.nelts)?;
            part = current.next;
        }
        Some(count)
    }
}

/// An iterator over a typed nginx list.
pub struct NgxListIter<'a, T> {
    part: *const ngx_list_part_t,
    index: usize,
    remaining: usize,
    _lifetime: PhantomData<&'a T>,
}

impl<'a, T> Iterator for NgxListIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        loop {
            let part = unsafe { self.part.as_ref() }?;
            if self.index < part.nelts {
                let element = unsafe { &*part.elts.cast::<T>().add(self.index) };
                self.index += 1;
                self.remaining -= 1;
                return Some(element);
            }
            self.part = part.next;
            self.index = 0;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T> ExactSizeIterator for NgxListIter<'_, T> {}
impl<T> FusedIterator for NgxListIter<'_, T> {}

/// A mutable iterator over a typed nginx list.
pub struct NgxListIterMut<'a, T> {
    part: *mut ngx_list_part_t,
    index: usize,
    remaining: usize,
    _lifetime: PhantomData<&'a mut T>,
}

impl<'a, T> Iterator for NgxListIterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        loop {
            let part = unsafe { self.part.as_mut() }?;
            if self.index < part.nelts {
                let element = unsafe { &mut *part.elts.cast::<T>().add(self.index) };
                self.index += 1;
                self.remaining -= 1;
                return Some(element);
            }
            self.part = part.next;
            self.index = 0;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T> ExactSizeIterator for NgxListIterMut<'_, T> {}
impl<T> FusedIterator for NgxListIterMut<'_, T> {}

impl<'a, T> IntoIterator for &'a NgxList<T> {
    type Item = &'a T;
    type IntoIter = NgxListIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut NgxList<T> {
    type Item = &'a mut T;
    type IntoIter = NgxListIterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use core::mem;
    #[cfg(feature = "test-link")]
    use core::mem::MaybeUninit;

    #[cfg(feature = "test-link")]
    use nginx_sys::ngx_pool_t;
    use nginx_sys::{ngx_list_part_t, ngx_list_t};

    use super::NgxList;

    #[test]
    fn typed_list_iterates_and_mutates_across_parts() {
        let mut first = [10_i32, 20];
        let mut second_storage = [30_i32, 0];
        let mut second = ngx_list_part_t {
            elts: second_storage.as_mut_ptr().cast(),
            nelts: 1,
            next: core::ptr::null_mut(),
        };
        let mut raw = ngx_list_t {
            last: &raw mut second,
            part: ngx_list_part_t {
                elts: first.as_mut_ptr().cast(),
                nelts: first.len(),
                next: &raw mut second,
            },
            size: mem::size_of::<i32>(),
            nalloc: first.len(),
            pool: core::ptr::null_mut(),
        };
        let list = unsafe { NgxList::<i32>::from_ngx_list_mut(&mut raw) }.unwrap();

        assert_eq!(list.len(), 3);
        assert_eq!(list.get(1), Some(&20));
        assert_eq!(list.get(3), None);
        assert_eq!(list.iter().copied().collect::<alloc::vec::Vec<_>>(), [10, 20, 30]);

        for value in list.iter_mut() {
            *value += 1;
        }

        assert_eq!(list.iter().copied().collect::<alloc::vec::Vec<_>>(), [11, 21, 31]);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn typed_list_pushes_into_the_last_nginx_part() {
        let mut first = [10_i32, 20];
        let mut second_storage = [30_i32, 0];
        let mut second = ngx_list_part_t {
            elts: second_storage.as_mut_ptr().cast(),
            nelts: 1,
            next: core::ptr::null_mut(),
        };
        let mut pool = MaybeUninit::<ngx_pool_t>::zeroed();
        let mut raw = ngx_list_t {
            last: &raw mut second,
            part: ngx_list_part_t {
                elts: first.as_mut_ptr().cast(),
                nelts: first.len(),
                next: &raw mut second,
            },
            size: mem::size_of::<i32>(),
            nalloc: first.len(),
            pool: pool.as_mut_ptr(),
        };
        let list = unsafe { NgxList::<i32>::from_ngx_list_mut(&mut raw) }.unwrap();

        let inserted = list.push(40).unwrap();

        assert_eq!(*inserted, 40);
        assert_eq!(list.iter().copied().collect::<alloc::vec::Vec<_>>(), [10, 20, 30, 40]);
    }

    #[test]
    fn typed_list_rejects_the_wrong_element_layout() {
        let mut storage = [10_i32, 20];
        let mut raw = ngx_list_t {
            last: core::ptr::null_mut(),
            part: ngx_list_part_t {
                elts: storage.as_mut_ptr().cast(),
                nelts: storage.len(),
                next: core::ptr::null_mut(),
            },
            size: mem::size_of::<i32>(),
            nalloc: storage.len(),
            pool: core::ptr::null_mut(),
        };
        raw.last = &raw mut raw.part;

        assert!(unsafe { NgxList::<u64>::from_ngx_list(&raw) }.is_none());
    }
}
