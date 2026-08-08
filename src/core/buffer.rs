use core::marker::PhantomData;
use core::ptr::NonNull;
use core::slice;

use crate::ffi::*;

/// The `Buffer` trait provides methods for working with an nginx buffer (`ngx_buf_t`).
///
/// See <https://nginx.org/en/docs/dev/development_guide.html#buffer>
pub trait Buffer {
    /// Returns a raw pointer to the underlying `ngx_buf_t` of the buffer.
    fn as_ngx_buf(&self) -> *const ngx_buf_t;

    /// Returns a mutable raw pointer to the underlying `ngx_buf_t` of the buffer.
    fn as_ngx_buf_mut(&mut self) -> *mut ngx_buf_t;

    /// Returns the buffer contents as a byte slice.
    fn as_bytes(&self) -> &[u8] {
        let buf = self.as_ngx_buf();
        unsafe { slice::from_raw_parts((*buf).pos, self.len()) }
    }

    /// Returns the length of the buffer contents.
    fn len(&self) -> usize {
        let buf = self.as_ngx_buf();
        unsafe {
            let pos = (*buf).pos;
            let last = (*buf).last;
            assert!(last >= pos);
            usize::wrapping_sub(last as _, pos as _)
        }
    }

    /// Returns `true` if the buffer is empty, i.e., it has zero length.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sets the `last_buf` flag of the buffer.
    ///
    /// # Arguments
    ///
    /// * `last` - A boolean indicating whether the buffer is the last buffer in a request.
    fn set_last_buf(&mut self, last: bool) {
        let buf = self.as_ngx_buf_mut();
        unsafe {
            (*buf).set_last_buf(if last { 1 } else { 0 });
        }
    }

    /// Sets the `last_in_chain` flag of the buffer.
    ///
    /// # Arguments
    ///
    /// * `last` - A boolean indicating whether the buffer is the last buffer in a chain of buffers.
    fn set_last_in_chain(&mut self, last: bool) {
        let buf = self.as_ngx_buf_mut();
        unsafe {
            (*buf).set_last_in_chain(if last { 1 } else { 0 });
        }
    }
}

/// The `MutableBuffer` trait extends the `Buffer` trait and provides methods for working with a
/// mutable buffer.
pub trait MutableBuffer: Buffer {
    /// Returns a mutable reference to the buffer contents as a byte slice.
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let buf = self.as_ngx_buf_mut();
        unsafe { slice::from_raw_parts_mut((*buf).pos, self.len()) }
    }
}

/// Wrapper struct for a temporary buffer, providing methods for working with an `ngx_buf_t`.
pub struct TemporaryBuffer<'pool> {
    raw: NonNull<ngx_buf_t>,
    _lifetime: PhantomData<&'pool mut ngx_buf_t>,
}

impl TemporaryBuffer<'_> {
    /// Creates a new `TemporaryBuffer` from an `ngx_buf_t` pointer.
    ///
    /// # Safety
    /// `buf` must point to an initialized `ngx_buf_t` that remains live and exclusively owned for
    /// the returned lifetime. Null and misaligned pointers are rejected.
    pub unsafe fn from_ngx_buf<'pool>(buf: *mut ngx_buf_t) -> Option<TemporaryBuffer<'pool>> {
        let raw = NonNull::new(buf)?;
        if !buf.is_aligned() {
            return None;
        }

        Some(TemporaryBuffer { raw, _lifetime: PhantomData })
    }
}

impl Buffer for TemporaryBuffer<'_> {
    /// Returns the underlying `ngx_buf_t` pointer as a raw pointer.
    fn as_ngx_buf(&self) -> *const ngx_buf_t {
        self.raw.as_ptr()
    }

    /// Returns a mutable reference to the underlying `ngx_buf_t` pointer.
    fn as_ngx_buf_mut(&mut self) -> *mut ngx_buf_t {
        self.raw.as_ptr()
    }
}

impl MutableBuffer for TemporaryBuffer<'_> {
    /// Returns a mutable reference to the buffer contents as a byte slice.
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut((*self.raw.as_ptr()).pos, self.len()) }
    }
}

/// Wrapper struct for a memory buffer, providing methods for working with an `ngx_buf_t`.
pub struct MemoryBuffer<'pool> {
    raw: NonNull<ngx_buf_t>,
    _lifetime: PhantomData<&'pool mut ngx_buf_t>,
}

impl MemoryBuffer<'_> {
    /// Creates a new `MemoryBuffer` from an `ngx_buf_t` pointer.
    ///
    /// # Safety
    /// `buf` must point to an initialized `ngx_buf_t` that remains live and exclusively owned for
    /// the returned lifetime. Null and misaligned pointers are rejected.
    pub unsafe fn from_ngx_buf<'pool>(buf: *mut ngx_buf_t) -> Option<MemoryBuffer<'pool>> {
        let raw = NonNull::new(buf)?;
        if !buf.is_aligned() {
            return None;
        }

        Some(MemoryBuffer { raw, _lifetime: PhantomData })
    }
}

impl Buffer for MemoryBuffer<'_> {
    /// Returns the underlying `ngx_buf_t` pointer as a raw pointer.
    fn as_ngx_buf(&self) -> *const ngx_buf_t {
        self.raw.as_ptr()
    }

    /// Returns a mutable reference to the underlying `ngx_buf_t` pointer.
    fn as_ngx_buf_mut(&mut self) -> *mut ngx_buf_t {
        self.raw.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::{MemoryBuffer, TemporaryBuffer};
    use crate::ffi::ngx_buf_t;

    #[test]
    fn raw_buffer_construction_rejects_null_and_misaligned_pointers() {
        assert!(unsafe { TemporaryBuffer::from_ngx_buf(ptr::null_mut()) }.is_none());
        assert!(unsafe { MemoryBuffer::from_ngx_buf(ptr::null_mut()) }.is_none());

        let misaligned = ptr::without_provenance_mut::<ngx_buf_t>(1);
        assert!(unsafe { TemporaryBuffer::from_ngx_buf(misaligned) }.is_none());
        assert!(unsafe { MemoryBuffer::from_ngx_buf(misaligned) }.is_none());
    }
}
