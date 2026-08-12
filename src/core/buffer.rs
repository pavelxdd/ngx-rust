use core::marker::PhantomData;
use core::ops::Range;
use core::ptr::{self, NonNull};
use core::slice;

use crate::ffi::*;
use crate::core::Pool;

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
    /// Returns the buffer's output control flags.
    fn flags(&self) -> BufferFlags {
        BufferFlags::read(unsafe { &*self.as_ngx_buf() })
    }

    /// Replaces the output control flags.
    fn set_flags(&mut self, flags: BufferFlags) {
        flags.write(unsafe { &mut *self.as_ngx_buf_mut() });
    }

    /// Returns a validated file range when the buffer is file-backed.
    fn file(&self) -> Result<Option<FileView<'_>>, BufferError> {
        file_range(unsafe { &*self.as_ngx_buf() })
    }

    /// Returns the nginx-visible size, including file-backed data.
    fn size(&self) -> Result<usize, BufferError> {
        let buffer = unsafe { &*self.as_ngx_buf() };
        if in_memory(buffer) {
            return Ok(self.len());
        }
        Ok(self.file()?.map_or(0, |file| file.len()))
    }

    /// Classifies memory, file, and control-only output.
    fn kind(&self) -> Result<BufferView<'_>, BufferError> {
        let buffer = unsafe { &*self.as_ngx_buf() };
        if in_memory(buffer) && !self.is_empty() {
            return Ok(BufferView::Memory(self.as_bytes()));
        }
        if !in_memory(buffer) {
            if let Some(file) = self.file()? {
                if !file.is_empty() {
                    return Ok(BufferView::File(file));
                }
            }
        }
        Ok(BufferView::Control(ControlView { flags: self.flags() }))
    }

    /// Advances memory and file positions without partial mutation on failure.
    fn consume(&mut self, amount: usize) -> Result<(), BufferError> {
        let visible = self.size()?;
        let file = self.file()?;
        if amount > visible || file.is_some_and(|value| amount > value.len()) {
            return Err(BufferError::OutOfRange);
        }
        let file_amount = if file.is_some() {
            Some(off_t::try_from(amount).map_err(|_| BufferError::Overflow)?)
        } else {
            None
        };
        let buffer = unsafe { &mut *self.as_ngx_buf_mut() };
        if in_memory(buffer) {
            buffer.pos = unsafe { buffer.pos.add(amount) };
        }
        if let Some(amount) = file_amount {
            buffer.file_pos = buffer.file_pos.checked_add(amount).ok_or(BufferError::Overflow)?;
        }
        Ok(())
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

    /// Returns the available space in the buffer.
    ///
    /// A buffer from [`crate::core::Pool::create_buffer`] starts empty, with
    /// its whole allocation available.
    fn capacity(&self) -> usize {
        let buf = self.as_ngx_buf();
        // msrv(1.87.0): ptr::offset_from_unsigned()
        unsafe { (*buf).end.offset_from((*buf).last) as usize }
    }

    /// Appends as much of `bytes` as fits and returns the number of bytes
    /// written.
    ///
    /// Use [`MutableBuffer::capacity`] beforehand to avoid a partial write.
    fn append(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len().min(self.capacity());

        let buf = self.as_ngx_buf_mut();
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), (*buf).last, n);
            (*buf).last = (*buf).last.add(n);
        }

        n
    }
}

/// Wrapper struct for a temporary buffer, providing methods for working with an `ngx_buf_t`.
pub struct TemporaryBuffer(*mut ngx_buf_t);

impl TemporaryBuffer {
    /// Creates a new `TemporaryBuffer` from an `ngx_buf_t` pointer.
    ///
    /// # Panics
    /// Panics if the given buffer pointer is null.
    pub fn from_ngx_buf(buf: *mut ngx_buf_t) -> TemporaryBuffer {
        assert!(!buf.is_null());
        TemporaryBuffer(buf)
    }
}

impl Buffer for TemporaryBuffer {
    /// Returns the underlying `ngx_buf_t` pointer as a raw pointer.
    fn as_ngx_buf(&self) -> *const ngx_buf_t {
        self.0
    }

    /// Returns a mutable reference to the underlying `ngx_buf_t` pointer.
    fn as_ngx_buf_mut(&mut self) -> *mut ngx_buf_t {
        self.0
    }
}

impl MutableBuffer for TemporaryBuffer {
    /// Returns a mutable reference to the buffer contents as a byte slice.
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut((*self.0).pos, self.len()) }
    }
}

/// Wrapper struct for a memory buffer, providing methods for working with an `ngx_buf_t`.
pub struct MemoryBuffer(*mut ngx_buf_t);

impl MemoryBuffer {
    /// Creates a new `MemoryBuffer` from an `ngx_buf_t` pointer.
    ///
    /// # Panics
    /// Panics if the given buffer pointer is null.
    pub fn from_ngx_buf(buf: *mut ngx_buf_t) -> MemoryBuffer {
        assert!(!buf.is_null());
        MemoryBuffer(buf)
    }
}

impl Buffer for MemoryBuffer {
    /// Returns the underlying `ngx_buf_t` pointer as a raw pointer.
    fn as_ngx_buf(&self) -> *const ngx_buf_t {
        self.0
    }

    /// Returns a mutable reference to the underlying `ngx_buf_t` pointer.
    fn as_ngx_buf_mut(&mut self) -> *mut ngx_buf_t {
        self.0
    }
}

/// Failure returned while validating or constructing an nginx buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferError {
    /// The buffer pointer is null.
    NullBuffer,
    /// The buffer pointer does not satisfy `ngx_buf_t` alignment.
    MisalignedBuffer,
    /// A memory buffer has a null, reversed, or otherwise invalid range.
    InvalidMemoryRange,
    /// A file buffer has a missing file or invalid offsets.
    InvalidFileRange,
    /// The requested operation requires a memory buffer.
    NotMemory,
    /// The requested operation requires a file buffer.
    NotFile,
    /// A requested offset or length is outside the available range.
    OutOfRange,
    /// Integer conversion or size arithmetic overflowed.
    Overflow,
    /// The buffer belongs to a different nginx pool.
    ForeignPool,
    /// Nginx could not allocate buffer storage.
    Allocation,
}

/// Control flags copied to newly built buffers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BufferFlags {
    /// Flush buffered output.
    pub flush: bool,
    /// Synchronization-only buffer.
    pub sync: bool,
    /// Final buffer for the complete output.
    pub last_buf: bool,
    /// Final buffer in the current chain.
    pub last_in_chain: bool,
}

impl BufferFlags {
    fn read(buffer: &ngx_buf_t) -> Self {
        Self {
            flush: buffer.flush() != 0,
            sync: buffer.sync() != 0,
            last_buf: buffer.last_buf() != 0,
            last_in_chain: buffer.last_in_chain() != 0,
        }
    }

    fn write(self, buffer: &mut ngx_buf_t) {
        buffer.set_flush(u32::from(self.flush));
        buffer.set_sync(u32::from(self.sync));
        buffer.set_last_buf(u32::from(self.last_buf));
        buffer.set_last_in_chain(u32::from(self.last_in_chain));
    }
}

/// Validated file metadata and offsets from an nginx file buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileView<'buffer> {
    file: NonNull<ngx_file_t>,
    start: off_t,
    end: off_t,
    len: usize,
    _lifetime: PhantomData<&'buffer ngx_file_t>,
}

impl FileView<'_> {
    /// Returns the native file descriptor structure for FFI calls.
    pub fn file_ptr(&self) -> *mut ngx_file_t {
        self.file.as_ptr()
    }

    /// Returns the inclusive file offset at which this buffer starts.
    pub fn start(&self) -> off_t {
        self.start
    }

    /// Returns the exclusive file offset at which this buffer ends.
    pub fn end(&self) -> off_t {
        self.end
    }

    /// Returns the checked byte length of the file range.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the file range is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Validated zero-size or control-only buffer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlView {
    flags: BufferFlags,
}

impl ControlView {
    /// Returns the buffer's control flags.
    pub fn flags(self) -> BufferFlags {
        self.flags
    }
}

/// The checked active representation of an nginx buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferView<'buffer> {
    /// Nonempty bytes held in memory.
    Memory(&'buffer [u8]),
    /// Nonempty bytes represented by a file range.
    File(FileView<'buffer>),
    /// A zero-size or control-only buffer.
    Control(ControlView),
}


impl Buffer for ngx_buf_t {
    fn as_ngx_buf(&self) -> *const ngx_buf_t { self }
    fn as_ngx_buf_mut(&mut self) -> *mut ngx_buf_t { self }
}
impl<'pool> Pool<'pool> {
    /// Copies bytes into a pool-owned temporary buffer.
    pub fn copy_buffer(
        &self,
        bytes: &[u8],
        flags: BufferFlags,
    ) -> Result<MemoryBuffer, BufferError> {
        let mut buffer = self.create_buffer(bytes.len()).ok_or(BufferError::Allocation)?;
        buffer.set_flags(flags);
        if buffer.append(bytes) != bytes.len() {
            return Err(BufferError::OutOfRange);
        }
        Ok(MemoryBuffer::from_ngx_buf(buffer.as_ngx_buf_mut()))
    }

    /// Builds a pool-owned descriptor over static read-only bytes.
    pub fn static_buffer(
        &self,
        bytes: &'static [u8],
        flags: BufferFlags,
    ) -> Result<MemoryBuffer, BufferError> {
        if bytes.is_empty() {
            return self.control_buffer(flags);
        }
        self.reference_memory(bytes.as_ptr(), bytes.len(), flags)
    }

    /// Builds a bounded memory slice, copying partial ranges.
    ///
    /// # Safety
    /// The source storage must remain valid for the destination pool lifetime.
    pub unsafe fn buffer_slice(
        &self,
        source: &impl Buffer,
        range: Range<usize>,
        flags: BufferFlags,
    ) -> Result<MemoryBuffer, BufferError> {
        let len = source.len();
        if range.start > range.end || range.end > len {
            return Err(BufferError::OutOfRange);
        }
        if range.is_empty() {
            return self.control_buffer(flags);
        }
        let bytes = source.as_bytes();
        if range.start == 0 && range.end == len {
            return self.reference_memory(bytes.as_ptr(), bytes.len(), flags);
        }
        self.copy_buffer(&bytes[range], flags)
    }

    /// Duplicates file metadata and builds a bounded file slice.
    ///
    /// # Safety
    /// The source file must remain valid for the destination pool lifetime.
    pub unsafe fn file_buffer_slice(
        &self,
        source: &impl Buffer,
        range: Range<usize>,
        flags: BufferFlags,
    ) -> Result<MemoryBuffer, BufferError> {
        let file = source.file()?.ok_or(BufferError::NotFile)?;
        if range.start > range.end || range.end > file.len {
            return Err(BufferError::OutOfRange);
        }
        if range.is_empty() {
            return self.control_buffer(flags);
        }

        let start = off_t::try_from(range.start).map_err(|_| BufferError::Overflow)?;
        let end = off_t::try_from(range.end).map_err(|_| BufferError::Overflow)?;
        let file_start = file.start.checked_add(start).ok_or(BufferError::Overflow)?;
        let file_end = file.start.checked_add(end).ok_or(BufferError::Overflow)?;

        let copied_file =
            NonNull::new(self.alloc_type::<ngx_file_t>()).ok_or(BufferError::Allocation)?;
        unsafe { copied_file.as_ptr().write(file.file.as_ptr().read()) };

        let mut raw = self.empty_buffer()?;
        unsafe {
            raw.as_mut().file = copied_file.as_ptr();
            raw.as_mut().file_pos = file_start;
            raw.as_mut().file_last = file_end;
            raw.as_mut().set_in_file(1);
            flags.write(raw.as_mut());
        }
        Ok(MemoryBuffer::from_ngx_buf(raw.as_ptr()))
    }

    /// Builds a zero-size buffer carrying only the requested control flags.
    pub fn control_buffer(&self, flags: BufferFlags) -> Result<MemoryBuffer, BufferError> {
        let mut raw = self.empty_buffer()?;
        flags.write(unsafe { raw.as_mut() });
        Ok(MemoryBuffer::from_ngx_buf(raw.as_ptr()))
    }

    /// Starts an empty pool-owned chain builder.
    pub fn chain(&self) -> PoolChain<'pool> {
        PoolChain { head: None, tail: None, pool: self.clone() }
    }

    fn reference_memory(
        &self,
        start: *const u8,
        len: usize,
        flags: BufferFlags,
    ) -> Result<MemoryBuffer, BufferError> {
        if start.is_null() || len == 0 {
            return Err(BufferError::InvalidMemoryRange);
        }
        let end = unsafe { start.add(len) }.cast_mut();
        let mut raw = self.empty_buffer()?;
        unsafe {
            raw.as_mut().start = start.cast_mut();
            raw.as_mut().pos = start.cast_mut();
            raw.as_mut().last = end;
            raw.as_mut().end = end;
            raw.as_mut().set_memory(1);
            flags.write(raw.as_mut());
        }
        Ok(MemoryBuffer::from_ngx_buf(raw.as_ptr()))
    }

    fn empty_buffer(&self) -> Result<NonNull<ngx_buf_t>, BufferError> {
        NonNull::new(self.calloc_type::<ngx_buf_t>()).ok_or(BufferError::Allocation)
    }
}

/// Failure returned while validating or extending an nginx chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    /// A chain node has a null buffer pointer.
    NullBuffer,
    /// A chain node pointer is misaligned.
    MisalignedLink,
    /// A buffer in the chain is invalid.
    Buffer(BufferError),
    /// Nginx could not allocate a chain node.
    Allocation,
    /// The aggregate chain size overflowed `usize`.
    Overflow,
}

impl From<BufferError> for ChainError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

/// Shared callback-scoped access to a nullable nginx chain.
#[derive(Clone, Copy, Debug)]
pub struct ChainRef<'chain> {
    head: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain ngx_chain_t>,
}

impl<'chain> ChainRef<'chain> {
    /// Creates a shared view over a nullable nginx chain.
    ///
    /// # Safety
    /// Every non-null link and buffer must remain readable for `'chain`; links must be aligned,
    /// form a terminating acyclic list, and not be mutably accessed for that lifetime. Every
    /// buffer must also satisfy the native buffer lifetime requirements.
    pub unsafe fn from_raw(head: *mut ngx_chain_t) -> Result<Self, ChainError> {
        check_chain_ptr(head)?;
        Ok(Self { head, _lifetime: PhantomData })
    }

    /// Invokes a closure with a chain view that cannot escape through a safe value.
    ///
    /// # Safety
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// # use ngx::core::ChainRef;
    /// # use ngx::ffi::ngx_chain_t;
    /// # fn escape(raw: *mut ngx_chain_t) {
    /// let _chain = unsafe { ChainRef::with_raw(raw, |chain| chain) };
    /// # }
    /// ```
    pub unsafe fn with_raw<R>(
        head: *mut ngx_chain_t,
        f: impl for<'scope> FnOnce(ChainRef<'scope>) -> R,
    ) -> Result<R, ChainError> {
        let chain = unsafe { ChainRef::from_raw(head) }?;
        Ok(f(chain))
    }

    /// Iterates over checked buffer links in order.
    pub fn iter(self) -> ChainIter<'chain> {
        ChainIter { next: self.head, _lifetime: PhantomData }
    }

    /// Returns the checked sum of all nginx-visible buffer sizes.
    pub fn len(self) -> Result<usize, ChainError> {
        self.iter().try_fold(0usize, |total, buffer| {
            let len = buffer?.size().map_err(ChainError::Buffer)?;
            total.checked_add(len).ok_or(ChainError::Overflow)
        })
    }

    /// Returns whether the chain has no nginx-visible bytes.
    pub fn is_empty(self) -> Result<bool, ChainError> {
        self.len().map(|len| len == 0)
    }

    pub(crate) fn as_ptr(self) -> *mut ngx_chain_t {
        self.head
    }
}

/// Exclusive callback-scoped access to a nullable nginx chain.
#[derive(Debug)]
pub struct ChainMut<'chain> {
    head: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain mut ngx_chain_t>,
}

impl<'chain> ChainMut<'chain> {
    /// Creates an exclusive view over a nullable nginx chain.
    ///
    /// # Safety
    /// Every non-null link and buffer must remain valid and exclusively accessible for `'chain`;
    /// links must be aligned and form a terminating acyclic list, and buffer pointers must not
    /// alias each other. Every buffer must also satisfy the native buffer lifetime requirements.
    pub unsafe fn from_raw(head: *mut ngx_chain_t) -> Result<Self, ChainError> {
        check_chain_ptr(head)?;
        Ok(Self { head, _lifetime: PhantomData })
    }

    /// Invokes a closure with an exclusive chain view that cannot escape through a safe value.
    ///
    /// # Safety
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// # use ngx::core::ChainMut;
    /// # use ngx::ffi::ngx_chain_t;
    /// # fn escape(raw: *mut ngx_chain_t) {
    /// let _chain = unsafe { ChainMut::with_raw(raw, |chain| chain) };
    /// # }
    /// ```
    pub unsafe fn with_raw<R>(
        head: *mut ngx_chain_t,
        f: impl for<'scope> FnOnce(ChainMut<'scope>) -> R,
    ) -> Result<R, ChainError> {
        let chain = unsafe { ChainMut::from_raw(head) }?;
        Ok(f(chain))
    }

    /// Iterates over shared checked buffer views without consuming this exclusive chain handle.
    pub fn iter(&self) -> ChainIter<'_> {
        ChainIter { next: self.head, _lifetime: PhantomData }
    }

    /// Iterates over exclusive checked buffer views in order.
    pub fn into_iter_mut(self) -> ChainIterMut<'chain> {
        ChainIterMut { next: self.head, _lifetime: PhantomData }
    }

    pub(crate) fn as_ptr(&self) -> *mut ngx_chain_t {
        self.head
    }

    pub(crate) fn contains_link(&self, target: *mut ngx_chain_t) -> bool {
        let mut link = self.head;
        while !link.is_null() {
            if ptr::eq(link, target) {
                return true;
            }
            link = unsafe { (*link).next };
        }
        false
    }
}

/// Checked shared nginx chain iterator.
pub struct ChainIter<'chain> {
    next: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain ngx_chain_t>,
}

impl<'chain> Iterator for ChainIter<'chain> {
    type Item = Result<&'chain ngx_buf_t, ChainError>;

    fn next(&mut self) -> Option<Self::Item> {
        let link = NonNull::new(self.next)?;
        if !self.next.is_aligned() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::MisalignedLink));
        }
        let link = unsafe { link.as_ref() };
        self.next = link.next;
        if link.buf.is_null() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::NullBuffer));
        }
        Some(Ok(unsafe { &*link.buf }))
    }
}

/// Checked exclusive nginx chain iterator.
pub struct ChainIterMut<'chain> {
    next: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain mut ngx_chain_t>,
}

impl<'chain> Iterator for ChainIterMut<'chain> {
    type Item = Result<&'chain mut ngx_buf_t, ChainError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut link = NonNull::new(self.next)?;
        if !self.next.is_aligned() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::MisalignedLink));
        }
        let link = unsafe { link.as_mut() };
        self.next = link.next;
        if link.buf.is_null() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::NullBuffer));
        }
        Some(Ok(unsafe { &mut *link.buf }))
    }
}

/// Pool-owned nginx chain builder with explicit head and tail ownership.
#[derive(Debug)]
pub struct PoolChain<'pool> {
    head: Option<NonNull<ngx_chain_t>>,
    tail: Option<NonNull<ngx_chain_t>>,
    pool: Pool<'pool>,
}

impl<'pool> PoolChain<'pool> {
    /// Appends a buffer whose native storage remains live for the chain.
    ///
    /// # Safety
    /// The buffer and its backing storage must remain valid until nginx releases the chain.
    pub unsafe fn append(&mut self, mut buffer: impl Buffer) -> Result<(), ChainError> {
        let raw = NonNull::new(buffer.as_ngx_buf_mut()).ok_or(ChainError::NullBuffer)?;
        self.append_raw(raw)
    }

    /// Appends every fully prepared link from `candidate` and leaves it empty.
    ///
    /// The candidate remains unchanged when it belongs to a different pool.
    pub fn append_chain(&mut self, candidate: &mut PoolChain<'pool>) -> Result<(), ChainError> {
        if !ptr::eq(self.pool.as_ptr(), candidate.pool.as_ptr()) {
            return Err(ChainError::Buffer(BufferError::ForeignPool));
        }

        debug_assert_eq!(candidate.head.is_some(), candidate.tail.is_some());
        let Some((head, tail)) = candidate.head.zip(candidate.tail) else {
            return Ok(());
        };

        if let Some(mut output_tail) = self.tail {
            unsafe { output_tail.as_mut().next = head.as_ptr() };
        } else {
            self.head = Some(head);
        }
        self.tail = Some(tail);
        candidate.head = None;
        candidate.tail = None;
        Ok(())
    }

    /// Iterates over the current chain in append order.
    pub fn iter(&self) -> ChainIter<'_> {
        ChainIter { next: self.head_ptr(), _lifetime: PhantomData }
    }

    /// Transfers the nullable chain head while the pool retains all storage.
    pub fn into_raw(self) -> *mut ngx_chain_t {
        self.head_ptr()
    }

    /// Transfers the nullable chain endpoints while the pool retains all storage.
    ///
    /// A request-pool context can retain the endpoints and append another fully prepared chain
    /// without walking raw links again.
    pub fn into_raw_parts(self) -> (*mut ngx_chain_t, *mut ngx_chain_t) {
        (self.head_ptr(), self.tail.map_or(ptr::null_mut(), NonNull::as_ptr))
    }

    fn append_raw(&mut self, buffer: NonNull<ngx_buf_t>) -> Result<(), ChainError> {
        let mut link = NonNull::new(unsafe { ngx_alloc_chain_link(self.pool.as_ptr()) })
            .ok_or(ChainError::Allocation)?;
        unsafe {
            link.as_mut().buf = buffer.as_ptr();
            link.as_mut().next = ptr::null_mut();
        }

        if let Some(mut tail) = self.tail {
            unsafe { tail.as_mut().next = link.as_ptr() };
        } else {
            self.head = Some(link);
        }
        self.tail = Some(link);
        Ok(())
    }

    fn head_ptr(&self) -> *mut ngx_chain_t {
        self.head.map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    #[cfg(test)]
    fn tail_ptr(&self) -> *mut ngx_chain_t {
        self.tail.map_or(ptr::null_mut(), NonNull::as_ptr)
    }
}

fn check_chain_ptr(chain: *mut ngx_chain_t) -> Result<(), ChainError> {
    if !chain.is_null() && !chain.is_aligned() {
        return Err(ChainError::MisalignedLink);
    }
    Ok(())
}

pub(crate) fn validate_native_buffer(buffer: &ngx_buf_t) -> Result<(), BufferError> {
    if in_memory(buffer) {
        let pos = NonNull::new(buffer.pos).ok_or(BufferError::InvalidMemoryRange)?;
        let last = NonNull::new(buffer.last).ok_or(BufferError::InvalidMemoryRange)?;
        let len = (last.as_ptr() as usize).checked_sub(pos.as_ptr() as usize)
            .ok_or(BufferError::InvalidMemoryRange)?;
        if len > isize::MAX as usize {
            return Err(BufferError::InvalidMemoryRange);
        }
        if buffer.temporary() != 0 && (buffer.end.is_null() || buffer.end < buffer.last) {
            return Err(BufferError::InvalidMemoryRange);
        }
    }
    file_range(buffer)?;
    Ok(())
}

fn in_memory(buffer: &ngx_buf_t) -> bool {
    buffer.temporary() != 0 || buffer.memory() != 0 || buffer.mmap() != 0
}

fn file_range(buffer: &ngx_buf_t) -> Result<Option<FileView<'_>>, BufferError> {
    if buffer.in_file() == 0 {
        return Ok(None);
    }
    let file = NonNull::new(buffer.file).ok_or(BufferError::InvalidFileRange)?;
    if !buffer.file.is_aligned() || buffer.file_pos < 0 || buffer.file_last < buffer.file_pos {
        return Err(BufferError::InvalidFileRange);
    }
    let len = buffer
        .file_last
        .checked_sub(buffer.file_pos)
        .and_then(|len| usize::try_from(len).ok())
        .ok_or(BufferError::Overflow)?;
    Ok(Some(FileView {
        file,
        start: buffer.file_pos,
        end: buffer.file_last,
        len,
        _lifetime: PhantomData,
    }))
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    /// Builds the shape `ngx_create_temp_buf` produces: `pos == last == start`.
    fn temp_buf(storage: &mut [u8], raw: &mut ngx_buf_t) -> TemporaryBuffer {
        raw.start = storage.as_mut_ptr();
        raw.pos = raw.start;
        raw.last = raw.start;
        raw.end = unsafe { raw.start.add(storage.len()) };
        TemporaryBuffer::from_ngx_buf(raw)
    }

    #[cfg(feature = "test-link")]
    struct TestPool {
        raw: *mut nginx_sys::ngx_pool_t,
        _log: alloc::boxed::Box<nginx_sys::ngx_log_t>,
    }

    #[cfg(feature = "test-link")]
    impl TestPool {
        fn new() -> Self {
            let mut log = alloc::boxed::Box::new(unsafe { core::mem::zeroed() });
            let raw = unsafe { nginx_sys::ngx_create_pool(4096, &raw mut *log) };
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
            unsafe { nginx_sys::ngx_destroy_pool(self.raw) };
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn buffer_slice_references_full_memory_and_copies_partial_ranges() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let source = pool.create_buffer_from_str("borrowed").unwrap();
        let full = unsafe { pool.buffer_slice(&source, 0..8, BufferFlags::default()) }.unwrap();
        assert_eq!(full.as_bytes(), b"borrowed");
        assert_eq!(full.as_bytes().as_ptr(), source.as_bytes().as_ptr());
        let partial = unsafe { pool.buffer_slice(&source, 1..4, BufferFlags::default()) }.unwrap();
        assert_eq!(partial.as_bytes(), b"orr");
        assert_ne!(partial.as_bytes().as_ptr(), unsafe { source.as_bytes().as_ptr().add(1) });

        let mut file: ngx_file_t = unsafe { core::mem::zeroed() };
        file.fd = 23;
        let mut raw_file: ngx_buf_t = unsafe { core::mem::zeroed() };
        raw_file.file = &raw mut file;
        raw_file.file_pos = 100;
        raw_file.file_last = 110;
        raw_file.set_in_file(1);
        let sliced = unsafe { pool.buffer_slice(&raw_file, 2..7, BufferFlags::default()) }.unwrap();
        let view = sliced.as_ngx_buf().file().unwrap().unwrap();
        assert_ne!(view.file_ptr(), &raw mut file);
        assert_eq!((view.start(), view.end()), (102, 107));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_chain_appends_a_completed_candidate_without_partial_publication() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut output = pool.chain();
        unsafe { output.append(pool.copy_buffer(b"head", BufferFlags::default()).unwrap()) }.unwrap();
        let mut candidate = pool.chain();
        unsafe { candidate.append(pool.copy_buffer(b"body", BufferFlags::default()).unwrap()) }.unwrap();
        output.append_chain(&mut candidate).unwrap();
        assert!(candidate.iter().next().is_none());
        let values: alloc::vec::Vec<_> = output.iter().map(|b| b.unwrap().as_bytes()).collect();
        assert_eq!(values, [b"head".as_slice(), b"body".as_slice()]);

        let foreign_owner = TestPool::new();
        let foreign_pool = foreign_owner.handle();
        let mut foreign = foreign_pool.chain();
        unsafe { foreign.append(foreign_pool.copy_buffer(b"foreign", BufferFlags::default()).unwrap()) }.unwrap();
        assert_eq!(output.append_chain(&mut foreign), Err(ChainError::Buffer(BufferError::ForeignPool)));
        assert_eq!(foreign.iter().count(), 1);
        assert_eq!(output.iter().count(), 2);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_chain_transfers_matching_raw_endpoints() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut chain = pool.chain();
        unsafe { chain.append(pool.copy_buffer(b"one", BufferFlags::default()).unwrap()) }.unwrap();
        unsafe { chain.append(pool.copy_buffer(b"two", BufferFlags::default()).unwrap()) }.unwrap();
        let (head, tail) = chain.into_raw_parts();
        assert!(!head.is_null());
        assert!(!tail.is_null());
        assert_ne!(head, tail);
        assert_eq!(unsafe { (*tail).next }, ptr::null_mut());
    }

    #[test]
    fn native_file_buffers_preserve_ranges_and_control_flags() {
        let mut file: ngx_file_t = unsafe { core::mem::zeroed() };
        let mut buffer: ngx_buf_t = unsafe { core::mem::zeroed() };
        buffer.file = &raw mut file;
        buffer.file_pos = 10;
        buffer.file_last = 18;
        buffer.set_in_file(1);
        buffer.set_flags(BufferFlags { flush: true, ..BufferFlags::default() });
        assert_eq!(buffer.size(), Ok(8));
        assert_eq!(buffer.file().unwrap().unwrap().start(), 10);
        assert_eq!(buffer.consume(3), Ok(()));
        assert_eq!(buffer.file_pos, 13);
        assert_eq!(buffer.consume(6), Err(BufferError::OutOfRange));
        assert_eq!(buffer.file_pos, 13);
        assert!(buffer.flags().flush);
    }

    #[test]
    fn chain_iteration_preserves_native_buffer_order() {
        let mut first: ngx_buf_t = unsafe { core::mem::zeroed() };
        let mut second: ngx_buf_t = unsafe { core::mem::zeroed() };
        first.set_flush(1);
        second.set_sync(1);
        let mut tail = ngx_chain_t { buf: &raw mut second, next: ptr::null_mut() };
        let mut head = ngx_chain_t { buf: &raw mut first, next: &raw mut tail };
        let chain = unsafe { ChainRef::from_raw(&raw mut head) }.unwrap();
        let flags: alloc::vec::Vec<_> = chain.iter().map(|buffer| buffer.unwrap().flags()).collect();
        assert_eq!(flags.len(), 2);
        assert!(flags[0].flush);
        assert!(flags[1].sync);
    }

    #[test]
    fn append_fills_a_freshly_created_buffer() {
        let mut storage = [0u8; 64];
        let mut raw: ngx_buf_t = unsafe { core::mem::zeroed() };
        let mut buf = temp_buf(&mut storage, &mut raw);

        // A new buffer holds nothing, and all of its allocation is available.
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 64);
        assert!(buf.as_bytes_mut().is_empty());

        assert_eq!(buf.append(b"hello "), 6);
        assert_eq!(buf.append(b"world"), 5);

        assert_eq!(buf.as_bytes(), b"hello world");
        assert_eq!(buf.len(), 11);
        assert_eq!(buf.capacity(), 53);
    }

    #[test]
    fn append_writes_what_fits_when_full() {
        let mut storage = [0u8; 4];
        let mut raw: ngx_buf_t = unsafe { core::mem::zeroed() };
        let mut buf = temp_buf(&mut storage, &mut raw);

        assert_eq!(buf.append(b"too long"), 4);
        assert_eq!(buf.as_bytes(), b"too ");
        assert_eq!(buf.capacity(), 0);

        // A full buffer accepts nothing more.
        assert_eq!(buf.append(b"x"), 0);
        assert_eq!(buf.as_bytes(), b"too ");
    }
}
