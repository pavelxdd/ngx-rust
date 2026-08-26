use core::marker::PhantomData;
use core::mem;
use core::ops::Range;
use core::ptr::{self, NonNull};
use core::slice;

use nginx_sys::{
    ngx_alloc_chain_link, ngx_buf_t, ngx_chain_t, ngx_create_temp_buf, ngx_fd_t, ngx_file_t,
    ngx_str_t, off_t,
};

use crate::core::{Pool, PoolCleanupError};

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
    /// The source file descriptor could not be retained independently.
    FileDescriptor,
}

struct RetainedFile {
    file: ngx_file_t,
}

#[cfg(unix)]
impl Drop for RetainedFile {
    fn drop(&mut self) {
        unsafe { libc::close(self.file.fd) };
    }
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

/// Shared callback-scoped access to an nginx buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferRef<'buffer> {
    raw: NonNull<ngx_buf_t>,
    _lifetime: PhantomData<&'buffer ngx_buf_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'buffer> BufferRef<'buffer> {
    /// Creates a checked shared view from a raw nginx buffer.
    ///
    /// # Safety
    /// `buffer` must be null or point to a readable initialized `ngx_buf_t` that remains stable and
    /// is not mutably accessed for `'buffer`. A selected memory range must lie within one
    /// allocation, and selected memory and file pointers must remain valid for the same lifetime.
    ///
    /// ```compile_fail
    /// # use ngx::core::BufferRef;
    /// # use ngx::ffi::ngx_buf_t;
    /// # fn construct(raw: *const ngx_buf_t) {
    /// let _buffer = BufferRef::from_raw(raw);
    /// # }
    /// ```
    pub unsafe fn from_raw(buffer: *const ngx_buf_t) -> Result<Self, BufferError> {
        let raw = checked_buffer_ptr(buffer)?;
        Ok(Self { raw, _lifetime: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with a shared buffer view that cannot escape through a safe value.
    ///
    /// # Safety
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// # use ngx::core::BufferRef;
    /// # use ngx::ffi::ngx_buf_t;
    /// # fn escape(raw: *const ngx_buf_t) {
    /// let _bytes = unsafe { BufferRef::with_raw(raw, |buffer| buffer.bytes().unwrap()) };
    /// # }
    /// ```
    pub unsafe fn with_raw<R>(
        buffer: *const ngx_buf_t,
        f: impl for<'scope> FnOnce(BufferRef<'scope>) -> R,
    ) -> Result<R, BufferError> {
        let buffer = unsafe { BufferRef::from_raw(buffer) }?;
        Ok(f(buffer))
    }

    /// Returns the native buffer pointer for FFI calls.
    pub fn as_ptr(self) -> *const ngx_buf_t {
        self.raw.as_ptr()
    }

    /// Returns the buffer control flags.
    pub fn flags(self) -> BufferFlags {
        BufferFlags::read(unsafe { self.raw.as_ref() })
    }

    /// Returns memory bytes, including a valid empty memory range.
    pub fn memory_bytes(self) -> Result<Option<&'buffer [u8]>, BufferError> {
        let Some((start, len)) = memory_range(unsafe { self.raw.as_ref() })? else {
            return Ok(None);
        };
        Ok(Some(unsafe { slice::from_raw_parts(start.as_ptr(), len) }))
    }

    /// Returns nonempty memory bytes when nginx marks the buffer as memory-backed.
    pub fn bytes(self) -> Result<Option<&'buffer [u8]>, BufferError> {
        let Some(bytes) = self.memory_bytes()? else {
            return Ok(None);
        };
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    /// Returns whether a memory-backed buffer has writable bytes after its visible range.
    pub fn has_space(self) -> Result<bool, BufferError> {
        let buffer = unsafe { self.raw.as_ref() };
        if !in_memory(buffer) {
            return Ok(false);
        }

        memory_range(buffer)?;
        let last = NonNull::new(buffer.last).ok_or(BufferError::InvalidMemoryRange)?;
        let end = NonNull::new(buffer.end).ok_or(BufferError::InvalidMemoryRange)?;
        let available = (end.as_ptr() as usize)
            .checked_sub(last.as_ptr() as usize)
            .ok_or(BufferError::InvalidMemoryRange)?;
        if available > isize::MAX as usize {
            return Err(BufferError::InvalidMemoryRange);
        }
        Ok(available != 0)
    }

    /// Returns a nonempty file range when nginx marks the buffer as file-backed.
    pub fn file(self) -> Result<Option<FileView<'buffer>>, BufferError> {
        let Some(file) = self.file_range()? else {
            return Ok(None);
        };
        if file.len == 0 {
            return Ok(None);
        }
        Ok(Some(file))
    }

    /// Returns the checked file range, including a valid empty range.
    pub fn file_range(self) -> Result<Option<FileView<'buffer>>, BufferError> {
        file_range(unsafe { self.raw.as_ref() })
    }

    /// Returns the checked nginx-visible byte count.
    pub fn len(self) -> Result<usize, BufferError> {
        let buffer = unsafe { self.raw.as_ref() };
        if let Some((_, len)) = memory_range(buffer)? {
            return Ok(len);
        }
        Ok(file_range(buffer)?.map_or(0, |file| file.len))
    }

    /// Returns whether the nginx-visible byte count is zero.
    pub fn is_empty(self) -> Result<bool, BufferError> {
        self.len().map(|len| len == 0)
    }

    /// Returns the checked active representation of this buffer.
    pub fn kind(self) -> Result<BufferView<'buffer>, BufferError> {
        if let Some(bytes) = self.bytes()? {
            return Ok(BufferView::Memory(bytes));
        }

        let buffer = unsafe { self.raw.as_ref() };
        if !in_memory(buffer) {
            if let Some(file) = self.file()? {
                return Ok(BufferView::File(file));
            }
        } else {
            file_range(buffer)?;
        }

        Ok(BufferView::Control(ControlView { flags: self.flags() }))
    }
}

/// Exclusive callback-scoped access to an nginx buffer.
#[derive(Debug, Eq, PartialEq)]
pub struct BufferMut<'buffer> {
    raw: NonNull<ngx_buf_t>,
    _lifetime: PhantomData<&'buffer mut ngx_buf_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl BufferMut<'_> {
    /// Creates a checked exclusive view from a raw nginx buffer.
    ///
    /// # Safety
    /// `buffer` must be null or point to an initialized `ngx_buf_t` that remains valid and
    /// exclusively accessible for `'buffer`. A selected memory range must lie within one
    /// allocation, and selected memory and file pointers must remain valid.
    pub unsafe fn from_raw<'buffer>(
        buffer: *mut ngx_buf_t,
    ) -> Result<BufferMut<'buffer>, BufferError> {
        let raw = checked_buffer_ptr(buffer)?;
        Ok(BufferMut { raw, _lifetime: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with an exclusive buffer view that cannot escape through a safe value.
    ///
    /// # Safety
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// # use ngx::core::BufferMut;
    /// # use ngx::ffi::ngx_buf_t;
    /// # fn escape(raw: *mut ngx_buf_t) {
    /// let _buffer = unsafe { BufferMut::with_raw(raw, |buffer| buffer) };
    /// # }
    /// ```
    pub unsafe fn with_raw<R>(
        buffer: *mut ngx_buf_t,
        f: impl for<'scope> FnOnce(BufferMut<'scope>) -> R,
    ) -> Result<R, BufferError> {
        let buffer = unsafe { BufferMut::from_raw(buffer) }?;
        Ok(f(buffer))
    }

    /// Returns a checked shared reborrow.
    pub fn view(&self) -> BufferRef<'_> {
        BufferRef { raw: self.raw, _lifetime: PhantomData, _not_thread_safe: PhantomData }
    }

    /// Returns the native buffer pointer for FFI calls.
    pub fn as_mut_ptr(&mut self) -> *mut ngx_buf_t {
        self.raw.as_ptr()
    }

    /// Returns the buffer control flags.
    pub fn flags(&self) -> BufferFlags {
        self.view().flags()
    }

    /// Replaces only the four public control flags.
    pub fn set_flags(&mut self, flags: BufferFlags) {
        flags.write(unsafe { self.raw.as_mut() });
    }

    /// Returns the checked nginx-visible byte count.
    pub fn len(&self) -> Result<usize, BufferError> {
        self.view().len()
    }

    /// Returns whether the nginx-visible byte count is zero.
    pub fn is_empty(&self) -> Result<bool, BufferError> {
        self.len().map(|len| len == 0)
    }

    /// Advances memory and file positions by `amount` without partial mutation on failure.
    pub fn consume(&mut self, amount: usize) -> Result<(), BufferError> {
        let buffer = unsafe { self.raw.as_ref() };
        let memory = memory_range(buffer)?;
        let file = file_range(buffer)?;
        let visible = memory.map_or_else(|| file.map_or(0, |value| value.len), |(_, len)| len);
        if amount > visible || file.is_some_and(|value| amount > value.len) {
            return Err(BufferError::OutOfRange);
        }
        let file_amount = if file.is_some() {
            Some(off_t::try_from(amount).map_err(|_| BufferError::Overflow)?)
        } else {
            None
        };

        let buffer = unsafe { self.raw.as_mut() };
        if let Some((position, _)) = memory {
            buffer.pos = unsafe { position.as_ptr().add(amount) };
        }
        if let Some(file_amount) = file_amount {
            buffer.file_pos =
                buffer.file_pos.checked_add(file_amount).ok_or(BufferError::Overflow)?;
        }
        Ok(())
    }
}

/// A buffer descriptor and optional data owned by an nginx pool.
///
/// Pool-owned buffers cannot escape a callback-scoped pool handle:
///
/// ```compile_fail
/// # use ngx::core::{BufferFlags, Pool};
/// # use ngx::ffi::ngx_pool_t;
/// # fn escape(raw: *mut ngx_pool_t) {
/// let _buffer = unsafe {
///     Pool::with_raw(raw, |pool| pool.copy_buffer(b"data", BufferFlags::default()).unwrap())
/// };
/// # }
/// ```
#[derive(Debug)]
pub struct PoolBuffer<'pool> {
    raw: NonNull<ngx_buf_t>,
    pool: Pool<'pool>,
}

impl<'pool> PoolBuffer<'pool> {
    /// Returns a checked shared view tied to this handle borrow.
    pub fn view(&self) -> BufferRef<'_> {
        BufferRef { raw: self.raw, _lifetime: PhantomData, _not_thread_safe: PhantomData }
    }

    /// Returns a checked exclusive view tied to this handle borrow.
    pub fn view_mut(&mut self) -> BufferMut<'_> {
        BufferMut { raw: self.raw, _lifetime: PhantomData, _not_thread_safe: PhantomData }
    }

    /// Returns the stable native buffer pointer for FFI calls.
    pub fn as_ptr(&self) -> *mut ngx_buf_t {
        self.raw.as_ptr()
    }

    pub(crate) fn pool_ptr(&self) -> *mut nginx_sys::ngx_pool_t {
        self.pool.as_ptr()
    }

    /// Transfers the stable native buffer pointer while the pool retains ownership.
    pub fn into_non_null(self) -> NonNull<ngx_buf_t> {
        self.raw
    }

    /// Appends initialized bytes to a temporary buffer.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        let buffer = unsafe { self.raw.as_mut() };
        if buffer.temporary() == 0 || buffer.last.is_null() || buffer.end.is_null() {
            return Err(BufferError::InvalidMemoryRange);
        }
        let available = (buffer.end as usize)
            .checked_sub(buffer.last as usize)
            .ok_or(BufferError::InvalidMemoryRange)?;
        if bytes.len() > available {
            return Err(BufferError::OutOfRange);
        }
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.last, bytes.len()) };
        buffer.last = unsafe { buffer.last.add(bytes.len()) };
        Ok(())
    }

    fn pool_view(&self) -> BufferRef<'pool> {
        BufferRef { raw: self.raw, _lifetime: PhantomData, _not_thread_safe: PhantomData }
    }
}

impl<'pool> Pool<'pool> {
    /// Allocates an empty temporary buffer with `capacity` writable bytes.
    pub fn temporary_buffer(
        &self,
        capacity: usize,
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
        let mut raw = NonNull::new(unsafe { ngx_create_temp_buf(self.as_ptr(), capacity) })
            .ok_or(BufferError::Allocation)?;
        flags.write(unsafe { raw.as_mut() });
        Ok(PoolBuffer { raw, pool: self.clone() })
    }

    /// Copies bytes into a pool-owned temporary buffer.
    pub fn copy_buffer(
        &self,
        bytes: &[u8],
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
        let mut buffer = self.temporary_buffer(bytes.len(), flags)?;
        buffer.extend_from_slice(bytes)?;
        Ok(buffer)
    }

    /// Builds a pool-owned descriptor over static read-only bytes.
    pub fn static_buffer(
        &self,
        bytes: &'static [u8],
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
        if bytes.is_empty() {
            return self.control_buffer(flags);
        }
        self.reference_memory(bytes.as_ptr(), bytes.len(), flags)
    }

    /// Builds a bounded memory slice from another buffer owned by this pool.
    ///
    /// A full slice references the original pool-owned bytes. A partial slice is copied.
    pub fn slice_buffer(
        &self,
        source: &PoolBuffer<'pool>,
        range: Range<usize>,
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
        if !ptr::eq(self.as_ptr(), source.pool.as_ptr()) {
            return Err(BufferError::ForeignPool);
        }
        let view = source.pool_view();
        let len = view.len()?;
        if range.start > range.end || range.end > len {
            return Err(BufferError::OutOfRange);
        }
        if range.is_empty() {
            return self.control_buffer(flags);
        }
        let bytes = view.bytes()?.ok_or(BufferError::NotMemory)?;
        if range.start == 0 && range.end == len {
            return self.reference_memory(bytes.as_ptr(), bytes.len(), flags);
        }
        self.copy_buffer(&bytes[range], flags)
    }

    /// Builds a bounded slice from a checked memory or file buffer view.
    ///
    /// Full memory slices retain the source bytes, while partial memory slices are copied.
    /// File slices duplicate only the native file descriptor and adjust its offsets.
    pub fn buffer_slice(
        &self,
        source: BufferRef<'pool>,
        range: Range<usize>,
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
        let length = source.len()?;
        if range.start > range.end || range.end > length {
            return Err(BufferError::OutOfRange);
        }

        match source.kind()? {
            BufferView::Memory(bytes) => {
                if range.is_empty() {
                    return self.control_buffer(flags);
                }
                if range.start == 0 && range.end == bytes.len() {
                    return self.reference_memory(bytes.as_ptr(), bytes.len(), flags);
                }
                self.copy_buffer(&bytes[range], flags)
            }
            BufferView::File(_) => self.file_buffer_slice(source, range, flags),
            BufferView::Control(_) => self.control_buffer(flags),
        }
    }

    /// Builds a bounded file slice whose metadata remains borrowed for the pool lifetime.
    pub fn file_buffer_slice(
        &self,
        source: BufferRef<'pool>,
        range: Range<usize>,
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
        let file = source.file()?.ok_or(BufferError::NotFile)?;
        self.build_file_buffer(file, range, flags)
    }

    /// Retains a callback-scoped file descriptor and builds a pool-owned bounded slice.
    ///
    /// The retained file has an independent close-on-exec descriptor and fresh asynchronous I/O
    /// state. Its descriptor is closed by the pool cleanup.
    pub fn retain_file_buffer_slice(
        &self,
        source: BufferRef<'_>,
        range: Range<usize>,
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
        let source = source.file()?.ok_or(BufferError::NotFile)?;
        if range.start > range.end || range.end > source.len {
            return Err(BufferError::OutOfRange);
        }
        if range.is_empty() {
            return self.control_buffer(flags);
        }

        let source_file = unsafe { source.file.as_ref() };
        let name = self.copy_file_name(source_file.name)?;
        let log = unsafe { (*self.as_ptr()).log };
        if log.is_null() {
            return Err(BufferError::InvalidFileRange);
        }
        let directio = source_file.directio();
        let retained = self
            .try_allocate_with_cleanup(|| {
                let fd = duplicate_file_descriptor(source_file.fd)?;
                let mut file: ngx_file_t = unsafe { mem::zeroed() };
                file.fd = fd;
                file.name = name;
                file.log = log;
                file.set_directio(directio);
                Ok(RetainedFile { file })
            })
            .map_err(|error| match error {
                PoolCleanupError::Allocation => BufferError::Allocation,
                PoolCleanupError::Construction(error) => error,
            })?;
        let file = FileView {
            file: NonNull::from(&retained.file),
            start: source.start,
            end: source.end,
            len: source.len,
            _lifetime: PhantomData,
        };
        match self.build_file_buffer(file, range, flags) {
            Ok(output) => Ok(output),
            Err(error) => {
                retained.remove();
                Err(error)
            }
        }
    }

    fn build_file_buffer(
        &self,
        file: FileView<'_>,
        range: Range<usize>,
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
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
        let mut raw = self.empty_buffer()?;
        unsafe {
            raw.as_mut().file = file.file.as_ptr();
            raw.as_mut().file_pos = file_start;
            raw.as_mut().file_last = file_end;
            raw.as_mut().set_in_file(1);
            flags.write(raw.as_mut());
        }
        Ok(PoolBuffer { raw, pool: self.clone() })
    }

    fn copy_file_name(&self, name: ngx_str_t) -> Result<ngx_str_t, BufferError> {
        if name.len == 0 {
            return Ok(ngx_str_t { len: 0, data: ptr::null_mut() });
        }
        if name.data.is_null() || name.len > isize::MAX as usize {
            return Err(BufferError::InvalidFileRange);
        }
        let data =
            NonNull::new(self.alloc(name.len).cast::<u8>()).ok_or(BufferError::Allocation)?;
        unsafe { ptr::copy_nonoverlapping(name.data, data.as_ptr(), name.len) };
        Ok(ngx_str_t { len: name.len, data: data.as_ptr() })
    }

    /// Builds a zero-size buffer carrying only the requested control flags.
    pub fn control_buffer(&self, flags: BufferFlags) -> Result<PoolBuffer<'pool>, BufferError> {
        let mut raw = self.empty_buffer()?;
        flags.write(unsafe { raw.as_mut() });
        Ok(PoolBuffer { raw, pool: self.clone() })
    }

    /// Starts an empty pool-owned chain builder.
    pub fn chain(&self) -> PoolChain<'pool> {
        PoolChain { head: None, tail: None, pool: self.clone() }
    }

    /// Wraps a fully initialized buffer owned by this pool.
    ///
    /// # Safety
    /// `raw` and every selected memory or file resource must remain valid for the pool lifetime.
    /// The caller transfers exclusive ownership of the buffer cursor to the returned value.
    pub(crate) unsafe fn owned_buffer_from_raw(
        &self,
        raw: NonNull<ngx_buf_t>,
    ) -> PoolBuffer<'pool> {
        PoolBuffer { raw, pool: self.clone() }
    }

    fn reference_memory(
        &self,
        start: *const u8,
        len: usize,
        flags: BufferFlags,
    ) -> Result<PoolBuffer<'pool>, BufferError> {
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
        Ok(PoolBuffer { raw, pool: self.clone() })
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
    /// buffer must also satisfy [`BufferRef::from_raw`].
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
            let len = buffer?.len().map_err(ChainError::Buffer)?;
            total.checked_add(len).ok_or(ChainError::Overflow)
        })
    }

    /// Returns whether the chain has no nginx-visible bytes.
    pub fn is_empty(self) -> Result<bool, ChainError> {
        self.len().map(|len| len == 0)
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
    /// alias each other. Every buffer must also satisfy [`BufferMut::from_raw`].
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

    /// Appends `suffix` before passing the combined chain to an nginx output filter.
    ///
    /// The appended raw links remain connected after `f` returns because an nginx output filter
    /// may retain the chain when it returns `NGX_AGAIN`. Both input handles are consumed, and the
    /// combined callback-scoped handle cannot escape through a safe return value.
    /// # Safety
    ///
    /// `suffix` must remain valid for as long as the output filter can retain the combined chain.
    /// This is normally true for an nginx output-filter input chain, whose links remain valid
    /// after the callback returns `NGX_AGAIN`.
    pub unsafe fn append_for_output_filter<'suffix, R>(
        self,
        suffix: ChainMut<'suffix>,
        f: impl for<'scope> FnOnce(ChainMut<'scope>) -> R,
    ) -> Result<R, ChainError> {
        let Some(mut tail) = self.tail()? else {
            return unsafe { Self::with_raw(suffix.head, f) };
        };
        if suffix.head.is_null() {
            return unsafe { Self::with_raw(self.head, f) };
        }

        unsafe { tail.as_mut().next = suffix.head };
        unsafe { Self::with_raw(self.head, f) }
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

    fn tail(&self) -> Result<Option<NonNull<ngx_chain_t>>, ChainError> {
        let mut current = NonNull::new(self.head);
        while let Some(link) = current {
            if !link.as_ptr().is_aligned() {
                return Err(ChainError::MisalignedLink);
            }
            let next = unsafe { link.as_ref().next };
            if next.is_null() {
                return Ok(Some(link));
            }
            if !next.is_aligned() {
                return Err(ChainError::MisalignedLink);
            }
            current = NonNull::new(next);
        }
        Ok(None)
    }
}

/// Checked shared nginx chain iterator.
pub struct ChainIter<'chain> {
    next: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain ngx_chain_t>,
}

impl<'chain> Iterator for ChainIter<'chain> {
    type Item = Result<BufferRef<'chain>, ChainError>;

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
        Some(unsafe { BufferRef::from_raw(link.buf) }.map_err(ChainError::Buffer))
    }
}

/// Checked exclusive nginx chain iterator.
pub struct ChainIterMut<'chain> {
    next: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain mut ngx_chain_t>,
}

impl<'chain> Iterator for ChainIterMut<'chain> {
    type Item = Result<BufferMut<'chain>, ChainError>;

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
        Some(unsafe { BufferMut::from_raw(link.buf) }.map_err(ChainError::Buffer))
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
    /// Appends one pool-owned buffer at the current tail.
    pub fn append(&mut self, buffer: PoolBuffer<'pool>) -> Result<(), ChainError> {
        if !ptr::eq(self.pool.as_ptr(), buffer.pool.as_ptr()) {
            return Err(ChainError::Buffer(BufferError::ForeignPool));
        }
        self.append_raw(buffer.raw)
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

    pub(crate) fn belongs_to(&self, pool: &Pool<'_>) -> bool {
        ptr::eq(self.pool.as_ptr(), pool.as_ptr())
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

#[cfg(unix)]
fn duplicate_file_descriptor(fd: ngx_fd_t) -> Result<ngx_fd_t, BufferError> {
    let retained = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if retained == -1 {
        return Err(BufferError::FileDescriptor);
    }
    Ok(retained)
}

#[cfg(not(unix))]
fn duplicate_file_descriptor(_fd: ngx_fd_t) -> Result<ngx_fd_t, BufferError> {
    Err(BufferError::FileDescriptor)
}

fn checked_buffer_ptr(buffer: *const ngx_buf_t) -> Result<NonNull<ngx_buf_t>, BufferError> {
    let raw = NonNull::new(buffer.cast_mut()).ok_or(BufferError::NullBuffer)?;
    if !buffer.is_aligned() {
        return Err(BufferError::MisalignedBuffer);
    }
    Ok(raw)
}

fn check_chain_ptr(chain: *mut ngx_chain_t) -> Result<(), ChainError> {
    if !chain.is_null() && !chain.is_aligned() {
        return Err(ChainError::MisalignedLink);
    }
    Ok(())
}

fn in_memory(buffer: &ngx_buf_t) -> bool {
    buffer.temporary() != 0 || buffer.memory() != 0 || buffer.mmap() != 0
}

fn memory_range(buffer: &ngx_buf_t) -> Result<Option<(NonNull<u8>, usize)>, BufferError> {
    if !in_memory(buffer) {
        return Ok(None);
    }
    let start = NonNull::new(buffer.pos).ok_or(BufferError::InvalidMemoryRange)?;
    let end = NonNull::new(buffer.last).ok_or(BufferError::InvalidMemoryRange)?;
    let len = (end.as_ptr() as usize)
        .checked_sub(start.as_ptr() as usize)
        .ok_or(BufferError::InvalidMemoryRange)?;
    if len > isize::MAX as usize {
        return Err(BufferError::InvalidMemoryRange);
    }
    Ok(Some((start, len)))
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

    use alloc::boxed::Box;
    use core::mem;
    use core::panic::AssertUnwindSafe;
    use core::ptr;
    #[cfg(all(feature = "test-link", unix))]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use nginx_sys::{
        ngx_buf_t, ngx_chain_t, ngx_create_pool, ngx_destroy_pool, ngx_file_t, ngx_log_t, off_t,
    };

    use super::{
        BufferError, BufferFlags, BufferMut, BufferRef, BufferView, ChainError, ChainMut, ChainRef,
    };
    use crate::core::Pool;

    fn memory_buffer(bytes: &[u8]) -> ngx_buf_t {
        let mut buffer: ngx_buf_t = unsafe { mem::zeroed() };
        buffer.pos = bytes.as_ptr().cast_mut();
        buffer.last = unsafe { buffer.pos.add(bytes.len()) };
        buffer.start = buffer.pos;
        buffer.end = buffer.last;
        buffer.set_memory(1);
        buffer
    }

    #[test]
    fn raw_buffer_construction_rejects_null_and_misaligned_pointers() {
        assert_eq!(unsafe { BufferRef::from_raw(ptr::null()) }, Err(BufferError::NullBuffer));
        assert_eq!(unsafe { BufferMut::from_raw(ptr::null_mut()) }, Err(BufferError::NullBuffer));

        let misaligned = ptr::without_provenance_mut::<ngx_buf_t>(1);
        assert_eq!(unsafe { BufferRef::from_raw(misaligned) }, Err(BufferError::MisalignedBuffer));
        assert_eq!(unsafe { BufferMut::from_raw(misaligned) }, Err(BufferError::MisalignedBuffer));
    }

    #[test]
    fn memory_bytes_preserves_a_valid_empty_memory_range() {
        let storage = [0_u8; 1];
        let mut buffer = memory_buffer(&storage);
        buffer.last = buffer.pos;

        let view = unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap();
        assert_eq!(view.memory_bytes(), Ok(Some(b"".as_slice())));
        assert_eq!(view.bytes(), Ok(None));
        assert_eq!(view.has_space(), Ok(true));
    }

    #[test]
    fn memory_views_reject_invalid_ranges_without_creating_slices() {
        let bytes = *b"abcdef";
        let mut buffer = memory_buffer(&bytes);
        let view = unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap();

        assert_eq!(view.len(), Ok(bytes.len()));
        assert_eq!(view.bytes(), Ok(Some(bytes.as_slice())));
        assert!(matches!(view.kind(), Ok(BufferView::Memory(value)) if value == bytes));

        buffer.last = ptr::null_mut();
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().bytes(),
            Err(BufferError::InvalidMemoryRange)
        );

        buffer.pos = ptr::null_mut();
        buffer.last = bytes.as_ptr_range().end.cast_mut();
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().bytes(),
            Err(BufferError::InvalidMemoryRange)
        );

        buffer.last = ptr::null_mut();
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().bytes(),
            Err(BufferError::InvalidMemoryRange)
        );

        buffer.pos = ptr::without_provenance_mut(usize::MAX);
        buffer.last = ptr::without_provenance_mut(1);
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().len(),
            Err(BufferError::InvalidMemoryRange)
        );

        buffer.pos = ptr::without_provenance_mut(1);
        buffer.last = ptr::without_provenance_mut(isize::MAX as usize + 2);
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().len(),
            Err(BufferError::InvalidMemoryRange)
        );
    }

    #[test]
    fn file_and_control_views_validate_ranges_and_keep_flags() {
        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        file.fd = 17;
        let mut buffer: ngx_buf_t = unsafe { mem::zeroed() };
        buffer.file = &raw mut file;
        buffer.file_pos = 10;
        buffer.file_last = 18;
        buffer.set_in_file(1);
        buffer.set_flush(1);

        let view = unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap();
        let file_view = view.file().unwrap().unwrap();
        assert_eq!(file_view.file_ptr(), &raw mut file);
        assert_eq!(file_view.start(), 10);
        assert_eq!(file_view.end(), 18);
        assert_eq!(file_view.len(), 8);
        assert_eq!(view.len(), Ok(8));

        buffer.file = ptr::null_mut();
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().file(),
            Err(BufferError::InvalidFileRange)
        );

        buffer.file = &raw mut file;
        buffer.file_pos = -1;
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().file(),
            Err(BufferError::InvalidFileRange)
        );

        buffer.file_pos = 18;
        buffer.file_last = 10;
        assert_eq!(
            unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap().file(),
            Err(BufferError::InvalidFileRange)
        );

        buffer.file_pos = off_t::MAX;
        buffer.file_last = off_t::MAX;
        let view = unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap();
        assert_eq!(view.len(), Ok(0));
        assert_eq!(view.file(), Ok(None));

        let mut control: ngx_buf_t = unsafe { mem::zeroed() };
        control.set_flush(1);
        control.set_sync(1);
        control.set_last_in_chain(1);
        let view = unsafe { BufferRef::from_raw(&raw const control) }.unwrap();
        assert_eq!(view.bytes(), Ok(None));
        assert_eq!(view.file(), Ok(None));
        assert_eq!(view.len(), Ok(0));
        assert!(matches!(view.kind(), Ok(BufferView::Control(value)) if value.flags().flush));
    }

    #[test]
    fn exclusive_views_consume_memory_and_file_ranges_atomically() {
        let bytes = *b"abcdef";
        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        let mut buffer = memory_buffer(&bytes);
        buffer.file = &raw mut file;
        buffer.file_pos = 20;
        buffer.file_last = 26;
        buffer.set_in_file(1);
        buffer.set_last_buf(1);
        buffer.set_last_in_chain(1);

        {
            let mut view = unsafe { BufferMut::from_raw(&raw mut buffer) }.unwrap();
            assert_eq!(view.consume(2), Ok(()));
            assert_eq!(view.len(), Ok(4));
            assert_eq!(view.consume(5), Err(BufferError::OutOfRange));
            assert!(view.flags().last_buf);
            assert!(view.flags().last_in_chain);
        }

        assert_eq!(buffer.pos, unsafe { bytes.as_ptr().add(2) }.cast_mut());
        assert_eq!(buffer.file_pos, 22);

        let mut file_only: ngx_buf_t = unsafe { mem::zeroed() };
        file_only.file = &raw mut file;
        file_only.file_pos = 30;
        file_only.file_last = 34;
        file_only.set_in_file(1);
        let mut view = unsafe { BufferMut::from_raw(&raw mut file_only) }.unwrap();
        view.set_flags(BufferFlags {
            sync: true,
            last_buf: true,
            last_in_chain: true,
            ..BufferFlags::default()
        });
        assert_eq!(view.consume(4), Ok(()));
        assert_eq!(view.len(), Ok(0));
        assert!(view.flags().sync);
        assert!(view.flags().last_buf);
        assert!(view.flags().last_in_chain);
        assert_eq!(file_only.file_pos, 34);
    }

    #[test]
    fn mutable_chain_iteration_consumes_each_buffer_once() {
        let first_bytes = *b"abc";
        let second_bytes = *b"def";
        let mut first = memory_buffer(&first_bytes);
        let mut second = memory_buffer(&second_bytes);
        let mut second_link = ngx_chain_t { buf: &raw mut second, next: ptr::null_mut() };
        let mut first_link = ngx_chain_t { buf: &raw mut first, next: &raw mut second_link };

        let chain = unsafe { ChainMut::from_raw(&raw mut first_link) }.unwrap();
        for buffer in chain.into_iter_mut() {
            buffer.unwrap().consume(1).unwrap();
        }

        assert_eq!(first.pos, unsafe { first_bytes.as_ptr().add(1) }.cast_mut());
        assert_eq!(second.pos, unsafe { second_bytes.as_ptr().add(1) }.cast_mut());
    }

    #[test]
    fn mutable_chain_appends_a_suffix_for_an_output_filter() {
        let prefix_bytes = *b"prefix";
        let suffix_bytes = *b"suffix";
        let mut prefix_buffer = memory_buffer(&prefix_bytes);
        let mut suffix_buffer = memory_buffer(&suffix_bytes);
        let mut prefix_link = ngx_chain_t { buf: &raw mut prefix_buffer, next: ptr::null_mut() };
        let mut suffix_link = ngx_chain_t { buf: &raw mut suffix_buffer, next: ptr::null_mut() };

        let prefix = unsafe { ChainMut::from_raw(&raw mut prefix_link) }.unwrap();
        let suffix = unsafe { ChainMut::from_raw(&raw mut suffix_link) }.unwrap();
        let bytes = unsafe {
            prefix.append_for_output_filter(suffix, |chain| {
                chain
                    .iter()
                    .map(|buffer| buffer.unwrap().bytes().unwrap().unwrap().to_vec())
                    .collect::<alloc::vec::Vec<_>>()
            })
        }
        .unwrap();

        assert_eq!(bytes, [b"prefix".to_vec(), b"suffix".to_vec()]);
        assert_eq!(prefix_link.next, &raw mut suffix_link);
        assert_eq!(suffix_link.next, ptr::null_mut());
    }

    #[test]
    fn mutable_chain_keeps_an_appended_suffix_when_its_output_filter_panics() {
        let prefix_bytes = *b"prefix";
        let suffix_bytes = *b"suffix";
        let mut prefix_buffer = memory_buffer(&prefix_bytes);
        let mut suffix_buffer = memory_buffer(&suffix_bytes);
        let mut prefix_link = ngx_chain_t { buf: &raw mut prefix_buffer, next: ptr::null_mut() };
        let mut suffix_link = ngx_chain_t { buf: &raw mut suffix_buffer, next: ptr::null_mut() };

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let prefix = unsafe { ChainMut::from_raw(&raw mut prefix_link) }.unwrap();
            let suffix = unsafe { ChainMut::from_raw(&raw mut suffix_link) }.unwrap();
            unsafe { prefix.append_for_output_filter(suffix, |_| panic!("test callback panic")) }
                .unwrap();
        }));

        assert!(result.is_err());
        assert_eq!(prefix_link.next, &raw mut suffix_link);
        assert_eq!(suffix_link.next, ptr::null_mut());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_builders_cover_copy_static_slice_file_and_control_buffers() {
        static STATIC: &[u8] = b"static";

        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        file.fd = 23;
        file.offset = 99;
        let mut raw_file: ngx_buf_t = unsafe { mem::zeroed() };
        raw_file.file = &raw mut file;
        raw_file.file_pos = 100;
        raw_file.file_last = 110;
        raw_file.set_in_file(1);

        let owner = TestPool::new();
        let pool = owner.handle();
        let flags = BufferFlags { flush: true, last_in_chain: true, ..BufferFlags::default() };

        let copied = pool.copy_buffer(b"abcdef", flags).unwrap();
        assert_eq!(copied.view().bytes(), Ok(Some(b"abcdef".as_slice())));
        assert_eq!(copied.view().flags(), flags);

        let static_buffer = pool.static_buffer(STATIC, BufferFlags::default()).unwrap();
        assert_eq!(static_buffer.view().bytes(), Ok(Some(STATIC)));
        assert_eq!(static_buffer.view().bytes().unwrap().unwrap().as_ptr(), STATIC.as_ptr());

        let full = pool.slice_buffer(&copied, 0..6, BufferFlags::default()).unwrap();
        assert_eq!(full.view().bytes(), Ok(Some(b"abcdef".as_slice())));
        assert_eq!(
            full.view().bytes().unwrap().unwrap().as_ptr(),
            copied.view().bytes().unwrap().unwrap().as_ptr()
        );

        let partial = pool.slice_buffer(&copied, 1..4, BufferFlags::default()).unwrap();
        assert_eq!(partial.view().bytes(), Ok(Some(b"bcd".as_slice())));
        assert_ne!(
            partial.view().bytes().unwrap().unwrap().as_ptr(),
            copied.view().bytes().unwrap().unwrap().as_ptr()
        );

        let file_buffer = pool
            .file_buffer_slice(
                unsafe { BufferRef::from_raw(&raw const raw_file) }.unwrap(),
                2..7,
                BufferFlags { last_buf: true, ..BufferFlags::default() },
            )
            .unwrap();
        let file_view = file_buffer.view().file().unwrap().unwrap();
        assert_eq!(file_view.file_ptr(), &raw mut file);
        assert_eq!(unsafe { (*file_view.file_ptr()).fd }, 23);
        assert_eq!(unsafe { (*file_view.file_ptr()).offset }, 99);
        assert_eq!((file_view.start(), file_view.end()), (102, 107));

        let control = pool
            .control_buffer(BufferFlags { sync: true, last_buf: true, ..BufferFlags::default() })
            .unwrap();
        assert!(matches!(control.view().kind(), Ok(BufferView::Control(_))));
        assert!(control.view().flags().sync);
        assert!(control.view().flags().last_buf);
    }

    #[cfg(all(feature = "test-link", unix))]
    #[test]
    fn retained_file_buffer_slice_owns_its_descriptor_until_pool_cleanup() {
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let source = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let _writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };

        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        file.fd = source.as_raw_fd();
        let mut raw_file: ngx_buf_t = unsafe { mem::zeroed() };
        raw_file.file = &raw mut file;
        raw_file.file_last = 1;
        raw_file.set_in_file(1);

        let retained_fd = {
            let owner = TestPool::new();
            let pool = owner.handle();
            let retained = pool
                .retain_file_buffer_slice(
                    unsafe { BufferRef::from_raw(&raw const raw_file) }.unwrap(),
                    0..1,
                    BufferFlags::default(),
                )
                .unwrap();
            let retained_fd = unsafe { (*retained.view().file().unwrap().unwrap().file_ptr()).fd };

            assert_ne!(retained_fd, source.as_raw_fd());
            drop(source);
            assert_ne!(unsafe { libc::fcntl(retained_fd, libc::F_GETFD) }, -1);
            retained_fd
        };

        assert_eq!(unsafe { libc::fcntl(retained_fd, libc::F_GETFD) }, -1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn buffer_slice_references_full_memory_and_file_metadata() {
        static BORROWED: &[u8] = b"borrowed";

        let owner = TestPool::new();
        let pool = owner.handle();

        let memory = memory_buffer(BORROWED);
        let full = pool
            .buffer_slice(
                unsafe { BufferRef::from_raw(&raw const memory) }.unwrap(),
                0..BORROWED.len(),
                BufferFlags::default(),
            )
            .unwrap();
        assert_eq!(full.view().bytes(), Ok(Some(BORROWED)));
        assert_eq!(full.view().bytes().unwrap().unwrap().as_ptr(), BORROWED.as_ptr());

        let partial = pool
            .buffer_slice(
                unsafe { BufferRef::from_raw(&raw const memory) }.unwrap(),
                1..4,
                BufferFlags::default(),
            )
            .unwrap();
        assert_eq!(partial.view().bytes(), Ok(Some(b"orr".as_slice())));
        assert_ne!(partial.view().bytes().unwrap().unwrap().as_ptr(), unsafe {
            BORROWED.as_ptr().add(1)
        });

        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        file.fd = 23;
        let mut raw_file: ngx_buf_t = unsafe { mem::zeroed() };
        raw_file.file = &raw mut file;
        raw_file.file_pos = 100;
        raw_file.file_last = 110;
        raw_file.set_in_file(1);
        let sliced_file = pool
            .buffer_slice(
                unsafe { BufferRef::from_raw(&raw const raw_file) }.unwrap(),
                2..7,
                BufferFlags::default(),
            )
            .unwrap();
        let file_view = sliced_file.view().file().unwrap().unwrap();
        assert_eq!(file_view.file_ptr(), &raw mut file);
        assert_eq!((file_view.start(), file_view.end()), (102, 107));
    }

    #[test]
    fn file_range_keeps_a_checked_empty_file_visible() {
        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        let mut raw: ngx_buf_t = unsafe { mem::zeroed() };
        raw.file = &raw mut file;
        raw.file_pos = 9;
        raw.file_last = 9;
        raw.set_in_file(1);

        let view = unsafe { BufferRef::from_raw(&raw const raw) }.expect("file buffer");
        assert_eq!(view.file(), Ok(None));
        let range = view.file_range().expect("checked file range").expect("present file range");
        assert_eq!((range.start(), range.end(), range.len()), (9, 9, 0));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_chain_preserves_append_order_and_rejects_null_links() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut chain = pool.chain();
        chain.append(pool.copy_buffer(b"one", BufferFlags::default()).unwrap()).unwrap();
        chain.append(pool.copy_buffer(b"two", BufferFlags::default()).unwrap()).unwrap();
        chain.append(pool.copy_buffer(b"three", BufferFlags::default()).unwrap()).unwrap();

        let values = chain
            .iter()
            .map(|value| value.unwrap().bytes().unwrap().unwrap())
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(values, [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()]);
        assert_eq!(unsafe { (*chain.tail_ptr()).next }, ptr::null_mut());

        let mut invalid = ngx_chain_t { buf: ptr::null_mut(), next: ptr::null_mut() };
        let raw = unsafe { ChainRef::from_raw(&raw mut invalid) }.unwrap();
        assert_eq!(raw.iter().next().unwrap(), Err(ChainError::NullBuffer));
        assert!(unsafe { ChainRef::from_raw(ptr::null_mut()) }.unwrap().iter().next().is_none());

        let bytes = *b"valid";
        let mut buffer = memory_buffer(&bytes);
        let mut invalid_next =
            ngx_chain_t { buf: &raw mut buffer, next: ptr::without_provenance_mut(1) };
        let mut iter = unsafe { ChainRef::from_raw(&raw mut invalid_next) }.unwrap().iter();
        assert!(iter.next().unwrap().is_ok());
        assert_eq!(iter.next().unwrap(), Err(ChainError::MisalignedLink));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_chain_appends_a_completed_candidate_without_partial_publication() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut output = pool.chain();
        output.append(pool.copy_buffer(b"head", BufferFlags::default()).unwrap()).unwrap();

        let mut candidate = pool.chain();
        candidate.append(pool.copy_buffer(b"body", BufferFlags::default()).unwrap()).unwrap();
        output.append_chain(&mut candidate).unwrap();

        let values = output
            .iter()
            .map(|buffer| buffer.unwrap().bytes().unwrap().unwrap())
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(values, [b"head".as_slice(), b"body".as_slice()]);

        let foreign_owner = TestPool::new();
        let foreign_pool = foreign_owner.handle();
        let mut foreign = foreign_pool.chain();
        foreign
            .append(foreign_pool.copy_buffer(b"foreign", BufferFlags::default()).unwrap())
            .unwrap();

        assert_eq!(
            output.append_chain(&mut foreign),
            Err(ChainError::Buffer(BufferError::ForeignPool))
        );
        let values = output
            .iter()
            .map(|buffer| buffer.unwrap().bytes().unwrap().unwrap())
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(values, [b"head".as_slice(), b"body".as_slice()]);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_chain_transfers_matching_raw_endpoints() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut chain = pool.chain();
        chain.append(pool.copy_buffer(b"one", BufferFlags::default()).unwrap()).unwrap();
        chain.append(pool.copy_buffer(b"two", BufferFlags::default()).unwrap()).unwrap();

        let (head, tail) = chain.into_raw_parts();
        assert!(!head.is_null());
        assert!(!tail.is_null());
        assert_ne!(head, tail);
        assert_eq!(unsafe { (*tail).next }, ptr::null_mut());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn aggregate_chain_size_rejects_overflow() {
        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        let mut first: ngx_buf_t = unsafe { mem::zeroed() };
        first.file = &raw mut file;
        first.file_last = off_t::MAX;
        first.set_in_file(1);
        let mut second = first;
        let mut third = first;
        third.file_last = 2;

        let mut third_link = ngx_chain_t { buf: &raw mut third, next: ptr::null_mut() };
        let mut second_link = ngx_chain_t { buf: &raw mut second, next: &raw mut third_link };
        let mut first_link = ngx_chain_t { buf: &raw mut first, next: &raw mut second_link };
        let chain = unsafe { ChainRef::from_raw(&raw mut first_link) }.unwrap();

        assert_eq!(chain.len(), Err(ChainError::Overflow));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn real_pool_reports_impossible_temporary_buffer_allocation() {
        let owner = TestPool::new();
        let pool = owner.handle();
        let chain = pool.chain();

        assert!(matches!(
            pool.temporary_buffer(usize::MAX, BufferFlags::default()),
            Err(BufferError::Allocation)
        ));
        assert!(chain.iter().next().is_none());
    }

    #[cfg(feature = "test-link")]
    struct TestPool {
        raw: *mut nginx_sys::ngx_pool_t,
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
