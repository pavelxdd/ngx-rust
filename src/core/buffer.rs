use core::marker::PhantomData;
use core::mem;
use core::ops::Range;
use core::ptr::{self, NonNull};
use core::slice;

use nginx_sys::{ngx_buf_t, ngx_create_temp_buf, ngx_fd_t, ngx_file_t, ngx_str_t, off_t};

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

    /// Returns whether a temporary buffer has writable bytes after its visible range.
    pub fn has_space(self) -> Result<bool, BufferError> {
        let buffer = unsafe { self.raw.as_ref() };
        if buffer.temporary() == 0 {
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
#[path = "buffer/tests.rs"]
mod tests;
