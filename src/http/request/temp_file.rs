use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::core::*;
use crate::ffi::*;
use crate::http::{HttpConfigError, NgxHttpCoreModule};

use super::context::*;
use super::view::*;

/// Failure while copying a checked HTTP chain into a request-pool temporary file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestTempFileError {
    /// The request could not provide a usable pool or logger.
    Request(RequestError),
    /// The HTTP core module configuration could not be resolved.
    Configuration(HttpConfigError),
    /// The request owner registry could not be created.
    Owner(RequestContextError),
    /// Nginx did not install a core location configuration for this request.
    MissingCoreLocationConfiguration,
    /// The core location configuration has no client-body temporary path.
    MissingTempPath,
    /// The configured temporary path pointer is not aligned for `ngx_path_t`.
    MisalignedTempPath,
    /// The request connection has no logger for the temporary file.
    MissingLog,
    /// An input or output chain is malformed or could not allocate a link.
    Chain(ChainError),
    /// A buffer is malformed or could not allocate request-pool storage.
    Buffer(BufferError),
    /// Nginx could not allocate the request-pool temporary-file state or output descriptor.
    Allocation,
    /// The temporary-file offset is negative.
    NegativeOffset,
    /// The input length cannot be represented by nginx's file offset type.
    LengthOverflow,
    /// Appending the input length would overflow the temporary-file offset.
    OffsetOverflow,
    /// Nginx failed to open or write the temporary file.
    Write,
    /// Nginx did not write the complete requested range.
    ShortWrite {
        /// Number of bytes requested from nginx.
        expected: usize,
        /// Number of bytes reported as written by nginx.
        written: usize,
    },
    /// The handle belongs to a different request owner or generation.
    ForeignRequest,
    /// The live temporary file has no matching request-pool cleanup.
    MissingCleanup,
}

impl From<RequestError> for RequestTempFileError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<HttpConfigError> for RequestTempFileError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<RequestContextError> for RequestTempFileError {
    fn from(error: RequestContextError) -> Self {
        Self::Owner(error)
    }
}

impl From<ChainError> for RequestTempFileError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<BufferError> for RequestTempFileError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

/// Callback-scoped owner for a lazily created nginx temporary file.
///
/// The temporary file uses the HTTP core `client_body_temp_path`, is removed by nginx pool
/// cleanup, and creates its file descriptor only when a nonempty memory buffer is appended.
/// File-backed input is copied into the returned request-pool chain without a second disk write.
pub struct RequestTempFile<'callback> {
    pub(super) state: RequestTempFileHandle,
    pub(super) pool: Pool<'callback>,
}

pub(super) struct RequestTempFileState {
    pub(super) path: NonNull<ngx_path_t>,
    pub(super) log: NonNull<ngx_log_t>,
}

/// Checked handle for request-pool temporary-file state retained across HTTP callbacks.
///
/// Store this handle in a request-pool context. Every operation verifies the current request owner
/// and generation before accessing the private pool-backed state, and returns callback-scoped
/// output.
///
/// ```compile_fail
/// use ngx::http::RequestTempFileState;
/// ```
pub struct RequestTempFileHandle {
    pub(super) request: NonNull<ngx_http_request_t>,
    pub(super) pool: *mut ngx_pool_t,
    pub(super) owner: usize,
    pub(super) generation: u64,
    pub(super) state: RequestTempFileState,
    pub(super) temp_file: Option<NonNull<ngx_temp_file_t>>,
    pub(super) _not_thread_safe: PhantomData<*mut ()>,
}

static REQUEST_TEMP_FILE_WARNING: &[u8] = b"an HTTP body is buffered to a temporary file\0";

impl<'request> RequestTempFile<'request> {
    pub(super) fn new(request: &'request RequestRefMut<'_>) -> Result<Self, RequestTempFileError> {
        let pool = request.pool()?;
        let state = RequestTempFileHandle::new(request)?;
        Ok(Self { state, pool })
    }

    /// Copies one checked nginx chain into request-pool owned output.
    ///
    /// Nonempty memory buffers are appended to this temporary file. File-backed buffers receive
    /// request-pool file descriptors over their original ranges, and zero-size control buffers
    /// retain their control flags without opening a temporary file.
    pub fn append(
        &mut self,
        input: ChainRef<'request>,
    ) -> Result<PoolChain<'request>, RequestTempFileError> {
        self.state.append_with_pool(&self.pool, input)
    }
}

impl RequestTempFileHandle {
    pub(super) fn new(request: &RequestRefMut<'_>) -> Result<Self, RequestTempFileError> {
        let pool = request.pool()?;
        let request_view = request.view();
        let location = request_view
            .location_conf::<NgxHttpCoreModule>()?
            .ok_or(RequestTempFileError::MissingCoreLocationConfiguration)?;
        let path = NonNull::new(location.client_body_temp_path)
            .ok_or(RequestTempFileError::MissingTempPath)?;
        if !path.as_ptr().is_aligned() {
            return Err(RequestTempFileError::MisalignedTempPath);
        }
        let log = request.log()?.ok_or(RequestTempFileError::MissingLog)?;

        let main = request_view.main_raw()?;
        let (registry, _) = get_or_create_request_context_registry(&pool, main)?;
        let registry = unsafe { registry.as_ref() };

        Ok(Self {
            request: request.raw,
            pool: pool.as_ptr(),
            owner: registry.owner,
            generation: registry.generation,
            state: RequestTempFileState {
                path,
                log: NonNull::new(log.as_ptr()).expect("request logger"),
            },
            temp_file: None,
            _not_thread_safe: PhantomData,
        })
    }

    /// Copies one checked nginx chain into request-pool owned output.
    ///
    /// Nonempty memory buffers are appended to this temporary file. File-backed buffers receive
    /// request-pool file descriptors over their original ranges, and zero-size control buffers
    /// retain their control flags without opening a temporary file.
    ///
    pub fn append<'request>(
        &mut self,
        request: &'request RequestRefMut<'_>,
        input: ChainRef<'request>,
    ) -> Result<PoolChain<'request>, RequestTempFileError> {
        let pool = self.checked_pool(request)?;
        self.append_with_pool(&pool, input)
    }

    fn append_with_pool<'callback>(
        &mut self,
        pool: &Pool<'callback>,
        input: ChainRef<'callback>,
    ) -> Result<PoolChain<'callback>, RequestTempFileError> {
        for buffer in input.iter() {
            buffer?.kind()?;
        }

        let mut output = pool.chain();
        for buffer in input.iter() {
            let buffer = buffer?;
            match buffer.kind()? {
                BufferView::Memory(bytes) => {
                    let (temp_file, start, end) =
                        self.append_memory(buffer.as_ptr(), bytes.len())?;
                    self.append_temp_file_buffer(
                        &mut output,
                        pool,
                        temp_file,
                        start,
                        end,
                        buffer.flags(),
                    )?;
                }
                BufferView::File(file) => {
                    output.append(pool.file_buffer_slice(
                        buffer,
                        0..file.len(),
                        buffer.flags(),
                    )?)?;
                }
                BufferView::Control(_) => output.append(pool.control_buffer(buffer.flags())?)?,
            }
        }

        Ok(output)
    }

    /// Releases the temporary file after every returned file buffer has been discarded.
    ///
    /// This consumes the state, disables the matching request-pool cleanup, and invokes that
    /// cleanup immediately. A state that has not created a file is a no-op. A missing cleanup
    /// leaves the request-pool cleanup list unchanged.
    ///
    /// # Safety
    ///
    /// No file-backed buffer returned by this state may be read or passed to nginx after release.
    pub unsafe fn release(
        mut self,
        request: &RequestRefMut<'_>,
    ) -> Result<(), RequestTempFileError> {
        let pool = self.checked_pool(request)?;
        let Some(mut temp_file) = self.temp_file.take() else {
            return Ok(());
        };
        let fd = unsafe { temp_file.as_ref().file.fd };
        if fd == NGX_INVALID_FILE as _ {
            return Ok(());
        }

        let mut current = unsafe { (*pool.as_ptr()).cleanup };
        while let Some(mut cleanup) = NonNull::new(current) {
            let cleanup_ref = unsafe { cleanup.as_mut() };
            current = cleanup_ref.next;
            let Some(handler) = cleanup_ref.handler else {
                continue;
            };
            if !is_temp_file_cleanup_handler(handler) {
                continue;
            }
            let Some(cleanup_file) =
                NonNull::new(cleanup_ref.data.cast::<ngx_pool_cleanup_file_t>())
            else {
                continue;
            };
            if !cleanup_file.as_ptr().is_aligned() || unsafe { cleanup_file.as_ref().fd } != fd {
                continue;
            }

            cleanup_ref.handler = None;
            unsafe {
                handler(cleanup_ref.data);
                temp_file.as_mut().file.fd = NGX_INVALID_FILE as _;
            }
            return Ok(());
        }

        Err(RequestTempFileError::MissingCleanup)
    }

    /// Appends one checked buffer into its request-pool-owned representation.
    ///
    /// Nonempty memory is written to the persistent temporary file. File and control buffers are
    /// recreated in the request pool without opening a temporary file.
    pub fn append_buffer<'request>(
        &mut self,
        request: &'request RequestRefMut<'_>,
        input: BufferRef<'_>,
        flags: BufferFlags,
    ) -> Result<PoolChain<'request>, RequestTempFileError> {
        let pool = self.checked_pool(request)?;
        let mut output = pool.chain();
        match input.kind()? {
            BufferView::Memory(bytes) => {
                let (temp_file, start, end) = self.append_memory(input.as_ptr(), bytes.len())?;
                self.append_temp_file_buffer(&mut output, &pool, temp_file, start, end, flags)?;
            }
            BufferView::File(file) => {
                output.append(pool.retain_file_buffer_slice(input, 0..file.len(), flags)?)?;
            }
            BufferView::Control(_) => output.append(pool.control_buffer(flags)?)?,
        }
        Ok(output)
    }

    fn append_memory(
        &mut self,
        buffer: *const ngx_buf_t,
        length: usize,
    ) -> Result<(NonNull<ngx_temp_file_t>, off_t, off_t), RequestTempFileError> {
        let mut temp_file = self.temp_file()?;
        let (start, end) = temp_file_range(unsafe { temp_file.as_ref().offset }, length)?;
        let mut link: ngx_chain_t = unsafe { core::mem::zeroed() };
        link.buf = buffer.cast_mut();

        let written = unsafe { ngx_write_chain_to_temp_file(temp_file.as_ptr(), &raw mut link) };
        let actual_end = unsafe { temp_file.as_ref().file.offset };
        if actual_end < start {
            return Err(RequestTempFileError::Write);
        }
        unsafe { temp_file.as_mut().offset = actual_end };
        check_temp_file_write(length, written)?;
        if actual_end != end {
            return Err(RequestTempFileError::Write);
        }

        Ok((temp_file, start, end))
    }

    fn append_temp_file_buffer<'callback>(
        &self,
        output: &mut PoolChain<'callback>,
        pool: &Pool<'callback>,
        temp_file: NonNull<ngx_temp_file_t>,
        start: off_t,
        end: off_t,
        flags: BufferFlags,
    ) -> Result<(), RequestTempFileError> {
        let mut buffer = NonNull::new(pool.calloc_type::<ngx_buf_t>())
            .ok_or(RequestTempFileError::Allocation)?;
        unsafe {
            let buffer = buffer.as_mut();
            buffer.file = &raw mut (*temp_file.as_ptr()).file;
            buffer.file_pos = start;
            buffer.file_last = end;
            buffer.set_in_file(1);
            buffer.set_flush(u32::from(flags.flush));
            buffer.set_sync(u32::from(flags.sync));
            buffer.set_last_buf(u32::from(flags.last_buf));
            buffer.set_last_in_chain(u32::from(flags.last_in_chain));
        }

        let buffer = unsafe { pool.owned_buffer_from_raw(buffer) };
        output.append(buffer)?;
        Ok(())
    }

    fn temp_file(&mut self) -> Result<NonNull<ngx_temp_file_t>, RequestTempFileError> {
        if let Some(temp_file) = self.temp_file {
            return Ok(temp_file);
        }

        let pool = unsafe { Pool::from_raw(self.pool) }.ok_or(RequestError::MisalignedPool)?;
        let mut temp_file = NonNull::new(pool.calloc_type::<ngx_temp_file_t>())
            .ok_or(RequestTempFileError::Allocation)?;
        unsafe {
            let temp_file_ref = temp_file.as_mut();
            temp_file_ref.file.fd = NGX_INVALID_FILE as _;
            temp_file_ref.file.log = self.state.log.as_ptr();
            temp_file_ref.path = self.state.path.as_ptr();
            temp_file_ref.pool = self.pool;
            temp_file_ref.warn = REQUEST_TEMP_FILE_WARNING.as_ptr().cast_mut();
            temp_file_ref.access = 0o600;
            temp_file_ref.set_log_level(NGX_LOG_WARN as _);
            temp_file_ref.set_clean(1);
        }
        self.temp_file = Some(temp_file);
        Ok(temp_file)
    }

    fn checked_pool<'request>(
        &self,
        request: &'request RequestRefMut<'_>,
    ) -> Result<Pool<'request>, RequestTempFileError> {
        let pool = request.pool()?;
        let Some(registry) = find_request_context_registry(
            NonNull::new(pool.as_ptr()).expect("checked request pool must have a pointer"),
        ) else {
            return Err(RequestTempFileError::ForeignRequest);
        };
        let registry = unsafe { registry.as_ref() };
        if registry.has_stale()
            || self.owner != registry.owner
            || self.generation != registry.generation
            || self.request != request.raw
            || self.pool != pool.as_ptr()
        {
            return Err(RequestTempFileError::ForeignRequest);
        }

        Ok(pool)
    }
}

pub(super) fn is_temp_file_cleanup_handler(handler: unsafe extern "C" fn(*mut c_void)) -> bool {
    ptr::fn_addr_eq(handler, ngx_pool_cleanup_file as unsafe extern "C" fn(*mut c_void))
        || ptr::fn_addr_eq(handler, ngx_pool_delete_file as unsafe extern "C" fn(*mut c_void))
}

pub(super) fn temp_file_range(
    offset: off_t,
    length: usize,
) -> Result<(off_t, off_t), RequestTempFileError> {
    if offset < 0 {
        return Err(RequestTempFileError::NegativeOffset);
    }

    let length = off_t::try_from(length).map_err(|_| RequestTempFileError::LengthOverflow)?;
    let end = offset.checked_add(length).ok_or(RequestTempFileError::OffsetOverflow)?;
    Ok((offset, end))
}

pub(super) fn check_temp_file_write(
    expected: usize,
    written: isize,
) -> Result<(), RequestTempFileError> {
    if written < 0 {
        return Err(RequestTempFileError::Write);
    }

    let written = usize::try_from(written).map_err(|_| RequestTempFileError::Write)?;
    if written != expected {
        return Err(RequestTempFileError::ShortWrite { expected, written });
    }

    Ok(())
}

impl<'callback> RequestRefMut<'callback> {
    /// Creates request-pool state for the configured HTTP temporary-file path.
    ///
    /// The owner allocates its native state and opens its file only when a nonempty memory buffer
    /// is appended through [`RequestTempFile::append`].
    ///
    /// ```compile_fail
    /// use ngx::http::{HTTPStatus, RequestRefMut};
    ///
    /// fn finalize_then_keep_temp_file(request: RequestRefMut<'_>) {
    ///     let temp_file = request.temp_file().unwrap();
    ///     request.finalize(HTTPStatus::BAD_REQUEST).unwrap();
    ///     drop(temp_file);
    /// }
    /// ```
    pub fn temp_file(&self) -> Result<RequestTempFile<'_>, RequestTempFileError> {
        RequestTempFile::new(self)
    }

    /// Creates a checked handle for temporary-file state retained by a request-pool context.
    ///
    /// The handle can be reused by later callbacks for this request; each append still requires a
    /// current callback-scoped request view and returns callback-scoped output.
    pub fn temp_file_state(&self) -> Result<RequestTempFileHandle, RequestTempFileError> {
        RequestTempFileHandle::new(self)
    }
}
