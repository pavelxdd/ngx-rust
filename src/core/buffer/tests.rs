extern crate alloc;

use alloc::boxed::Box;
use core::mem;
use core::ptr;
#[cfg(all(feature = "test-link", unix))]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use nginx_sys::{ngx_buf_t, ngx_create_pool, ngx_destroy_pool, ngx_file_t, ngx_log_t, off_t};

use super::{BufferError, BufferFlags, BufferMut, BufferRef, BufferView};
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
fn read_only_memory_without_start_or_end_has_no_writable_space() {
    let storage = *b"read-only";
    let mut buffer: ngx_buf_t = unsafe { mem::zeroed() };
    buffer.pos = storage.as_ptr().cast_mut();
    buffer.last = unsafe { buffer.pos.add(storage.len()) };
    buffer.set_memory(1);

    let view = unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap();
    assert_eq!(view.memory_bytes(), Ok(Some(storage.as_slice())));
    assert_eq!(view.bytes(), Ok(Some(storage.as_slice())));
    assert_eq!(view.has_space(), Ok(false));
}

#[test]
fn temporary_memory_reports_checked_writable_space() {
    let mut storage = [0_u8; 4];
    let mut buffer: ngx_buf_t = unsafe { mem::zeroed() };
    buffer.pos = storage.as_mut_ptr();
    buffer.last = unsafe { buffer.pos.add(2) };
    buffer.start = buffer.pos;
    buffer.end = unsafe { buffer.pos.add(storage.len()) };
    buffer.set_temporary(1);

    let view = unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap();
    assert_eq!(view.has_space(), Ok(true));

    buffer.end = unsafe { buffer.pos.add(1) };
    let view = unsafe { BufferRef::from_raw(&raw const buffer) }.unwrap();
    assert_eq!(view.has_space(), Err(BufferError::InvalidMemoryRange));
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
fn real_pool_reports_impossible_temporary_buffer_allocation() {
    let owner = TestPool::new();
    let pool = owner.handle();
    assert!(matches!(
        pool.temporary_buffer(usize::MAX, BufferFlags::default()),
        Err(BufferError::Allocation)
    ));
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
