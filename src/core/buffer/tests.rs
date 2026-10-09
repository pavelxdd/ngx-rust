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

#[cfg(all(feature = "test-link", target_os = "linux"))]
#[test]
fn retained_file_fragments_share_one_descriptor_but_not_io_state() {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    let mut source = tempfile::tempfile().unwrap();
    source.write_all(b"abcdef").unwrap();
    let identity = source.metadata().unwrap();
    let count_descriptors = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| std::fs::metadata(entry.ok()?.path()).ok())
            .filter(|metadata| metadata.dev() == identity.dev() && metadata.ino() == identity.ino())
            .count()
    };
    assert_eq!(count_descriptors(), 1);

    {
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut file: ngx_file_t = unsafe { mem::zeroed() };
        file.fd = source.as_raw_fd();
        file.offset = 91;
        file.set_directio(1);
        #[cfg(any(ngx_feature = "threads", ngx_feature = "compat"))]
        {
            file.thread_task = ptr::without_provenance_mut(1);
        }
        #[cfg(any(ngx_feature = "have_file_aio", ngx_feature = "compat"))]
        {
            file.aio = ptr::without_provenance_mut(1);
        }
        let mut raw_file: ngx_buf_t = unsafe { mem::zeroed() };
        raw_file.file = &raw mut file;
        raw_file.file_pos = 1;
        raw_file.file_last = 6;
        raw_file.set_in_file(1);
        let mut first_file: *mut ngx_file_t = ptr::null_mut();
        let mut retained_fd = -1;
        for _ in 0..2048 {
            let fragment = pool
                .retain_file_buffer_slice(
                    unsafe { BufferRef::from_raw(&raw const raw_file) }.unwrap(),
                    1..4,
                    BufferFlags::default(),
                )
                .unwrap();
            let view = fragment.view().file().unwrap().unwrap();
            assert_eq!((view.start(), view.end()), (2, 5));
            assert_eq!(unsafe { (*view.file_ptr()).directio() }, 1);
            #[cfg(any(ngx_feature = "threads", ngx_feature = "compat"))]
            assert!(unsafe { (*view.file_ptr()).thread_task.is_null() });
            #[cfg(any(ngx_feature = "have_file_aio", ngx_feature = "compat"))]
            assert!(unsafe { (*view.file_ptr()).aio.is_null() });
            if first_file.is_null() {
                first_file = view.file_ptr();
                retained_fd = unsafe { (*first_file).fd };
                assert_ne!(retained_fd, source.as_raw_fd());
                assert_ne!(
                    unsafe { libc::fcntl(retained_fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                    0
                );
                unsafe { (*first_file).offset = 42 };
                #[cfg(any(ngx_feature = "threads", ngx_feature = "compat"))]
                unsafe {
                    (*first_file).thread_task = ptr::without_provenance_mut(2);
                }
                #[cfg(any(ngx_feature = "have_file_aio", ngx_feature = "compat"))]
                unsafe {
                    (*first_file).aio = ptr::without_provenance_mut(2);
                }
            } else {
                assert_eq!(count_descriptors(), 2, "one retained fd per backing file");
                assert_eq!(unsafe { (*view.file_ptr()).fd }, retained_fd);
                assert_ne!(view.file_ptr(), first_file);
                assert_eq!(unsafe { (*view.file_ptr()).offset }, 0);
            }
            let mut bytes = [0; 3];
            assert_eq!(unsafe { libc::pread(retained_fd, bytes.as_mut_ptr().cast(), 3, 2) }, 3);
            assert_eq!(&bytes, b"cde");
        }
        // A second open descriptor for the same inode must use the same retained owner.
        let alias = source.try_clone().unwrap();
        file.fd = alias.as_raw_fd();
        raw_file.file = &raw mut file;
        let fragment = pool
            .retain_file_buffer_slice(
                unsafe { BufferRef::from_raw(&raw const raw_file) }.unwrap(),
                0..5,
                BufferFlags::default(),
            )
            .unwrap();
        assert_eq!(
            unsafe { (*fragment.view().file().unwrap().unwrap().file_ptr()).fd },
            retained_fd
        );
        drop(alias);
        drop(source);
        assert_eq!(count_descriptors(), 1);
        let mut bytes = [0; 3];
        assert_eq!(unsafe { libc::pread(retained_fd, bytes.as_mut_ptr().cast(), 3, 2) }, 3);
        assert_eq!(&bytes, b"cde");

        // Reusing the source metadata for a different file must not reuse its retained fd.
        let mut other = tempfile::tempfile().unwrap();
        other.write_all(b"uvwxyz").unwrap();
        file.fd = other.as_raw_fd();
        raw_file.file = &raw mut file;
        let fragment = pool
            .retain_file_buffer_slice(
                unsafe { BufferRef::from_raw(&raw const raw_file) }.unwrap(),
                1..4,
                BufferFlags::default(),
            )
            .unwrap();
        let other_fd = unsafe { (*fragment.view().file().unwrap().unwrap().file_ptr()).fd };
        assert_ne!(other_fd, retained_fd);
        assert_eq!(unsafe { libc::pread(other_fd, bytes.as_mut_ptr().cast(), 3, 2) }, 3);
        assert_eq!(&bytes, b"wxy");
    }
    assert_eq!(count_descriptors(), 0);
}

#[cfg(all(feature = "test-link", target_os = "linux"))]
#[test]
fn retained_buffered_slice_does_not_reuse_a_direct_io_descriptor() {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut storage = tempfile::NamedTempFile::new().unwrap();
    storage.write_all(&[b'x'; 8192]).unwrap();
    let buffered = OpenOptions::new().read(true).open(storage.path()).unwrap();
    let direct =
        match OpenOptions::new().read(true).custom_flags(libc::O_DIRECT).open(storage.path()) {
            Ok(file) => file,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::EOPNOTSUPP)) => {
                std::eprintln!("O_DIRECT open unsupported: {error}; checking mode separation");
                OpenOptions::new().read(true).open(storage.path()).unwrap()
            }
            Err(error) => panic!("O_DIRECT open failed: {error}"),
        };
    let mut bytes = [0; 3];
    let read = unsafe { libc::pread(direct.as_raw_fd(), bytes.as_mut_ptr().cast(), 3, 1) };
    if read == -1 {
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
        std::eprintln!("O_DIRECT rejects an unaligned read on this filesystem");
    } else {
        assert_eq!(read, 3);
        std::eprintln!("O_DIRECT alignment not enforced; checking mode separation");
    }

    let owner = TestPool::new();
    let pool = owner.handle();
    let mut direct_file: ngx_file_t = unsafe { mem::zeroed() };
    direct_file.fd = direct.as_raw_fd();
    direct_file.set_directio(1);
    let mut buffered_file: ngx_file_t = unsafe { mem::zeroed() };
    buffered_file.fd = buffered.as_raw_fd();
    let mut raw: ngx_buf_t = unsafe { mem::zeroed() };
    raw.file = &raw mut direct_file;
    raw.file_pos = 1;
    raw.file_last = 4;
    raw.set_in_file(1);
    let direct_slice = pool
        .retain_file_buffer_slice(
            unsafe { BufferRef::from_raw(&raw const raw) }.unwrap(),
            0..3,
            BufferFlags::default(),
        )
        .unwrap();
    raw.file = &raw mut buffered_file;
    let buffered_slice = pool
        .retain_file_buffer_slice(
            unsafe { BufferRef::from_raw(&raw const raw) }.unwrap(),
            0..3,
            BufferFlags::default(),
        )
        .unwrap();
    let direct_view = direct_slice.view().file().unwrap().unwrap();
    let buffered_view = buffered_slice.view().file().unwrap().unwrap();
    let direct_fd = unsafe { (*direct_view.file_ptr()).fd };
    let buffered_fd = unsafe { (*buffered_view.file_ptr()).fd };
    assert_eq!(unsafe { (*direct_view.file_ptr()).directio() }, 1);
    assert_eq!(unsafe { (*buffered_view.file_ptr()).directio() }, 0);
    drop(direct);
    drop(buffered);
    assert_eq!(
        unsafe { libc::pread(buffered_fd, bytes.as_mut_ptr().cast(), 3, buffered_view.start()) },
        3,
        "buffered slice must still allow unaligned reads: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(&bytes, b"xxx");
    let buffered_flags = unsafe { libc::fcntl(buffered_fd, libc::F_GETFL) };
    assert_ne!(buffered_flags, -1);
    assert_eq!(buffered_flags & libc::O_DIRECT, 0);
    assert_ne!(direct_fd, buffered_fd, "incompatible modes need separate retained descriptors");
    let repeated =
        pool.retain_file_buffer_slice(buffered_slice.view(), 0..3, BufferFlags::default()).unwrap();
    assert_eq!(unsafe { (*repeated.view().file().unwrap().unwrap().file_ptr()).fd }, buffered_fd);
}

#[cfg(all(feature = "test-link", target_os = "linux"))]
#[test]
fn retained_buffered_slice_rechecks_flags_after_source_mode_changes() {
    use std::fs::File;
    use std::io::Write;

    let mut storage = tempfile::NamedTempFile::new().unwrap();
    storage.write_all(&[b'x'; 8192]).unwrap();
    let source = File::open(storage.path()).unwrap();
    let buffered = File::open(storage.path()).unwrap();
    let owner = TestPool::new();
    let pool = owner.handle();
    let mut source_file: ngx_file_t = unsafe { mem::zeroed() };
    source_file.fd = source.as_raw_fd();
    let mut raw: ngx_buf_t = unsafe { mem::zeroed() };
    raw.file = &raw mut source_file;
    raw.file_pos = 1;
    raw.file_last = 4;
    raw.set_in_file(1);
    let retained = pool
        .retain_file_buffer_slice(
            unsafe { BufferRef::from_raw(&raw const raw) }.unwrap(),
            0..3,
            BufferFlags::default(),
        )
        .unwrap();
    let retained_fd = unsafe { (*retained.view().file().unwrap().unwrap().file_ptr()).fd };
    let flags = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags, -1);
    assert_eq!(
        unsafe { libc::fcntl(source.as_raw_fd(), libc::F_SETFL, flags | libc::O_DIRECT) },
        0
    );
    source_file.set_directio(1);
    assert_ne!(unsafe { libc::fcntl(retained_fd, libc::F_GETFL) } & libc::O_DIRECT, 0);

    let mut buffered_file: ngx_file_t = unsafe { mem::zeroed() };
    buffered_file.fd = buffered.as_raw_fd();
    raw.file = &raw mut buffered_file;
    let slice = pool
        .retain_file_buffer_slice(
            unsafe { BufferRef::from_raw(&raw const raw) }.unwrap(),
            0..3,
            BufferFlags::default(),
        )
        .unwrap();
    let view = slice.view().file().unwrap().unwrap();
    let buffered_fd = unsafe { (*view.file_ptr()).fd };
    assert_eq!(unsafe { (*view.file_ptr()).directio() }, 0);
    assert_ne!(buffered_fd, retained_fd, "cached source mode no longer matches the retained fd");
    let buffered_flags = unsafe { libc::fcntl(buffered_fd, libc::F_GETFL) };
    assert_ne!(buffered_flags, -1);
    assert_eq!(buffered_flags & libc::O_DIRECT, 0);
    drop(source);
    drop(buffered);
    assert_ne!(unsafe { libc::fcntl(retained_fd, libc::F_GETFD) }, -1);
    let mut bytes = [0; 3];
    assert_eq!(unsafe { libc::pread(buffered_fd, bytes.as_mut_ptr().cast(), 3, view.start()) }, 3);
    assert_eq!(&bytes, b"xxx");
    let repeated =
        pool.retain_file_buffer_slice(slice.view(), 0..3, BufferFlags::default()).unwrap();
    assert_eq!(unsafe { (*repeated.view().file().unwrap().unwrap().file_ptr()).fd }, buffered_fd);
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
