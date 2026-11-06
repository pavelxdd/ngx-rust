extern crate alloc;
extern crate std;

use crate::core::{Buffer, BufferFlags, Pool};
use crate::ffi::{ngx_buf_t, ngx_create_pool, ngx_destroy_pool, ngx_file_t, ngx_log_t};
use alloc::boxed::Box;
use core::{mem, ptr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(all(feature = "test-link", unix))]
#[test]
fn retained_file_buffer_slice_owns_its_descriptor_until_pool_cleanup() {
    let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
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
        let retained =
            pool.retain_file_buffer_slice(&raw_file, 0..1, BufferFlags::default()).unwrap();
        let retained_fd = unsafe { (*retained.file().unwrap().unwrap().file_ptr()).fd };

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
    let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
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
            let fragment =
                pool.retain_file_buffer_slice(&raw_file, 1..4, BufferFlags::default()).unwrap();
            let view = fragment.file().unwrap().unwrap();
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
        let fragment =
            pool.retain_file_buffer_slice(&raw_file, 0..5, BufferFlags::default()).unwrap();
        assert_eq!(unsafe { (*fragment.file().unwrap().unwrap().file_ptr()).fd }, retained_fd);
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
        let fragment =
            pool.retain_file_buffer_slice(&raw_file, 1..4, BufferFlags::default()).unwrap();
        let other_fd = unsafe { (*fragment.file().unwrap().unwrap().file_ptr()).fd };
        assert_ne!(other_fd, retained_fd);
        assert_eq!(unsafe { libc::pread(other_fd, bytes.as_mut_ptr().cast(), 3, 2) }, 3);
        assert_eq!(&bytes, b"wxy");
    }
    assert_eq!(count_descriptors(), 0);
}

#[cfg(all(feature = "test-link", target_os = "linux"))]
#[test]
fn retained_buffered_slice_does_not_reuse_a_direct_io_descriptor() {
    let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
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
    let direct_slice = pool.retain_file_buffer_slice(&raw, 0..3, BufferFlags::default()).unwrap();
    raw.file = &raw mut buffered_file;
    let buffered_slice = pool.retain_file_buffer_slice(&raw, 0..3, BufferFlags::default()).unwrap();
    let direct_view = direct_slice.file().unwrap().unwrap();
    let buffered_view = buffered_slice.file().unwrap().unwrap();
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
        pool.retain_file_buffer_slice(&buffered_slice, 0..3, BufferFlags::default()).unwrap();
    assert_eq!(unsafe { (*repeated.file().unwrap().unwrap().file_ptr()).fd }, buffered_fd);
}

#[cfg(all(feature = "test-link", target_os = "linux"))]
#[test]
fn retained_buffered_slice_rechecks_flags_after_source_mode_changes() {
    let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
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
    let retained = pool.retain_file_buffer_slice(&raw, 0..3, BufferFlags::default()).unwrap();
    let retained_fd = unsafe { (*retained.file().unwrap().unwrap().file_ptr()).fd };
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
    let slice = pool.retain_file_buffer_slice(&raw, 0..3, BufferFlags::default()).unwrap();
    let view = slice.file().unwrap().unwrap();
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
    let repeated = pool.retain_file_buffer_slice(&slice, 0..3, BufferFlags::default()).unwrap();
    assert_eq!(unsafe { (*repeated.file().unwrap().unwrap().file_ptr()).fd }, buffered_fd);
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
