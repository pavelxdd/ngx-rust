extern crate alloc;

use alloc::boxed::Box;
use core::mem;
use core::panic::AssertUnwindSafe;
use core::ptr;

use nginx_sys::{
    ngx_buf_t, ngx_chain_t, ngx_create_pool, ngx_destroy_pool, ngx_file_t, ngx_log_t, off_t,
};

use super::{ChainError, ChainMut, ChainRef};
use crate::core::{BufferError, BufferFlags, Pool};

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
    foreign.append(foreign_pool.copy_buffer(b"foreign", BufferFlags::default()).unwrap()).unwrap();

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
