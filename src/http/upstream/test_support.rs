#[cfg(feature = "test-link")]
use alloc::boxed::Box;
#[cfg(feature = "test-link")]
use core::mem::MaybeUninit;

#[cfg(feature = "test-link")]
use crate::core::Pool;
#[cfg(feature = "test-link")]
use crate::ffi::{ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_pool_t};

#[cfg(feature = "test-link")]
pub(super) struct TestPool {
    pub(super) raw: *mut ngx_pool_t,
    _log: Box<ngx_log_t>,
}

#[cfg(feature = "test-link")]
impl TestPool {
    pub(super) fn new() -> Self {
        let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
        let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!raw.is_null());
        Self { raw, _log: log }
    }

    pub(super) fn pool(&self) -> Pool<'_> {
        unsafe { Pool::from_raw(self.raw) }.unwrap()
    }
}

#[cfg(feature = "test-link")]
impl Drop for TestPool {
    fn drop(&mut self) {
        unsafe { ngx_destroy_pool(self.raw) };
    }
}
