//! Types and utilities for working with [`ngx_hash_t`].

use core::ffi::CStr;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use nginx_sys::{
    ngx_hash_find, ngx_hash_init, ngx_hash_init_t, ngx_hash_key, ngx_hash_key_t, ngx_hash_t,
    ngx_str_t, ngx_uint_t,
};

use crate::core::{Pool, Status};

/// A typed view over an nginx hash table.
///
/// Hash storage remains owned by the nginx pool used during construction. Values remain owned by
/// the caller and are accessed through the pointers supplied by [`NgxHashKey`].
#[repr(transparent)]
pub struct NgxHash<T> {
    inner: ngx_hash_t,
    _type: PhantomData<T>,
}

impl<T> NgxHash<T> {
    /// Creates a typed shared view over an nginx hash table.
    ///
    /// # Safety
    ///
    /// The hash, its pool storage, and every non-null value pointer must remain valid for the
    /// returned borrow. Each value pointer must point to a valid `T` that may be shared for the
    /// borrow's lifetime.
    pub unsafe fn from_ngx_hash(hash: &ngx_hash_t) -> &Self {
        unsafe { &*(hash as *const ngx_hash_t).cast() }
    }

    /// Builds a typed hash in `pool` from the supplied keys.
    ///
    /// Nginx copies key names into the pool. The values themselves are not copied.
    ///
    /// # Safety
    ///
    /// The pool storage and every value referenced by `keys` must remain valid while the returned
    /// hash or references obtained from it are used. The configured nginx global state, including
    /// its cache-line size, must be initialized.
    pub unsafe fn build(
        pool: &Pool,
        name: &CStr,
        max_size: usize,
        bucket_size: usize,
        keys: &mut [NgxHashKey<'_, T>],
    ) -> Result<Self, Status> {
        let mut hash =
            Self { inner: ngx_hash_t { buckets: ptr::null_mut(), size: 0 }, _type: PhantomData };
        if keys.is_empty() {
            return Ok(hash);
        }

        let mut init = ngx_hash_init_t {
            hash: &raw mut hash.inner,
            key: Some(ngx_hash_key),
            max_size,
            bucket_size,
            name: name.as_ptr().cast_mut(),
            pool: pool.as_ptr(),
            temp_pool: pool.as_ptr(),
        };

        let status = unsafe {
            ngx_hash_init(
                &raw mut init,
                keys.as_mut_ptr().cast::<ngx_hash_key_t>(),
                keys.len() as ngx_uint_t,
            )
        };
        Status(status).into_result().map(|()| hash)
    }

    /// Looks up a lowercase key.
    pub fn get(&self, name: &[u8]) -> Option<&T> {
        if !Self::valid_name(name) {
            return None;
        }

        self.get_hashed(Self::hash_key(name), name)
    }

    /// Looks up a lowercase key using its precomputed nginx hash.
    pub fn get_hashed(&self, key: ngx_uint_t, name: &[u8]) -> Option<&T> {
        if self.inner.buckets.is_null() || self.inner.size == 0 || !Self::valid_name(name) {
            return None;
        }

        let value = unsafe {
            ngx_hash_find(
                ptr::from_ref(&self.inner).cast_mut(),
                key,
                name.as_ptr().cast_mut(),
                name.len(),
            )
        };
        let value = NonNull::new(value.cast::<T>())?;
        Some(unsafe { value.as_ref() })
    }

    /// Returns a pointer to the underlying nginx hash table.
    pub fn as_ptr(&self) -> *const ngx_hash_t {
        &raw const self.inner
    }

    fn valid_name(name: &[u8]) -> bool {
        name.len() <= usize::from(u16::MAX) && !name.iter().any(u8::is_ascii_uppercase)
    }

    fn hash_key(name: &[u8]) -> ngx_uint_t {
        name.iter().fold(0, |key, byte| key.wrapping_mul(31).wrapping_add(ngx_uint_t::from(*byte)))
    }
}

/// A lowercase key and typed value pointer used to construct an [`NgxHash`].
#[repr(transparent)]
pub struct NgxHashKey<'a, T> {
    inner: ngx_hash_key_t,
    _lifetime: PhantomData<(&'a [u8], &'a T)>,
}

impl<'a, T> NgxHashKey<'a, T> {
    /// Creates a construction key.
    ///
    /// Returns `None` when `name` contains ASCII uppercase bytes or cannot fit in nginx's
    /// `u_short` key-length field.
    pub fn new(name: &'a [u8], value: &'a T) -> Option<Self> {
        if !NgxHash::<T>::valid_name(name) {
            return None;
        }

        Some(Self {
            inner: ngx_hash_key_t {
                key: ngx_str_t { len: name.len(), data: name.as_ptr().cast_mut() },
                key_hash: NgxHash::<T>::hash_key(name),
                value: ptr::from_ref(value).cast_mut().cast(),
            },
            _lifetime: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    #[cfg(feature = "test-link")]
    extern crate std;

    use alloc::vec;
    #[cfg(feature = "test-link")]
    use core::mem;

    #[cfg(feature = "test-link")]
    use nginx_sys::{ngx_cacheline_size, ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_pool_t};

    #[cfg(feature = "test-link")]
    use crate::core::Pool;
    #[cfg(feature = "test-link")]
    use std::sync::{Mutex, MutexGuard};

    #[cfg(feature = "test-link")]
    use super::NgxHash;
    use super::NgxHashKey;

    #[cfg(feature = "test-link")]
    static NGINX_GLOBALS: Mutex<()> = Mutex::new(());

    #[test]
    fn hash_keys_reject_names_nginx_cannot_store_exactly() {
        let value = 10_i32;
        let long = vec![b'a'; usize::from(u16::MAX) + 1];

        assert!(NgxHashKey::new(b"Content-Type", &value).is_none());
        assert!(NgxHashKey::new(&long, &value).is_none());
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn typed_hash_builds_and_finds_values() {
        let pool = TestPool::new();
        let alpha = 10_i32;
        let beta = 20_i32;
        let mut keys =
            [NgxHashKey::new(b"alpha", &alpha).unwrap(), NgxHashKey::new(b"beta", &beta).unwrap()];

        let hash =
            unsafe { NgxHash::build(&pool.handle(), c"test_hash", 32, 64, &mut keys) }.unwrap();

        assert_eq!(hash.get(b"alpha"), Some(&10));
        assert_eq!(hash.get_hashed(NgxHash::<i32>::hash_key(b"alpha"), b"alpha"), Some(&10));
        assert_eq!(hash.get(b"beta"), Some(&20));
        assert_eq!(hash.get(b"missing"), None);
        assert_eq!(hash.get(b"Alpha"), None);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn empty_hash_needs_no_bucket_allocation() {
        let pool = TestPool::new();
        let mut keys: [NgxHashKey<'_, i32>; 0] = [];

        let hash =
            unsafe { NgxHash::build(&pool.handle(), c"empty_hash", 0, 0, &mut keys) }.unwrap();

        assert_eq!(hash.get(b"missing"), None);
    }

    #[cfg(feature = "test-link")]
    struct TestPool {
        pool: *mut ngx_pool_t,
        _log: alloc::boxed::Box<ngx_log_t>,
        cacheline_size: usize,
        _global_lock: MutexGuard<'static, ()>,
    }

    #[cfg(feature = "test-link")]
    impl TestPool {
        fn new() -> Self {
            let global_lock = NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let cacheline_size = unsafe { ngx_cacheline_size };
            unsafe { ngx_cacheline_size = 64 };

            let mut log = alloc::boxed::Box::new(unsafe { mem::zeroed() });
            let pool = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!pool.is_null());

            Self { pool, _log: log, cacheline_size, _global_lock: global_lock }
        }

        fn handle(&self) -> Pool {
            unsafe { Pool::from_ngx_pool(self.pool) }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe {
                ngx_destroy_pool(self.pool);
                ngx_cacheline_size = self.cacheline_size;
            }
        }
    }
}
