#![cfg(feature = "test-link")]

use core::ffi::c_void;

use ngx::ffi::{
    ngx_array_push, ngx_array_t, ngx_palloc, ngx_pool_cleanup_add, ngx_pool_cleanup_t, ngx_pool_t,
};

#[test]
fn test_binary_retains_nginx_ffi_calls() {
    core::hint::black_box(
        ngx_palloc as unsafe extern "C" fn(*mut ngx_pool_t, usize) -> *mut c_void,
    );
    core::hint::black_box(
        ngx_pool_cleanup_add
            as unsafe extern "C" fn(*mut ngx_pool_t, usize) -> *mut ngx_pool_cleanup_t,
    );
    core::hint::black_box(ngx_array_push as unsafe extern "C" fn(*mut ngx_array_t) -> *mut c_void);
}
