#![cfg(all(feature = "http", feature = "test-link", feature = "vendored"))]

use core::ffi::{c_int, c_ulong, c_void};
use core::mem::MaybeUninit;
use core::ptr;

use nginx_sys::{
    NGX_HTTP_MODULE, NGX_OK, ngx_create_pool, ngx_cycle, ngx_cycle_t, ngx_destroy_pool, ngx_log_t,
    ngx_module_t, ngx_pagesize, ngx_pagesize_shift, ngx_regex_compile, ngx_regex_compile_t,
    ngx_regex_exec, ngx_regex_init, ngx_ssl_cleanup_ctx, ngx_ssl_create, ngx_ssl_init, ngx_ssl_t,
    ngx_str_t,
};

const Z_OK: c_int = 0;
const Z_BEST_SPEED: c_int = 1;

unsafe extern "C" {
    static ngx_http_gzip_filter_module: ngx_module_t;

    fn compress2(
        destination: *mut u8,
        destination_len: *mut c_ulong,
        source: *const u8,
        source_len: c_ulong,
        level: c_int,
    ) -> c_int;
    fn compressBound(source_len: c_ulong) -> c_ulong;
    fn uncompress(
        destination: *mut u8,
        destination_len: *mut c_ulong,
        source: *const u8,
        source_len: c_ulong,
    ) -> c_int;
}

#[test]
fn source_built_native_dependencies_execute_through_test_link() {
    let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
    let mut cycle = unsafe { MaybeUninit::<ngx_cycle_t>::zeroed().assume_init() };
    cycle.log = &raw mut log;
    let previous_cycle = unsafe { ngx_cycle };
    let previous_pagesize = unsafe { ngx_pagesize };
    let previous_pagesize_shift = unsafe { ngx_pagesize_shift };
    unsafe {
        ngx_cycle = &raw mut cycle;
        ngx_pagesize = 4096;
        ngx_pagesize_shift = 12;
    }

    assert_eq!(unsafe { ngx_ssl_init(&raw mut log) }, NGX_OK as _);
    let mut ssl = unsafe { MaybeUninit::<ngx_ssl_t>::zeroed().assume_init() };
    ssl.log = &raw mut log;
    assert_eq!(unsafe { ngx_ssl_create(&raw mut ssl, 0, ptr::null_mut()) }, NGX_OK as _);
    assert!(!ssl.ctx.is_null());
    unsafe { ngx_ssl_cleanup_ctx((&raw mut ssl).cast::<c_void>()) };

    let pool = unsafe { ngx_create_pool(4096, &raw mut log) };
    assert!(!pool.is_null());
    unsafe { ngx_regex_init() };
    let mut pattern = *b"^native+$";
    let mut error = [0_u8; 256];
    let mut regex = unsafe { MaybeUninit::<ngx_regex_compile_t>::zeroed().assume_init() };
    regex.pattern = ngx_str_t { len: pattern.len(), data: pattern.as_mut_ptr() };
    regex.pool = pool;
    regex.err = ngx_str_t { len: error.len(), data: error.as_mut_ptr() };
    assert_eq!(unsafe { ngx_regex_compile(&raw mut regex) }, NGX_OK as _);
    assert!(!regex.regex.is_null());

    let mut subject = *b"nativeee";
    let mut captures = [0 as c_int; 3];
    let mut subject = ngx_str_t { len: subject.len(), data: subject.as_mut_ptr() };
    assert!(
        unsafe {
            ngx_regex_exec(
                regex.regex,
                &raw mut subject,
                captures.as_mut_ptr(),
                captures.len() as _,
            )
        } > 0
    );
    assert_eq!(&captures[..2], &[0, subject.len as c_int]);
    unsafe { ngx_destroy_pool(pool) };

    assert_eq!(
        unsafe { ptr::read_volatile(ptr::addr_of!(ngx_http_gzip_filter_module.type_)) },
        NGX_HTTP_MODULE as _
    );
    let input = b"vendored zlib through nginx test-link";
    let mut compressed = vec![0_u8; unsafe { compressBound(input.len() as _) } as usize];
    let mut compressed_len = compressed.len() as c_ulong;
    assert_eq!(
        unsafe {
            compress2(
                compressed.as_mut_ptr(),
                &raw mut compressed_len,
                input.as_ptr(),
                input.len() as _,
                Z_BEST_SPEED,
            )
        },
        Z_OK
    );
    compressed.truncate(compressed_len as usize);

    let mut output = vec![0_u8; input.len()];
    let mut output_len = output.len() as c_ulong;
    assert_eq!(
        unsafe {
            uncompress(
                output.as_mut_ptr(),
                &raw mut output_len,
                compressed.as_ptr(),
                compressed.len() as _,
            )
        },
        Z_OK
    );
    output.truncate(output_len as usize);
    assert_eq!(output, input);

    unsafe {
        ngx_cycle = previous_cycle;
        ngx_pagesize = previous_pagesize;
        ngx_pagesize_shift = previous_pagesize_shift;
    }
}
