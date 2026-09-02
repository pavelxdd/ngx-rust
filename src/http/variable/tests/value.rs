use super::*;

#[test]
fn static_values_replace_every_http_output_field_on_success() {
    static CACHED: &[u8] = b"cached";
    static UNCACHED: &[u8] = b"uncached";

    let mut raw = poisoned_value();
    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_static(CACHED).unwrap();
    output.publish_success();
    assert_found(&raw, CACHED, true, CACHED.as_ptr().cast_mut());

    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_static_uncached(UNCACHED).unwrap();
    output.publish_success();
    assert_found(&raw, UNCACHED, false, UNCACHED.as_ptr().cast_mut());
}

#[test]
fn borrowed_values_keep_their_original_backing() {
    static BACKING: &[u8] = b"borrowed";

    let mut raw = poisoned_value();
    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    unsafe { output.set_borrowed(BACKING.as_ptr().cast_mut(), BACKING.len()) }.unwrap();
    output.publish_success();
    assert_found(&raw, BACKING, true, BACKING.as_ptr().cast_mut());
}

#[test]
fn borrowed_uncached_values_keep_their_original_backing() {
    static BACKING: &[u8] = b"borrowed";

    let mut raw = poisoned_value();
    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    unsafe { output.set_borrowed_uncached(BACKING.as_ptr().cast_mut(), BACKING.len()) }.unwrap();
    output.publish_success();
    assert_found(&raw, BACKING, false, BACKING.as_ptr().cast_mut());
}

#[test]
fn raw_variable_value_construction_rejects_null_and_misaligned_pointers() {
    assert!(unsafe { HttpVariableOutput::from_raw(ptr::null_mut()) }.is_none());

    let mut storage = [0_u8;
        core::mem::size_of::<ngx_variable_value_t>()
            + core::mem::align_of::<ngx_variable_value_t>()];
    let raw = misaligned_ptr::<ngx_variable_value_t>(&mut storage);
    assert!(unsafe { HttpVariableOutput::from_raw(raw) }.is_none());
}

#[test]
fn successful_getter_without_a_value_publishes_not_found() {
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = poisoned_value();

    let status = unsafe {
        raw_get_handler::<SuccessfulMissingVariable>(&raw mut request, &raw mut value, 0)
    };

    assert_eq!(status, Status::NGX_OK.0);
    assert_eq!(value.len(), 0);
    assert_eq!(value.valid(), 0);
    assert_eq!(value.no_cacheable(), 1);
    assert_eq!(value.not_found(), 1);
    assert_eq!(value.escape(), 0);
    assert!(value.data.is_null());
}

#[test]
fn failed_getter_preserves_the_native_output() {
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = poisoned_value();

    let status = unsafe { raw_get_handler::<DataVariable>(&raw mut request, &raw mut value, 0) };

    assert_eq!(status, Status::NGX_DECLINED.0);
    assert_eq!(value.len(), 17);
    assert_eq!(value.valid(), 0);
    assert_eq!(value.no_cacheable(), 0);
    assert_eq!(value.not_found(), 1);
    assert_eq!(value.escape(), 1);
    assert_eq!(value.data, NonNull::<u8>::dangling().as_ptr());
}

#[test]
fn empty_and_not_found_values_replace_every_http_output_field_on_success() {
    let mut raw = poisoned_value();
    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_empty();
    output.publish_success();
    assert_found(&raw, b"", true, ptr::null_mut());

    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_empty_uncached();
    output.publish_success();
    assert_found(&raw, b"", false, ptr::null_mut());

    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_not_found();
    output.publish_success();
    assert_not_found(&raw);
}

#[test]
fn setter_errors_preserve_the_previous_candidate() {
    let mut raw = poisoned_value();
    let mut output = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
    let data = NonNull::<u8>::dangling().as_ptr();

    output.set_found(HttpVariableOutput::MAX_LEN, data, true).unwrap();
    assert_eq!(raw.len(), 17);
    assert_eq!(
        output.set_found(HttpVariableOutput::MAX_LEN + 1, data, true),
        Err(HttpVariableOutputError::TooLong)
    );
    assert_eq!(output.set_found(1, ptr::null_mut(), false), Err(HttpVariableOutputError::NullData));

    output.publish_success();
    assert_eq!(raw.len() as usize, HttpVariableOutput::MAX_LEN);
    assert_eq!(raw.data, data);
    assert_eq!(raw.valid(), 1);
    assert_eq!(raw.no_cacheable(), 0);
    assert_eq!(raw.not_found(), 0);
    assert_eq!(raw.escape(), 0);
}

#[test]
fn successful_publication_initializes_uninitialized_storage() {
    let mut raw = MaybeUninit::<ngx_variable_value_t>::uninit();
    let mut output = unsafe { HttpVariableOutput::from_raw(raw.as_mut_ptr()) }.unwrap();

    output.set_empty();
    output.publish_success();

    let raw = unsafe { raw.assume_init() };
    assert_found(&raw, b"", true, ptr::null_mut());
}

#[cfg(feature = "test-link")]
#[test]
fn request_pool_values_replace_every_output_field() {
    let owner = TestPool::new();

    with_request(&owner, |request| {
        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
        let bytes = HttpVariablePoolBytes::copy_from_request(&*request, b"pool").unwrap();
        let data = bytes.data.as_ptr();
        assert_eq!(bytes.bytes(), b"pool");
        assert_ne!(data, b"pool".as_ptr().cast_mut());

        value.set_pool(&*request, bytes).unwrap();
        value.publish_success();
        assert_found(&raw, b"pool", true, data);

        let bytes = HttpVariablePoolBytes::copy_from_request(&*request, b"uncached-pool").unwrap();
        let data = bytes.data.as_ptr();
        let mut value = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
        value.set_pool_uncached(&*request, bytes).unwrap();
        value.publish_success();
        assert_found(&raw, b"uncached-pool", false, data);
    });
}

#[cfg(feature = "test-link")]
#[test]
fn copied_request_values_replace_every_output_field() {
    let owner = TestPool::new();

    with_request(&owner, |request| {
        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
        let copied = *b"copied";

        value.copy_from_request(&*request, &copied).unwrap();
        value.publish_success();
        assert_ne!(raw.data, copied.as_ptr().cast_mut());
        assert_found(&raw, &copied, true, raw.data);

        let uncached = *b"uncached";
        let mut value = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
        value.copy_from_request_uncached(&*request, &uncached).unwrap();
        value.publish_success();
        assert_ne!(raw.data, uncached.as_ptr().cast_mut());
        assert_found(&raw, &uncached, false, raw.data);

        let mut value = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
        value.copy_from_request(&*request, b"").unwrap();
        value.publish_success();
        assert_found(&raw, b"", true, ptr::null_mut());
    });
}

#[cfg(feature = "test-link")]
#[test]
fn foreign_request_pool_bytes_do_not_publish_an_output() {
    let current_owner = TestPool::new();
    let foreign_owner = TestPool::new();

    with_request(&current_owner, |current| {
        with_request(&foreign_owner, |foreign| {
            let bytes = HttpVariablePoolBytes::copy_from_request(&*foreign, b"foreign").unwrap();
            let mut raw = poisoned_value();
            let mut value = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
            let before = (
                raw.len(),
                raw.valid(),
                raw.no_cacheable(),
                raw.not_found(),
                raw.escape(),
                raw.data,
            );

            assert_eq!(
                value.set_pool(&*current, bytes),
                Err(HttpVariableOutputError::PoolMismatch)
            );
            assert_eq!(
                (
                    raw.len(),
                    raw.valid(),
                    raw.no_cacheable(),
                    raw.not_found(),
                    raw.escape(),
                    raw.data,
                ),
                before
            );
        });
    });
}

#[cfg(feature = "test-link")]
#[test]
fn allocation_failure_does_not_publish_partial_output() {
    let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
    let owner = TestPool::new();
    unsafe { (*owner.raw).max = 0 };

    with_request(&owner, |request| {
        let mut raw = poisoned_value();
        let mut value = unsafe { HttpVariableOutput::from_raw(&raw mut raw) }.unwrap();
        let before =
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data);

        unsafe { ngx_rs_test_fail_allocations_after(0) };
        let result = value.copy_from_request(&*request, b"copied");
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert_eq!(result, Err(HttpVariableOutputError::Allocation));
        assert_eq!(
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data,),
            before
        );
    });
}
