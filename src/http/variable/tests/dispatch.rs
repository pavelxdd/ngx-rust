use super::*;

#[test]
fn raw_variable_handler_rejects_invalid_callback_pointers_without_calling_the_getter() {
    RAW_VARIABLE_CALLS.store(0, Ordering::Relaxed);
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(ptr::null_mut(), &raw mut value, 0) },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(&raw mut request, ptr::null_mut(), 0) },
        NGX_ERROR as _
    );

    let mut request_storage = [0_u8;
        core::mem::size_of::<ngx_http_request_t>() + core::mem::align_of::<ngx_http_request_t>()];
    let misaligned_request = misaligned_ptr::<ngx_http_request_t>(&mut request_storage);
    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(misaligned_request, &raw mut value, 0) },
        NGX_ERROR as _
    );

    let mut value_storage = [0_u8;
        core::mem::size_of::<ngx_variable_value_t>()
            + core::mem::align_of::<ngx_variable_value_t>()];
    let value = misaligned_ptr::<ngx_variable_value_t>(&mut value_storage);
    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(&raw mut request, value, 0) },
        NGX_ERROR as _
    );
    assert_eq!(RAW_VARIABLE_CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn raw_variable_handler_forwards_zero_and_maximum_data() {
    RAW_VARIABLE_DATA.store(1, Ordering::Relaxed);
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_get_handler::<DataVariable>(&raw mut request, &raw mut value, 0) },
        Status::NGX_DECLINED.0
    );
    assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), 0);

    assert_eq!(
        unsafe { raw_get_handler::<DataVariable>(&raw mut request, &raw mut value, usize::MAX) },
        Status::NGX_DECLINED.0
    );
    assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), usize::MAX);
}

#[test]
fn raw_variable_setter_reads_a_checked_input_value() {
    RAW_SET_VARIABLE_CALLS.store(0, Ordering::Relaxed);
    RAW_SET_VARIABLE_DATA.store(0, Ordering::Relaxed);
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };
    value.data = b"set value".as_ptr().cast_mut();
    value.set_len(b"set value".len() as _);
    value.set_valid(1);

    unsafe { raw_set_handler::<SetVariable>(&raw mut request, &raw mut value, usize::MAX) };

    assert_eq!(RAW_SET_VARIABLE_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(RAW_SET_VARIABLE_DATA.load(Ordering::Relaxed), usize::MAX);
}

#[test]
fn raw_variable_setter_rejects_invalid_callback_pointers_without_calling_the_setter() {
    let calls = AtomicUsize::new(0);
    let data = (&raw const calls).cast::<AtomicUsize>() as usize;
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    unsafe { raw_set_handler::<CountingSetter>(ptr::null_mut(), &raw mut value, data) };
    unsafe { raw_set_handler::<CountingSetter>(&raw mut request, ptr::null_mut(), data) };

    let mut request_storage = [0_u8;
        core::mem::size_of::<ngx_http_request_t>() + core::mem::align_of::<ngx_http_request_t>()];
    let misaligned_request = misaligned_ptr::<ngx_http_request_t>(&mut request_storage);
    unsafe { raw_set_handler::<CountingSetter>(misaligned_request, &raw mut value, data) };

    let mut value_storage = [0_u8;
        core::mem::size_of::<ngx_variable_value_t>()
            + core::mem::align_of::<ngx_variable_value_t>()];
    let value = misaligned_ptr::<ngx_variable_value_t>(&mut value_storage);
    unsafe { raw_set_handler::<CountingSetter>(&raw mut request, value, data) };

    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn raw_variable_handler_converts_every_supported_status_output() {
    assert_eq!(raw_handler_status::<RawStatusVariable>(), Status::NGX_OK.0);
    assert_eq!(raw_handler_status::<OptionalStatusVariable>(), Status::NGX_AGAIN.0);
    assert_eq!(raw_handler_status::<MissingStatusVariable>(), NGX_ERROR as _);
    assert_eq!(raw_handler_status::<ResultStatusVariable>(), Status::NGX_DECLINED.0);
    assert_eq!(raw_handler_status::<ErrorStatusVariable>(), Status::NGX_AGAIN.0);
}

#[test]
fn raw_variable_handler_wraps_the_request_and_value() {
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut raw_value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    let status = unsafe {
        raw_get_handler::<TestVariable>(&raw mut request, &raw mut raw_value, Status::NGX_OK.0 as _)
    };

    assert_eq!(status, Status::NGX_OK.0);
    assert_eq!(request.headers_out.status, Status::NGX_OK.0 as _);
    assert_found(&raw_value, TEST_VARIABLE_VALUE, true, TEST_VARIABLE_VALUE.as_ptr().cast_mut());
}

#[cfg(feature = "test-link")]
#[test]
fn native_exact_lookup_initializes_found_and_not_found_outputs() {
    let mut fixture = VariableFixture::new();
    let found_name = NgxStr::from_bytes(b"ngx_rs_native_found");
    let not_found_name = NgxStr::from_bytes(b"ngx_rs_native_not_found");
    let error_name = NgxStr::from_bytes(b"ngx_rs_native_error");
    add_variable::<TestVariable>(
        &mut fixture.configuration(),
        found_name,
        HttpVariableFlags::empty(),
        Status::NGX_OK.0 as _,
    )
    .unwrap();
    add_variable::<SuccessfulMissingVariable>(
        &mut fixture.configuration(),
        not_found_name,
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    add_variable::<DataVariable>(
        &mut fixture.configuration(),
        error_name,
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    fixture.configuration.finalize_variables();

    fixture.configuration.with_request(|request| {
        let mut found_name = found_name.as_ngx_str();
        let found = unsafe {
            ngx_http_get_variable(
                request.as_ptr(),
                &raw mut found_name,
                ngx_hash_key_lc(found_name.data, found_name.len),
            )
        };
        assert!(!found.is_null());
        assert_found(
            unsafe { &*found },
            TEST_VARIABLE_VALUE,
            true,
            TEST_VARIABLE_VALUE.as_ptr().cast_mut(),
        );
        assert_eq!(unsafe { (*request.as_ptr()).headers_out.status }, Status::NGX_OK.0 as _);

        let mut not_found_name = not_found_name.as_ngx_str();
        let not_found = unsafe {
            ngx_http_get_variable(
                request.as_ptr(),
                &raw mut not_found_name,
                ngx_hash_key_lc(not_found_name.data, not_found_name.len),
            )
        };
        assert!(!not_found.is_null());
        assert_not_found(unsafe { &*not_found });

        let mut error_name = error_name.as_ngx_str();
        let error = unsafe {
            ngx_http_get_variable(
                request.as_ptr(),
                &raw mut error_name,
                ngx_hash_key_lc(error_name.data, error_name.len),
            )
        };
        assert!(error.is_null());
    });
}

#[cfg(feature = "test-link")]
#[test]
fn native_prefix_lookups_pass_the_full_queried_name() {
    let mut fixture = VariableFixture::new();
    let prefix = NgxStr::from_bytes(b"ngx_rs_native_prefix_");
    let full_name = NgxStr::from_bytes(b"ngx_rs_native_prefix_suffix");
    add_prefix_variable::<PrefixVariable>(
        &mut fixture.configuration(),
        prefix,
        HttpVariableFlags::empty(),
    )
    .unwrap();
    let index = get_variable_index(&mut fixture.configuration(), full_name).unwrap();
    fixture.configuration.finalize_variables();
    PREFIX_VARIABLE_CALLS.store(0, Ordering::Relaxed);

    fixture.configuration.with_request(|request| {
        let mut name = full_name.as_ngx_str();
        let value = unsafe {
            ngx_http_get_variable(
                request.as_ptr(),
                &raw mut name,
                ngx_hash_key_lc(name.data, name.len),
            )
        };
        assert!(!value.is_null());
        assert_found(
            unsafe { &*value },
            PREFIX_VARIABLE_VALUE,
            true,
            PREFIX_VARIABLE_VALUE.as_ptr().cast_mut(),
        );

        assert_eq!(index.get_cached(request).unwrap().bytes(), Some(PREFIX_VARIABLE_VALUE));
    });

    assert_eq!(PREFIX_VARIABLE_CALLS.load(Ordering::Relaxed), 2);
}

#[cfg(feature = "test-link")]
#[test]
fn raw_prefix_handler_rejects_an_invalid_name_descriptor() {
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;
    let mut value = MaybeUninit::<ngx_variable_value_t>::uninit();

    assert_eq!(
        unsafe {
            raw_prefix_get_handler::<PrefixVariable>(&raw mut request, value.as_mut_ptr(), 0)
        },
        NGX_ERROR as _
    );
}
