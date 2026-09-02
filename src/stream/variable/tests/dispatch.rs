use super::*;

#[test]
fn raw_variable_handler_rejects_invalid_callback_pointers_without_calling_the_getter() {
    RAW_VARIABLE_CALLS.store(0, Ordering::Relaxed);
    let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(ptr::null_mut(), &raw mut value, 0) },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(&raw mut session, ptr::null_mut(), 0) },
        NGX_ERROR as _
    );

    let mut session_storage = [0_u8;
        core::mem::size_of::<ngx_stream_session_t>()
            + core::mem::align_of::<ngx_stream_session_t>()];
    let misaligned_session = misaligned_ptr::<ngx_stream_session_t>(&mut session_storage);
    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(misaligned_session, &raw mut value, 0) },
        NGX_ERROR as _
    );

    let mut value_storage = [0_u8;
        core::mem::size_of::<ngx_variable_value_t>()
            + core::mem::align_of::<ngx_variable_value_t>()];
    let value = misaligned_ptr::<ngx_variable_value_t>(&mut value_storage);
    assert_eq!(
        unsafe { raw_get_handler::<CountingVariable>(&raw mut session, value, 0) },
        NGX_ERROR as _
    );
    assert_eq!(RAW_VARIABLE_CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn raw_variable_handler_forwards_zero_and_maximum_data() {
    RAW_VARIABLE_DATA.store(1, Ordering::Relaxed);
    let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_get_handler::<DataVariable>(&raw mut session, &raw mut value, 0) },
        Status::NGX_DECLINED.0
    );
    assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), 0);

    assert_eq!(
        unsafe { raw_get_handler::<DataVariable>(&raw mut session, &raw mut value, usize::MAX) },
        Status::NGX_DECLINED.0
    );
    assert_eq!(RAW_VARIABLE_DATA.load(Ordering::Relaxed), usize::MAX);
}

#[test]
fn raw_variable_handler_converts_every_supported_status_output() {
    assert_eq!(raw_handler_status::<RawStatusVariable>(), NGX_STREAM_OK as _);
    assert_eq!(raw_handler_status::<OptionalStatusVariable>(), Status::NGX_AGAIN.0);
    assert_eq!(raw_handler_status::<MissingStatusVariable>(), NGX_ERROR as _);
    assert_eq!(raw_handler_status::<ResultStatusVariable>(), Status::NGX_DECLINED.0);
    assert_eq!(raw_handler_status::<ErrorStatusVariable>(), Status::NGX_AGAIN.0);
}

#[test]
fn raw_variable_handler_wraps_the_session_and_value() {
    let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    let mut raw_value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };

    let status = unsafe {
        raw_get_handler::<TestVariable>(&raw mut session, &raw mut raw_value, NGX_STREAM_OK as _)
    };

    assert_eq!(status, Status::NGX_OK.0);
    assert_eq!(session.status, NGX_STREAM_OK as _);
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
        StreamVariableFlags::empty(),
        NGX_STREAM_OK as _,
    )
    .unwrap();
    add_variable::<SuccessfulMissingVariable>(
        &mut fixture.configuration(),
        not_found_name,
        StreamVariableFlags::empty(),
        0,
    )
    .unwrap();
    add_variable::<DataVariable>(
        &mut fixture.configuration(),
        error_name,
        StreamVariableFlags::empty(),
        0,
    )
    .unwrap();
    fixture.finalize_variables();

    fixture.with_session(|session| {
        let mut found_name = found_name.as_ngx_str();
        let found = unsafe {
            ngx_stream_get_variable(
                session.as_ptr(),
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
        assert_eq!(unsafe { (*session.as_ptr()).status }, NGX_STREAM_OK as _);

        let mut not_found_name = not_found_name.as_ngx_str();
        let not_found = unsafe {
            ngx_stream_get_variable(
                session.as_ptr(),
                &raw mut not_found_name,
                ngx_hash_key_lc(not_found_name.data, not_found_name.len),
            )
        };
        assert!(!not_found.is_null());
        assert_not_found(unsafe { &*not_found });

        let mut error_name = error_name.as_ngx_str();
        let error = unsafe {
            ngx_stream_get_variable(
                session.as_ptr(),
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
        StreamVariableFlags::empty(),
    )
    .unwrap();
    let mut indexed_name = full_name.as_ngx_str();
    let index =
        unsafe { ngx_stream_get_variable_index(&raw mut *fixture.cf, &raw mut indexed_name) };
    assert_ne!(index, NGX_ERROR as _);
    fixture.finalize_variables();
    PREFIX_VARIABLE_CALLS.store(0, Ordering::Relaxed);

    fixture.with_session(|session| {
        let mut name = full_name.as_ngx_str();
        let value = unsafe {
            ngx_stream_get_variable(
                session.as_ptr(),
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

        let value = unsafe { ngx_stream_get_indexed_variable(session.as_ptr(), index as _) };
        assert!(!value.is_null());
        assert_found(
            unsafe { &*value },
            PREFIX_VARIABLE_VALUE,
            true,
            PREFIX_VARIABLE_VALUE.as_ptr().cast_mut(),
        );
    });

    assert_eq!(PREFIX_VARIABLE_CALLS.load(Ordering::Relaxed), 2);
}

#[cfg(feature = "test-link")]
#[test]
fn raw_prefix_handler_rejects_an_invalid_name_descriptor() {
    let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    let mut value = MaybeUninit::<ngx_variable_value_t>::uninit();

    assert_eq!(
        unsafe {
            raw_prefix_get_handler::<PrefixVariable>(&raw mut session, value.as_mut_ptr(), 0)
        },
        NGX_ERROR as _
    );
}
