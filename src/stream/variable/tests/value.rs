use super::*;

#[test]
fn raw_variable_value_construction_rejects_null_and_misaligned_pointers() {
    assert!(unsafe { StreamVariableOutput::from_raw(ptr::null_mut()) }.is_none());

    let mut storage = [0_u8;
        core::mem::size_of::<ngx_variable_value_t>()
            + core::mem::align_of::<ngx_variable_value_t>()];
    let raw = misaligned_ptr::<ngx_variable_value_t>(&mut storage);
    assert!(unsafe { StreamVariableOutput::from_raw(raw) }.is_none());
}

#[test]
fn successful_getter_without_a_value_publishes_not_found() {
    let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    let mut value = poisoned_value();

    let status = unsafe {
        raw_get_handler::<SuccessfulMissingVariable>(&raw mut session, &raw mut value, 0)
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
    let mut session = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    let mut value = poisoned_value();

    let status = unsafe { raw_get_handler::<DataVariable>(&raw mut session, &raw mut value, 0) };

    assert_eq!(status, Status::NGX_DECLINED.0);
    assert_eq!(value.len(), 17);
    assert_eq!(value.valid(), 0);
    assert_eq!(value.no_cacheable(), 0);
    assert_eq!(value.not_found(), 1);
    assert_eq!(value.escape(), 1);
    assert_eq!(value.data, NonNull::<u8>::dangling().as_ptr());
}

#[test]
fn static_values_replace_every_output_field_on_success() {
    static CACHED: &[u8] = b"cached";
    static UNCACHED: &[u8] = b"uncached";

    let mut raw = poisoned_value();
    let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_static(CACHED).unwrap();
    output.publish_success();
    assert_found(&raw, CACHED, true, CACHED.as_ptr().cast_mut());

    let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_static_uncached(UNCACHED).unwrap();
    output.publish_success();
    assert_found(&raw, UNCACHED, false, UNCACHED.as_ptr().cast_mut());
}

#[test]
fn empty_and_not_found_values_replace_every_output_field_on_success() {
    let mut raw = poisoned_value();
    let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_empty();
    output.publish_success();
    assert_found(&raw, b"", true, ptr::null_mut());

    let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_empty_uncached();
    output.publish_success();
    assert_found(&raw, b"", false, ptr::null_mut());

    let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
    output.set_not_found();
    output.publish_success();
    assert_not_found(&raw);
}

#[test]
fn setter_errors_preserve_the_previous_candidate() {
    let mut raw = poisoned_value();
    let mut output = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
    let data = NonNull::<u8>::dangling().as_ptr();

    output.set_found(StreamVariableOutput::MAX_LEN, data, true).unwrap();
    assert_eq!(raw.len(), 17);
    assert_eq!(
        output.set_found(StreamVariableOutput::MAX_LEN + 1, data, true),
        Err(StreamVariableOutputError::TooLong)
    );
    assert_eq!(
        output.set_found(1, ptr::null_mut(), false),
        Err(StreamVariableOutputError::NullData)
    );

    output.publish_success();
    assert_eq!(raw.len() as usize, StreamVariableOutput::MAX_LEN);
    assert_eq!(raw.data, data);
    assert_eq!(raw.valid(), 1);
    assert_eq!(raw.no_cacheable(), 0);
    assert_eq!(raw.not_found(), 0);
    assert_eq!(raw.escape(), 0);
}

#[test]
fn successful_publication_initializes_uninitialized_storage() {
    let mut raw = MaybeUninit::<ngx_variable_value_t>::uninit();
    let mut output = unsafe { StreamVariableOutput::from_raw(raw.as_mut_ptr()) }.unwrap();

    output.set_empty();
    output.publish_success();

    let raw = unsafe { raw.assume_init() };
    assert_found(&raw, b"", true, ptr::null_mut());
}

#[cfg(feature = "test-link")]
#[test]
fn session_pool_values_replace_every_output_field() {
    let owner = TestPool::new();

    with_session(&owner, |session| {
        let mut raw = poisoned_value();
        let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        let bytes = StreamVariablePoolBytes::copy_from_session(&*session, b"pool").unwrap();
        let data = bytes.data.as_ptr();
        assert_eq!(bytes.bytes(), b"pool");
        assert_ne!(data, b"pool".as_ptr().cast_mut());

        value.set_pool(&*session, bytes).unwrap();
        value.publish_success();
        assert_found(&raw, b"pool", true, data);

        let bytes =
            StreamVariablePoolBytes::copy_from_session(&*session, b"uncached-pool").unwrap();
        let data = bytes.data.as_ptr();
        let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        value.set_pool_uncached(&*session, bytes).unwrap();
        value.publish_success();
        assert_found(&raw, b"uncached-pool", false, data);
    });
}

#[cfg(feature = "test-link")]
#[test]
fn copied_session_values_replace_every_output_field() {
    let owner = TestPool::new();

    with_session(&owner, |session| {
        let mut raw = poisoned_value();
        let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        let copied = *b"copied";

        value.copy_from_session(&*session, &copied).unwrap();
        value.publish_success();
        assert_ne!(raw.data, copied.as_ptr().cast_mut());
        assert_found(&raw, &copied, true, raw.data);

        let uncached = *b"uncached";
        let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        value.copy_from_session_uncached(&*session, &uncached).unwrap();
        value.publish_success();
        assert_ne!(raw.data, uncached.as_ptr().cast_mut());
        assert_found(&raw, &uncached, false, raw.data);

        let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        value.copy_from_session(&*session, b"").unwrap();
        value.publish_success();
        assert_found(&raw, b"", true, ptr::null_mut());
    });
}

#[cfg(feature = "test-link")]
#[test]
fn foreign_session_pool_bytes_do_not_publish_an_output() {
    let current_owner = TestPool::new();
    let foreign_owner = TestPool::new();
    let mut current_connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    current_connection.pool = current_owner.raw;
    let mut foreign_connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    foreign_connection.pool = foreign_owner.raw;
    let mut current = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    current.connection = &raw mut *current_connection;
    let mut foreign = unsafe { MaybeUninit::<ngx_stream_session_t>::zeroed().assume_init() };
    foreign.connection = &raw mut *foreign_connection;

    unsafe {
        Session::with_raw(&raw mut current, |current| {
            Session::with_raw(&raw mut foreign, |foreign| {
                let bytes =
                    StreamVariablePoolBytes::copy_from_session(&foreign, b"foreign").unwrap();
                let mut raw = poisoned_value();
                let mut value = StreamVariableOutput::from_raw(&raw mut raw).unwrap();
                let before = (
                    raw.len(),
                    raw.valid(),
                    raw.no_cacheable(),
                    raw.not_found(),
                    raw.escape(),
                    raw.data,
                );

                assert_eq!(
                    value.set_pool(&current, bytes),
                    Err(StreamVariableOutputError::PoolMismatch)
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
            })
            .unwrap();
        })
        .unwrap();
    }
}

#[cfg(feature = "test-link")]
#[test]
fn allocation_failure_does_not_publish_partial_output() {
    let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
    let owner = TestPool::new();
    unsafe { (*owner.raw).max = 0 };

    with_session(&owner, |session| {
        let mut raw = poisoned_value();
        let mut value = unsafe { StreamVariableOutput::from_raw(&raw mut raw) }.unwrap();
        let before =
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data);

        unsafe { ngx_rs_test_fail_allocations_after(0) };
        let result = value.copy_from_session(&*session, b"copied");
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert_eq!(result, Err(StreamVariableOutputError::Allocation));
        assert_eq!(
            (raw.len(), raw.valid(), raw.no_cacheable(), raw.not_found(), raw.escape(), raw.data,),
            before
        );
    });
}
