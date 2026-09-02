use super::*;

#[test]
fn variable_index_rejects_missing_http_context() {
    let mut cf = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };

    assert_eq!(
        get_variable_index(
            &mut HttpConfigurationParser::from_test_callback(&mut cf),
            NgxStr::from_bytes(b"ngx_rs_index"),
        ),
        Err(HttpVariableIndexError::MissingCoreMainConfiguration)
    );
}

#[test]
fn indexed_lookup_rejects_missing_request_configuration() {
    let mut core = unsafe { MaybeUninit::<ngx_http_core_main_conf_t>::zeroed().assume_init() };
    let index = HttpVariableIndex {
        index: 0,
        core_main: NonNull::from(&mut core),
        _not_thread_safe: PhantomData,
    };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    request.signature = NGX_HTTP_MODULE as _;

    unsafe {
        RequestRefMut::with_raw(&raw mut request, |mut request| {
            assert!(matches!(
                index.get_cached(&mut request),
                Err(HttpVariableLookupError::Configuration(_)
                    | HttpVariableLookupError::MissingCoreMainConfiguration)
            ));
        })
    }
    .unwrap();
}

#[cfg(feature = "test-link")]
#[test]
fn indexed_lookup_preserves_nginx_cache_and_flush_semantics() {
    let mut fixture = VariableFixture::new();
    add_variable::<IndexedVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_indexed"),
        HttpVariableFlags::NOCACHEABLE,
        0,
    )
    .unwrap();
    let index =
        get_variable_index(&mut fixture.configuration(), NgxStr::from_bytes(b"ngx_rs_indexed"))
            .unwrap();
    fixture.configuration.finalize_variables();
    INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

    fixture.configuration.with_request(|request| {
        {
            let value = index.get_cached(request).unwrap();
            assert_eq!(value.bytes(), Some(&b"indexed"[..]));
            assert!(!value.is_cacheable());
        }
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);

        {
            let value = index.get_cached(request).unwrap();
            assert_eq!(value.bytes(), Some(&b"indexed"[..]));
        }
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);

        {
            let value = index.get_flushed(request).unwrap();
            assert_eq!(value.bytes(), Some(&b"indexed"[..]));
        }
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 2);
    });
}

#[cfg(feature = "test-link")]
#[test]
fn variable_cache_invalidation_refreshes_getters_but_preserves_assigned_and_excluded_values() {
    let mut fixture = VariableFixture::new();
    let definitions = [
        (b"ngx_rs_refresh".as_slice(), HttpVariableFlags::empty()),
        (b"ngx_rs_changeable_getter".as_slice(), HttpVariableFlags::CHANGEABLE),
        (b"ngx_rs_assigned".as_slice(), HttpVariableFlags::CHANGEABLE | HttpVariableFlags::WEAK),
        (b"ngx_rs_preserved".as_slice(), HttpVariableFlags::empty()),
    ];
    for (name, flags) in definitions {
        add_variable::<IndexedVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(name),
            flags,
            0,
        )
        .unwrap();
    }
    let indexes = definitions.map(|(name, _)| {
        get_variable_index(&mut fixture.configuration(), NgxStr::from_bytes(name)).unwrap()
    });
    fixture.configuration.finalize_variables();
    INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

    fixture.configuration.with_request(|request| {
        for index in &indexes {
            assert_eq!(index.get_cached(request).unwrap().bytes(), Some(&b"indexed"[..]));
        }
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 4);

        let preserved = [indexes[3]];
        let invalidation = HttpVariableCacheInvalidation::prepare(request, &preserved).unwrap();
        invalidation.commit(request).unwrap();

        assert_eq!(indexes[0].get_cached(request).unwrap().bytes(), Some(&b"indexed"[..]));
        assert_eq!(indexes[1].get_cached(request).unwrap().bytes(), Some(&b"indexed"[..]));
        assert_eq!(indexes[2].get_cached(request).unwrap().bytes(), Some(&b"indexed"[..]));
        assert_eq!(indexes[3].get_cached(request).unwrap().bytes(), Some(&b"indexed"[..]));
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 6);
    });
}

#[cfg(feature = "test-link")]
#[test]
fn indexed_getter_can_finish_a_nested_lookup_before_publishing_its_output() {
    let mut fixture = VariableFixture::new();
    add_variable::<IndexedVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_nested_inner"),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let nested_index = Box::new(
        get_variable_index(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_nested_inner"),
        )
        .unwrap(),
    );
    add_variable::<NestedVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_nested_outer"),
        HttpVariableFlags::empty(),
        nested_index.as_ref() as *const HttpVariableIndex as usize,
    )
    .unwrap();
    let outer_index = get_variable_index(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_nested_outer"),
    )
    .unwrap();
    fixture.configuration.finalize_variables();
    INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

    fixture.configuration.with_request(|request| {
        let value = outer_index.get_cached(request).unwrap();
        assert_eq!(value.bytes(), Some(&b"outer"[..]));
    });
    assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn flushed_lookup_keeps_a_cacheable_value() {
    let mut fixture = VariableFixture::new();
    add_variable::<IndexedVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_cached_index"),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let index = get_variable_index(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_cached_index"),
    )
    .unwrap();
    fixture.configuration.finalize_variables();
    INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

    fixture.configuration.with_request(|request| {
        {
            let value = index.get_flushed(request).unwrap();
            assert_eq!(value.bytes(), Some(&b"indexed"[..]));
            assert!(value.is_cacheable());
        }
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);

        {
            let value = index.get_flushed(request).unwrap();
            assert_eq!(value.bytes(), Some(&b"indexed"[..]));
        }
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);
    });
}

#[cfg(feature = "test-link")]
#[test]
fn variable_index_rejects_empty_names() {
    let mut fixture = VariableFixture::new();

    assert_eq!(
        get_variable_index(&mut fixture.configuration(), NgxStr::from_bytes(b"")),
        Err(HttpVariableIndexError::Registration)
    );
}

#[cfg(feature = "test-link")]
#[test]
fn post_push_variable_index_name_allocation_failure_rolls_back_definition() {
    let mut fixture = VariableFixture::new();
    let name = NgxStr::from_bytes(b"ngx_rs_index_allocation_failure");
    add_variable::<IndexedVariable>(
        &mut fixture.configuration(),
        name,
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();

    let variable_count = fixture.configuration.main.variables.nelts;
    assert!(fixture.configuration.main.variables.elts.is_null());

    unsafe {
        (*fixture.pool.raw).max = 0;
        ngx_rs_test_fail_allocations_after(1);
    }
    let result = get_variable_index(&mut fixture.configuration(), name);
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert_eq!(result, Err(HttpVariableIndexError::Registration));
    assert_eq!(fixture.configuration.main.variables.nelts, variable_count);
    assert!(!fixture.configuration.main.variables.elts.is_null());
    assert!(fixture.configuration.main.variables.nalloc > variable_count);

    let index = get_variable_index(&mut fixture.configuration(), name).unwrap();
    assert_eq!(index.index, variable_count);
    assert_eq!(fixture.configuration.main.variables.nelts, variable_count + 1);
    fixture.configuration.finalize_variables();
    fixture.configuration.with_request(|request| {
        assert_eq!(index.get_cached(request).unwrap().bytes(), Some(&b"indexed"[..]));
    });
}

#[cfg(feature = "test-link")]
#[test]
fn indexed_lookup_rejects_invalid_bounds_and_request_storage() {
    let mut fixture = VariableFixture::new();
    add_variable::<IndexedVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_lookup_bounds"),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let index = get_variable_index(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_lookup_bounds"),
    )
    .unwrap();
    fixture.configuration.finalize_variables();

    let mut out_of_bounds = index;
    out_of_bounds.index = fixture.configuration.main.variables.nelts;
    fixture.configuration.with_request(|request| {
        assert!(matches!(
            out_of_bounds.get_cached(request),
            Err(HttpVariableLookupError::IndexOutOfBounds)
        ));
    });

    fixture.configuration.with_request_variables(ptr::null_mut(), |request| {
        assert!(matches!(
            index.get_cached(request),
            Err(HttpVariableLookupError::MissingRequestVariables)
        ));
    });

    let mut storage = [0_u8;
        core::mem::size_of::<ngx_variable_value_t>()
            + core::mem::align_of::<ngx_variable_value_t>()];
    let variables = misaligned_ptr::<ngx_variable_value_t>(&mut storage);
    fixture.configuration.with_request_variables(variables, |request| {
        assert!(matches!(
            index.get_cached(request),
            Err(HttpVariableLookupError::MisalignedRequestVariables)
        ));
    });
}

#[cfg(feature = "test-link")]
#[test]
fn indexed_lookup_rejects_invalid_definition_handlers() {
    let mut fixture = VariableFixture::new();
    add_variable::<IndexedVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_missing_handler"),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let index = get_variable_index(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_missing_handler"),
    )
    .unwrap();
    fixture.configuration.finalize_variables();

    fixture.configuration.indexed_variable_mut(index.index).get_handler = None;
    fixture.configuration.with_request(|request| {
        assert!(matches!(index.get_cached(request), Err(HttpVariableLookupError::MissingHandler)));
    });
}

#[cfg(feature = "test-link")]
#[test]
fn indexed_lookup_maps_a_failed_native_getter_to_a_null_result() {
    let mut fixture = VariableFixture::new();
    add_variable::<FailingVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_failed_index"),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let index = get_variable_index(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_failed_index"),
    )
    .unwrap();
    fixture.configuration.finalize_variables();

    fixture.configuration.with_request(|request| {
        assert!(matches!(index.get_cached(request), Err(HttpVariableLookupError::NullResult)));
    });
}

#[cfg(feature = "test-link")]
#[test]
fn variable_indexes_are_recreated_for_a_reload_configuration() {
    let mut fixture = VariableFixture::new();
    add_variable::<IndexedVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let old_index = get_variable_index(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
    )
    .unwrap();

    let mut reloaded = VariableConfiguration::new(&mut fixture.pool);
    add_variable::<IndexedVariable>(
        &mut reloaded.configuration(),
        NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let new_index = get_variable_index(
        &mut reloaded.configuration(),
        NgxStr::from_bytes(b"ngx_rs_reloaded_index"),
    )
    .unwrap();
    reloaded.finalize_variables();
    INDEXED_VARIABLE_CALLS.store(0, Ordering::Relaxed);

    reloaded.with_request(|request| {
        assert!(matches!(
            old_index.get_cached(request),
            Err(HttpVariableLookupError::ForeignConfiguration)
        ));

        {
            let value = new_index.get_cached(request).unwrap();
            assert_eq!(value.bytes(), Some(&b"indexed"[..]));
        }
        assert_eq!(INDEXED_VARIABLE_CALLS.load(Ordering::Relaxed), 1);
    });
}
