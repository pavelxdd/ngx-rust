use super::*;

#[cfg(feature = "test-link")]
#[test]
fn exact_registration_rejects_prefix_flags() {
    let mut fixture = VariableFixture::new();
    let name = NgxStr::from_bytes(b"ngx_rs_rejected_prefix_");
    let prefix_count = fixture.configuration.prefix_variables().len();

    assert!(
        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            name,
            HttpVariableFlags::PREFIX,
            1,
        )
        .is_err()
    );
    assert!(
        add_variable_with_setter::<CountingVariable, CountingSetter>(
            &mut fixture.configuration(),
            name,
            HttpVariableFlags::PREFIX,
            1,
        )
        .is_err()
    );
    assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);
}

#[cfg(feature = "test-link")]
#[test]
fn add_variable_supports_every_public_flag_and_preserves_name_bytes() {
    let mut fixture = VariableFixture::new();
    let cases: [(&[u8], &[u8], HttpVariableFlags, usize); 5] = [
        (b"ngx_rs_changeable", b"ngx_rs_changeable", HttpVariableFlags::CHANGEABLE, 0),
        (b"ngx_rs_nocacheable", b"ngx_rs_nocacheable", HttpVariableFlags::NOCACHEABLE, usize::MAX),
        (b"ngx_rs_nohash", b"ngx_rs_nohash", HttpVariableFlags::NOHASH, 8),
        (b"ngx_rs_weak", b"ngx_rs_weak", HttpVariableFlags::WEAK, 16),
        (
            b"NgX_Rs_\xFF",
            b"ngx_rs_\xFF",
            HttpVariableFlags::NOCACHEABLE | HttpVariableFlags::NOHASH,
            42,
        ),
    ];

    for (name, lower_name, flags, data) in cases {
        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(name),
            flags,
            data,
        )
        .unwrap();
        let variable = fixture.configuration.exact_variable(lower_name);
        assert_eq!(variable.flags, flags.bits());
        assert_handler::<CountingVariable>(variable, data);
    }

    add_prefix_variable::<CountingPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"NgX_Rs_PrEfIx_"),
        HttpVariableFlags::CHANGEABLE,
    )
    .unwrap();
    let prefix = fixture.configuration.prefix_variable(b"ngx_rs_prefix_");
    assert_eq!(prefix.flags, (HttpVariableFlags::PREFIX | HttpVariableFlags::CHANGEABLE).bits());
    assert_prefix_handler::<CountingPrefixVariable>(prefix);
}

#[cfg(feature = "test-link")]
#[test]
fn add_variable_with_setter_installs_both_typed_handlers() {
    let mut fixture = VariableFixture::new();
    let calls = AtomicUsize::new(0);
    let data = (&raw const calls).cast::<AtomicUsize>() as usize;
    let name = b"ngx_rs_setter";

    add_variable_with_setter::<CountingVariable, CountingSetter>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(name),
        HttpVariableFlags::CHANGEABLE,
        data,
    )
    .unwrap();
    let variable = fixture.configuration.exact_variable(name);
    assert_eq!(variable.flags, HttpVariableFlags::CHANGEABLE.bits());
    assert_handler::<CountingVariable>(variable, data);
    let setter = variable.set_handler.unwrap();

    let mut value = unsafe { MaybeUninit::<ngx_variable_value_t>::zeroed().assume_init() };
    fixture.configuration.with_request(|request| {
        unsafe { setter(request.as_ptr(), &raw mut value, data) };
    });

    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn read_only_redefinition_clears_an_existing_setter() {
    let mut fixture = VariableFixture::new();
    let name = b"ngx_rs_replaced_setter";

    add_variable_with_setter::<CountingVariable, CountingSetter>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(name),
        HttpVariableFlags::CHANGEABLE,
        1,
    )
    .unwrap();
    assert!(fixture.configuration.exact_variable(name).set_handler.is_some());

    add_variable::<DataVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(name),
        HttpVariableFlags::CHANGEABLE,
        2,
    )
    .unwrap();

    let variable = fixture.configuration.exact_variable(name);
    assert_handler::<DataVariable>(variable, 2);
    assert!(variable.set_handler.is_none());
}

#[cfg(feature = "test-link")]
#[test]
fn add_variable_preserves_registration_order() {
    let mut fixture = VariableFixture::new();
    let names: [&[u8]; 3] = [b"ngx_rs_order_one", b"ngx_rs_order_two", b"ngx_rs_order_three"];

    for (index, name) in names.iter().enumerate() {
        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(name),
            HttpVariableFlags::empty(),
            index,
        )
        .unwrap();
    }

    let mut positions = [usize::MAX; 3];
    for (index, key) in fixture.configuration.exact_variables().iter().enumerate() {
        for (name_index, name) in names.iter().enumerate() {
            if key.key.as_bytes() == *name {
                positions[name_index] = index;
            }
        }
    }

    assert!(positions.iter().all(|position| *position != usize::MAX));
    assert!(positions[0] < positions[1]);
    assert!(positions[1] < positions[2]);
}

#[cfg(feature = "test-link")]
#[test]
fn rejected_registration_preserves_existing_handler_state() {
    let mut fixture = VariableFixture::new();
    let name = b"ngx_rs_rejected";
    add_variable::<CountingVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(name),
        HttpVariableFlags::empty(),
        0,
    )
    .unwrap();
    let before = fixture.configuration.exact_variable(name);
    let before_handler = before.get_handler;
    let before_flags = before.flags;
    let before_data = before.data;
    let exact_count = fixture.configuration.exact_variables().len();
    let prefix_count = fixture.configuration.prefix_variables().len();

    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_ReJeCtEd"),
            HttpVariableFlags::empty(),
            usize::MAX,
        )
        .is_err()
    );
    let after = fixture.configuration.exact_variable(name);
    assert!(same_handler(before_handler, after.get_handler));
    assert_eq!(after.flags, before_flags);
    assert_eq!(after.data, before_data);
    assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
    assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);

    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b""),
            HttpVariableFlags::empty(),
            1,
        )
        .is_err()
    );
    assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
    assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);

    let internal = HttpVariableFlags::from_bits_retain(NGX_HTTP_VAR_INDEXED as _);
    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_internal"),
            internal,
            2,
        )
        .is_err()
    );
    let unknown = HttpVariableFlags::from_bits_retain(1_usize << (usize::BITS - 1));
    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_unknown"),
            unknown,
            3,
        )
        .is_err()
    );
    assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
    assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);
}

#[cfg(feature = "test-link")]
#[test]
fn allocation_failure_does_not_publish_a_variable_handler() {
    let mut fixture = VariableFixture::new();
    let exact_count = fixture.configuration.exact_variables().len();
    let prefix_count = fixture.configuration.prefix_variables().len();

    unsafe {
        (*fixture.pool.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let result = add_variable::<DataVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_registration_allocation_failure"),
        HttpVariableFlags::empty(),
        1,
    );
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert!(result.is_err());
    assert_eq!(fixture.configuration.exact_variables().len(), exact_count);
    assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);
}

#[cfg(feature = "test-link")]
#[test]
fn post_push_prefix_name_allocation_failure_rolls_back_entry() {
    let mut fixture = VariableFixture::new();
    let prefix_count = fixture.configuration.prefix_variables().len();
    let prefix_capacity = fixture.configuration.main.prefix_variables.nalloc;
    let prefix_storage = fixture.configuration.main.prefix_variables.elts;
    assert!(prefix_count < prefix_capacity);

    unsafe {
        (*fixture.pool.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let result = add_prefix_variable::<DataPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_prefix_allocation_failure_"),
        HttpVariableFlags::empty(),
    );
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert!(result.is_err());
    assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count);
    assert_eq!(fixture.configuration.main.prefix_variables.nalloc, prefix_capacity);
    assert_eq!(fixture.configuration.main.prefix_variables.elts, prefix_storage);

    add_prefix_variable::<CountingPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_prefix_allocation_failure_"),
        HttpVariableFlags::empty(),
    )
    .unwrap();
    let index = get_variable_index(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_prefix_allocation_failure_suffix"),
    )
    .unwrap();
    assert_eq!(fixture.configuration.prefix_variables().len(), prefix_count + 1);
    assert_prefix_handler::<CountingPrefixVariable>(
        fixture.configuration.prefix_variable(b"ngx_rs_prefix_allocation_failure_"),
    );
    fixture.configuration.finalize_variables();
    fixture.configuration.with_request(|request| {
        assert_eq!(index.get_cached(request).unwrap().bytes(), Some(&b""[..]));
    });
}

#[cfg(feature = "test-link")]
#[test]
fn add_variable_keeps_nginx_duplicate_changeable_and_weak_rules() {
    let mut fixture = VariableFixture::new();
    let exact_name = b"ngx_rs_changeable_weak";
    let weak_flags = HttpVariableFlags::CHANGEABLE | HttpVariableFlags::WEAK;

    add_variable::<CountingVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(exact_name),
        weak_flags,
        1,
    )
    .unwrap();
    let variable = fixture.configuration.exact_variable(exact_name);
    assert_eq!(variable.flags, weak_flags.bits());
    assert_handler::<CountingVariable>(variable, 1);

    add_variable::<DataVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"NgX_Rs_ChAnGeAbLe_WeAk"),
        weak_flags,
        2,
    )
    .unwrap();
    let variable = fixture.configuration.exact_variable(exact_name);
    assert_eq!(variable.flags, weak_flags.bits());
    assert_handler::<DataVariable>(variable, 2);

    add_variable::<TestVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(exact_name),
        HttpVariableFlags::CHANGEABLE,
        usize::MAX,
    )
    .unwrap();
    let variable = fixture.configuration.exact_variable(exact_name);
    assert_eq!(variable.flags, HttpVariableFlags::CHANGEABLE.bits());
    assert_handler::<TestVariable>(variable, usize::MAX);

    let prefix_name = b"ngx_rs_prefix_weak_";
    add_prefix_variable::<CountingPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(prefix_name),
        weak_flags,
    )
    .unwrap();
    add_prefix_variable::<DataPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"NgX_Rs_PrEfIx_WeAk_"),
        HttpVariableFlags::CHANGEABLE,
    )
    .unwrap();
    let prefix = fixture.configuration.prefix_variable(prefix_name);
    assert_eq!(prefix.flags, (HttpVariableFlags::CHANGEABLE | HttpVariableFlags::PREFIX).bits());
    assert_prefix_handler::<DataPrefixVariable>(prefix);
}
