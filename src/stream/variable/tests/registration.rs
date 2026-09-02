use super::*;

#[cfg(feature = "test-link")]
#[test]
fn add_variable_supports_every_public_flag_and_preserves_name_bytes() {
    let mut fixture = VariableFixture::new();
    let cases: [(&[u8], &[u8], StreamVariableFlags, usize); 5] = [
        (b"ngx_rs_changeable", b"ngx_rs_changeable", StreamVariableFlags::CHANGEABLE, 0),
        (
            b"ngx_rs_nocacheable",
            b"ngx_rs_nocacheable",
            StreamVariableFlags::NOCACHEABLE,
            usize::MAX,
        ),
        (b"ngx_rs_nohash", b"ngx_rs_nohash", StreamVariableFlags::NOHASH, 8),
        (b"ngx_rs_weak", b"ngx_rs_weak", StreamVariableFlags::WEAK, 16),
        (
            b"NgX_Rs_\xFF",
            b"ngx_rs_\xFF",
            StreamVariableFlags::NOCACHEABLE | StreamVariableFlags::NOHASH,
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
        let variable = fixture.exact_variable(lower_name);
        assert_eq!(variable.flags, flags.bits());
        assert_handler::<CountingVariable>(variable, data);
    }

    add_prefix_variable::<CountingPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"NgX_Rs_PrEfIx_"),
        StreamVariableFlags::CHANGEABLE,
    )
    .unwrap();
    let prefix = fixture.prefix_variable(b"ngx_rs_prefix_");
    assert_eq!(
        prefix.flags,
        (StreamVariableFlags::PREFIX | StreamVariableFlags::CHANGEABLE).bits()
    );
    assert_prefix_handler::<CountingPrefixVariable>(prefix);
}

#[cfg(feature = "test-link")]
#[test]
fn exact_registration_rejects_prefix_flags() {
    let mut fixture = VariableFixture::new();
    let prefix_count = fixture.prefix_variables().len();

    assert!(
        add_variable::<CountingVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_rejected_prefix_"),
            StreamVariableFlags::PREFIX,
            1,
        )
        .is_err()
    );
    assert_eq!(fixture.prefix_variables().len(), prefix_count);
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
            StreamVariableFlags::empty(),
            index,
        )
        .unwrap();
    }

    let mut positions = [usize::MAX; 3];
    for (index, key) in fixture.exact_variables().iter().enumerate() {
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
        StreamVariableFlags::empty(),
        0,
    )
    .unwrap();
    let before = fixture.exact_variable(name);
    let before_handler = before.get_handler;
    let before_flags = before.flags;
    let before_data = before.data;
    let exact_count = fixture.exact_variables().len();
    let prefix_count = fixture.prefix_variables().len();

    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"NgX_Rs_ReJeCtEd"),
            StreamVariableFlags::empty(),
            usize::MAX,
        )
        .is_err()
    );
    let after = fixture.exact_variable(name);
    assert!(same_handler(before_handler, after.get_handler));
    assert_eq!(after.flags, before_flags);
    assert_eq!(after.data, before_data);
    assert_eq!(fixture.exact_variables().len(), exact_count);
    assert_eq!(fixture.prefix_variables().len(), prefix_count);

    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b""),
            StreamVariableFlags::empty(),
            1,
        )
        .is_err()
    );
    assert_eq!(fixture.exact_variables().len(), exact_count);
    assert_eq!(fixture.prefix_variables().len(), prefix_count);

    let internal = StreamVariableFlags::from_bits_retain(NGX_STREAM_VAR_INDEXED as _);
    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_internal"),
            internal,
            2,
        )
        .is_err()
    );
    let unknown = StreamVariableFlags::from_bits_retain(1_usize << (usize::BITS - 1));
    assert!(
        add_variable::<DataVariable>(
            &mut fixture.configuration(),
            NgxStr::from_bytes(b"ngx_rs_unknown"),
            unknown,
            3,
        )
        .is_err()
    );
    assert_eq!(fixture.exact_variables().len(), exact_count);
    assert_eq!(fixture.prefix_variables().len(), prefix_count);
}

#[cfg(feature = "test-link")]
#[test]
fn allocation_failure_does_not_publish_a_variable_handler() {
    let mut fixture = VariableFixture::new();
    let exact_count = fixture.exact_variables().len();
    let prefix_count = fixture.prefix_variables().len();

    unsafe {
        (*fixture._pool.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let result = add_variable::<DataVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_allocation_failure"),
        StreamVariableFlags::empty(),
        1,
    );
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert!(result.is_err());
    assert_eq!(fixture.exact_variables().len(), exact_count);
    assert_eq!(fixture.prefix_variables().len(), prefix_count);
}

#[cfg(feature = "test-link")]
#[test]
fn post_push_prefix_name_allocation_failure_rolls_back_entry() {
    let mut fixture = VariableFixture::new();
    let prefix_count = fixture.prefix_variables().len();
    let prefix_capacity = fixture.main.prefix_variables.nalloc;
    let prefix_storage = fixture.main.prefix_variables.elts;
    assert!(prefix_count < prefix_capacity);

    unsafe {
        (*fixture._pool.raw).max = 0;
        ngx_rs_test_fail_allocations_after(0);
    }
    let result = add_prefix_variable::<DataPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_prefix_allocation_failure_"),
        StreamVariableFlags::empty(),
    );
    unsafe { ngx_rs_test_reset_allocation_failures() };

    assert!(result.is_err());
    assert_eq!(fixture.prefix_variables().len(), prefix_count);
    assert_eq!(fixture.main.prefix_variables.nalloc, prefix_capacity);
    assert_eq!(fixture.main.prefix_variables.elts, prefix_storage);

    add_prefix_variable::<CountingPrefixVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"ngx_rs_prefix_allocation_failure_"),
        StreamVariableFlags::empty(),
    )
    .unwrap();
    assert_eq!(fixture.prefix_variables().len(), prefix_count + 1);
    assert_prefix_handler::<CountingPrefixVariable>(
        fixture.prefix_variable(b"ngx_rs_prefix_allocation_failure_"),
    );
    fixture.finalize_variables();
}

#[cfg(feature = "test-link")]
#[test]
fn add_variable_keeps_nginx_duplicate_changeable_and_weak_rules() {
    let mut fixture = VariableFixture::new();
    let exact_name = b"ngx_rs_changeable_weak";
    let weak_flags = StreamVariableFlags::CHANGEABLE | StreamVariableFlags::WEAK;

    add_variable::<CountingVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(exact_name),
        weak_flags,
        1,
    )
    .unwrap();
    let variable = fixture.exact_variable(exact_name);
    assert_eq!(variable.flags, weak_flags.bits());
    assert_handler::<CountingVariable>(variable, 1);

    add_variable::<DataVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(b"NgX_Rs_ChAnGeAbLe_WeAk"),
        weak_flags,
        2,
    )
    .unwrap();
    let variable = fixture.exact_variable(exact_name);
    assert_eq!(variable.flags, weak_flags.bits());
    assert_handler::<DataVariable>(variable, 2);

    add_variable::<TestVariable>(
        &mut fixture.configuration(),
        NgxStr::from_bytes(exact_name),
        StreamVariableFlags::CHANGEABLE,
        usize::MAX,
    )
    .unwrap();
    let variable = fixture.exact_variable(exact_name);
    assert_eq!(variable.flags, StreamVariableFlags::CHANGEABLE.bits());
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
        StreamVariableFlags::CHANGEABLE,
    )
    .unwrap();
    let prefix = fixture.prefix_variable(prefix_name);
    assert_eq!(
        prefix.flags,
        (StreamVariableFlags::CHANGEABLE | StreamVariableFlags::PREFIX).bits()
    );
    assert_prefix_handler::<DataPrefixVariable>(prefix);
}
