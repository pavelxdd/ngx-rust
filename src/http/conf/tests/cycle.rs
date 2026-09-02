use super::*;

#[cfg(feature = "test-link")]
#[test]
fn cycle_access_keeps_old_and_active_slots_explicit() {
    let globals = HttpGlobals::new(2, 1);

    assert_eq!(unsafe { TestHttpModule::with_active_main_conf(|value| *value) }, Ok(None));
    let empty_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    assert_eq!(
        unsafe { TestHttpModule::main_conf_from_cycle(&empty_cycle, 1) }
            .map(|value| value.copied()),
        Ok(None)
    );
    let mut misaligned_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    misaligned_cycle.conf_ctx = ptr::without_provenance_mut(1);
    assert_eq!(
        unsafe { TestHttpModule::main_conf_from_cycle(&misaligned_cycle, 1) }
            .map(|value| value.copied()),
        Ok(None)
    );

    let mut old_main = 11_u32;
    let mut old_slots: [*mut c_void; 1] = [(&raw mut old_main).cast()];
    let mut old_context = ngx_http_conf_ctx_t {
        main_conf: old_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut old_contexts: [*mut *mut *mut c_void; 2] =
        [(&raw mut old_context).cast(), ptr::null_mut()];
    let mut old_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    old_cycle.conf_ctx = old_contexts.as_mut_ptr();

    assert_eq!(
        unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) }.map(|value| value.copied()),
        Ok(Some(11))
    );
    assert_eq!(
        unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 0) },
        Err(HttpConfigError::ContextIndexOutOfBounds)
    );

    globals.set_http_module_index(1);
    assert_eq!(
        unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) }.map(|value| value.copied()),
        Ok(None)
    );
    globals.set_http_module_index(ngx_uint_t::MAX);
    assert_eq!(
        unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) },
        Err(HttpConfigError::UnsetHttpModuleIndex)
    );
    globals.set_http_module_index(2);
    assert_eq!(
        unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) },
        Err(HttpConfigError::HttpModuleIndexOutOfBounds)
    );
    globals.set_http_module_index(0);

    let mut active_main = 42_u32;
    let mut active_slots: [*mut c_void; 1] = [(&raw mut active_main).cast()];
    let mut active_context = ngx_http_conf_ctx_t {
        main_conf: active_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut active_contexts: [*mut *mut *mut c_void; 2] =
        [(&raw mut active_context).cast(), ptr::null_mut()];
    let mut active_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    active_cycle.conf_ctx = active_contexts.as_mut_ptr();

    globals.set_active_cycle(&raw mut active_cycle);
    assert_eq!(unsafe { TestHttpModule::with_active_main_conf(|value| *value) }, Ok(Some(42)));

    globals.set_active_cycle(&raw mut old_cycle);
    assert_eq!(unsafe { TestHttpModule::with_active_main_conf(|value| *value) }, Ok(Some(11)));
}

#[cfg(feature = "test-link")]
#[test]
fn process_callbacks_ignore_absent_http_context_before_slot_validation() {
    let _globals = HttpGlobals::new(2, 0);
    let mut contexts: [*mut *mut *mut c_void; 2] = [ptr::null_mut(), ptr::null_mut()];
    let mut cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    cycle.conf_ctx = contexts.as_mut_ptr();

    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut cycle, |cycle| {
                cycle.main_conf::<ProcessModule>().map(|value| value.copied())
            })
        },
        Ok(Ok(None))
    );
    assert_eq!(unsafe { init_process::<ProcessModule>(&raw mut cycle) }, Status::NGX_OK.0);
}

#[cfg(feature = "test-link")]
#[test]
fn process_cycle_checks_http_context_and_returns_its_main_configuration() {
    let globals = HttpGlobals::new(2, 1);
    let mut cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };

    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Ok(None))
    );

    let mut value = 42_u32;
    let mut slots: [*mut c_void; 1] = [(&raw mut value).cast()];
    let mut context = ngx_http_conf_ctx_t {
        main_conf: slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut contexts: [*mut *mut *mut c_void; 2] = [(&raw mut context).cast(), ptr::null_mut()];
    cycle.conf_ctx = contexts.as_mut_ptr();

    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Ok(Some(42)))
    );

    globals.set_http_module_type(NGX_HTTP_MODULE as _);
    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Err(HttpConfigError::WrongHttpModuleType))
    );
    globals.set_http_module_type(NGX_CORE_MODULE as _);

    globals.set_http_module_index(ngx_uint_t::MAX);
    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Err(HttpConfigError::UnsetHttpModuleIndex))
    );
    globals.set_http_module_index(2);
    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Err(HttpConfigError::HttpModuleIndexOutOfBounds))
    );
    globals.set_http_module_index(0);

    let mut missing_context_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    let mut missing_contexts: [*mut *mut *mut c_void; 2] = [ptr::null_mut(), ptr::null_mut()];
    missing_context_cycle.conf_ctx = missing_contexts.as_mut_ptr();
    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut missing_context_cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Ok(None))
    );

    let mut misaligned_context_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    let mut misaligned_contexts: [*mut *mut *mut c_void; 2] =
        [ptr::without_provenance_mut(1), ptr::null_mut()];
    misaligned_context_cycle.conf_ctx = misaligned_contexts.as_mut_ptr();
    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut misaligned_context_cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Ok(None))
    );

    let mut missing_main_context = ngx_http_conf_ctx_t {
        main_conf: ptr::null_mut(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut missing_main_contexts: [*mut *mut *mut c_void; 2] =
        [(&raw mut missing_main_context).cast(), ptr::null_mut()];
    let mut missing_main_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    missing_main_cycle.conf_ctx = missing_main_contexts.as_mut_ptr();
    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut missing_main_cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Ok(None))
    );

    let mut missing_slot: [*mut c_void; 1] = [ptr::null_mut()];
    let mut missing_slot_context = ngx_http_conf_ctx_t {
        main_conf: missing_slot.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut missing_slot_contexts: [*mut *mut *mut c_void; 2] =
        [(&raw mut missing_slot_context).cast(), ptr::null_mut()];
    let mut missing_slot_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    missing_slot_cycle.conf_ctx = missing_slot_contexts.as_mut_ptr();
    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut missing_slot_cycle, |cycle| {
                cycle.main_conf::<TestHttpModule>().map(|value| value.copied())
            })
        },
        Ok(Ok(None))
    );

    assert_eq!(
        unsafe {
            ProcessCycle::with_raw(&raw mut cycle, |cycle| {
                cycle.main_conf::<WrongTypeModule>().map(|value| value.copied())
            })
        },
        Ok(Err(HttpConfigError::WrongModuleType))
    );
}

#[cfg(feature = "test-link")]
#[test]
fn process_callbacks_keep_old_and_new_cycles_separate() {
    let globals = HttpGlobals::new(2, 1);
    PROCESS_INIT_TOTAL.store(0, Ordering::Relaxed);
    PROCESS_EXIT_TOTAL.store(0, Ordering::Relaxed);

    let mut empty_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    assert_eq!(unsafe { init_process::<ProcessModule>(&raw mut empty_cycle) }, Status::NGX_OK.0);
    unsafe { exit_process::<ProcessModule>(&raw mut empty_cycle) };
    assert_eq!(PROCESS_INIT_TOTAL.load(Ordering::Relaxed), 0);
    assert_eq!(PROCESS_EXIT_TOTAL.load(Ordering::Relaxed), 0);

    let mut old_value = 11_u32;
    let mut old_slots: [*mut c_void; 1] = [(&raw mut old_value).cast()];
    let mut old_context = ngx_http_conf_ctx_t {
        main_conf: old_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut old_contexts: [*mut *mut *mut c_void; 2] =
        [(&raw mut old_context).cast(), ptr::null_mut()];
    let mut old_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    old_cycle.conf_ctx = old_contexts.as_mut_ptr();

    let mut new_value = 42_u32;
    let mut new_slots: [*mut c_void; 1] = [(&raw mut new_value).cast()];
    let mut new_context = ngx_http_conf_ctx_t {
        main_conf: new_slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut new_contexts: [*mut *mut *mut c_void; 2] =
        [(&raw mut new_context).cast(), ptr::null_mut()];
    let mut new_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    new_cycle.conf_ctx = new_contexts.as_mut_ptr();

    globals.set_active_cycle(&raw mut new_cycle);
    assert_eq!(unsafe { init_process::<ProcessModule>(&raw mut old_cycle) }, Status::NGX_OK.0);
    assert_eq!(unsafe { init_process::<ProcessModule>(&raw mut new_cycle) }, Status::NGX_OK.0);
    unsafe { exit_process::<ProcessModule>(&raw mut old_cycle) };
    unsafe { exit_process::<ProcessModule>(&raw mut old_cycle) };
    unsafe { exit_process::<ProcessModule>(&raw mut new_cycle) };

    assert_eq!(PROCESS_INIT_TOTAL.load(Ordering::Relaxed), 53);
    assert_eq!(PROCESS_EXIT_TOTAL.load(Ordering::Relaxed), 64);
}
