use super::*;

#[test]
fn http_module_type_is_required() {
    let module = ngx_module_t::default();

    assert!(matches!(
        module_indexes(ModuleDescriptor::from_test(module), 2, 1),
        Err(HttpConfigError::WrongModuleType)
    ));
}

#[cfg(feature = "test-link")]
#[test]
fn native_assignment_keeps_the_opaque_http_descriptor_reload_safe() {
    let _guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
    let child = unsafe { fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        unsafe { _exit(if native_http_module_lifecycle_succeeds() { 0 } else { 1 }) };
    }

    let mut status = 0;
    assert_eq!(unsafe { waitpid(child, &raw mut status, 0) }, child);
    assert_eq!(status, 0);
}

#[test]
fn module_index_requires_assignment_and_available_global_slot() {
    let mut module = http_module(ngx_uint_t::MAX, 0);

    assert!(matches!(
        module_indexes(ModuleDescriptor::from_test(module), 2, 1),
        Err(HttpConfigError::UnsetModuleIndex)
    ));

    module.index = 2;
    assert!(matches!(
        module_indexes(ModuleDescriptor::from_test(module), 2, 1),
        Err(HttpConfigError::ModuleIndexOutOfBounds)
    ));

    module.index = 3;
    assert!(matches!(
        module_indexes(ModuleDescriptor::from_test(module), 2, 1),
        Err(HttpConfigError::ModuleIndexOutOfBounds)
    ));

    module.index = 0;
    assert!(module_indexes(ModuleDescriptor::from_test(module), 1, 1).is_ok());
}

#[test]
fn context_index_requires_assignment_and_available_http_slot() {
    let mut module = http_module(0, ngx_uint_t::MAX);

    assert!(matches!(
        module_indexes(ModuleDescriptor::from_test(module), 1, 1),
        Err(HttpConfigError::UnsetContextIndex)
    ));

    module.ctx_index = 1;
    assert!(matches!(
        module_indexes(ModuleDescriptor::from_test(module), 1, 1),
        Err(HttpConfigError::ContextIndexOutOfBounds)
    ));

    module.ctx_index = 2;
    assert!(matches!(
        module_indexes(ModuleDescriptor::from_test(module), 1, 1),
        Err(HttpConfigError::ContextIndexOutOfBounds)
    ));

    module.ctx_index = 0;
    assert!(module_indexes(ModuleDescriptor::from_test(module), 1, 1).is_ok());
}

#[cfg(feature = "test-link")]
#[test]
fn parser_rejects_wrong_module_type_before_reading_a_slot() {
    let _globals = HttpGlobals::new(1, 1);
    let mut value = 42_u32;
    let mut slots: [*mut c_void; 1] = [(&raw mut value).cast()];
    let mut context = ngx_http_conf_ctx_t {
        main_conf: slots.as_mut_ptr(),
        srv_conf: ptr::null_mut(),
        loc_conf: ptr::null_mut(),
    };
    let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
    configuration.ctx = (&raw mut context).cast();
    let parser = HttpConfigurationParser::from_test_callback(&mut configuration);

    assert_eq!(WrongTypeModule::main_conf(&parser), Err(HttpConfigError::WrongModuleType));
}

#[cfg(feature = "test-link")]
#[test]
fn parser_checks_callback_pointer_and_http_context() {
    assert_eq!(
        unsafe { HttpConfigurationParser::with_raw(ptr::null_mut(), |_| Status::NGX_OK.0) },
        Err(HttpConfigError::NullConfiguration)
    );
    assert_eq!(
        unsafe {
            HttpConfigurationParser::with_raw(ptr::without_provenance_mut(1), |_| Status::NGX_OK.0)
        },
        Err(HttpConfigError::MisalignedConfiguration)
    );

    let _globals = HttpGlobals::new(2, 1);
    let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
    assert_eq!(
        unsafe {
            HttpConfigurationParser::with_raw(&raw mut configuration, |parser| {
                TestHttpModule::main_conf(parser).map(|value| value.copied())
            })
        },
        Ok(Ok(None))
    );

    configuration.ctx = ptr::without_provenance_mut(1);
    assert_eq!(
        unsafe {
            HttpConfigurationParser::with_raw(&raw mut configuration, |parser| {
                TestHttpModule::main_conf(parser).map(|value| value.copied())
            })
        },
        Ok(Err(HttpConfigError::MisalignedContext))
    );
}

#[cfg(feature = "test-link")]
#[test]
fn parser_owns_mutable_configuration_access_and_runtime_request_is_shared() {
    let _globals = HttpGlobals::new(2, 1);
    let mut main = 42_u32;
    let mut server = 99_u32;
    let mut location = 7_u32;
    let mut main_slots: [*mut c_void; 1] = [(&raw mut main).cast()];
    let mut server_slots: [*mut c_void; 1] = [(&raw mut server).cast()];
    let mut location_slots: [*mut c_void; 1] = [(&raw mut location).cast()];
    let mut context = ngx_http_conf_ctx_t {
        main_conf: main_slots.as_mut_ptr(),
        srv_conf: server_slots.as_mut_ptr(),
        loc_conf: location_slots.as_mut_ptr(),
    };
    let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
    configuration.ctx = (&raw mut context).cast();

    unsafe {
        HttpConfigurationParser::with_raw(&raw mut configuration, |parser| {
            assert_eq!(TestHttpModule::main_conf(parser).map(|value| value.copied()), Ok(Some(42)));
            assert_eq!(
                TestHttpModule::server_conf(parser).map(|value| value.copied()),
                Ok(Some(99))
            );
            assert_eq!(
                TestHttpModule::location_conf(parser).map(|value| value.copied()),
                Ok(Some(7))
            );
            *TestHttpModule::main_conf_mut(parser).unwrap().unwrap() = 1;
            *TestHttpModule::server_conf_mut(parser).unwrap().unwrap() = 2;
            *TestHttpModule::location_conf_mut(parser).unwrap().unwrap() = 3;
        })
    }
    .unwrap();

    let mut request = ngx_http_request_t {
        signature: NGX_HTTP_MODULE as _,
        main_conf: main_slots.as_mut_ptr(),
        srv_conf: server_slots.as_mut_ptr(),
        loc_conf: location_slots.as_mut_ptr(),
        ..unsafe { mem::zeroed() }
    };
    request.main = &raw mut request;
    unsafe {
        RequestRefMut::with_raw(&raw mut request, |request| {
            let request = request.view();
            assert_eq!(
                request.main_conf::<TestHttpModule>().map(|value| value.copied()),
                Ok(Some(1))
            );
            assert_eq!(
                request.server_conf::<TestHttpModule>().map(|value| value.copied()),
                Ok(Some(2))
            );
            assert_eq!(
                request.location_conf::<TestHttpModule>().map(|value| value.copied()),
                Ok(Some(3))
            );
        })
    }
    .unwrap();
}
