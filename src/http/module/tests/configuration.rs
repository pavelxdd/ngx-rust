use super::*;

#[test]
fn default_configuration_hooks_reject_null_and_misaligned_parser_contexts() {
    assert_eq!(unsafe { preconfiguration::<TestHttpModule>(ptr::null_mut()) }, Status::NGX_ERROR.0);
    assert_eq!(
        unsafe { postconfiguration::<TestHttpModule>(ptr::null_mut()) },
        Status::NGX_ERROR.0
    );

    let misaligned = ptr::without_provenance_mut::<ngx_conf_t>(1);
    assert_eq!(unsafe { preconfiguration::<TestHttpModule>(misaligned) }, Status::NGX_ERROR.0);
    assert_eq!(unsafe { postconfiguration::<TestHttpModule>(misaligned) }, Status::NGX_ERROR.0);

    let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
    assert_eq!(
        unsafe { preconfiguration::<TestHttpModule>(&raw mut configuration) },
        Status::NGX_OK.0
    );
    assert_eq!(
        unsafe { postconfiguration::<TestHttpModule>(&raw mut configuration) },
        Status::NGX_OK.0
    );
}

#[test]
fn configuration_callbacks_reject_null_misaligned_and_aliasing_values() {
    assert!(unsafe { TestHttpModule::create_main_conf(ptr::null_mut()) }.is_null());
    assert!(unsafe { TestHttpModule::create_srv_conf(ptr::null_mut()) }.is_null());
    assert!(unsafe { TestHttpModule::create_loc_conf(ptr::null_mut()) }.is_null());

    let misaligned = ptr::without_provenance_mut::<ngx_conf_t>(1);
    assert!(unsafe { TestHttpModule::create_main_conf(misaligned) }.is_null());
    assert!(unsafe { TestHttpModule::create_srv_conf(misaligned) }.is_null());
    assert!(unsafe { TestHttpModule::create_loc_conf(misaligned) }.is_null());

    let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
    let mut main = MainConf::default();
    assert_eq!(
        unsafe {
            TestHttpModule::init_main_conf(ptr::without_provenance_mut(1), (&raw mut main).cast())
        },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe { TestHttpModule::init_main_conf(&raw mut parser, ptr::null_mut()) },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe {
            TestHttpModule::init_main_conf(
                &raw mut parser,
                ptr::without_provenance_mut::<c_void>(1),
            )
        },
        NGX_CONF_ERROR
    );

    let mut server = ServerConf::default();
    assert_eq!(
        unsafe {
            TestHttpModule::merge_srv_conf(
                &raw mut parser,
                ptr::null_mut(),
                (&raw mut server).cast(),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe {
            TestHttpModule::merge_srv_conf(
                &raw mut parser,
                (&raw mut server).cast(),
                ptr::null_mut(),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe {
            TestHttpModule::merge_srv_conf(
                &raw mut parser,
                ptr::without_provenance_mut(1),
                (&raw mut server).cast(),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe {
            TestHttpModule::merge_srv_conf(
                &raw mut parser,
                (&raw mut server).cast(),
                (&raw mut server).cast(),
            )
        },
        NGX_CONF_ERROR
    );

    let mut location = LocationConf::default();
    assert_eq!(
        unsafe {
            TestHttpModule::merge_loc_conf(
                &raw mut parser,
                ptr::null_mut(),
                (&raw mut location).cast(),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe {
            TestHttpModule::merge_loc_conf(
                &raw mut parser,
                (&raw mut location).cast(),
                ptr::null_mut(),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe {
            TestHttpModule::merge_loc_conf(
                &raw mut parser,
                (&raw mut location).cast(),
                ptr::without_provenance_mut(1),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(
        unsafe {
            TestHttpModule::merge_loc_conf(
                &raw mut parser,
                (&raw mut location).cast(),
                (&raw mut location).cast(),
            )
        },
        NGX_CONF_ERROR
    );
}

#[test]
fn main_initialization_and_server_location_merges_update_values() {
    let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
    let mut main = MainConf::default();
    assert!(
        unsafe { TestHttpModule::init_main_conf(&raw mut parser, (&raw mut main).cast()) }
            .is_null()
    );
    assert!(main.initialized);

    let mut server_parent = ServerConf(2);
    let mut server_child = ServerConf(3);
    assert!(
        unsafe {
            TestHttpModule::merge_srv_conf(
                &raw mut parser,
                (&raw mut server_parent).cast(),
                (&raw mut server_child).cast(),
            )
        }
        .is_null()
    );
    assert_eq!(server_child.0, 5);

    let mut location_parent = LocationConf(5);
    let mut location_child = LocationConf(8);
    assert!(
        unsafe {
            TestHttpModule::merge_loc_conf(
                &raw mut parser,
                (&raw mut location_parent).cast(),
                (&raw mut location_child).cast(),
            )
        }
        .is_null()
    );
    assert_eq!(location_child.0, 13);
}

#[cfg(feature = "test-link")]
#[test]
fn main_initialization_logs_no_value_once_and_returns_the_silent_sentinel() {
    let mut pool = TestPool::new();
    let mut capture = ConfigLogCapture::default();
    pool._log.log_level = NGX_LOG_EMERG as _;
    pool._log.writer = Some(capture_config_log);
    pool._log.wdata = (&raw mut capture).cast();
    let mut parser = pool.configuration();
    let mut configuration = RejectMainConf;

    assert_eq!(
        unsafe {
            RejectMainModule::init_main_conf(&raw mut parser, (&raw mut configuration).cast())
        },
        NGX_CONF_ERROR
    );
    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.records[0].0, NGX_LOG_EMERG as _);
    assert!(
        capture.records[0]
            .1
            .windows(b"failed to initialize main configuration: no value".len())
            .any(|message| message == b"failed to initialize main configuration: no value")
    );
}

#[cfg(feature = "test-link")]
#[test]
fn server_and_location_merges_log_messages_once_and_return_the_silent_sentinel() {
    let mut pool = TestPool::new();
    let mut capture = ConfigLogCapture::default();
    pool._log.log_level = NGX_LOG_EMERG as _;
    pool._log.writer = Some(capture_config_log);
    pool._log.wdata = (&raw mut capture).cast();
    let mut parser = pool.configuration();
    let mut server_parent = RejectServerConf;
    let mut server_child = RejectServerConf;
    assert_eq!(
        unsafe {
            RejectServerModule::merge_srv_conf(
                &raw mut parser,
                (&raw mut server_parent).cast(),
                (&raw mut server_child).cast(),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.records[0].0, NGX_LOG_EMERG as _);
    assert!(
        capture.records[0]
            .1
            .windows(b"failed to merge server configuration: server rejected".len())
            .any(|message| message == b"failed to merge server configuration: server rejected")
    );

    capture.records.clear();
    let mut location_parent = RejectLocationConf;
    let mut location_child = RejectLocationConf;
    assert_eq!(
        unsafe {
            RejectLocationModule::merge_loc_conf(
                &raw mut parser,
                (&raw mut location_parent).cast(),
                (&raw mut location_child).cast(),
            )
        },
        NGX_CONF_ERROR
    );
    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.records[0].0, NGX_LOG_EMERG as _);
    assert!(
        capture.records[0]
            .1
            .windows(b"failed to merge location configuration: location rejected".len())
            .any(|message| message == b"failed to merge location configuration: location rejected")
    );
}

#[cfg(feature = "test-link")]
#[test]
fn configuration_pool_owns_main_server_and_location_values_once() {
    MAIN_CONF_DROPS.store(0, Ordering::Relaxed);
    SERVER_CONF_DROPS.store(0, Ordering::Relaxed);
    LOCATION_CONF_DROPS.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut configuration = pool.configuration();

    let main = unsafe { AllocationHttpModule::create_main_conf(&raw mut configuration) };
    let server = unsafe { AllocationHttpModule::create_srv_conf(&raw mut configuration) };
    let location = unsafe { AllocationHttpModule::create_loc_conf(&raw mut configuration) };
    assert!(!main.is_null());
    assert!(!server.is_null());
    assert!(!location.is_null());
    assert!(!unsafe { (*main.cast::<AllocatedMainConf>()).initialized });
    assert!(
        unsafe { AllocationHttpModule::init_main_conf(&raw mut configuration, main) }.is_null()
    );
    assert!(unsafe { (*main.cast::<AllocatedMainConf>()).initialized });
    assert_eq!(MAIN_CONF_DROPS.load(Ordering::Relaxed), 0);
    assert_eq!(SERVER_CONF_DROPS.load(Ordering::Relaxed), 0);
    assert_eq!(LOCATION_CONF_DROPS.load(Ordering::Relaxed), 0);

    drop(pool);
    assert_eq!(MAIN_CONF_DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(SERVER_CONF_DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(LOCATION_CONF_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn cleanup_rejection_does_not_publish_configuration() {
    let pool = TestPool::new();
    let mut configuration = pool.configuration();
    let cleanup = unsafe { (*pool.raw).cleanup };

    assert!(unsafe { OverAlignedHttpModule::create_main_conf(&raw mut configuration) }.is_null());
    assert!(unsafe { OverAlignedHttpModule::create_srv_conf(&raw mut configuration) }.is_null());
    assert!(unsafe { OverAlignedHttpModule::create_loc_conf(&raw mut configuration) }.is_null());
    assert_eq!(unsafe { (*pool.raw).cleanup }, cleanup);
}

#[cfg(feature = "test-link")]
#[test]
fn cleanup_allocation_failure_does_not_publish_configuration() {
    let pool = TestPool::new();
    let mut configuration = pool.configuration();
    let cleanup = unsafe { (*pool.raw).cleanup };
    unsafe { (*pool.raw).max = 0 };

    for successes in 0..=1 {
        unsafe { ngx_rs_test_fail_allocations_after(successes) };
        let main = unsafe { AllocationHttpModule::create_main_conf(&raw mut configuration) };
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert!(main.is_null());
        assert_eq!(unsafe { (*pool.raw).cleanup }, cleanup);
    }
}
