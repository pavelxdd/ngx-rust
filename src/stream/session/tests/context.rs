use super::*;

#[cfg(feature = "test-link")]
#[test]
fn session_access_reports_missing_slots_and_module_index_errors() {
    let _globals = StreamGlobals::new();
    let mut raw = zeroed_session();

    unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            assert!(matches!(session.connection(), Err(ConnectionError::NullConnection)));
            assert_eq!(
                session.main_conf::<TestContextModule>().map(|value| value.copied()),
                Ok(None)
            );
            assert_eq!(
                session.server_conf::<TestContextModule>().map(|value| value.copied()),
                Ok(None)
            );
            assert!(matches!(session.module_context::<PoolContextModule>(), Ok(None)));
            assert!(matches!(
                session
                    .get_or_insert_module_context_with::<PoolContextModule>(|| { TestContext(42) }),
                Err(SessionContextError::MissingSlots)
            ));
            assert!(matches!(
                session.module_context::<OutOfBoundsContextModule>(),
                Err(SessionContextError::Configuration(StreamConfigError::ModuleIndexOutOfBounds))
            ));
        })
    }
    .unwrap();
}

#[cfg(feature = "test-link")]
#[test]
fn context_cleanup_registration_failure_does_not_publish_a_slot() {
    let _globals = StreamGlobals::new();
    let owner = TestPool::new();
    let cleanup = unsafe { (*owner.raw).cleanup };
    unsafe { (*owner.raw).max = 0 };
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_session();
    raw.connection = &raw mut *connection;
    raw.ctx = contexts.as_mut_ptr();

    for successes in 0..=1 {
        unsafe { ngx_rs_test_fail_allocations_after(successes) };
        let result = unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                session
                    .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                    .map(|_| ())
            })
        };
        unsafe { ngx_rs_test_reset_allocation_failures() };

        assert!(matches!(result, Ok(Err(SessionContextError::Allocation))));
        assert!(contexts[0].is_null());
        assert_eq!(unsafe { (*owner.raw).cleanup }, cleanup);
    }
}

#[cfg(feature = "test-link")]
#[test]
fn pinned_context_reuses_its_stable_pool_address() {
    let _globals = StreamGlobals::new();
    PINNED_CONTEXT_DROPS.store(0, Ordering::Relaxed);
    let owner = TestPool::new();
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_session();
    raw.connection = &raw mut *connection;
    raw.ctx = contexts.as_mut_ptr();

    let address = unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            let address = {
                let mut context = session
                    .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                        PinnedContext { value: 42, _pin: PhantomPinned }
                    })
                    .unwrap();
                let address = NonNull::from(context.as_ref().get_ref()).as_ptr();
                context.as_mut().get_unchecked_mut().value = 99;
                address
            };

            let context =
                session.pinned_module_context_mut::<PinnedContextModule>().unwrap().unwrap();
            assert_eq!(NonNull::from(context.as_ref().get_ref()).as_ptr(), address);
            assert_eq!(context.as_ref().get_ref().value, 99);
            address
        })
    }
    .unwrap();

    assert_eq!(contexts[0], address.cast());
    drop(owner);
    assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn failed_context_cleanup_unlink_restores_the_slot() {
    let _globals = StreamGlobals::new();
    CONTEXT_DROPS.store(0, Ordering::Relaxed);
    let owner = TestPool::new();
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_session();
    raw.connection = &raw mut *connection;
    raw.ctx = contexts.as_mut_ptr();

    unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            session
                .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                .unwrap();
        })
    }
    .unwrap();

    let context = contexts[0];
    let cleanup = unsafe { (*owner.raw).cleanup };
    assert!(!cleanup.is_null());
    unsafe {
        (*owner.raw).cleanup = (*cleanup).next;
        (*cleanup).next = ptr::null_mut();
    }

    assert_eq!(
        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                session.remove_module_context::<PoolContextModule>()
            })
        }
        .unwrap()
        .unwrap(),
        None
    );
    assert_eq!(contexts[0], context);

    unsafe {
        (*cleanup).handler = None;
        core::ptr::drop_in_place(context.cast::<TestContext>());
    }
    assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);

    drop(owner);
    assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn pool_destroy_cancels_a_pinned_context_timer_before_dropping_its_state() {
    let _globals = StreamGlobals::new();
    unsafe {
        assert_eq!(ngx_event_timer_init(ptr::null_mut()), 0);
        ngx_current_msec = 0;
    }
    TIMER_CONTEXT_DROPS.store(0, Ordering::Relaxed);
    TIMER_CONTEXT_CALLBACKS.store(0, Ordering::Relaxed);
    let owner = TestPool::new();
    let log = static_log_ref();
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_session();
    raw.connection = &raw mut *connection;
    raw.ctx = contexts.as_mut_ptr();

    unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            let mut context = session
                .get_or_insert_pinned_module_context_with::<TimerContextModule>(|| {
                    let callback: TimerContextCallback = timer_context_callback;
                    TimerContext { timer: Timer::new(log, (), callback), _drop: TimerContextDrop }
                })
                .unwrap();
            let mut timer = context.as_mut().map_unchecked_mut(|context| &mut context.timer);
            timer.as_mut().arm(5).unwrap();
        })
    }
    .unwrap();

    drop(owner);
    assert_eq!(TIMER_CONTEXT_DROPS.load(Ordering::Relaxed), 1);

    unsafe {
        ngx_current_msec = 5;
        ngx_event_expire_timers();
    }
    assert_eq!(TIMER_CONTEXT_CALLBACKS.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "test-link")]
#[test]
fn context_removal_keeps_the_slot_when_the_connection_pool_is_unavailable() {
    let _globals = StreamGlobals::new();
    CONTEXT_DROPS.store(0, Ordering::Relaxed);
    let owner = TestPool::new();
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_session();
    raw.connection = &raw mut *connection;
    raw.ctx = contexts.as_mut_ptr();
    unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            session
                .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                .unwrap();
        })
    }
    .unwrap();

    let context_ptr = contexts[0];
    raw.connection = ptr::null_mut();
    let result = unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            session.remove_module_context::<PoolContextModule>()
        })
    }
    .unwrap();

    assert!(matches!(
        result,
        Err(SessionContextError::Connection(ConnectionError::NullConnection))
    ));
    assert_eq!(contexts[0], context_ptr);

    raw.connection = &raw mut *connection;
    assert_eq!(
        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                session.remove_module_context::<PoolContextModule>()
            })
        }
        .unwrap()
        .unwrap(),
        Some(())
    );
    assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn module_context_insertion_and_removal_follow_connection_pool_ownership() {
    let _globals = StreamGlobals::new();
    CONTEXT_DROPS.store(0, Ordering::Relaxed);
    let owner = TestPool::new();
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_session();
    raw.connection = &raw mut *connection;
    raw.ctx = contexts.as_mut_ptr();
    unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            let context = session
                .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                .unwrap();
            context.0 = 99;
            assert_eq!(
                session.module_context::<PoolContextModule>().unwrap().map(|value| value.0),
                Some(99)
            );
            session.module_context_mut::<PoolContextModule>().unwrap().unwrap().0 = 100;
            let same = session
                .get_or_insert_module_context_with::<PoolContextModule>(|| unreachable!())
                .unwrap();
            assert_eq!(same.0, 100);
            assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 0);

            assert_eq!(session.remove_module_context::<PoolContextModule>().unwrap(), Some(()));
            assert!(session.module_context::<PoolContextModule>().unwrap().is_none());
        })
    }
    .unwrap();
    assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);

    drop(owner);
    assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "test-link")]
#[test]
fn pool_destruction_drops_an_attached_unpinned_context_once() {
    let _globals = StreamGlobals::new();
    CONTEXT_DROPS.store(0, Ordering::Relaxed);
    let owner = TestPool::new();
    let mut connection =
        Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
    connection.pool = owner.raw;
    let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
    let mut raw = zeroed_session();
    raw.connection = &raw mut *connection;
    raw.ctx = contexts.as_mut_ptr();

    unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            session
                .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                .unwrap();
        })
    }
    .unwrap();

    assert!(!contexts[0].is_null());
    drop(owner);
    assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
}
