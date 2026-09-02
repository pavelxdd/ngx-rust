use super::*;

#[test]
fn session_raw_construction_rejects_null_and_misaligned_pointers() {
    assert!(matches!(
        unsafe { Session::from_raw(ptr::null_mut()) },
        Err(SessionError::NullSession)
    ));

    let mut storage = [0_u8;
        core::mem::size_of::<ngx_stream_session_t>()
            + core::mem::align_of::<ngx_stream_session_t>()];
    let raw = misaligned_session_ptr(&mut storage);
    assert!(matches!(unsafe { Session::from_raw(raw) }, Err(SessionError::MisalignedSession)));
}

#[cfg(feature = "test-link")]
#[test]
fn stream_configuration_access_follows_the_session_borrow() {
    let _globals = StreamGlobals::new();
    let mut main = 7_u32;
    let mut server = 8_u32;
    let mut main_conf: [*mut c_void; 1] = [(&raw mut main).cast()];
    let mut server_conf: [*mut c_void; 1] = [(&raw mut server).cast()];
    let mut raw = zeroed_session();
    raw.main_conf = main_conf.as_mut_ptr();
    raw.srv_conf = server_conf.as_mut_ptr();
    unsafe {
        Session::with_raw(&raw mut raw, |session| {
            assert_eq!(
                session.main_conf::<TestContextModule>().map(|value| value.copied()),
                Ok(Some(7))
            );
            assert_eq!(
                session.server_conf::<TestContextModule>().map(|value| value.copied()),
                Ok(Some(8))
            );
        })
    }
    .unwrap();
}

#[test]
fn typed_handler_converts_the_result() {
    let mut raw = zeroed_session();
    let status = unsafe {
        Session::with_raw(&raw mut raw, |mut session| {
            TestHandler::handler(&mut session).into_handler_status(&session)
        })
    }
    .unwrap();

    assert_eq!(status, Status::NGX_DECLINED.0);
}

#[test]
fn raw_handler_uses_one_fresh_session_borrow_and_converts_the_status() {
    RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);
    let mut raw = zeroed_session();

    let status = unsafe { raw_handler::<RawHandler>(&raw mut raw) };

    assert_eq!(status, Status::NGX_DECLINED.0);
    assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn raw_handler_rejects_a_null_session_without_invoking_the_handler() {
    RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);

    assert_eq!(unsafe { raw_handler::<RawHandler>(ptr::null_mut()) }, NGX_ERROR as _);
    assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn raw_handler_rejects_a_misaligned_session_without_invoking_the_handler() {
    RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);
    let mut storage = [0_u8;
        core::mem::size_of::<ngx_stream_session_t>()
            + core::mem::align_of::<ngx_stream_session_t>()];
    let raw = misaligned_session_ptr(&mut storage);

    assert_eq!(unsafe { raw_handler::<RawHandler>(raw) }, NGX_ERROR as _);
    assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 0);
}

#[test]
fn handler_result_converts_only_the_selected_branch() {
    let mut raw = zeroed_session();
    unsafe {
        Session::with_raw(&raw mut raw, |session| {
            assert_eq!(
                Result::<Status, Status>::Ok(Status::NGX_AGAIN).into_handler_status(&session),
                Status::NGX_AGAIN.0
            );
            assert_eq!(
                Result::<Status, Status>::Err(Status::NGX_DECLINED).into_handler_status(&session),
                Status::NGX_DECLINED.0
            );
            assert_eq!(Option::<Status>::None.into_handler_status(&session), NGX_ERROR as _);
        })
    }
    .unwrap();
}
