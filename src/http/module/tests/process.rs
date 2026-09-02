use super::*;

#[test]
fn process_callbacks_reject_invalid_cycles_and_preserve_ffi_statuses() {
    PROCESS_STARTS.store(0, Ordering::Relaxed);
    PROCESS_STOPS.store(0, Ordering::Relaxed);

    assert_eq!(unsafe { init_process::<ProcessModule>(ptr::null_mut()) }, Status::NGX_ERROR.0);
    unsafe { exit_process::<ProcessModule>(ptr::null_mut()) };
    assert_eq!(PROCESS_STARTS.load(Ordering::Relaxed), 0);
    assert_eq!(PROCESS_STOPS.load(Ordering::Relaxed), 0);

    let misaligned = ptr::without_provenance_mut::<ngx_cycle_t>(1);
    assert_eq!(unsafe { init_process::<ProcessModule>(misaligned) }, Status::NGX_ERROR.0);
    unsafe { exit_process::<ProcessModule>(misaligned) };
    assert_eq!(PROCESS_STARTS.load(Ordering::Relaxed), 0);
    assert_eq!(PROCESS_STOPS.load(Ordering::Relaxed), 0);

    let mut cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    assert_eq!(unsafe { init_process::<ProcessModule>(&raw mut cycle) }, Status::NGX_OK.0);
    assert_eq!(
        unsafe { init_process::<FailingProcessModule>(&raw mut cycle) },
        Status::NGX_ERROR.0
    );
    unsafe { exit_process::<ProcessModule>(&raw mut cycle) };
    unsafe { exit_process::<ProcessModule>(&raw mut cycle) };
    assert_eq!(PROCESS_STARTS.load(Ordering::Relaxed), 1);
    assert_eq!(PROCESS_STOPS.load(Ordering::Relaxed), 2);
}
