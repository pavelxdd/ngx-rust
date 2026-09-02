use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicIsize, AtomicPtr, AtomicUsize, Ordering};
use std::sync::MutexGuard;

use super::super::test_support::TestPool;
use super::*;
use crate::core::{ModuleDescriptor, Status};
use crate::ffi::{
    NGX_BUSY, NGX_DECLINED, NGX_ERROR, NGX_HTTP_MODULE, NGX_LOG_ERR, ngx_conf_t, ngx_connection_t,
    ngx_http_request_t, ngx_http_upstream_srv_conf_t, ngx_http_upstream_t, ngx_int_t, ngx_log_t,
    ngx_module_t, ngx_peer_connection_t, ngx_str_t, ngx_uint_t, sockaddr,
};
use crate::http::{HttpModule, HttpModuleServerConf};

static ORIGINAL_INIT_PEER_CALLS: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_INIT_UPSTREAM_CALLS: AtomicUsize = AtomicUsize::new(0);
static DELEGATED_INIT_UPSTREAM_CALLS: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_GET_STATUS: AtomicIsize = AtomicIsize::new(0);
static CALLBACK_ORDER: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_GET_PEER_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_GET_CALLBACK_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_FREE_PEER_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_FREE_CALLBACK_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_FREE_STATE: AtomicUsize = AtomicUsize::new(0);
static OBSERVED_NOTIFY_PEER_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_NOTIFY_CALLBACK_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_NOTIFY_TYPE: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
static OBSERVED_SET_SESSION_PEER_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
static OBSERVED_SET_SESSION_CALLBACK_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
static OBSERVED_SAVE_SESSION_PEER_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
static OBSERVED_SAVE_SESSION_CALLBACK_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[derive(Default)]
struct LogCapture {
    records: Vec<(ngx_uint_t, Vec<u8>)>,
}

unsafe extern "C" fn capture_log(
    log: *mut ngx_log_t,
    level: ngx_uint_t,
    bytes: *mut u8,
    len: usize,
) {
    let Some(log) = (unsafe { log.as_mut() }) else {
        return;
    };
    let Some(capture) = (unsafe { log.wdata.cast::<LogCapture>().as_mut() }) else {
        return;
    };
    if bytes.is_null() {
        return;
    }
    capture.records.push((level, unsafe { slice::from_raw_parts(bytes, len) }.to_vec()));
}

fn attach_log(log: &mut ngx_log_t, capture: &mut LogCapture) {
    log.log_level = NGX_LOG_ERR as _;
    log.writer = Some(capture_log);
    log.wdata = ptr::from_mut(capture).cast();
}

fn assert_single_record(capture: &LogCapture, level: ngx_uint_t, message: &[u8]) {
    assert_eq!(capture.records.len(), 1);
    assert_eq!(capture.records[0].0, level);
    assert!(capture.records[0].1.windows(message.len()).any(|record| record == message));
}

struct HttpSlotCounts {
    _guard: MutexGuard<'static, ()>,
    max_module: ngx_uint_t,
    http_max_module: ngx_uint_t,
}

impl HttpSlotCounts {
    fn one() -> Self {
        let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe {
            Self {
                _guard: guard,
                max_module: nginx_sys::ngx_max_module,
                http_max_module: nginx_sys::ngx_http_max_module,
            }
        };
        unsafe {
            nginx_sys::ngx_max_module = 1;
            nginx_sys::ngx_http_max_module = 1;
        }
        previous
    }
}

impl Drop for HttpSlotCounts {
    fn drop(&mut self) {
        unsafe {
            nginx_sys::ngx_max_module = self.max_module;
            nginx_sys::ngx_http_max_module = self.http_max_module;
        }
    }
}

struct ConfiguredServer {
    _counts: HttpSlotCounts,
    raw: Box<ngx_http_upstream_srv_conf_t>,
    configuration: Box<TestServerConfig>,
    _slots: Box<[*mut c_void; 1]>,
}

impl ConfiguredServer {
    fn new(value: u32) -> Self {
        let counts = HttpSlotCounts::one();
        let mut configuration = Box::new(TestServerConfig::new(value));
        let mut slots = Box::new([ptr::from_mut(&mut *configuration).cast()]);
        let mut raw = Box::new(unsafe {
            MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init()
        });
        raw.srv_conf = slots.as_mut_ptr();
        Self { _counts: counts, raw, configuration, _slots: slots }
    }

    fn install_peer<H>(&mut self) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamPeerHandler,
    {
        UpstreamServerConf::from_mut(&mut self.raw).install_peer_initializer::<H>()
    }
}

struct TestServerModule;

unsafe impl HttpModule for TestServerModule {
    fn module() -> ModuleDescriptor {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_HTTP_MODULE as _;
        module.index = 0;
        module.ctx_index = 0;
        ModuleDescriptor::from_test(module)
    }
}

struct TestServerConfig {
    value: u32,
    callbacks: UpstreamCallbackSlot,
}

impl TestServerConfig {
    fn new(value: u32) -> Self {
        Self { value, callbacks: UpstreamCallbackSlot::new() }
    }
}

unsafe impl HttpModuleServerConf for TestServerModule {
    type ServerConf = TestServerConfig;
}

macro_rules! test_callback_owner {
    () => {
        type Module = TestServerModule;

        fn callback_slot(configuration: &mut TestServerConfig) -> &mut UpstreamCallbackSlot {
            &mut configuration.callbacks
        }
    };
}

unsafe extern "C" fn incomplete_init_peer(
    _request: *mut ngx_http_request_t,
    _upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t {
    Status::NGX_OK.0
}

unsafe extern "C" fn declined_init_peer(
    _request: *mut ngx_http_request_t,
    _upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t {
    ORIGINAL_INIT_PEER_CALLS.fetch_add(1, Ordering::Relaxed);
    NGX_DECLINED as _
}

unsafe extern "C" fn busy_init_upstream(
    _configuration: *mut ngx_conf_t,
    _upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t {
    ORIGINAL_INIT_UPSTREAM_CALLS.fetch_add(1, Ordering::Relaxed);
    NGX_BUSY as _
}

unsafe extern "C" fn delegated_busy_init_upstream(
    _configuration: *mut ngx_conf_t,
    _upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t {
    DELEGATED_INIT_UPSTREAM_CALLS.fetch_add(1, Ordering::Relaxed);
    NGX_BUSY as _
}

struct DecliningInitializer;

impl HttpUpstreamInitializer for DecliningInitializer {
    test_callback_owner!();

    fn init<'upstream>(
        _configuration: &mut UpstreamConfiguration<'_>,
        _upstream: &'upstream mut UpstreamServerConf<'_>,
        _original: OriginalUpstreamInit<Self>,
    ) -> Result<UpstreamInitialization<'upstream>, UpstreamCallbackError> {
        Ok(UpstreamInitialization::Unavailable)
    }
}

struct DelegatingInitializer;

impl HttpUpstreamInitializer for DelegatingInitializer {
    test_callback_owner!();

    fn init<'upstream>(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &'upstream mut UpstreamServerConf<'_>,
        original: OriginalUpstreamInit<Self>,
    ) -> Result<UpstreamInitialization<'upstream>, UpstreamCallbackError> {
        match original.call(configuration, upstream)? {
            UpstreamInitStatus::Initialized => {
                Ok(UpstreamInitialization::Initialized(upstream.initialized()?))
            }
            UpstreamInitStatus::Unavailable => Ok(UpstreamInitialization::Unavailable),
        }
    }
}

struct MissingOriginalInitializer;

impl HttpUpstreamInitializer for MissingOriginalInitializer {
    test_callback_owner!();

    fn init<'upstream>(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &'upstream mut UpstreamServerConf<'_>,
        original: OriginalUpstreamInit<Self>,
    ) -> Result<UpstreamInitialization<'upstream>, UpstreamCallbackError> {
        match original.call(configuration, upstream)? {
            UpstreamInitStatus::Initialized => {
                Ok(UpstreamInitialization::Initialized(upstream.initialized()?))
            }
            UpstreamInitStatus::Unavailable => Ok(UpstreamInitialization::Unavailable),
        }
    }
}

struct PoolInitializer;

impl HttpUpstreamInitializer for PoolInitializer {
    test_callback_owner!();

    fn init<'upstream>(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &'upstream mut UpstreamServerConf<'_>,
        _original: OriginalUpstreamInit<Self>,
    ) -> Result<UpstreamInitialization<'upstream>, UpstreamCallbackError> {
        let _ = configuration.pool()?;
        Ok(UpstreamInitialization::Initialized(upstream.initialized()?))
    }
}

struct IncompleteOriginalPeerInitializer;

impl HttpUpstreamPeerHandler for IncompleteOriginalPeerInitializer {
    test_callback_owner!();

    type Data = ();

    fn init(
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
        original: OriginalPeerInit<Self>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        match original.call(request, upstream)? {
            UpstreamPeerInitStatus::Initialized => Ok(UpstreamPeerInit::Install(())),
            UpstreamPeerInitStatus::Unavailable => Ok(UpstreamPeerInit::Unavailable),
        }
    }

    fn get<'callback>(
        _peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _original: OriginalPeerGet<'callback>,
    ) -> Result<UpstreamPeerSelection<'callback>, UpstreamCallbackError> {
        Ok(UpstreamPeerSelection::Error)
    }

    fn free<'callback>(
        _peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _state: UpstreamPeerState,
        _original: OriginalPeerFree<'callback>,
    ) -> Result<(), UpstreamCallbackError> {
        Ok(())
    }
}

struct IncompleteOriginalPeerSelection;

impl HttpUpstreamPeerHandler for IncompleteOriginalPeerSelection {
    test_callback_owner!();

    type Data = ();

    fn init(
        _request: &mut UpstreamPeerInitRequest<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
        _original: OriginalPeerInit<Self>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        Ok(UpstreamPeerInit::Install(()))
    }

    fn get<'callback>(
        peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        original: OriginalPeerGet<'callback>,
    ) -> Result<UpstreamPeerSelection<'callback>, UpstreamCallbackError> {
        original.call(peer)
    }

    fn free<'callback>(
        _peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _state: UpstreamPeerState,
        _original: OriginalPeerFree<'callback>,
    ) -> Result<(), UpstreamCallbackError> {
        Ok(())
    }
}

struct TypedConfigurationInitializer;

impl HttpUpstreamInitializer for TypedConfigurationInitializer {
    test_callback_owner!();

    fn init<'upstream>(
        _configuration: &mut UpstreamConfiguration<'_>,
        upstream: &'upstream mut UpstreamServerConf<'_>,
        _original: OriginalUpstreamInit<Self>,
    ) -> Result<UpstreamInitialization<'upstream>, UpstreamCallbackError> {
        {
            let configuration = upstream.module_conf::<TestServerModule>()?.unwrap();
            assert_eq!(configuration.value, 41);
        }
        upstream.module_conf_mut::<TestServerModule>()?.unwrap().value = 42;
        Ok(UpstreamInitialization::Initialized(upstream.initialized()?))
    }
}

struct DelegatePeerInit;

impl HttpUpstreamPeerHandler for DelegatePeerInit {
    test_callback_owner!();

    type Data = ();

    fn init(
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
        original: OriginalPeerInit<Self>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        match original.call(request, upstream)? {
            UpstreamPeerInitStatus::Initialized => Ok(UpstreamPeerInit::Install(())),
            UpstreamPeerInitStatus::Unavailable => Ok(UpstreamPeerInit::Unavailable),
        }
    }

    fn get<'callback>(
        _peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _original: OriginalPeerGet<'callback>,
    ) -> Result<UpstreamPeerSelection<'callback>, UpstreamCallbackError> {
        Ok(UpstreamPeerSelection::Error)
    }

    fn free<'callback>(
        _peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _state: UpstreamPeerState,
        _original: OriginalPeerFree<'callback>,
    ) -> Result<(), UpstreamCallbackError> {
        Ok(())
    }
}

unsafe extern "C" fn ordered_init_peer(
    request: *mut ngx_http_request_t,
    _upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t {
    let upstream = unsafe { (*request).upstream };
    let peer = unsafe { &mut (*upstream).peer };
    peer.data = ORIGINAL_DATA.load(Ordering::Relaxed);
    peer.get = Some(ordered_get_peer);
    peer.free = Some(ordered_free_peer);
    peer.notify = Some(ordered_notify_peer);
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    {
        peer.set_session = Some(ordered_set_session);
        peer.save_session = Some(ordered_save_session);
    }
    CALLBACK_ORDER.fetch_add(1, Ordering::Relaxed);
    Status::NGX_OK.0
}

unsafe extern "C" fn selected_status_get_peer(
    _peer: *mut ngx_peer_connection_t,
    _data: *mut c_void,
) -> ngx_int_t {
    ORIGINAL_GET_STATUS.load(Ordering::Relaxed)
}

fn original_peer_get<'callback>() -> OriginalPeerGet<'callback> {
    OriginalPeerGet {
        original: OriginalPeerCallbacks {
            get: Some(selected_status_get_peer),
            free: None,
            notify: None,
            #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
            set_session: None,
            #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
            save_session: None,
            data: ptr::null_mut(),
        },
        _callback: PhantomData,
    }
}

unsafe extern "C" fn incomplete_selected_get_peer(
    _peer: *mut ngx_peer_connection_t,
    _data: *mut c_void,
) -> ngx_int_t {
    Status::NGX_OK.0
}

unsafe extern "C" fn ordered_get_peer(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
) -> ngx_int_t {
    OBSERVED_GET_PEER_DATA.store(unsafe { (*peer).data }, Ordering::Relaxed);
    OBSERVED_GET_CALLBACK_DATA.store(data, Ordering::Relaxed);
    CALLBACK_ORDER.fetch_add(1, Ordering::Relaxed);
    NGX_BUSY as _
}

unsafe extern "C" fn ordered_free_peer(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
    state: ngx_uint_t,
) {
    OBSERVED_FREE_PEER_DATA.store(unsafe { (*peer).data }, Ordering::Relaxed);
    OBSERVED_FREE_CALLBACK_DATA.store(data, Ordering::Relaxed);
    OBSERVED_FREE_STATE.store(state, Ordering::Relaxed);
    CALLBACK_ORDER.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn ordered_notify_peer(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
    type_: ngx_uint_t,
) {
    OBSERVED_NOTIFY_PEER_DATA.store(unsafe { (*peer).data }, Ordering::Relaxed);
    OBSERVED_NOTIFY_CALLBACK_DATA.store(data, Ordering::Relaxed);
    OBSERVED_NOTIFY_TYPE.store(type_, Ordering::Relaxed);
    CALLBACK_ORDER.fetch_add(1, Ordering::Relaxed);
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
unsafe extern "C" fn ordered_set_session(
    peer: *mut ngx_peer_connection_t,
    data: *mut c_void,
) -> ngx_int_t {
    OBSERVED_SET_SESSION_PEER_DATA.store(unsafe { (*peer).data }, Ordering::Relaxed);
    OBSERVED_SET_SESSION_CALLBACK_DATA.store(data, Ordering::Relaxed);
    CALLBACK_ORDER.fetch_add(1, Ordering::Relaxed);
    NGX_BUSY as _
}

#[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
unsafe extern "C" fn ordered_save_session(peer: *mut ngx_peer_connection_t, data: *mut c_void) {
    OBSERVED_SAVE_SESSION_PEER_DATA.store(unsafe { (*peer).data }, Ordering::Relaxed);
    OBSERVED_SAVE_SESSION_CALLBACK_DATA.store(data, Ordering::Relaxed);
    CALLBACK_ORDER.fetch_add(1, Ordering::Relaxed);
}

struct OrderedPeer;

impl HttpUpstreamPeerHandler for OrderedPeer {
    test_callback_owner!();

    type Data = ();

    fn init(
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
        original: OriginalPeerInit<Self>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        match original.call(request, upstream)? {
            UpstreamPeerInitStatus::Initialized => Ok(UpstreamPeerInit::Install(())),
            UpstreamPeerInitStatus::Unavailable => Ok(UpstreamPeerInit::Unavailable),
        }
    }

    fn get<'callback>(
        peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        original: OriginalPeerGet<'callback>,
    ) -> Result<UpstreamPeerSelection<'callback>, UpstreamCallbackError> {
        original.call(peer)
    }

    fn free<'callback>(
        peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _state: UpstreamPeerState,
        original: OriginalPeerFree<'callback>,
    ) -> Result<(), UpstreamCallbackError> {
        original.call(peer)
    }
}

struct MissingOriginalPeer;

impl HttpUpstreamPeerHandler for MissingOriginalPeer {
    test_callback_owner!();

    type Data = ();

    fn init(
        _request: &mut UpstreamPeerInitRequest<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
        _original: OriginalPeerInit<Self>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        Ok(UpstreamPeerInit::Install(()))
    }

    fn get<'callback>(
        peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        original: OriginalPeerGet<'callback>,
    ) -> Result<UpstreamPeerSelection<'callback>, UpstreamCallbackError> {
        original.call(peer)
    }

    fn free<'callback>(
        peer: &'callback mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _state: UpstreamPeerState,
        original: OriginalPeerFree<'callback>,
    ) -> Result<(), UpstreamCallbackError> {
        original.call(peer)
    }
}

fn initialized_request(
    pool: &TestPool,
    request: &mut ngx_http_request_t,
    upstream: &mut ngx_http_upstream_t,
) {
    request.signature = NGX_HTTP_MODULE as _;
    request.main = request;
    request.pool = pool.raw;
    request.upstream = upstream;
}

#[test]
fn repeated_initializer_installation_is_rejected_before_publication() {
    DELEGATED_INIT_UPSTREAM_CALLS.store(0, Ordering::Relaxed);
    let mut server = ConfiguredServer::new(0);
    server.raw.peer.init_upstream = Some(busy_init_upstream);

    assert_eq!(install_upstream_initializer::<DecliningInitializer>(&mut server.raw), Ok(()));
    server.raw.peer.init_upstream = Some(delegated_busy_init_upstream);
    assert_eq!(
        install_upstream_initializer::<DecliningInitializer>(&mut server.raw),
        Err(UpstreamCallbackError::DuplicateUpstreamInitializer)
    );
    assert_eq!(
        unsafe { server.raw.peer.init_upstream.unwrap()(ptr::null_mut(), ptr::null_mut()) },
        NGX_BUSY as _
    );
    assert_eq!(DELEGATED_INIT_UPSTREAM_CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn repeated_peer_initializer_installation_is_rejected_before_publication() {
    let mut server = ConfiguredServer::new(0);
    server.raw.peer.init = Some(declined_init_peer);

    assert_eq!(server.install_peer::<DelegatePeerInit>(), Ok(()));
    server.raw.peer.init = Some(incomplete_init_peer);
    assert_eq!(
        server.install_peer::<DelegatePeerInit>(),
        Err(UpstreamCallbackError::DuplicatePeerInitializer)
    );
    assert_eq!(
        unsafe { server.raw.peer.init.unwrap()(ptr::null_mut(), ptr::null_mut()) },
        Status::NGX_OK.0
    );
}

#[test]
fn initializer_slots_reject_a_foreign_upstream_generation() {
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    let mut server = ConfiguredServer::new(0);
    assert_eq!(install_upstream_initializer::<DecliningInitializer>(&mut server.raw), Ok(()));
    assert_eq!(server.install_peer::<MissingOriginalPeer>(), Ok(()));

    let mut foreign =
        unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    foreign.srv_conf = server.raw.srv_conf;
    assert_eq!(
        unsafe {
            raw_init_upstream::<DecliningInitializer>(&raw mut configuration, &raw mut foreign)
        },
        Status::NGX_ERROR.0
    );

    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut foreign) },
        Status::NGX_ERROR.0
    );
}

#[test]
fn upstream_initializer_receives_its_saved_callback_and_rejects_invalid_inputs() {
    ORIGINAL_INIT_UPSTREAM_CALLS.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    let mut server = ConfiguredServer::new(0);
    server.raw.peer.init_upstream = Some(busy_init_upstream);

    assert_eq!(install_upstream_initializer::<DelegatingInitializer>(&mut server.raw), Ok(()));
    let callback = server.raw.peer.init_upstream.unwrap();
    assert_eq!(unsafe { callback(&raw mut configuration, &raw mut *server.raw) }, NGX_ERROR as _);
    assert_eq!(ORIGINAL_INIT_UPSTREAM_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(
        unsafe {
            raw_init_upstream::<DelegatingInitializer>(ptr::null_mut(), &raw mut *server.raw)
        },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe {
            raw_init_upstream::<DelegatingInitializer>(
                ptr::without_provenance_mut::<ngx_conf_t>(1),
                &raw mut *server.raw,
            )
        },
        NGX_ERROR as _
    );
}

#[test]
fn success_without_an_installed_peer_initializer_is_rejected() {
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    let mut server = ConfiguredServer::new(0);
    assert_eq!(install_upstream_initializer::<PoolInitializer>(&mut server.raw), Ok(()));

    assert_eq!(
        unsafe {
            raw_init_upstream::<PoolInitializer>(&raw mut configuration, &raw mut *server.raw)
        },
        NGX_ERROR as _
    );
}

#[test]
fn peer_initializer_success_without_installing_callbacks_is_rejected() {
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = ConfiguredServer::new(0);
    server.raw.peer.init = Some(incomplete_init_peer);
    assert_eq!(server.install_peer::<IncompleteOriginalPeerInitializer>(), Ok(()));

    assert_eq!(
        unsafe {
            raw_init_peer::<IncompleteOriginalPeerInitializer>(
                &raw mut request,
                &raw mut *server.raw,
            )
        },
        NGX_ERROR as _
    );
    assert!(request_upstream.peer.get.is_none());
}

#[test]
fn selected_status_without_native_peer_state_is_rejected() {
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = ConfiguredServer::new(0);
    assert_eq!(server.install_peer::<IncompleteOriginalPeerSelection>(), Ok(()));

    request_upstream.peer.get = Some(incomplete_selected_get_peer);
    assert_eq!(
        unsafe {
            raw_init_peer::<IncompleteOriginalPeerSelection>(&raw mut request, &raw mut *server.raw)
        },
        Status::NGX_OK.0
    );
    let typed_data = request_upstream.peer.data;
    assert_eq!(
        unsafe {
            raw_get_peer::<IncompleteOriginalPeerSelection>(
                &raw mut request_upstream.peer,
                typed_data,
            )
        },
        NGX_ERROR as _
    );
}

#[test]
fn original_peer_selection_accepts_only_native_statuses_with_required_state() {
    let mut raw_peer = unsafe { MaybeUninit::<ngx_peer_connection_t>::zeroed().assume_init() };
    let mut peer = unsafe { UpstreamPeerConnection::from_raw(&raw mut raw_peer) }.unwrap();

    for (status, expected) in [
        (Status::NGX_ERROR.0, Status::NGX_ERROR.0),
        (Status::NGX_BUSY.0, Status::NGX_BUSY.0),
        (Status::NGX_DECLINED.0, Status::NGX_DECLINED.0),
    ] {
        ORIGINAL_GET_STATUS.store(status, Ordering::Relaxed);
        assert_eq!(original_peer_get().call(&mut peer).unwrap().status(), expected);
    }

    ORIGINAL_GET_STATUS.store(Status::NGX_ABORT.0, Ordering::Relaxed);
    assert_eq!(
        original_peer_get().call(&mut peer).err(),
        Some(UpstreamCallbackError::InvalidOriginalGetStatus(Status::NGX_ABORT.0))
    );

    ORIGINAL_GET_STATUS.store(Status::NGX_OK.0, Ordering::Relaxed);
    assert_eq!(
        original_peer_get().call(&mut peer).err(),
        Some(UpstreamCallbackError::MissingSelectedPeerName)
    );
    let mut name = ngx_str_t::default();
    unsafe { peer.raw.as_mut().name = &raw mut name };
    assert_eq!(
        original_peer_get().call(&mut peer).err(),
        Some(UpstreamCallbackError::MissingSelectedPeerAddress)
    );
    let mut address = unsafe { MaybeUninit::<sockaddr>::zeroed().assume_init() };
    unsafe { peer.raw.as_mut().sockaddr = &raw mut address };
    assert_eq!(original_peer_get().call(&mut peer).unwrap().status(), Status::NGX_OK.0);

    unsafe { peer.raw.as_mut().sockaddr = ptr::null_mut() };
    ORIGINAL_GET_STATUS.store(Status::NGX_AGAIN.0, Ordering::Relaxed);
    assert_eq!(
        original_peer_get().call(&mut peer).err(),
        Some(UpstreamCallbackError::MissingSelectedPeerConnection)
    );
    let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
    unsafe { peer.raw.as_mut().connection = &raw mut connection };
    assert_eq!(original_peer_get().call(&mut peer).unwrap().status(), Status::NGX_AGAIN.0);

    ORIGINAL_GET_STATUS.store(Status::NGX_DONE.0, Ordering::Relaxed);
    assert_eq!(original_peer_get().call(&mut peer).unwrap().status(), Status::NGX_DONE.0);
}

#[test]
fn upstream_initializer_reads_and_mutates_typed_server_configuration() {
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    let mut server = ConfiguredServer::new(41);
    server.raw.peer.init = Some(declined_init_peer);

    assert_eq!(
        install_upstream_initializer::<TypedConfigurationInitializer>(&mut server.raw),
        Ok(())
    );
    let callback = server.raw.peer.init_upstream.unwrap();
    assert_eq!(unsafe { callback(&raw mut configuration, &raw mut *server.raw) }, Status::NGX_OK.0);
    assert_eq!(server.configuration.value, 42);
}

#[test]
fn upstream_initializer_delegates_and_validates_each_owner() {
    DELEGATED_INIT_UPSTREAM_CALLS.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;

    {
        let mut server = ConfiguredServer::new(0);
        server.raw.peer.init_upstream = Some(delegated_busy_init_upstream);
        assert_eq!(install_upstream_initializer::<DelegatingInitializer>(&mut server.raw), Ok(()));
        assert_eq!(
            unsafe {
                raw_init_upstream::<DelegatingInitializer>(
                    &raw mut configuration,
                    &raw mut *server.raw,
                )
            },
            NGX_ERROR as _
        );
    }
    assert_eq!(DELEGATED_INIT_UPSTREAM_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(
        unsafe {
            raw_init_upstream::<DelegatingInitializer>(&raw mut configuration, ptr::null_mut())
        },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe {
            raw_init_upstream::<DelegatingInitializer>(
                &raw mut configuration,
                ptr::without_provenance_mut::<ngx_http_upstream_srv_conf_t>(1),
            )
        },
        NGX_ERROR as _
    );

    let mut missing_pool = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    {
        let mut server = ConfiguredServer::new(0);
        assert_eq!(install_upstream_initializer::<PoolInitializer>(&mut server.raw), Ok(()));
        assert_eq!(
            unsafe {
                raw_init_upstream::<PoolInitializer>(&raw mut missing_pool, &raw mut *server.raw)
            },
            NGX_ERROR as _
        );
    }

    let mut server = ConfiguredServer::new(0);
    assert_eq!(install_upstream_initializer::<MissingOriginalInitializer>(&mut server.raw), Ok(()));
    assert_eq!(
        unsafe {
            raw_init_upstream::<MissingOriginalInitializer>(
                &raw mut configuration,
                &raw mut *server.raw,
            )
        },
        NGX_ERROR as _
    );
}

#[test]
fn peer_initializer_preserves_an_original_non_success_outcome() {
    ORIGINAL_INIT_PEER_CALLS.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);

    let mut server = ConfiguredServer::new(0);
    server.raw.peer.init = Some(declined_init_peer);
    assert_eq!(server.install_peer::<DelegatePeerInit>(), Ok(()));

    assert_eq!(
        unsafe { raw_init_peer::<DelegatePeerInit>(&raw mut request, &raw mut *server.raw) },
        NGX_ERROR as _
    );
    assert_eq!(ORIGINAL_INIT_PEER_CALLS.load(Ordering::Relaxed), 1);
    assert!(request_upstream.peer.data.is_null());
    assert!(request_upstream.peer.get.is_none());
    assert!(request_upstream.peer.free.is_none());
}

#[test]
fn peer_initializer_rejects_missing_and_invalid_owners() {
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_init_peer::<DelegatePeerInit>(&raw mut request, &raw mut server) },
        NGX_ERROR as _
    );
    assert!(request_upstream.peer.data.is_null());
    assert!(request_upstream.peer.get.is_none());
    assert!(request_upstream.peer.free.is_none());

    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, ptr::null_mut()) },
        NGX_ERROR as _
    );

    request.upstream = ptr::null_mut();
    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut server) },
        NGX_ERROR as _
    );
    request.upstream = ptr::without_provenance_mut::<ngx_http_upstream_t>(1);
    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut server) },
        NGX_ERROR as _
    );

    request.upstream = &raw mut request_upstream;
    assert_eq!(
        unsafe {
            raw_init_peer::<MissingOriginalPeer>(
                &raw mut request,
                ptr::without_provenance_mut::<ngx_http_upstream_srv_conf_t>(1),
            )
        },
        NGX_ERROR as _
    );
}

#[test]
fn peer_callback_family_composes_with_distinct_outer_and_original_data() {
    CALLBACK_ORDER.store(0, Ordering::Relaxed);
    OBSERVED_GET_PEER_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_GET_CALLBACK_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_FREE_PEER_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_FREE_CALLBACK_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_FREE_STATE.store(0, Ordering::Relaxed);
    OBSERVED_NOTIFY_PEER_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_NOTIFY_CALLBACK_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_NOTIFY_TYPE.store(0, Ordering::Relaxed);
    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    {
        OBSERVED_SET_SESSION_PEER_DATA.store(ptr::null_mut(), Ordering::Relaxed);
        OBSERVED_SET_SESSION_CALLBACK_DATA.store(ptr::null_mut(), Ordering::Relaxed);
        OBSERVED_SAVE_SESSION_PEER_DATA.store(ptr::null_mut(), Ordering::Relaxed);
        OBSERVED_SAVE_SESSION_CALLBACK_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    }
    let pool = TestPool::new();
    let mut original_data = 7_u8;
    let original_data = ptr::from_mut(&mut original_data).cast::<c_void>();
    ORIGINAL_DATA.store(original_data, Ordering::Relaxed);

    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = ConfiguredServer::new(0);
    server.raw.peer.init = Some(ordered_init_peer);
    assert_eq!(server.install_peer::<OrderedPeer>(), Ok(()));

    assert_eq!(
        unsafe { raw_init_peer::<OrderedPeer>(&raw mut request, &raw mut *server.raw) },
        Status::NGX_OK.0
    );
    let typed_data = request_upstream.peer.data;
    assert_ne!(typed_data, original_data);
    let mut outer_data = 8_u8;
    let outer_data = ptr::from_mut(&mut outer_data).cast::<c_void>();
    request_upstream.peer.data = outer_data;
    assert_eq!(CALLBACK_ORDER.load(Ordering::Relaxed), 1);

    assert_eq!(
        unsafe { raw_get_peer::<OrderedPeer>(&raw mut request_upstream.peer, typed_data) },
        NGX_BUSY as _
    );
    assert_eq!(OBSERVED_GET_PEER_DATA.load(Ordering::Relaxed), outer_data);
    assert_eq!(OBSERVED_GET_CALLBACK_DATA.load(Ordering::Relaxed), original_data);
    assert_eq!(request_upstream.peer.data, outer_data);

    let state = 0x5a_u32 as ngx_uint_t;
    unsafe { raw_free_peer::<OrderedPeer>(&raw mut request_upstream.peer, typed_data, state) };
    assert_eq!(OBSERVED_FREE_PEER_DATA.load(Ordering::Relaxed), outer_data);
    assert_eq!(OBSERVED_FREE_CALLBACK_DATA.load(Ordering::Relaxed), original_data);
    assert_eq!(OBSERVED_FREE_STATE.load(Ordering::Relaxed), state as usize);
    assert_eq!(request_upstream.peer.data, outer_data);

    let notify_type = 0x6b_u32 as ngx_uint_t;
    unsafe {
        request_upstream.peer.notify.unwrap()(
            &raw mut request_upstream.peer,
            typed_data,
            notify_type,
        )
    };
    assert_eq!(OBSERVED_NOTIFY_PEER_DATA.load(Ordering::Relaxed), outer_data);
    assert_eq!(OBSERVED_NOTIFY_CALLBACK_DATA.load(Ordering::Relaxed), original_data);
    assert_eq!(OBSERVED_NOTIFY_TYPE.load(Ordering::Relaxed), notify_type);
    assert_eq!(request_upstream.peer.data, outer_data);

    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    unsafe {
        assert_eq!(
            request_upstream.peer.set_session.unwrap()(&raw mut request_upstream.peer, typed_data,),
            NGX_BUSY as _
        );
        assert_eq!(OBSERVED_SET_SESSION_PEER_DATA.load(Ordering::Relaxed), outer_data);
        assert_eq!(OBSERVED_SET_SESSION_CALLBACK_DATA.load(Ordering::Relaxed), original_data);
        assert_eq!(request_upstream.peer.data, outer_data);

        request_upstream.peer.save_session.unwrap()(&raw mut request_upstream.peer, typed_data);
        assert_eq!(OBSERVED_SAVE_SESSION_PEER_DATA.load(Ordering::Relaxed), outer_data);
        assert_eq!(OBSERVED_SAVE_SESSION_CALLBACK_DATA.load(Ordering::Relaxed), original_data);
        assert_eq!(request_upstream.peer.data, outer_data);
    }

    #[cfg(any(ngx_feature = "ssl", ngx_feature = "compat"))]
    assert_eq!(CALLBACK_ORDER.load(Ordering::Relaxed), 6);
    #[cfg(not(any(ngx_feature = "ssl", ngx_feature = "compat")))]
    assert_eq!(CALLBACK_ORDER.load(Ordering::Relaxed), 4);
}

#[test]
fn peer_callback_adapters_reject_null_inputs_without_unwinding() {
    assert_eq!(
        unsafe { raw_init_peer::<DelegatePeerInit>(ptr::null_mut(), ptr::null_mut()) },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe {
            raw_init_peer::<DelegatePeerInit>(
                ptr::without_provenance_mut::<ngx_http_request_t>(1),
                ptr::null_mut(),
            )
        },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe { raw_get_peer::<OrderedPeer>(ptr::null_mut(), ptr::null_mut()) },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe {
            raw_get_peer::<OrderedPeer>(
                ptr::without_provenance_mut::<ngx_peer_connection_t>(1),
                ptr::null_mut(),
            )
        },
        NGX_ERROR as _
    );
    unsafe { raw_free_peer::<OrderedPeer>(ptr::null_mut(), ptr::null_mut(), 0) };

    let mut peer = unsafe { MaybeUninit::<ngx_peer_connection_t>::zeroed().assume_init() };
    assert_eq!(
        unsafe { raw_get_peer::<OrderedPeer>(&raw mut peer, ptr::null_mut()) },
        NGX_ERROR as _
    );
    unsafe { raw_free_peer::<OrderedPeer>(&raw mut peer, ptr::null_mut(), 0) };
}

#[test]
fn absent_original_peer_callbacks_return_error_without_losing_typed_data() {
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = ConfiguredServer::new(0);
    assert_eq!(server.install_peer::<MissingOriginalPeer>(), Ok(()));

    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut *server.raw) },
        Status::NGX_OK.0
    );
    let typed_data = request_upstream.peer.data;
    assert_eq!(
        unsafe { raw_get_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, typed_data) },
        NGX_ERROR as _
    );
    assert_eq!(request_upstream.peer.data, typed_data);
    unsafe {
        raw_free_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, typed_data, 0x7 as _)
    };
    assert_eq!(request_upstream.peer.data, typed_data);
}

#[test]
fn callback_errors_emit_one_record_from_the_configuration_request_or_peer_owner() {
    let pool = TestPool::new();
    let mut capture = LogCapture::default();
    let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
    attach_log(&mut log, &mut capture);

    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    configuration.log = &raw mut log;
    {
        let mut server = ConfiguredServer::new(0);
        assert_eq!(
            install_upstream_initializer::<MissingOriginalInitializer>(&mut server.raw),
            Ok(())
        );
        assert_eq!(
            unsafe {
                raw_init_upstream::<MissingOriginalInitializer>(
                    &raw mut configuration,
                    &raw mut *server.raw,
                )
            },
            NGX_ERROR as _
        );
    }
    assert_single_record(
        &capture,
        crate::ffi::NGX_LOG_EMERG as _,
        b"HTTP upstream initialization failed",
    );

    capture.records.clear();
    let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
    connection.log = &raw mut log;
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    request.connection = &raw mut connection;
    {
        let mut server = ConfiguredServer::new(0);
        assert_eq!(server.install_peer::<DelegatePeerInit>(), Ok(()));
        assert_eq!(
            unsafe { raw_init_peer::<DelegatePeerInit>(&raw mut request, &raw mut *server.raw) },
            NGX_ERROR as _
        );
    }
    assert_single_record(&capture, NGX_LOG_ERR as _, b"HTTP upstream peer initialization failed");

    capture.records.clear();
    let mut server = ConfiguredServer::new(0);
    assert_eq!(server.install_peer::<MissingOriginalPeer>(), Ok(()));
    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut *server.raw) },
        Status::NGX_OK.0
    );
    request_upstream.peer.log = &raw mut log;
    let typed_data = request_upstream.peer.data;
    assert_eq!(
        unsafe { raw_get_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, typed_data) },
        NGX_ERROR as _
    );
    assert_single_record(&capture, NGX_LOG_ERR as _, b"HTTP upstream peer selection failed");

    capture.records.clear();
    unsafe { raw_free_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, typed_data, 0) };
    assert_single_record(&capture, NGX_LOG_ERR as _, b"HTTP upstream peer release failed");
}

#[test]
fn peer_callback_adapters_reject_misaligned_explicit_typed_data() {
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = ConfiguredServer::new(0);
    assert_eq!(server.install_peer::<MissingOriginalPeer>(), Ok(()));

    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut *server.raw) },
        Status::NGX_OK.0
    );
    let invalid_data = ptr::without_provenance_mut::<c_void>(1);
    assert_eq!(
        unsafe {
            raw_get_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, invalid_data)
        },
        NGX_ERROR as _
    );
    unsafe {
        raw_free_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, invalid_data, 0)
    };
}
