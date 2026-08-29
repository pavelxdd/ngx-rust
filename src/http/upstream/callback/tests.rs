use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::MutexGuard;

use super::super::test_support::TestPool;
use super::*;
use crate::core::{ModuleDescriptor, Status};
use crate::ffi::{
    NGX_BUSY, NGX_DECLINED, NGX_ERROR, NGX_HTTP_MODULE, NGX_LOG_ERR, ngx_conf_t, ngx_connection_t,
    ngx_http_request_t, ngx_http_upstream_srv_conf_t, ngx_http_upstream_t, ngx_int_t, ngx_log_t,
    ngx_module_t, ngx_peer_connection_t, ngx_uint_t,
};
use crate::http::{HttpModule, HttpModuleServerConf, RequestRefMut};

static ORIGINAL_INIT_PEER_CALLS: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_INIT_UPSTREAM_CALLS: AtomicUsize = AtomicUsize::new(0);
static DELEGATED_INIT_UPSTREAM_CALLS: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_ORDER: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_GET_PEER_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_GET_CALLBACK_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_FREE_PEER_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_FREE_CALLBACK_DATA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OBSERVED_FREE_STATE: AtomicUsize = AtomicUsize::new(0);

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

unsafe impl HttpModuleServerConf for TestServerModule {
    type ServerConf = u32;
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
    fn init(
        _configuration: &mut UpstreamConfiguration<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        Ok(NGX_DECLINED as _)
    }
}

struct DelegatingInitializer;

impl HttpUpstreamInitializer for DelegatingInitializer {
    fn init(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        let original = UpstreamInitCallback(Some(delegated_busy_init_upstream));
        original.call(configuration, upstream)
    }
}

struct MissingOriginalInitializer;

impl HttpUpstreamInitializer for MissingOriginalInitializer {
    fn init(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        UpstreamInitCallback::default().call(configuration, upstream)
    }
}

struct PoolInitializer;

impl HttpUpstreamInitializer for PoolInitializer {
    fn init(
        configuration: &mut UpstreamConfiguration<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        let _ = configuration.pool()?;
        Ok(Status::NGX_OK.0)
    }
}

struct TypedConfigurationInitializer;

impl HttpUpstreamInitializer for TypedConfigurationInitializer {
    fn init(
        _configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        {
            let configuration = upstream.module_conf::<TestServerModule>()?.unwrap();
            assert_eq!(*configuration, 41);
        }
        *upstream.module_conf_mut::<TestServerModule>()?.unwrap() = 42;
        Ok(Status::NGX_OK.0)
    }
}

struct DelegatePeerInit;

impl HttpUpstreamPeerHandler for DelegatePeerInit {
    type Data = ();

    fn init(
        request: &mut RequestRefMut<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        let status = upstream.init_peer().call(request, upstream)?;
        Ok(UpstreamPeerInit::Return(status))
    }

    fn get(
        _peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut HttpUpstreamPeerData<Self::Data>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        Ok(Status::NGX_ERROR.0)
    }

    fn free(
        _peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut HttpUpstreamPeerData<Self::Data>,
        _state: UpstreamPeerState,
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
    CALLBACK_ORDER.fetch_add(1, Ordering::Relaxed);
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

struct OrderedPeer;

impl HttpUpstreamPeerHandler for OrderedPeer {
    type Data = ();

    fn init(
        request: &mut RequestRefMut<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        let status = upstream.init_peer().call(request, upstream)?;
        if status == Status::NGX_OK.0 {
            Ok(UpstreamPeerInit::Install(()))
        } else {
            Ok(UpstreamPeerInit::Return(status))
        }
    }

    fn get(
        peer: &mut UpstreamPeerConnection<'_>,
        data: &mut HttpUpstreamPeerData<Self::Data>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        data.delegate_get(peer)
    }

    fn free(
        peer: &mut UpstreamPeerConnection<'_>,
        data: &mut HttpUpstreamPeerData<Self::Data>,
        state: UpstreamPeerState,
    ) -> Result<(), UpstreamCallbackError> {
        data.delegate_free(peer, state)
    }
}

struct MissingOriginalPeer;

impl HttpUpstreamPeerHandler for MissingOriginalPeer {
    type Data = ();

    fn init(
        _request: &mut RequestRefMut<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        Ok(UpstreamPeerInit::Install(()))
    }

    fn get(
        peer: &mut UpstreamPeerConnection<'_>,
        data: &mut HttpUpstreamPeerData<Self::Data>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        data.delegate_get(peer)
    }

    fn free(
        peer: &mut UpstreamPeerConnection<'_>,
        data: &mut HttpUpstreamPeerData<Self::Data>,
        state: UpstreamPeerState,
    ) -> Result<(), UpstreamCallbackError> {
        data.delegate_free(peer, state)
    }
}

struct PanicPeer;

impl HttpUpstreamPeerHandler for PanicPeer {
    type Data = ();

    fn init(
        _request: &mut RequestRefMut<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        Ok(UpstreamPeerInit::Install(()))
    }

    fn get(
        _peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut HttpUpstreamPeerData<Self::Data>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        panic!("peer getter panic")
    }

    fn free(
        _peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut HttpUpstreamPeerData<Self::Data>,
        _state: UpstreamPeerState,
    ) -> Result<(), UpstreamCallbackError> {
        panic!("peer releaser panic")
    }
}

#[cfg(feature = "std")]
struct PanicInitializer;

#[cfg(feature = "std")]
impl HttpUpstreamInitializer for PanicInitializer {
    fn init(
        _configuration: &mut UpstreamConfiguration<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        panic!("upstream initializer panic")
    }
}

#[cfg(feature = "std")]
struct PanicPeerInitializer;

#[cfg(feature = "std")]
impl HttpUpstreamPeerHandler for PanicPeerInitializer {
    type Data = ();

    fn init(
        _request: &mut RequestRefMut<'_>,
        _upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        panic!("peer initializer panic")
    }

    fn get(
        _peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut HttpUpstreamPeerData<Self::Data>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        Ok(Status::NGX_ERROR.0)
    }

    fn free(
        _peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut HttpUpstreamPeerData<Self::Data>,
        _state: UpstreamPeerState,
    ) -> Result<(), UpstreamCallbackError> {
        Ok(())
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
fn upstream_initializer_preserves_saved_callback_and_rejects_invalid_inputs() {
    ORIGINAL_INIT_UPSTREAM_CALLS.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    let mut upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    upstream.peer.init_upstream = Some(busy_init_upstream);

    let saved = install_upstream_initializer::<DecliningInitializer>(&mut upstream);
    assert!(saved.is_present());
    let mut configuration_view =
        unsafe { UpstreamConfiguration::from_raw(&raw mut configuration) }.unwrap();
    let mut upstream_view = unsafe { UpstreamServerConf::from_raw(&raw mut upstream) }.unwrap();
    assert_eq!(saved.call(&mut configuration_view, &mut upstream_view).unwrap(), NGX_BUSY as _);
    assert_eq!(ORIGINAL_INIT_UPSTREAM_CALLS.load(Ordering::Relaxed), 1);

    let callback = upstream.peer.init_upstream.unwrap();
    assert_eq!(unsafe { callback(&raw mut configuration, &raw mut upstream) }, NGX_DECLINED as _);
    assert_eq!(
        unsafe { raw_init_upstream::<DecliningInitializer>(ptr::null_mut(), &raw mut upstream) },
        NGX_ERROR as _
    );
    assert_eq!(
        unsafe {
            raw_init_upstream::<DecliningInitializer>(
                ptr::without_provenance_mut::<ngx_conf_t>(1),
                &raw mut upstream,
            )
        },
        NGX_ERROR as _
    );
}

#[test]
fn upstream_initializer_reads_and_mutates_typed_server_configuration() {
    let _slots = HttpSlotCounts::one();
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    let mut module_configuration = 41_u32;
    let mut slots: [*mut c_void; 1] = [(&raw mut module_configuration).cast()];
    let mut upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    upstream.srv_conf = slots.as_mut_ptr();

    install_upstream_initializer::<TypedConfigurationInitializer>(&mut upstream);
    let callback = upstream.peer.init_upstream.unwrap();
    assert_eq!(unsafe { callback(&raw mut configuration, &raw mut upstream) }, Status::NGX_OK.0);
    assert_eq!(module_configuration, 42);
}

#[test]
fn upstream_initializer_delegates_and_validates_each_owner() {
    DELEGATED_INIT_UPSTREAM_CALLS.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    let mut upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    upstream.peer.init_upstream = Some(busy_init_upstream);

    assert_eq!(
        unsafe {
            raw_init_upstream::<DelegatingInitializer>(&raw mut configuration, &raw mut upstream)
        },
        NGX_BUSY as _
    );
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
    assert_eq!(
        unsafe { raw_init_upstream::<PoolInitializer>(&raw mut missing_pool, &raw mut upstream) },
        NGX_ERROR as _
    );

    let mut no_original =
        unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    assert_eq!(
        unsafe {
            raw_init_upstream::<MissingOriginalInitializer>(
                &raw mut configuration,
                &raw mut no_original,
            )
        },
        NGX_ERROR as _
    );
}

#[test]
fn peer_initializer_preserves_an_original_non_ok_status() {
    ORIGINAL_INIT_PEER_CALLS.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);

    let mut server = unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    server.peer.init = Some(declined_init_peer);

    assert_eq!(
        unsafe { raw_init_peer::<DelegatePeerInit>(&raw mut request, &raw mut server) },
        NGX_DECLINED as _
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
fn peer_callbacks_delegate_in_order_and_restore_typed_data() {
    CALLBACK_ORDER.store(0, Ordering::Relaxed);
    OBSERVED_GET_PEER_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_GET_CALLBACK_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_FREE_PEER_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_FREE_CALLBACK_DATA.store(ptr::null_mut(), Ordering::Relaxed);
    OBSERVED_FREE_STATE.store(0, Ordering::Relaxed);
    let pool = TestPool::new();
    let mut original_data = 7_u8;
    let original_data = ptr::from_mut(&mut original_data).cast::<c_void>();
    ORIGINAL_DATA.store(original_data, Ordering::Relaxed);

    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    server.peer.init = Some(ordered_init_peer);

    assert_eq!(
        unsafe { raw_init_peer::<OrderedPeer>(&raw mut request, &raw mut server) },
        Status::NGX_OK.0
    );
    let typed_data = request_upstream.peer.data;
    assert_ne!(typed_data, original_data);
    assert_eq!(CALLBACK_ORDER.load(Ordering::Relaxed), 1);

    assert_eq!(
        unsafe { raw_get_peer::<OrderedPeer>(&raw mut request_upstream.peer, typed_data) },
        NGX_BUSY as _
    );
    assert_eq!(OBSERVED_GET_PEER_DATA.load(Ordering::Relaxed), original_data);
    assert_eq!(OBSERVED_GET_CALLBACK_DATA.load(Ordering::Relaxed), original_data);
    assert_eq!(request_upstream.peer.data, typed_data);

    let state = 0x5a_u32 as ngx_uint_t;
    unsafe { raw_free_peer::<OrderedPeer>(&raw mut request_upstream.peer, typed_data, state) };
    assert_eq!(OBSERVED_FREE_PEER_DATA.load(Ordering::Relaxed), original_data);
    assert_eq!(OBSERVED_FREE_CALLBACK_DATA.load(Ordering::Relaxed), original_data);
    assert_eq!(OBSERVED_FREE_STATE.load(Ordering::Relaxed), state as usize);
    assert_eq!(request_upstream.peer.data, typed_data);
    assert_eq!(CALLBACK_ORDER.load(Ordering::Relaxed), 3);
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
    let mut server = unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut server) },
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
    let mut server = unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    assert_eq!(
        unsafe {
            raw_init_upstream::<MissingOriginalInitializer>(&raw mut configuration, &raw mut server)
        },
        NGX_ERROR as _
    );
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
    assert_eq!(
        unsafe { raw_init_peer::<DelegatePeerInit>(&raw mut request, &raw mut server) },
        NGX_ERROR as _
    );
    assert_single_record(&capture, NGX_LOG_ERR as _, b"HTTP upstream peer initialization failed");

    capture.records.clear();
    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut server) },
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
fn peer_callback_adapters_reject_mismatched_or_misaligned_typed_data() {
    let pool = TestPool::new();
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    let mut server = unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_init_peer::<MissingOriginalPeer>(&raw mut request, &raw mut server) },
        Status::NGX_OK.0
    );
    let typed_data = request_upstream.peer.data;

    request_upstream.peer.data = ptr::null_mut();
    assert_eq!(
        unsafe { raw_get_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, typed_data) },
        NGX_ERROR as _
    );
    unsafe { raw_free_peer::<MissingOriginalPeer>(&raw mut request_upstream.peer, typed_data, 0) };

    let invalid_data = ptr::without_provenance_mut::<c_void>(1);
    request_upstream.peer.data = invalid_data;
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

#[cfg(feature = "std")]
#[test]
fn upstream_callback_adapters_log_rust_panics_once_before_returning_nginx_errors() {
    let pool = TestPool::new();
    let mut capture = LogCapture::default();
    let mut log = unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() };
    attach_log(&mut log, &mut capture);
    let mut configuration = unsafe { MaybeUninit::<ngx_conf_t>::zeroed().assume_init() };
    configuration.pool = pool.raw;
    configuration.log = &raw mut log;
    let mut init_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };
    assert_eq!(
        unsafe {
            raw_init_upstream::<PanicInitializer>(&raw mut configuration, &raw mut init_upstream)
        },
        NGX_ERROR as _
    );
    assert_single_record(
        &capture,
        crate::ffi::NGX_LOG_EMERG as _,
        b"HTTP upstream initialization failed: upstream callback panicked",
    );

    capture.records.clear();
    let mut connection = unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() };
    connection.log = &raw mut log;
    let mut request_upstream =
        unsafe { MaybeUninit::<ngx_http_upstream_t>::zeroed().assume_init() };
    let mut request = unsafe { MaybeUninit::<ngx_http_request_t>::zeroed().assume_init() };
    initialized_request(&pool, &mut request, &mut request_upstream);
    request.connection = &raw mut connection;
    let mut server = unsafe { MaybeUninit::<ngx_http_upstream_srv_conf_t>::zeroed().assume_init() };

    assert_eq!(
        unsafe { raw_init_peer::<PanicPeerInitializer>(&raw mut request, &raw mut server) },
        NGX_ERROR as _
    );
    assert!(request_upstream.peer.data.is_null());
    assert!(request_upstream.peer.get.is_none());
    assert!(request_upstream.peer.free.is_none());
    assert_single_record(
        &capture,
        NGX_LOG_ERR as _,
        b"HTTP upstream peer initialization failed: upstream callback panicked",
    );

    capture.records.clear();
    assert_eq!(
        unsafe { raw_init_peer::<PanicPeer>(&raw mut request, &raw mut server) },
        Status::NGX_OK.0
    );
    request_upstream.peer.log = &raw mut log;
    let typed_data = request_upstream.peer.data;
    assert_eq!(
        unsafe { raw_get_peer::<PanicPeer>(&raw mut request_upstream.peer, typed_data) },
        NGX_ERROR as _
    );
    assert_single_record(
        &capture,
        NGX_LOG_ERR as _,
        b"HTTP upstream peer selection failed: upstream callback panicked",
    );

    capture.records.clear();
    unsafe { raw_free_peer::<PanicPeer>(&raw mut request_upstream.peer, typed_data, 0) };
    assert_eq!(request_upstream.peer.data, typed_data);
    assert_single_record(
        &capture,
        NGX_LOG_ERR as _,
        b"HTTP upstream peer release failed: upstream callback panicked",
    );
}
