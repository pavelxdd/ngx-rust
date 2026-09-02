extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::ffi::c_void;
use core::mem;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::{
    HttpModule, InitMainConf, Merge, MergeConfigError, ProcessCycle, exit_process, init_process,
    postconfiguration, preconfiguration,
};
use crate::core::{ModuleDescriptor, NGX_CONF_ERROR, Status};
#[cfg(feature = "test-link")]
use crate::ffi::{
    NGX_LOG_EMERG, ngx_create_pool, ngx_destroy_pool, ngx_log_t, ngx_pool_t, ngx_uint_t,
};
use crate::ffi::{ngx_conf_t, ngx_cycle_t, ngx_int_t, ngx_module_t};
use crate::http::{HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf};

#[cfg(feature = "test-link")]
unsafe extern "C" {
    fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
    fn ngx_rs_test_reset_allocation_failures();
}

#[cfg(feature = "test-link")]
#[derive(Default)]
struct ConfigLogCapture {
    records: Vec<(ngx_uint_t, Vec<u8>)>,
}

#[cfg(feature = "test-link")]
unsafe extern "C" fn capture_config_log(
    log: *mut ngx_log_t,
    level: ngx_uint_t,
    bytes: *mut u8,
    len: usize,
) {
    let Some(log) = (unsafe { log.as_mut() }) else {
        return;
    };
    let Some(capture) = (unsafe { log.wdata.cast::<ConfigLogCapture>().as_mut() }) else {
        return;
    };
    if bytes.is_null() {
        return;
    }
    capture.records.push((level, unsafe { slice::from_raw_parts(bytes, len) }.to_vec()));
}

fn test_module() -> ModuleDescriptor {
    ModuleDescriptor::from_test(ngx_module_t::default())
}

#[derive(Default)]
struct MainConf {
    initialized: bool,
    _alignment: u32,
}

impl InitMainConf for MainConf {
    fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
        self.initialized = true;
        Ok(())
    }
}

#[derive(Default)]
struct ServerConf(u32);

impl Merge for ServerConf {
    fn merge(&mut self, parent: &Self) -> Result<(), MergeConfigError> {
        self.0 += parent.0;
        Ok(())
    }
}

#[derive(Default)]
struct LocationConf(u32);

impl Merge for LocationConf {
    fn merge(&mut self, parent: &Self) -> Result<(), MergeConfigError> {
        self.0 += parent.0;
        Ok(())
    }
}

struct TestHttpModule;

unsafe impl HttpModule for TestHttpModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }
}

static PROCESS_STARTS: AtomicUsize = AtomicUsize::new(0);
static PROCESS_STOPS: AtomicUsize = AtomicUsize::new(0);

struct ProcessModule;

unsafe impl HttpModule for ProcessModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }

    fn init_process(_cycle: ProcessCycle<'_>) -> ngx_int_t {
        PROCESS_STARTS.fetch_add(1, Ordering::Relaxed);
        Status::NGX_OK.0
    }

    fn exit_process(_cycle: ProcessCycle<'_>) {
        PROCESS_STOPS.fetch_add(1, Ordering::Relaxed);
    }
}

struct FailingProcessModule;

unsafe impl HttpModule for FailingProcessModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }

    fn init_process(_cycle: ProcessCycle<'_>) -> ngx_int_t {
        Status::NGX_ERROR.0
    }
}

unsafe impl HttpModuleMainConf for TestHttpModule {
    type MainConf = MainConf;
}

unsafe impl HttpModuleServerConf for TestHttpModule {
    type ServerConf = ServerConf;
}

unsafe impl HttpModuleLocationConf for TestHttpModule {
    type LocationConf = LocationConf;
}

struct RejectMainConf;

impl InitMainConf for RejectMainConf {
    fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
        Err(MergeConfigError::NoValue)
    }
}

struct RejectMainModule;

unsafe impl HttpModule for RejectMainModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }
}

unsafe impl HttpModuleMainConf for RejectMainModule {
    type MainConf = RejectMainConf;
}

struct RejectServerConf;

impl Merge for RejectServerConf {
    fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
        Err(MergeConfigError::Message(c"server rejected"))
    }
}

struct RejectServerModule;

unsafe impl HttpModule for RejectServerModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }
}

unsafe impl HttpModuleServerConf for RejectServerModule {
    type ServerConf = RejectServerConf;
}

struct RejectLocationConf;

impl Merge for RejectLocationConf {
    fn merge(&mut self, _parent: &Self) -> Result<(), MergeConfigError> {
        Err(MergeConfigError::Message(c"location rejected"))
    }
}

struct RejectLocationModule;

unsafe impl HttpModule for RejectLocationModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }
}

unsafe impl HttpModuleLocationConf for RejectLocationModule {
    type LocationConf = RejectLocationConf;
}

#[cfg(feature = "test-link")]
static MAIN_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static SERVER_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static LOCATION_CONF_DROPS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
#[derive(Default)]
struct AllocatedMainConf {
    initialized: bool,
}

#[cfg(feature = "test-link")]
impl InitMainConf for AllocatedMainConf {
    fn init_main_conf(&mut self) -> Result<(), MergeConfigError> {
        self.initialized = true;
        Ok(())
    }
}

#[cfg(feature = "test-link")]
impl Drop for AllocatedMainConf {
    fn drop(&mut self) {
        MAIN_CONF_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
#[derive(Default)]
struct AllocatedServerConf;

#[cfg(feature = "test-link")]
impl Drop for AllocatedServerConf {
    fn drop(&mut self) {
        SERVER_CONF_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
#[derive(Default)]
struct AllocatedLocationConf;

#[cfg(feature = "test-link")]
impl Drop for AllocatedLocationConf {
    fn drop(&mut self) {
        LOCATION_CONF_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "test-link")]
struct AllocationHttpModule;

#[cfg(feature = "test-link")]
unsafe impl HttpModule for AllocationHttpModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleMainConf for AllocationHttpModule {
    type MainConf = AllocatedMainConf;
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleServerConf for AllocationHttpModule {
    type ServerConf = AllocatedServerConf;
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleLocationConf for AllocationHttpModule {
    type LocationConf = AllocatedLocationConf;
}

#[cfg(feature = "test-link")]
struct TestPool {
    raw: *mut ngx_pool_t,
    _log: Box<ngx_log_t>,
}

#[cfg(feature = "test-link")]
impl TestPool {
    fn new() -> Self {
        let mut log = Box::new(unsafe { mem::zeroed::<ngx_log_t>() });
        let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!raw.is_null());
        Self { raw, _log: log }
    }

    fn configuration(&self) -> ngx_conf_t {
        let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
        configuration.pool = self.raw;
        configuration.log = (&raw const *self._log).cast_mut();
        configuration
    }
}

#[cfg(feature = "test-link")]
impl Drop for TestPool {
    fn drop(&mut self) {
        unsafe { ngx_destroy_pool(self.raw) };
    }
}

#[cfg(feature = "test-link")]
#[repr(align(64))]
#[derive(Default)]
struct OverAlignedConf;

#[cfg(feature = "test-link")]
struct OverAlignedHttpModule;

#[cfg(feature = "test-link")]
unsafe impl HttpModule for OverAlignedHttpModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleMainConf for OverAlignedHttpModule {
    type MainConf = OverAlignedConf;
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleServerConf for OverAlignedHttpModule {
    type ServerConf = OverAlignedConf;
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleLocationConf for OverAlignedHttpModule {
    type LocationConf = OverAlignedConf;
}

mod configuration;
mod process;
