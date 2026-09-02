#[cfg(feature = "test-link")]
use ::core::ffi::c_int;
use ::core::ffi::c_void;
#[cfg(feature = "test-link")]
use ::core::mem;
#[cfg(feature = "test-link")]
use ::core::ptr;
#[cfg(feature = "test-link")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "test-link")]
use std::sync::MutexGuard;

use super::{
    HttpConfigError, HttpConfigurationParser, HttpModuleLocationConf, HttpModuleMainConf,
    HttpModuleServerConf, module_indexes,
};
use crate::core::{ModuleDescriptor, Status};
use crate::ffi::{NGX_CORE_MODULE, NGX_HTTP_MODULE, ngx_http_conf_ctx_t, ngx_module_t, ngx_uint_t};
#[cfg(feature = "test-link")]
use crate::ffi::{NGX_OK, ngx_conf_t, ngx_cycle_t, ngx_http_request_t, ngx_int_t};
use crate::http::{HttpModule, ProcessCycle, RequestRefMut, exit_process, init_process};

#[cfg(feature = "test-link")]
unsafe extern "C" {
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
}

fn http_module(index: ngx_uint_t, context_index: ngx_uint_t) -> ngx_module_t {
    let mut module = ngx_module_t::default();
    module.type_ = NGX_HTTP_MODULE as _;
    module.index = index;
    module.ctx_index = context_index;
    module
}

#[cfg(feature = "test-link")]
fn native_http_module_lifecycle_succeeds() -> bool {
    let raw = core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module);
    let Some(descriptor) = (unsafe { ModuleDescriptor::from_raw(raw) }) else {
        return false;
    };
    if !matches!(
        module_indexes(descriptor, usize::MAX, usize::MAX),
        Err(HttpConfigError::UnsetModuleIndex)
    ) {
        return false;
    }
    if unsafe { nginx_sys::ngx_preinit_modules() } != NGX_OK as ngx_int_t {
        return false;
    }

    let mut modules = [raw, ptr::null_mut()];
    let mut first_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    first_cycle.modules = modules.as_mut_ptr();
    let http_slots = unsafe {
        nginx_sys::ngx_count_modules(&raw mut first_cycle, NGX_HTTP_MODULE as ngx_uint_t)
    };
    let Ok(http_slots) = usize::try_from(http_slots) else {
        return false;
    };
    let module_slots = unsafe { nginx_sys::ngx_max_module };
    let first = unsafe { descriptor.snapshot() };
    if module_indexes(descriptor, module_slots, http_slots).is_err() {
        return false;
    }

    let mut reload_modules = [raw, ptr::null_mut()];
    let mut reload_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
    reload_cycle.modules = reload_modules.as_mut_ptr();
    reload_cycle.old_cycle = &raw mut first_cycle;
    let reload_slots = unsafe {
        nginx_sys::ngx_count_modules(&raw mut reload_cycle, NGX_HTTP_MODULE as ngx_uint_t)
    };
    let Ok(reload_slots) = usize::try_from(reload_slots) else {
        return false;
    };
    let reloaded = unsafe { descriptor.snapshot() };

    reload_slots == http_slots
        && first.index == reloaded.index
        && first.context_index == reloaded.context_index
        && module_indexes(descriptor, module_slots, reload_slots).is_ok()
}

fn test_module() -> ModuleDescriptor {
    ModuleDescriptor::from_test(http_module(1, 0))
}

struct TestHttpModule;

unsafe impl HttpModule for TestHttpModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }
}

unsafe impl HttpModuleMainConf for TestHttpModule {
    type MainConf = u32;
}

unsafe impl HttpModuleServerConf for TestHttpModule {
    type ServerConf = u32;
}

unsafe impl HttpModuleLocationConf for TestHttpModule {
    type LocationConf = u32;
}

#[cfg(feature = "test-link")]
static PROCESS_INIT_TOTAL: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-link")]
static PROCESS_EXIT_TOTAL: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-link")]
struct ProcessModule;

#[cfg(feature = "test-link")]
unsafe impl HttpModule for ProcessModule {
    fn module() -> ModuleDescriptor {
        test_module()
    }

    fn init_process(cycle: ProcessCycle<'_>) -> ngx_int_t {
        match cycle.main_conf::<Self>() {
            Ok(Some(configuration)) => {
                PROCESS_INIT_TOTAL.fetch_add(*configuration as usize, Ordering::Relaxed);
                Status::NGX_OK.0
            }
            Ok(None) => Status::NGX_OK.0,
            Err(_) => Status::NGX_ERROR.0,
        }
    }

    fn exit_process(cycle: ProcessCycle<'_>) {
        if let Ok(Some(configuration)) = cycle.main_conf::<Self>() {
            PROCESS_EXIT_TOTAL.fetch_add(*configuration as usize, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "test-link")]
unsafe impl HttpModuleMainConf for ProcessModule {
    type MainConf = u32;
}

fn wrong_type_module() -> ModuleDescriptor {
    ModuleDescriptor::from_test(ngx_module_t { index: 0, ctx_index: 0, ..ngx_module_t::default() })
}

struct WrongTypeModule;

unsafe impl HttpModule for WrongTypeModule {
    fn module() -> ModuleDescriptor {
        wrong_type_module()
    }
}

unsafe impl HttpModuleMainConf for WrongTypeModule {
    type MainConf = u32;
}

#[cfg(feature = "test-link")]
struct GlobalState {
    cycle: *mut ngx_cycle_t,
    max_module: ngx_uint_t,
    http_max_module: ngx_uint_t,
    http_module_type: ngx_uint_t,
    http_module_index: ngx_uint_t,
    http_core_module_type: ngx_uint_t,
    http_core_module_index: ngx_uint_t,
    http_core_module_context_index: ngx_uint_t,
}

#[cfg(feature = "test-link")]
struct HttpGlobals {
    _guard: MutexGuard<'static, ()>,
    previous: GlobalState,
}

#[cfg(feature = "test-link")]
impl HttpGlobals {
    fn new(module_slots: ngx_uint_t, http_slots: ngx_uint_t) -> Self {
        let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe {
            GlobalState {
                cycle: nginx_sys::ngx_cycle,
                max_module: nginx_sys::ngx_max_module,
                http_max_module: nginx_sys::ngx_http_max_module,
                http_module_type: (*::core::ptr::addr_of!(nginx_sys::ngx_http_module)).type_,
                http_module_index: (*::core::ptr::addr_of!(nginx_sys::ngx_http_module)).index,
                http_core_module_type: (*::core::ptr::addr_of!(nginx_sys::ngx_http_core_module))
                    .type_,
                http_core_module_index: (*::core::ptr::addr_of!(nginx_sys::ngx_http_core_module))
                    .index,
                http_core_module_context_index: (*::core::ptr::addr_of!(
                    nginx_sys::ngx_http_core_module
                ))
                .ctx_index,
            }
        };

        unsafe {
            nginx_sys::ngx_cycle = ptr::null_mut();
            nginx_sys::ngx_max_module = module_slots;
            nginx_sys::ngx_http_max_module = http_slots;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).type_ = NGX_CORE_MODULE as _;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index = 0;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).type_ =
                NGX_HTTP_MODULE as _;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).index = 0;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).ctx_index = 0;
        }

        Self { _guard: guard, previous }
    }

    fn set_active_cycle(&self, cycle: *mut ngx_cycle_t) {
        unsafe {
            nginx_sys::ngx_cycle = cycle;
        }
    }

    fn set_http_module_index(&self, index: ngx_uint_t) {
        unsafe {
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index = index;
        }
    }

    fn set_http_module_type(&self, type_: ngx_uint_t) {
        unsafe {
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).type_ = type_;
        }
    }

    fn set_http_core_module(
        &self,
        type_: ngx_uint_t,
        index: ngx_uint_t,
        context_index: ngx_uint_t,
    ) {
        unsafe {
            let module = &raw mut nginx_sys::ngx_http_core_module;
            (*module).type_ = type_;
            (*module).index = index;
            (*module).ctx_index = context_index;
        }
    }
}

#[cfg(feature = "test-link")]
impl Drop for HttpGlobals {
    fn drop(&mut self) {
        unsafe {
            nginx_sys::ngx_cycle = self.previous.cycle;
            nginx_sys::ngx_max_module = self.previous.max_module;
            nginx_sys::ngx_http_max_module = self.previous.http_max_module;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).type_ =
                self.previous.http_module_type;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index =
                self.previous.http_module_index;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).type_ =
                self.previous.http_core_module_type;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).index =
                self.previous.http_core_module_index;
            (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_core_module)).ctx_index =
                self.previous.http_core_module_context_index;
        }
    }
}

mod access;
mod cycle;
mod phase;
