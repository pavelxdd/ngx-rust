extern crate alloc;

use alloc::string::ToString;
use core::ffi::{c_char, c_void};
use core::ptr;
use core::time::Duration;
use std::time::Instant;

use ngx::core::Status;
use ngx::ffi::{
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MODULE, NGX_LOG_EMERG,
    ngx_command_t, ngx_conf_t, ngx_http_module_t, ngx_int_t, ngx_module_t, ngx_str_t, ngx_uint_t,
};
use ngx::http::subrequest::{SubRequestBuilder, SubRequestError};
use ngx::http::{
    self, AsyncHandlerContext, AsyncHttpRequestHandler, HTTPStatus, HttpModule,
    HttpModuleLocationConf, HttpModuleRequestContext, MergeConfigError,
};
use ngx::{async_ as ngx_async, ngx_conf_log_error, ngx_log_debug_http, ngx_string};

struct Module;

impl http::HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_async_module) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        // SAFETY: this function is called with non-NULL cf always
        let cf = unsafe { &mut *cf };
        http::add_async_phase_handler::<AsyncAccessHandler>(cf)
            .map_or(Status::NGX_ERROR, |_| Status::NGX_OK)
            .into()
    }
}

#[derive(Debug, Default)]
struct ModuleConfig {
    enable: bool,
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = ModuleConfig;
}

static mut NGX_HTTP_ASYNC_COMMANDS: [ngx_command_t; 2] = [
    ngx_command_t {
        name: ngx_string!("async"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_async_commands_set_enable),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

static NGX_HTTP_ASYNC_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

// Generate the `ngx_modules` table with exported modules.
// This feature is required to build a 'cdylib' dynamic module outside of the NGINX buildsystem.
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_async_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_async_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_ASYNC_MODULE_CTX as _,
    commands: unsafe { &raw mut NGX_HTTP_ASYNC_COMMANDS[0] },
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

impl http::Merge for ModuleConfig {
    fn merge(&mut self, prev: &ModuleConfig) -> Result<(), MergeConfigError> {
        if prev.enable {
            self.enable = true;
        };
        Ok(())
    }
}

unsafe impl HttpModuleRequestContext for Module {
    type RequestContext = AsyncHandlerContext<AsyncAccessHandler>;
}

struct AsyncAccessHandler;

struct AsyncOutput {
    elapsed: u128,
    subrequest_status: Option<HTTPStatus>,
}

impl AsyncHttpRequestHandler for AsyncAccessHandler {
    const PHASE: ngx::http::HttpPhase = ngx::http::HttpPhase::Access;
    type Module = Module;
    type Output = Result<Option<AsyncOutput>, SubRequestError>;
    type Result = Status;

    fn start(
        request: &mut http::Request,
    ) -> impl core::future::Future<Output = Self::Output> + 'static {
        let co = Module::location_conf(request).expect("module config is none");
        ngx_log_debug_http!(request, "async module enabled: {}", co.enable);
        let enabled = co.enable;
        let subrequest = enabled.then(|| {
            let started = Instant::now();
            SubRequestBuilder::new(request, "/async-target")
                .and_then(|builder| {
                    builder.waited().build_async(|subrequest, completion_status| {
                        let status = subrequest
                            .status()
                            .or_else(|| HTTPStatus::try_from(completion_status).ok());
                        (status, Status::NGX_OK)
                    })
                })
                .map(|(future, _)| (started, future))
        });

        async move {
            let Some(subrequest) = subrequest else {
                return Ok(None);
            };
            let (started, subrequest) = subrequest?;
            let subrequest_status = subrequest.await?;

            ngx_async::sleep(Duration::from_millis(10)).await;
            Ok(Some(AsyncOutput { elapsed: started.elapsed().as_millis(), subrequest_status }))
        }
    }

    fn finish(request: &mut http::Request, output: Self::Output) -> Self::Result {
        let output = match output {
            Ok(Some(output)) => output,
            Ok(None) => return Status::NGX_DECLINED,
            Err(_) => return Status::NGX_ERROR,
        };
        let Some(subrequest_status) = output.subrequest_status else {
            return Status::NGX_ERROR;
        };

        let elapsed = output.elapsed.to_string();
        if request.add_header_out("X-Async-Time", &elapsed).is_none() {
            return Status::NGX_ERROR;
        }
        let subrequest_status = subrequest_status.0.to_string();
        if request.add_header_out("X-Async-Subrequest-Status", &subrequest_status).is_none() {
            return Status::NGX_ERROR;
        }
        Status::NGX_OK
    }
}

extern "C" fn ngx_http_async_commands_set_enable(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args: &[ngx_str_t] = (*(*cf).args).as_slice();
        let val = match args[1].to_str() {
            Ok(s) => s,
            Err(_) => {
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "`async` argument is not utf-8 encoded");
                return ngx::core::NGX_CONF_ERROR;
            }
        };

        // set default value optionally
        conf.enable = false;

        if val.eq_ignore_ascii_case("on") {
            conf.enable = true;
        } else if val.eq_ignore_ascii_case("off") {
            conf.enable = false;
        }
    };

    ngx::core::NGX_CONF_OK
}
