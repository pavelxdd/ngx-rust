extern crate alloc;

use alloc::string::ToString;
use core::ffi::{c_char, c_void};
use core::ptr::{self, NonNull};
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

unsafe impl http::HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_async_module) }
    }

    fn postconfigure(cf: &mut ngx_conf_t) -> ngx_int_t {
        http::add_async_phase_handler::<AsyncAccessHandler>(cf)
            .map_or(Status::NGX_ERROR.0, |_| Status::NGX_OK.0)
    }

    fn init_process(cycle: http::ProcessCycle<'_>) -> ngx_int_t {
        if ngx::log::interop::init().is_err() {
            return Status::NGX_ERROR.0;
        }

        let log = unsafe { NonNull::new((*cycle.as_ptr()).log) };
        let Some(log) = log else {
            return Status::NGX_ERROR.0;
        };
        if ngx_async::init_worker(log).is_err() {
            return Status::NGX_ERROR.0;
        }

        log::info!("async log facade initialized");
        Status::NGX_OK.0
    }

    fn exit_process(_cycle: http::ProcessCycle<'_>) {
        let _ = ngx_async::shutdown_worker();
    }
}

#[derive(Debug, Default)]
struct ModuleConfig {
    enable: Option<bool>,
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
    preconfiguration: Some(http::preconfiguration::<Module>),
    postconfiguration: Some(http::postconfiguration::<Module>),
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
    init_process: Some(http::init_process::<Module>),
    exit_process: Some(http::exit_process::<Module>),
    ..ngx_module_t::default()
};

impl http::Merge for ModuleConfig {
    fn merge(&mut self, prev: &ModuleConfig) -> Result<(), MergeConfigError> {
        self.enable = self.enable.or(prev.enable).or(Some(false));
        Ok(())
    }
}

unsafe impl HttpModuleRequestContext for Module {
    type RequestContext = AsyncHandlerContext<AsyncAccessHandler>;
}

struct AsyncAccessHandler;

#[cfg(not(windows))]
mod thread_wake {
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use core::time::Duration;
    use std::sync::Mutex;
    use std::thread;

    pub(super) struct ThreadWake {
        state: Arc<Mutex<ThreadWakeState>>,
    }

    #[derive(Default)]
    struct ThreadWakeState {
        ready: bool,
        waker: Option<Waker>,
    }

    impl ThreadWake {
        pub(super) fn new() -> Self {
            let state = Arc::new(Mutex::new(ThreadWakeState::default()));
            let thread_state = Arc::clone(&state);
            let _thread = thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                let waker = {
                    let mut state = thread_state.lock().unwrap_or_else(|error| error.into_inner());
                    state.ready = true;
                    state.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
            });

            Self { state }
        }
    }

    impl Future for ThreadWake {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.ready {
                return Poll::Ready(());
            }

            if state.waker.as_ref().is_none_or(|waker| !waker.will_wake(context.waker())) {
                state.waker = Some(context.waker().clone());
            }
            Poll::Pending
        }
    }
}

#[cfg(not(windows))]
use thread_wake::ThreadWake;

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
        request: &mut http::RequestRefMut<'_>,
    ) -> impl core::future::Future<Output = Self::Output> + 'static {
        let enabled = Module::location_conf(request)
            .map_err(|_| SubRequestError::Create(Status::NGX_ERROR.into()))
            .and_then(|configuration| {
                configuration
                    .map(|configuration| configuration.enable.unwrap_or(false))
                    .ok_or(SubRequestError::Create(Status::NGX_ERROR.into()))
            });
        let subrequest = match enabled {
            Ok(enabled) => {
                ngx_log_debug_http!(request, "async module enabled: {enabled}");
                Ok(enabled.then(|| {
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
                }))
            }
            Err(error) => Err(error),
        };

        async move {
            let subrequest = subrequest?;
            let Some(subrequest) = subrequest else {
                return Ok(None);
            };
            let (started, subrequest) = subrequest?;
            let subrequest_status = subrequest.await?;

            ngx_async::sleep(Duration::from_millis(10)).await;
            // nginx's IOCP event module has no cross-thread notification hook.
            #[cfg(not(windows))]
            ThreadWake::new().await;
            Ok(Some(AsyncOutput { elapsed: started.elapsed().as_millis(), subrequest_status }))
        }
    }

    fn finish(request: &mut http::RequestRefMut<'_>, output: Self::Output) -> Self::Result {
        let output = match output {
            Ok(Some(output)) => output,
            Ok(None) => return Status::NGX_DECLINED,
            Err(_) => return Status::NGX_ERROR,
        };
        let Some(subrequest_status) = output.subrequest_status else {
            return Status::NGX_ERROR;
        };

        let elapsed = output.elapsed.to_string();
        if request.add_header_out("X-Async-Time", &elapsed).is_err() {
            return Status::NGX_ERROR;
        }
        let subrequest_status = subrequest_status.0.to_string();
        if request.add_header_out("X-Async-Subrequest-Status", &subrequest_status).is_err() {
            return Status::NGX_ERROR;
        }
        #[cfg(not(windows))]
        {
            if request.add_header_out("X-Async-Thread-Wake", "1").is_err() {
                return Status::NGX_ERROR;
            }
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

        if val.eq_ignore_ascii_case("on") {
            conf.enable = Some(true);
        } else if val.eq_ignore_ascii_case("off") {
            conf.enable = Some(false);
        } else {
            ngx_conf_log_error!(NGX_LOG_EMERG, cf, "invalid value \"{val}\" in `async` directive");
            return ngx::core::NGX_CONF_ERROR;
        }
    };

    ngx::core::NGX_CONF_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_disabled_child_overrides_enabled_parent() {
        let parent = ModuleConfig { enable: Some(true) };
        let mut child = ModuleConfig { enable: Some(false) };

        http::Merge::merge(&mut child, &parent).unwrap();

        assert_eq!(child.enable, Some(false));
    }

    #[test]
    fn unset_child_inherits_parent() {
        let parent = ModuleConfig { enable: Some(true) };
        let mut child = ModuleConfig::default();

        http::Merge::merge(&mut child, &parent).unwrap();

        assert_eq!(child.enable, Some(true));
    }
}
