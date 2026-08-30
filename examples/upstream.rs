/*
 * This example is based on:
 * https://github.com/gabihodoroaga/nginx-upstream-module
 * as well as the NGINX keepalive module: ngx_http_upstream_keepalive_module.c.
 *
 * The NGINX authors are grateful to @gabihodoroaga for their contributions
 * to the community at large.
 */
use core::ffi::{c_char, c_void};
use core::ptr::{self, NonNull};

use ngx::collections::NgxArray;
use ngx::core::{ModuleDescriptor, Status};
use ngx::ffi::{
    NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_ERROR, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF_OFFSET,
    NGX_HTTP_UPS_CONF, NGX_LOG_EMERG, ngx_atoi, ngx_command_t, ngx_conf_t, ngx_http_module_t,
    ngx_http_upstream_init_round_robin, ngx_int_t, ngx_module_t, ngx_str_t, ngx_uint_t,
};
use ngx::http::{
    HttpConfigurationParser, HttpModule, HttpModuleServerConf, HttpUpstreamInitializer,
    HttpUpstreamPeerHandler, Merge, MergeConfigError, NgxHttpUpstreamModule, OriginalPeerFree,
    OriginalPeerGet, UpstreamCallbackError, UpstreamConfiguration, UpstreamInitCallback,
    UpstreamPeerConnection, UpstreamPeerInit, UpstreamPeerInitCallback, UpstreamPeerInitRequest,
    UpstreamPeerState, UpstreamServerConf, install_upstream_initializer, postconfiguration,
    preconfiguration,
};
use ngx::{ngx_conf_log_error, ngx_string};

#[derive(Clone, Copy)]
#[repr(C)]
struct SrvConfig {
    max: u32,

    original_init_upstream: UpstreamInitCallback,
    original_init_peer: UpstreamPeerInitCallback,
}

impl Default for SrvConfig {
    fn default() -> Self {
        Self {
            max: u32::MAX,
            original_init_upstream: Default::default(),
            original_init_peer: Default::default(),
        }
    }
}

impl Merge for SrvConfig {
    fn merge(&mut self, _prev: &SrvConfig) -> Result<(), MergeConfigError> {
        Ok(())
    }
}

static NGX_HTTP_UPSTREAM_CUSTOM_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(preconfiguration::<Module>),
    postconfiguration: Some(postconfiguration::<Module>),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: Some(Module::create_srv_conf),
    merge_srv_conf: Some(Module::merge_srv_conf),
    create_loc_conf: None,
    merge_loc_conf: None,
};

static mut NGX_HTTP_UPSTREAM_CUSTOM_COMMANDS: [ngx_command_t; 2] = [
    ngx_command_t {
        name: ngx_string!("custom"),
        type_: (NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_upstream_commands_set_custom),
        conf: NGX_HTTP_SRV_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

// Generate the `ngx_modules` table with exported modules.
// This feature is required to build a 'cdylib' dynamic module outside of the NGINX buildsystem.
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_upstream_custom_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_upstream_custom_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_UPSTREAM_CUSTOM_CTX as _,
    commands: unsafe { &raw mut NGX_HTTP_UPSTREAM_CUSTOM_COMMANDS[0] },
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

struct CustomUpstream;

impl HttpUpstreamInitializer for CustomUpstream {
    fn init(
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        let original = {
            let Some(config) = upstream.module_conf_mut::<Module>()? else {
                return Ok(Status::NGX_ERROR.0);
            };
            if config.max == u32::MAX {
                config.max = 100;
            }
            config.original_init_upstream
        };
        let status = original.call(configuration, upstream)?;
        if status != Status::NGX_OK.0 {
            return Ok(status);
        }

        let original_peer = upstream.init_peer();
        let Some(config) = upstream.module_conf_mut::<Module>()? else {
            return Ok(Status::NGX_ERROR.0);
        };
        config.original_init_peer = original_peer;
        upstream.replace_init_peer::<CustomPeer>();
        Ok(Status::NGX_OK.0)
    }
}

struct CustomPeer;

impl HttpUpstreamPeerHandler for CustomPeer {
    type Data = ();

    fn init(
        request: &mut UpstreamPeerInitRequest<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamPeerInit<Self::Data>, UpstreamCallbackError> {
        let original = match upstream.module_conf::<Module>()? {
            Some(config) => config.original_init_peer,
            None => return Ok(UpstreamPeerInit::Return(Status::NGX_ERROR.0)),
        };
        let status = original.call(request, upstream)?;
        if status == Status::NGX_OK.0 {
            Ok(UpstreamPeerInit::Install(()))
        } else {
            Ok(UpstreamPeerInit::Return(status))
        }
    }

    fn get(
        peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        original: OriginalPeerGet,
    ) -> Result<ngx_int_t, UpstreamCallbackError> {
        original.call(peer)
    }

    fn free(
        peer: &mut UpstreamPeerConnection<'_>,
        _data: &mut Self::Data,
        _state: UpstreamPeerState,
        original: OriginalPeerFree,
    ) -> Result<(), UpstreamCallbackError> {
        original.call(peer)
    }
}

// ngx_http_upstream_commands_set_custom
// Entry point for the module, if this command is set our custom upstreams take effect.
// The original upstream initializer function is saved and replaced with this module's initializer.
unsafe extern "C" fn ngx_http_upstream_commands_set_custom(
    cf: *mut ngx_conf_t,
    _command: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let Some(mut configuration) = NonNull::new(cf) else {
        return ngx::core::NGX_CONF_ERROR;
    };
    if !configuration.as_ptr().is_aligned() {
        return ngx::core::NGX_CONF_ERROR;
    }
    let configuration = unsafe { configuration.as_mut() };
    let Some(args) = NonNull::new(configuration.args) else {
        ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "CUSTOM UPSTREAM missing arguments");
        return ngx::core::NGX_CONF_ERROR;
    };
    if !args.as_ptr().is_aligned() {
        ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "CUSTOM UPSTREAM invalid arguments");
        return ngx::core::NGX_CONF_ERROR;
    }
    let Some(args) = (unsafe { NgxArray::<ngx_str_t>::from_ngx_array(args.as_ref()) }) else {
        ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "CUSTOM UPSTREAM invalid arguments");
        return ngx::core::NGX_CONF_ERROR;
    };
    let Some(mut config) = NonNull::new(conf.cast::<SrvConfig>()) else {
        ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "CUSTOM UPSTREAM missing server config");
        return ngx::core::NGX_CONF_ERROR;
    };
    if !config.as_ptr().is_aligned() {
        ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "CUSTOM UPSTREAM invalid server config");
        return ngx::core::NGX_CONF_ERROR;
    }
    let config = unsafe { config.as_mut() };

    if config.original_init_upstream.is_present() {
        ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "CUSTOM UPSTREAM is duplicate");
        return ngx::core::NGX_CONF_ERROR;
    }

    if let Some(value) = args.get(1) {
        if value.len == 0 || value.data.is_null() {
            ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "invalid custom upstream value");
            return ngx::core::NGX_CONF_ERROR;
        }
        let n = unsafe { ngx_atoi(value.data, value.len) };
        if n == (NGX_ERROR as isize) || n == 0 {
            ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "invalid custom upstream value");
            return ngx::core::NGX_CONF_ERROR;
        }
        config.max = n as u32;
    }

    let result = unsafe {
        HttpConfigurationParser::with_raw(cf, |parser| {
            let Some(upstream) = NgxHttpUpstreamModule::server_conf_mut(parser).map_err(|_| ())?
            else {
                return Err(());
            };

            if upstream.peer.init_upstream.is_none() {
                upstream.peer.init_upstream = Some(ngx_http_upstream_init_round_robin);
            }
            config.original_init_upstream =
                install_upstream_initializer::<CustomUpstream>(upstream);
            Ok(())
        })
    };
    if !matches!(result, Ok(Ok(()))) {
        ngx_conf_log_error!(NGX_LOG_EMERG, configuration, "CUSTOM UPSTREAM no upstream srv_conf");
        return ngx::core::NGX_CONF_ERROR;
    }

    ngx::core::NGX_CONF_OK
}

// The upstream module.
// Only server blocks are supported to trigger the module command; therefore, the only callback
// implemented is our `create_srv_conf` method.
struct Module;

unsafe impl HttpModule for Module {
    fn module() -> ModuleDescriptor {
        unsafe { ModuleDescriptor::from_raw(&raw mut ngx_http_upstream_custom_module) }
            .expect("ngx_http_upstream_custom_module descriptor")
    }
}

unsafe impl HttpModuleServerConf for Module {
    type ServerConf = SrvConfig;
}
