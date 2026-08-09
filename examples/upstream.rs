/*
 * This example is based on:
 * https://github.com/gabihodoroaga/nginx-upstream-module
 * as well as the NGINX keepalive module: ngx_http_upstream_keepalive_module.c.
 *
 * The NGINX authors are grateful to @gabihodoroaga for their contributions
 * to the community at large.
 */
use core::ffi::{c_char, c_void};
use core::mem;
use core::ptr;

use ngx::core::Status;
use ngx::ffi::{
    NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_ERROR, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF_OFFSET,
    NGX_HTTP_UPS_CONF, NGX_LOG_EMERG, ngx_atoi, ngx_command_t, ngx_conf_t, ngx_connection_t,
    ngx_event_free_peer_pt, ngx_event_get_peer_pt, ngx_http_module_t,
    ngx_http_upstream_init_peer_pt, ngx_http_upstream_init_pt, ngx_http_upstream_init_round_robin,
    ngx_http_upstream_srv_conf_t, ngx_http_upstream_t, ngx_int_t, ngx_module_t,
    ngx_peer_connection_t, ngx_str_t, ngx_uint_t,
};
use ngx::http::{
    HttpModule, Merge, MergeConfigError, RequestRefMut, postconfiguration, preconfiguration,
};
use ngx::http::{HttpModuleServerConf, NgxHttpUpstreamModule};
use ngx::{
    http_upstream_init_peer_pt, ngx_conf_log_error, ngx_log_debug_http, ngx_log_debug_mask,
    ngx_string,
};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct SrvConfig {
    max: u32,

    original_init_upstream: ngx_http_upstream_init_pt,
    original_init_peer: ngx_http_upstream_init_peer_pt,
}

impl Default for SrvConfig {
    fn default() -> Self {
        SrvConfig { max: u32::MAX, original_init_upstream: None, original_init_peer: None }
    }
}

impl Merge for SrvConfig {
    fn merge(&mut self, _prev: &SrvConfig) -> Result<(), MergeConfigError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct UpstreamPeerData {
    conf: Option<*const SrvConfig>,
    upstream: Option<*mut ngx_http_upstream_t>,
    client_connection: Option<*mut ngx_connection_t>,
    original_get_peer: ngx_event_get_peer_pt,
    original_free_peer: ngx_event_free_peer_pt,
    data: *mut c_void,
}

impl Default for UpstreamPeerData {
    fn default() -> Self {
        UpstreamPeerData {
            conf: None,
            upstream: None,
            client_connection: None,
            original_get_peer: None,
            original_free_peer: None,
            data: ptr::null_mut(),
        }
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

// http_upstream_init_custom_peer
// The module's custom peer.init callback. On HTTP request the peer upstream get and free callbacks
// are saved into peer data and replaced with this module's custom callbacks.
http_upstream_init_peer_pt!(
    http_upstream_init_custom_peer,
    |request: &mut RequestRefMut<'_>, us: *mut ngx_http_upstream_srv_conf_t| {
        ngx_log_debug_http!(request, "CUSTOM UPSTREAM request peer init");

        let hcpd = match request.pool() {
            Ok(pool) => pool.alloc_type::<UpstreamPeerData>(),
            Err(_) => return Status::NGX_ERROR,
        };
        if hcpd.is_null() {
            return Status::NGX_ERROR;
        }

        // SAFETY: this function is called with non-NULL uf always
        let us = unsafe { &mut *us };
        let original_init_peer = match Module::server_conf(us) {
            Ok(Some(hccf)) => match hccf.original_init_peer {
                Some(callback) => callback,
                None => return Status::NGX_ERROR,
            },
            Ok(None) | Err(_) => return Status::NGX_ERROR,
        };

        let raw_request = unsafe { request.as_ptr() };
        if unsafe { original_init_peer(raw_request, us) != Status::NGX_OK.into() } {
            return Status::NGX_ERROR;
        }

        let hccf = match Module::server_conf(us) {
            Ok(Some(hccf)) => ptr::from_ref(hccf),
            Ok(None) | Err(_) => return Status::NGX_ERROR,
        };

        let Some(upstream) = (unsafe { request.upstream() }) else {
            return Status::NGX_ERROR;
        };
        let upstream_ptr = upstream.as_ptr();
        if request.connection().is_err() {
            return Status::NGX_ERROR;
        }
        let client_connection = unsafe { (*request.as_ptr()).connection };

        unsafe {
            (*hcpd).conf = Some(hccf);
            (*hcpd).upstream = Some(upstream_ptr);
            (*hcpd).data = (*upstream_ptr).peer.data;
            (*hcpd).client_connection = Some(client_connection);
            (*hcpd).original_get_peer = (*upstream_ptr).peer.get;
            (*hcpd).original_free_peer = (*upstream_ptr).peer.free;

            (*upstream_ptr).peer.data = hcpd as *mut c_void;
            (*upstream_ptr).peer.get = Some(ngx_http_upstream_get_custom_peer);
            (*upstream_ptr).peer.free = Some(ngx_http_upstream_free_custom_peer);
        }

        ngx_log_debug_http!(request, "CUSTOM UPSTREAM end request peer init");
        Status::NGX_OK
    }
);

// ngx_http_usptream_get_custom_peer
// For demonstration purposes, use the original get callback, but log this callback proxies through
// to the original.
unsafe extern "C" fn ngx_http_upstream_get_custom_peer(
    pc: *mut ngx_peer_connection_t,
    data: *mut c_void,
) -> ngx_int_t {
    let hcpd: *mut UpstreamPeerData = unsafe { mem::transmute(data) };

    ngx_log_debug_mask!(
        DebugMask::Http,
        unsafe { (*pc).log },
        "CUSTOM UPSTREAM get peer, try: {}, conn: {:p}",
        unsafe { (*pc).tries },
        unsafe { (*hcpd).client_connection.unwrap() },
    );

    let original_get_peer = unsafe { (*hcpd).original_get_peer.unwrap() };
    let rc = unsafe { original_get_peer(pc, (*hcpd).data) };

    if rc != Status::NGX_OK.into() {
        return rc;
    }

    ngx_log_debug_mask!(DebugMask::Http, unsafe { (*pc).log }, "CUSTOM UPSTREAM end get peer");
    Status::NGX_OK.into()
}

// ngx_http_upstream_free_custom_peer
// For demonstration purposes, use the original free callback, but log this callback proxies
// through to the original.
unsafe extern "C" fn ngx_http_upstream_free_custom_peer(
    pc: *mut ngx_peer_connection_t,
    data: *mut c_void,
    state: ngx_uint_t,
) {
    ngx_log_debug_mask!(DebugMask::Http, unsafe { (*pc).log }, "CUSTOM UPSTREAM free peer");

    let hcpd: *mut UpstreamPeerData = unsafe { mem::transmute(data) };

    let original_free_peer = unsafe { (*hcpd).original_free_peer.unwrap() };

    unsafe { original_free_peer(pc, (*hcpd).data, state) };

    ngx_log_debug_mask!(DebugMask::Http, unsafe { (*pc).log }, "CUSTOM UPSTREAM end free peer");
}

// ngx_http_upstream_init_custom
// The module's custom `peer.init_upstream` callback.
// The original callback is saved in our SrvConfig data and reset to this module's `peer.init`.
unsafe extern "C" fn ngx_http_upstream_init_custom(
    cf: *mut ngx_conf_t,
    us: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t {
    ngx_log_debug_mask!(
        DebugMask::Http,
        unsafe { (*cf).log },
        "CUSTOM UPSTREAM peer init_upstream"
    );

    // SAFETY: this function is called with non-NULL uf always
    let us = unsafe { &mut *us };
    let init_upstream_ptr = {
        let Ok(Some(hccf)) = Module::server_conf_mut(us) else {
            ngx_conf_log_error!(NGX_LOG_EMERG, cf, "CUSTOM UPSTREAM no upstream srv_conf");
            return isize::from(Status::NGX_ERROR);
        };
        // NOTE: ngx_conf_init_uint_value macro is unavailable
        if hccf.max == u32::MAX {
            hccf.max = 100;
        }
        hccf.original_init_upstream.unwrap()
    };
    if unsafe { init_upstream_ptr(cf, us) } != Status::NGX_OK.into() {
        ngx_conf_log_error!(NGX_LOG_EMERG, cf, "CUSTOM UPSTREAM failed calling init_upstream");
        return isize::from(Status::NGX_ERROR);
    }

    let original_init_peer = us.peer.init;
    let Ok(Some(hccf)) = Module::server_conf_mut(us) else {
        ngx_conf_log_error!(NGX_LOG_EMERG, cf, "CUSTOM UPSTREAM no upstream srv_conf");
        return isize::from(Status::NGX_ERROR);
    };
    hccf.original_init_peer = original_init_peer;
    us.peer.init = Some(http_upstream_init_custom_peer);

    ngx_log_debug_mask!(
        DebugMask::Http,
        unsafe { (*cf).log },
        "CUSTOM UPSTREAM end peer init_upstream"
    );
    isize::from(Status::NGX_OK)
}

// ngx_http_upstream_commands_set_custom
// Entry point for the module, if this command is set our custom upstreams take effect.
// The original upstream initializer function is saved and replaced with this module's initializer.
unsafe extern "C" fn ngx_http_upstream_commands_set_custom(
    cf: *mut ngx_conf_t,
    cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: this function is called with non-NULL cf always
    let cf = unsafe { &mut *cf };
    ngx_log_debug_mask!(DebugMask::Http, cf.log, "CUSTOM UPSTREAM module init");
    let args: &[ngx_str_t] = unsafe { (*cf.args).as_slice() };

    let ccf = unsafe { &mut (*(conf as *mut SrvConfig)) };

    if let Some(value) = args.get(1) {
        let n = unsafe { ngx_atoi(value.data, value.len) };
        if n == (NGX_ERROR as isize) || n == 0 {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                cf,
                "invalid value \"{}\" in \"{}\" directive",
                value,
                unsafe { &(*cmd).name }
            );
            return ngx::core::NGX_CONF_ERROR;
        }
        ccf.max = n as u32;
    }

    let Ok(Some(uscf)) = NgxHttpUpstreamModule::server_conf_mut(cf) else {
        ngx_conf_log_error!(NGX_LOG_EMERG, cf, "CUSTOM UPSTREAM no upstream srv_conf");
        return ngx::core::NGX_CONF_ERROR;
    };

    ccf.original_init_upstream = if uscf.peer.init_upstream.is_some() {
        uscf.peer.init_upstream
    } else {
        Some(ngx_http_upstream_init_round_robin)
    };

    uscf.peer.init_upstream = Some(ngx_http_upstream_init_custom);

    ngx_log_debug_mask!(DebugMask::Http, cf.log, "CUSTOM UPSTREAM end module init");

    ngx::core::NGX_CONF_OK
}

// The upstream module.
// Only server blocks are supported to trigger the module command; therefore, the only callback
// implemented is our `create_srv_conf` method.
struct Module;

unsafe impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_upstream_custom_module) }
    }
}

unsafe impl HttpModuleServerConf for Module {
    type ServerConf = SrvConfig;
}
