use core::ffi::{c_char, c_void};
use core::ptr;

use ngx::core::{NGX_CONF_ERROR, NgxStr, Status};
use ngx::ffi::{
    NGX_CONF_TAKE1, NGX_STREAM_MODULE, NGX_STREAM_SRV_CONF, NGX_STREAM_SRV_CONF_OFFSET,
    ngx_command_t, ngx_conf_t, ngx_int_t, ngx_module_t, ngx_stream_module_t, ngx_uint_t,
};
use ngx::ngx_string;
use ngx::stream::{
    Merge, MergeConfigError, Session, StreamModule, StreamModuleServerConf,
    StreamModuleSessionContext, StreamPhase, StreamSessionHandler, StreamVariableFlags,
    StreamVariableHandler, StreamVariableValue, add_phase_handler, add_variable,
};

struct Module;

unsafe impl StreamModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*ptr::addr_of!(ngx_stream_probe_module) }
    }

    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let Some(cf) = (unsafe { cf.as_mut() }) else {
            return Status::NGX_ERROR.0;
        };
        add_variable::<ProbeVariable>(
            cf,
            NgxStr::from_bytes(b"stream_probe"),
            StreamVariableFlags::empty(),
            0,
        )
        .map_or(Status::NGX_ERROR, |_| Status::NGX_OK)
        .0
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let Some(cf) = (unsafe { cf.as_mut() }) else {
            return Status::NGX_ERROR.0;
        };
        add_phase_handler::<ProbeHandler>(cf).map_or(Status::NGX_ERROR, |_| Status::NGX_OK).0
    }
}

#[derive(Default)]
struct ServerConfig {
    enabled: Option<bool>,
}

impl Merge for ServerConfig {
    fn merge(&mut self, parent: &Self) -> Result<(), MergeConfigError> {
        if self.enabled.is_none() {
            self.enabled = parent.enabled.or(Some(false));
        }
        Ok(())
    }
}

unsafe impl StreamModuleServerConf for Module {
    type ServerConf = ServerConfig;
}

#[derive(Default)]
struct ProbeContext {
    seen: bool,
}

unsafe impl StreamModuleSessionContext for Module {
    type SessionContext = ProbeContext;
}

struct ProbeHandler;

impl StreamSessionHandler for ProbeHandler {
    const PHASE: StreamPhase = StreamPhase::Preread;
    type Output = Result<Status, Status>;

    fn handler(session: &mut Session) -> Self::Output {
        let enabled = session
            .server_conf::<Module>()
            .map_err(|_| Status::NGX_ERROR)?
            .and_then(|conf| conf.enabled)
            .unwrap_or(false);
        if !enabled {
            return Ok(Status::NGX_DECLINED);
        }

        let context = session
            .get_or_insert_module_context_with::<Module>(ProbeContext::default)
            .map_err(|_| Status::NGX_ERROR)?;
        context.seen = true;
        Ok(Status::NGX_DECLINED)
    }
}

struct ProbeVariable;

impl StreamVariableHandler for ProbeVariable {
    type Output = Status;

    fn get(session: &mut Session, value: &mut StreamVariableValue, _data: usize) -> Self::Output {
        let seen = session.module_context::<Module>().is_some_and(|context| context.seen);
        let bytes = if seen { b"seen".as_slice() } else { b"not-seen".as_slice() };
        value.set_static(bytes).map_or(Status::NGX_ERROR, |_| Status::NGX_OK)
    }
}

static mut COMMANDS: [ngx_command_t; 2] = [
    ngx_command_t {
        name: ngx_string!("stream_probe"),
        type_: (NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_probe),
        conf: NGX_STREAM_SRV_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

static MODULE_CONTEXT: ngx_stream_module_t = ngx_stream_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: Some(Module::create_srv_conf),
    merge_srv_conf: Some(Module::merge_srv_conf),
};

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_stream_probe_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_stream_probe_module: ngx_module_t = ngx_module_t {
    ctx: &raw const MODULE_CONTEXT as _,
    commands: unsafe { &raw mut COMMANDS[0] },
    type_: NGX_STREAM_MODULE as _,
    ..ngx_module_t::default()
};

unsafe extern "C" fn set_probe(
    cf: *mut ngx_conf_t,
    _command: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let Some(cf) = (unsafe { cf.as_ref() }) else {
        return NGX_CONF_ERROR;
    };
    let Some(conf) = (unsafe { conf.cast::<ServerConfig>().as_mut() }) else {
        return NGX_CONF_ERROR;
    };
    if conf.enabled.is_some() {
        return c"is duplicate".as_ptr().cast_mut();
    }

    let Some(args) = (unsafe { cf.args.as_ref() }) else {
        return NGX_CONF_ERROR;
    };
    let args = unsafe { args.as_slice::<ngx::ffi::ngx_str_t>() };
    let Some(value) = args.get(1) else {
        return NGX_CONF_ERROR;
    };
    conf.enabled = match value.as_bytes() {
        b"on" => Some(true),
        b"off" => Some(false),
        _ => return c"must be \"on\" or \"off\"".as_ptr().cast_mut(),
    };
    ptr::null_mut()
}
