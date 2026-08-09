use core::fmt;
use core::mem;
use core::ptr::{self, NonNull};

use nginx_sys::{
    NGX_CONF_TAKE1, NGX_ERROR, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MODULE,
    NGX_HTTP_SPECIAL_RESPONSE, NGX_LOG_ERR, NGX_OK, ngx_chain_t, ngx_command_t, ngx_conf_t,
    ngx_http_complex_value_t, ngx_http_module_t, ngx_http_send_response, ngx_int_t, ngx_module_t,
    ngx_str_t, ngx_uint_t,
};
use ngx::core::{BufferView, ChainRef, Status};
use ngx::http::subrequest::{SubRequestBuilder, SubRequestError};
use ngx::http::{
    HTTPStatus, HttpModule, HttpModuleLocationConf, HttpModuleRequestContext, HttpPhase,
    HttpRequestHandler, IntoHandlerStatus, Merge, MergeConfigError, RequestRef, RequestRefMut,
    add_phase_handler,
};
use ngx::{ngx_log_error, ngx_string};

struct Module;

unsafe impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*ptr::addr_of!(ngx_http_subrequest_module) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cf = unsafe { &mut *cf };
        add_phase_handler::<SubRequestAccessHandler>(cf)
            .map_or(Status::NGX_ERROR, |_| Status::NGX_OK)
            .into()
    }
}

#[derive(Debug, Default)]
struct ModuleConfig {
    uri: ngx_str_t,
}

impl Merge for ModuleConfig {
    fn merge(&mut self, prev: &Self) -> Result<(), MergeConfigError> {
        if self.uri.data.is_null() {
            self.uri = prev.uri;
        }
        Ok(())
    }
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = ModuleConfig;
}

#[derive(Clone, Copy)]
struct SubRequestResult {
    completion_status: ngx_int_t,
    response_status: Option<HTTPStatus>,
    output: Option<NonNull<ngx_chain_t>>,
    content_type: ngx_str_t,
}

#[derive(Default)]
struct SubRequestContext {
    result: Option<SubRequestResult>,
}

unsafe impl HttpModuleRequestContext for Module {
    type RequestContext = SubRequestContext;
}

#[derive(Debug)]
enum ExampleError {
    Config,
    ContextAllocation,
    InvalidUri,
    AddHeader,
    InvalidResponse(ngx_int_t),
    InvalidBody,
    Response(ngx_int_t),
    SubRequest(SubRequestError),
}

impl From<SubRequestError> for ExampleError {
    fn from(error: SubRequestError) -> Self {
        Self::SubRequest(error)
    }
}

impl fmt::Display for ExampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => f.write_str("location configuration is missing"),
            Self::ContextAllocation => f.write_str("request context allocation failed"),
            Self::InvalidUri => f.write_str("subrequest URI is not UTF-8"),
            Self::AddHeader => f.write_str("subrequest header allocation failed"),
            Self::InvalidResponse(status) => {
                write!(f, "subrequest completed with invalid status {status}")
            }
            Self::InvalidBody => f.write_str("subrequest returned an invalid buffered body"),
            Self::Response(status) => write!(f, "response failed with status {status}"),
            Self::SubRequest(error) => error.fmt(f),
        }
    }
}

impl IntoHandlerStatus for ExampleError {
    fn into_handler_status(self, request: &RequestRef<'_>) -> ngx_int_t {
        if let Ok(Some(log)) = request.log() {
            ngx_log_error!(NGX_LOG_ERR, log.as_ptr(), "subrequest example: {self}");
        }
        NGX_ERROR as ngx_int_t
    }
}

struct SubRequestAccessHandler;

impl HttpRequestHandler for SubRequestAccessHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Output = Result<Status, ExampleError>;

    fn handler(request: &mut RequestRefMut<'_>) -> Self::Output {
        let config = Module::location_conf(request)
            .map_err(|_| ExampleError::Config)?
            .ok_or(ExampleError::Config)?;
        if config.uri.data.is_null() {
            return Ok(Status::NGX_DECLINED);
        }
        let uri = config.uri;

        if let Some(context) =
            request.module_context::<Module>().map_err(|_| ExampleError::ContextAllocation)?
        {
            return context
                .result
                .map_or(Ok(Status::NGX_AGAIN), |result| send_subrequest_response(request, result));
        }

        request
            .get_or_insert_module_context_with::<Module>(SubRequestContext::default)
            .map_err(|_| ExampleError::ContextAllocation)?;

        let uri = uri.to_str().map_err(|_| ExampleError::InvalidUri)?;
        let mut subrequest = SubRequestBuilder::new(request, uri)?
            .args("probe=1")?
            .handler(subrequest_done)
            .in_memory()
            .waited()
            .build()?;
        subrequest.add_header_in("X-Subrequest", "1").map_err(|_| ExampleError::AddHeader)?;

        Ok(Status::NGX_AGAIN)
    }
}

fn subrequest_done(request: &mut RequestRefMut<'_>, completion_status: ngx_int_t) -> Status {
    let raw = unsafe { request.as_ptr() };
    let result = SubRequestResult {
        completion_status,
        response_status: request.status().or_else(|| HTTPStatus::try_from(completion_status).ok()),
        output: NonNull::new(unsafe { (*raw).out }),
        content_type: unsafe { (*raw).headers_out.content_type },
    };

    let Ok(mut main) = request.main_mut() else {
        return Status::NGX_ERROR;
    };
    let Ok(Some(context)) = main.module_context_mut::<Module>() else {
        if let Ok(Some(log)) = request.log() {
            ngx_log_error!(NGX_LOG_ERR, log.as_ptr(), "subrequest example: context is missing");
        }
        return Status::NGX_ERROR;
    };
    context.result = Some(result);
    Status::NGX_OK
}

fn send_subrequest_response(
    request: &mut RequestRefMut<'_>,
    result: SubRequestResult,
) -> Result<Status, ExampleError> {
    if result.completion_status != NGX_OK as ngx_int_t
        && HTTPStatus::try_from(result.completion_status).is_err()
    {
        return Err(ExampleError::InvalidResponse(result.completion_status));
    }

    let status =
        result.response_status.ok_or(ExampleError::InvalidResponse(result.completion_status))?;
    if status.0 >= NGX_HTTP_SPECIAL_RESPONSE as ngx_uint_t {
        return Ok(status.into());
    }

    let body = copy_buffered_body(&request.view(), result.output)?;
    let mut content_type = result.content_type;
    let content_type =
        if content_type.is_empty() { ptr::null_mut() } else { &raw mut content_type };
    let mut value = unsafe { mem::zeroed::<ngx_http_complex_value_t>() };
    value.value = body;

    let response_status =
        unsafe { ngx_http_send_response(request.as_ptr(), status.0, content_type, &raw mut value) };
    Status(response_status).into_result().map_err(|status| ExampleError::Response(status.0))?;
    Ok(status.into())
}

fn copy_buffered_body(
    request: &RequestRef<'_>,
    output: Option<NonNull<ngx_chain_t>>,
) -> Result<ngx_str_t, ExampleError> {
    let head = output.map_or(ptr::null_mut(), NonNull::as_ptr);
    // SAFETY: the subrequest output chain remains live and immutable while the main request
    // copies its buffered response in this handler invocation.
    let chain = unsafe { ChainRef::from_raw(head) }.map_err(|_| ExampleError::InvalidBody)?;
    let mut length = 0usize;
    for buffer in chain.iter() {
        let buffer = buffer.map_err(|_| ExampleError::InvalidBody)?;
        let size = match buffer.kind().map_err(|_| ExampleError::InvalidBody)? {
            BufferView::Memory(bytes) => bytes.len(),
            BufferView::Control(_) => 0,
            BufferView::File(_) => return Err(ExampleError::InvalidBody),
        };
        length = length.checked_add(size).ok_or(ExampleError::InvalidBody)?;
    }

    if length == 0 {
        return Ok(ngx_str_t::empty());
    }
    let data =
        request.pool().map_err(|_| ExampleError::InvalidBody)?.alloc_unaligned(length).cast::<u8>();
    if data.is_null() {
        return Err(ExampleError::InvalidBody);
    }

    let mut offset = 0;
    for buffer in chain.iter() {
        let buffer = buffer.map_err(|_| ExampleError::InvalidBody)?;
        match buffer.kind().map_err(|_| ExampleError::InvalidBody)? {
            BufferView::Memory(bytes) => {
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), data.add(offset), bytes.len()) };
                offset += bytes.len();
            }
            BufferView::Control(_) => {}
            BufferView::File(_) => return Err(ExampleError::InvalidBody),
        }
    }

    Ok(ngx_str_t { len: length, data })
}

static MODULE_CONTEXT: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_subrequest_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_subrequest_module: ngx_module_t = ngx_module_t {
    ctx: &raw const MODULE_CONTEXT as _,
    commands: &raw mut COMMANDS as *mut ngx_command_t,
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

static mut COMMANDS: [ngx_command_t; 2] = [
    ngx_command_t {
        name: ngx_string!("subrequest"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(nginx_sys::ngx_conf_set_str_slot),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: mem::offset_of!(ModuleConfig, uri),
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];
