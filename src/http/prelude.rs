//! Common imports for HTTP modules.

pub use crate::core::prelude::*;
pub use crate::ffi::{
    NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF_OFFSET,
    ngx_http_module_t,
};
#[cfg(feature = "async")]
pub use crate::http::{AsyncHandlerContext, AsyncHttpRequestHandler};
pub use crate::http::{
    HTTPStatus, HttpConfigError, HttpModule, HttpModuleLocationConf, HttpModuleLocationConfExt,
    HttpModuleLocationConfMutExt, HttpModuleMainConf, HttpModuleMainConfExt,
    HttpModuleMainConfMutExt, HttpModuleRequestContext, HttpModuleServerConf,
    HttpModuleServerConfExt, HttpModuleServerConfMutExt, HttpPhase, HttpRequestHandler,
    IntoHandlerStatus, Merge, MergeConfigError, RequestContextError, RequestError, RequestRef,
    RequestRefMut, add_phase_handler,
};
pub use crate::ngx_log_debug_http;
