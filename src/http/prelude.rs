//! Common imports for HTTP modules.

pub use crate::core::ChainRef;
pub use crate::core::prelude::*;
pub use crate::ffi::{
    NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF_OFFSET,
    ngx_http_module_t,
};
#[cfg(feature = "async")]
pub use crate::http::{AsyncHandlerContext, AsyncHttpRequestHandler};
pub use crate::http::{
    HTTPStatus, HeaderBuildError, HeaderListError, HttpConfigError, HttpFilter, HttpFilterError,
    HttpFilterSlot, HttpHeaderIter, HttpHeaderList, HttpHeaderRef, HttpHeadersInBuilder,
    HttpHeadersOutBuilder, HttpModule, HttpModuleLocationConf, HttpModuleLocationConfExt,
    HttpModuleLocationConfMutExt, HttpModuleMainConf, HttpModuleMainConfExt,
    HttpModuleMainConfMutExt, HttpModuleRequestContext, HttpModuleServerConf,
    HttpModuleServerConfExt, HttpModuleServerConfMutExt, HttpPhase, HttpRequestHandler,
    HttpVariableFlags, HttpVariableHandler, HttpVariableIndex, HttpVariableIndexError,
    HttpVariableLookupError, HttpVariablePoolBytes, HttpVariableRegistrationError,
    HttpVariableSetter, HttpVariableValue, HttpVariableValueError, HttpVariableValueReadError,
    HttpVariableValueRef, IntoHandlerStatus, Merge, MergeConfigError, ProcessCycle,
    ProcessCycleError, RequestContextCreateError, RequestContextError, RequestError, RequestRef,
    RequestRefMut, add_phase_handler, add_variable, add_variable_with_setter, exit_process,
    filter_postconfiguration, get_variable_index, init_process, phase_handler_postconfiguration,
    postconfiguration, preconfiguration,
};
pub use crate::ngx_log_debug_http;
