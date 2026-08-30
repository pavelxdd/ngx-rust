//! Common imports for HTTP modules.

pub use crate::core::prelude::*;
pub use crate::core::{BufferFlags, ChainRef, PoolChain};
pub use crate::ffi::{
    NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF_OFFSET,
    ngx_http_module_t,
};
#[cfg(feature = "async")]
pub use crate::http::{AsyncHandlerContext, AsyncHttpRequestHandler};
pub use crate::http::{
    ClientBodyReadStatus, ConfiguredUpstreamUrl, HTTPStatus, HeaderBuildError, HeaderListError,
    HttpClientBodyHandler, HttpConfigError, HttpConfigurationParser, HttpFilter, HttpFilterError,
    HttpFilterSlot, HttpHeaderIter, HttpHeaderList, HttpHeaderRef, HttpHeadersInBuilder,
    HttpHeadersOutBuilder, HttpModule, HttpModuleLocationConf, HttpModuleMainConf,
    HttpModuleRequestContext, HttpModuleServerConf, HttpPhase, HttpRequestHandler,
    HttpUpstreamInitializer, HttpUpstreamPeerHandler, HttpVariableFlags, HttpVariableHandler,
    HttpVariableIndex, HttpVariableIndexError, HttpVariableLookupError, HttpVariableOutput,
    HttpVariableOutputError, HttpVariablePoolBytes, HttpVariableRegistrationError,
    HttpVariableSetter, HttpVariableValueRef, IntoHandlerStatus, Merge, MergeConfigError,
    OriginalPeerFree, OriginalPeerGet, ProcessCycle, ProcessCycleError, RequestBodyBuildError,
    RequestBodyBuilder, RequestBodyError, RequestBodyRef, RequestBodySize,
    RequestContextCreateError, RequestContextError, RequestContinuation, RequestContinuationError,
    RequestError, RequestHold, RequestHoldError, RequestPhaseResumeError, RequestRef,
    RequestRefMut, RequestTempFile, RequestTempFileError, RequestTempFileState,
    SelectedUpstreamPeer, UpstreamAddress, UpstreamAddresses, UpstreamCallbackError,
    UpstreamConfiguration, UpstreamInitCallback, UpstreamInitStatus, UpstreamInitialization,
    UpstreamInitialized, UpstreamPeerConnection, UpstreamPeerInit, UpstreamPeerInitCallback,
    UpstreamPeerInitRequest, UpstreamPeerInitStatus, UpstreamPeerSelection, UpstreamPeerState,
    UpstreamPort, UpstreamServerConf, UpstreamState, UpstreamStateError, UpstreamStates,
    UpstreamUrlMessage, UpstreamUrlParseError, UpstreamUrlViewError, add_phase_handler,
    add_variable, add_variable_with_setter, exit_process, filter_postconfiguration,
    get_variable_index, init_process, install_upstream_initializer,
    phase_handler_postconfiguration, postconfiguration, preconfiguration,
};
pub use crate::ngx_log_debug_http;
