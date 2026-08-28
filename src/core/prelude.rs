//! Common imports for nginx modules.

pub use super::{CommandFlags, ModuleDescriptor, NGX_CONF_ERROR, NGX_CONF_OK, Status};
pub use crate::ffi::{
    NGX_LOG_ALERT, NGX_LOG_CRIT, NGX_LOG_DEBUG, NGX_LOG_EMERG, NGX_LOG_ERR, NGX_LOG_INFO,
    NGX_LOG_NOTICE, NGX_LOG_WARN, ngx_command_t, ngx_conf_t, ngx_cycle_t, ngx_int_t, ngx_module_t,
    ngx_str_t,
};
pub use crate::{ngx_conf_log_error, ngx_log_debug, ngx_log_error, ngx_modules, ngx_string};
