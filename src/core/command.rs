use crate::ffi::ngx_uint_t;

bitflags::bitflags! {
    /// Flags describing where a directive is valid and which arguments it accepts.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct CommandFlags: ngx_uint_t {
        /// The directive takes no arguments.
        const NO_ARGS = crate::ffi::NGX_CONF_NOARGS as ngx_uint_t;
        /// The directive takes one argument.
        const TAKE_1 = crate::ffi::NGX_CONF_TAKE1 as ngx_uint_t;
        /// The directive takes two arguments.
        const TAKE_2 = crate::ffi::NGX_CONF_TAKE2 as ngx_uint_t;
        /// The directive takes three arguments.
        const TAKE_3 = crate::ffi::NGX_CONF_TAKE3 as ngx_uint_t;
        /// The directive takes four arguments.
        const TAKE_4 = crate::ffi::NGX_CONF_TAKE4 as ngx_uint_t;
        /// The directive takes five arguments.
        const TAKE_5 = crate::ffi::NGX_CONF_TAKE5 as ngx_uint_t;
        /// The directive takes six arguments.
        const TAKE_6 = crate::ffi::NGX_CONF_TAKE6 as ngx_uint_t;
        /// The directive takes seven arguments.
        const TAKE_7 = crate::ffi::NGX_CONF_TAKE7 as ngx_uint_t;

        /// The directive starts a configuration block.
        const BLOCK = crate::ffi::NGX_CONF_BLOCK as ngx_uint_t;
        /// The directive accepts an `on` or `off` flag.
        const FLAG = crate::ffi::NGX_CONF_FLAG as ngx_uint_t;
        /// The directive accepts any number of arguments.
        const ANY_ARGS = crate::ffi::NGX_CONF_ANY as ngx_uint_t;
        /// The directive accepts one or more arguments.
        const ONE_OR_MORE = crate::ffi::NGX_CONF_1MORE as ngx_uint_t;
        /// The directive accepts two or more arguments.
        const TWO_OR_MORE = crate::ffi::NGX_CONF_2MORE as ngx_uint_t;

        /// The directive stores configuration directly in the module slot.
        const DIRECT = crate::ffi::NGX_DIRECT_CONF as ngx_uint_t;
        /// The directive is valid in the core main configuration.
        const MAIN = crate::ffi::NGX_MAIN_CONF as ngx_uint_t;
        /// The directive is valid in any module configuration.
        const ANY_CONTEXT = crate::ffi::NGX_ANY_CONF as ngx_uint_t;

        /// The directive is valid in the HTTP main configuration.
        #[cfg(ngx_feature = "http")]
        const HTTP_MAIN = crate::ffi::NGX_HTTP_MAIN_CONF as ngx_uint_t;
        /// The directive is valid in an HTTP server configuration.
        #[cfg(ngx_feature = "http")]
        const HTTP_SERVER = crate::ffi::NGX_HTTP_SRV_CONF as ngx_uint_t;
        /// The directive is valid in an HTTP location configuration.
        #[cfg(ngx_feature = "http")]
        const HTTP_LOCATION = crate::ffi::NGX_HTTP_LOC_CONF as ngx_uint_t;
        /// The directive is valid in an HTTP upstream configuration.
        #[cfg(ngx_feature = "http")]
        const HTTP_UPSTREAM = crate::ffi::NGX_HTTP_UPS_CONF as ngx_uint_t;
        /// The directive is valid in an HTTP server-level `if` block.
        #[cfg(ngx_feature = "http")]
        const HTTP_SERVER_IF = crate::ffi::NGX_HTTP_SIF_CONF as ngx_uint_t;
        /// The directive is valid in an HTTP location-level `if` block.
        #[cfg(ngx_feature = "http")]
        const HTTP_LOCATION_IF = crate::ffi::NGX_HTTP_LIF_CONF as ngx_uint_t;
        /// The directive is valid in an HTTP `limit_except` block.
        #[cfg(ngx_feature = "http")]
        const HTTP_LIMIT_EXCEPT = crate::ffi::NGX_HTTP_LMT_CONF as ngx_uint_t;
    }
}
