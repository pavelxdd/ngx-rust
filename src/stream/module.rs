use crate::ffi::ngx_module_t;

/// Identifies a concrete NGINX Stream module.
pub trait StreamModule {
    /// Returns the global module descriptor.
    fn module() -> &'static ngx_module_t;
}
