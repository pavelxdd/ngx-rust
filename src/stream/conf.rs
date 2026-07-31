use core::ffi::c_void;
use core::ptr::NonNull;

use crate::ffi::{
    ngx_conf_t, ngx_cycle_t, ngx_module_t, ngx_stream_conf_ctx_t, ngx_stream_core_srv_conf_t,
    ngx_stream_session_t, ngx_stream_upstream_srv_conf_t,
};
use crate::stream::StreamModule;

unsafe fn conf_slot<T>(slots: *mut *mut c_void, index: usize) -> Option<NonNull<T>> {
    let slots = NonNull::new(slots)?;
    let value = unsafe { *slots.as_ptr().add(index) };
    NonNull::new(value.cast())
}

/// Raw access to Stream module main-configuration slots.
pub trait StreamModuleMainConfExt {
    /// Gets a module's main-configuration slot as a typed pointer.
    ///
    /// # Safety
    /// `module.ctx_index` must select a valid slot whose value is either null or a valid `T`.
    unsafe fn stream_main_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>>;
}

/// Raw access to Stream module server-configuration slots.
pub trait StreamModuleServerConfExt {
    /// Gets a module's server-configuration slot as a typed pointer.
    ///
    /// # Safety
    /// `module.ctx_index` must select a valid slot whose value is either null or a valid `T`.
    unsafe fn stream_server_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>>;
}

impl StreamModuleMainConfExt for ngx_stream_conf_ctx_t {
    unsafe fn stream_main_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe { conf_slot(self.main_conf, module.ctx_index) }
    }
}

impl StreamModuleServerConfExt for ngx_stream_conf_ctx_t {
    unsafe fn stream_server_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe { conf_slot(self.srv_conf, module.ctx_index) }
    }
}

impl StreamModuleMainConfExt for ngx_cycle_t {
    unsafe fn stream_main_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        let conf_ctx = NonNull::new(self.conf_ctx)?;
        let stream_index = unsafe { nginx_sys::ngx_stream_module.index };
        let stream_conf = unsafe { *conf_ctx.as_ptr().add(stream_index) };
        let stream_conf = NonNull::new(stream_conf)?.cast::<ngx_stream_conf_ctx_t>();
        unsafe { stream_conf.as_ref().stream_main_conf_unchecked(module) }
    }
}

impl StreamModuleMainConfExt for ngx_conf_t {
    unsafe fn stream_main_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        let conf_ctx = NonNull::new(self.ctx.cast::<ngx_stream_conf_ctx_t>())?;
        unsafe { conf_ctx.as_ref().stream_main_conf_unchecked(module) }
    }
}

impl StreamModuleServerConfExt for ngx_conf_t {
    unsafe fn stream_server_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        let conf_ctx = NonNull::new(self.ctx.cast::<ngx_stream_conf_ctx_t>())?;
        unsafe { conf_ctx.as_ref().stream_server_conf_unchecked(module) }
    }
}

impl StreamModuleMainConfExt for ngx_stream_core_srv_conf_t {
    unsafe fn stream_main_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe { self.ctx.as_ref()?.stream_main_conf_unchecked(module) }
    }
}

impl StreamModuleServerConfExt for ngx_stream_core_srv_conf_t {
    unsafe fn stream_server_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe { self.ctx.as_ref()?.stream_server_conf_unchecked(module) }
    }
}

impl StreamModuleMainConfExt for ngx_stream_session_t {
    unsafe fn stream_main_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe { conf_slot(self.main_conf, module.ctx_index) }
    }
}

impl StreamModuleServerConfExt for ngx_stream_session_t {
    unsafe fn stream_server_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe { conf_slot(self.srv_conf, module.ctx_index) }
    }
}

impl StreamModuleServerConfExt for ngx_stream_upstream_srv_conf_t {
    unsafe fn stream_server_conf_unchecked<T>(&self, module: &ngx_module_t) -> Option<NonNull<T>> {
        unsafe { conf_slot(self.srv_conf, module.ctx_index) }
    }
}

/// Associates a Stream module with its main-configuration type.
///
/// # Safety
/// `MainConf` must be the main-configuration type stored for `Self::module()`.
pub unsafe trait StreamModuleMainConf: StreamModule {
    /// The module's main-configuration type.
    type MainConf;

    /// Gets the module's main configuration.
    fn main_conf(source: &impl StreamModuleMainConfExt) -> Option<&Self::MainConf> {
        unsafe { Some(source.stream_main_conf_unchecked(Self::module())?.as_ref()) }
    }

    /// Gets exclusive access to the module's main configuration.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::stream::StreamModuleMainConf;
    /// # fn access<M: StreamModuleMainConf>(cf: &ngx_conf_t) {
    /// let _ = unsafe { M::main_conf_mut(cf) };
    /// # }
    /// ```
    ///
    /// # Safety
    /// The caller must have exclusive access to the selected configuration slot for the returned
    /// reference's lifetime, with no other references to the same value.
    unsafe fn main_conf_mut(
        source: &mut impl StreamModuleMainConfExt,
    ) -> Option<&mut Self::MainConf> {
        unsafe { Some(source.stream_main_conf_unchecked(Self::module())?.as_mut()) }
    }
}

/// Associates a Stream module with its server-configuration type.
///
/// # Safety
/// `ServerConf` must be the server-configuration type stored for `Self::module()`.
pub unsafe trait StreamModuleServerConf: StreamModule {
    /// The module's server-configuration type.
    type ServerConf;

    /// Gets the module's server configuration.
    fn server_conf(source: &impl StreamModuleServerConfExt) -> Option<&Self::ServerConf> {
        unsafe { Some(source.stream_server_conf_unchecked(Self::module())?.as_ref()) }
    }

    /// Gets exclusive access to the module's server configuration.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::stream::StreamModuleServerConf;
    /// # fn access<M: StreamModuleServerConf>(cf: &ngx_conf_t) {
    /// let _ = unsafe { M::server_conf_mut(cf) };
    /// # }
    /// ```
    ///
    /// # Safety
    /// The caller must have exclusive access to the selected configuration slot for the returned
    /// reference's lifetime, with no other references to the same value.
    unsafe fn server_conf_mut(
        source: &mut impl StreamModuleServerConfExt,
    ) -> Option<&mut Self::ServerConf> {
        unsafe { Some(source.stream_server_conf_unchecked(Self::module())?.as_mut()) }
    }
}

mod core_module {
    use crate::ffi::{
        ngx_stream_core_main_conf_t, ngx_stream_core_module, ngx_stream_core_srv_conf_t,
    };
    use crate::stream::{StreamModule, StreamModuleMainConf, StreamModuleServerConf};

    /// Typed access to `ngx_stream_core_module` configuration.
    pub struct NgxStreamCoreModule;

    impl StreamModule for NgxStreamCoreModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*core::ptr::addr_of!(ngx_stream_core_module) }
        }
    }

    unsafe impl StreamModuleMainConf for NgxStreamCoreModule {
        type MainConf = ngx_stream_core_main_conf_t;
    }

    unsafe impl StreamModuleServerConf for NgxStreamCoreModule {
        type ServerConf = ngx_stream_core_srv_conf_t;
    }
}

pub use core_module::NgxStreamCoreModule;

#[cfg(ngx_feature = "stream_ssl")]
mod ssl {
    use crate::ffi::{ngx_stream_ssl_module, ngx_stream_ssl_srv_conf_t};
    use crate::stream::{StreamModule, StreamModuleServerConf};

    /// Typed access to `ngx_stream_ssl_module` configuration.
    pub struct NgxStreamSslModule;

    impl StreamModule for NgxStreamSslModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*core::ptr::addr_of!(ngx_stream_ssl_module) }
        }
    }

    unsafe impl StreamModuleServerConf for NgxStreamSslModule {
        type ServerConf = ngx_stream_ssl_srv_conf_t;
    }
}

#[cfg(ngx_feature = "stream_ssl")]
pub use ssl::NgxStreamSslModule;

mod upstream {
    use crate::ffi::{
        ngx_stream_upstream_main_conf_t, ngx_stream_upstream_module, ngx_stream_upstream_srv_conf_t,
    };
    use crate::stream::{StreamModule, StreamModuleMainConf, StreamModuleServerConf};

    /// Typed access to `ngx_stream_upstream_module` configuration.
    pub struct NgxStreamUpstreamModule;

    impl StreamModule for NgxStreamUpstreamModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*core::ptr::addr_of!(ngx_stream_upstream_module) }
        }
    }

    unsafe impl StreamModuleMainConf for NgxStreamUpstreamModule {
        type MainConf = ngx_stream_upstream_main_conf_t;
    }

    unsafe impl StreamModuleServerConf for NgxStreamUpstreamModule {
        type ServerConf = ngx_stream_upstream_srv_conf_t;
    }
}

pub use upstream::NgxStreamUpstreamModule;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use core::ffi::c_void;

    use super::{
        StreamModuleMainConf, StreamModuleMainConfExt, StreamModuleServerConf,
        StreamModuleServerConfExt,
    };
    use crate::ffi::{ngx_module_t, ngx_stream_conf_ctx_t};
    use crate::stream::StreamModule;

    fn module_with_index(index: usize) -> ngx_module_t {
        let mut module = ngx_module_t::default();
        module.ctx_index = index;
        module
    }

    #[test]
    fn stream_context_returns_main_and_server_configuration() {
        let mut main = 42_u32;
        let mut server = 99_u32;
        let mut main_slots: [*mut c_void; 1] = [(&raw mut main).cast()];
        let mut server_slots: [*mut c_void; 1] = [(&raw mut server).cast()];
        let context = ngx_stream_conf_ctx_t {
            main_conf: main_slots.as_mut_ptr(),
            srv_conf: server_slots.as_mut_ptr(),
        };
        let module = module_with_index(0);

        let got_main = unsafe {
            context.stream_main_conf_unchecked::<u32>(&module).map(|value| *value.as_ref())
        };
        let got_server = unsafe {
            context.stream_server_conf_unchecked::<u32>(&module).map(|value| *value.as_ref())
        };

        assert_eq!(got_main, Some(42));
        assert_eq!(got_server, Some(99));
    }

    #[test]
    fn null_stream_configuration_slots_return_none() {
        let context = ngx_stream_conf_ctx_t {
            main_conf: core::ptr::null_mut(),
            srv_conf: core::ptr::null_mut(),
        };
        let module = module_with_index(0);

        assert!(unsafe { context.stream_main_conf_unchecked::<u32>(&module) }.is_none());
        assert!(unsafe { context.stream_server_conf_unchecked::<u32>(&module) }.is_none());
    }

    struct TestStreamModule;

    impl StreamModule for TestStreamModule {
        fn module() -> &'static ngx_module_t {
            Box::leak(Box::new(module_with_index(0)))
        }
    }

    unsafe impl StreamModuleMainConf for TestStreamModule {
        type MainConf = u32;
    }

    unsafe impl StreamModuleServerConf for TestStreamModule {
        type ServerConf = u32;
    }

    #[test]
    fn typed_stream_configuration_access_follows_the_source_borrow() {
        let mut main = 42_u32;
        let mut server = 99_u32;
        let mut main_slots: [*mut c_void; 1] = [(&raw mut main).cast()];
        let mut server_slots: [*mut c_void; 1] = [(&raw mut server).cast()];
        let mut context = ngx_stream_conf_ctx_t {
            main_conf: main_slots.as_mut_ptr(),
            srv_conf: server_slots.as_mut_ptr(),
        };

        assert_eq!(TestStreamModule::main_conf(&context).copied(), Some(42));
        assert_eq!(TestStreamModule::server_conf(&context).copied(), Some(99));

        if let Some(value) = unsafe { TestStreamModule::main_conf_mut(&mut context) } {
            *value = 7;
        }
        if let Some(value) = unsafe { TestStreamModule::server_conf_mut(&mut context) } {
            *value = 8;
        }

        assert_eq!(main, 7);
        assert_eq!(server, 8);
    }
}
