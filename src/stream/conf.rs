use core::ffi::c_void;
use core::ptr::NonNull;

use crate::ffi::{
    NGX_STREAM_MODULE, ngx_conf_t, ngx_cycle_t, ngx_module_t, ngx_stream_conf_ctx_t,
    ngx_stream_core_srv_conf_t, ngx_stream_session_t, ngx_stream_upstream_srv_conf_t, ngx_uint_t,
};
use crate::stream::StreamModule;

/// Failure while resolving a typed Stream configuration slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamConfigError {
    /// The module descriptor is not a Stream module.
    WrongModuleType,
    /// Nginx has not assigned the module's global index.
    UnsetModuleIndex,
    /// Nginx has not assigned the module's Stream configuration index.
    UnsetContextIndex,
    /// The module's global index is outside the configured module array.
    ModuleIndexOutOfBounds,
    /// The module's Stream configuration index is outside the configured slot array.
    ContextIndexOutOfBounds,
    /// The configuration parser is not in a Stream context.
    WrongConfigurationContext,
    /// The Stream core module does not have a usable global index.
    UnsetStreamModuleIndex,
    /// The Stream core module index is outside the configured module array.
    StreamModuleIndexOutOfBounds,
}

#[derive(Clone, Copy)]
struct ModuleIndexes {
    context: usize,
    module_slots: usize,
    stream_slots: usize,
}

fn usize_index(index: ngx_uint_t, unset: StreamConfigError) -> Result<usize, StreamConfigError> {
    if index == ngx_uint_t::MAX {
        return Err(unset);
    }

    Ok(index)
}

fn module_indexes(
    module: &ngx_module_t,
    module_slots: usize,
    stream_slots: usize,
) -> Result<ModuleIndexes, StreamConfigError> {
    if module.type_ != NGX_STREAM_MODULE as ngx_uint_t {
        return Err(StreamConfigError::WrongModuleType);
    }

    let module_index = usize_index(module.index, StreamConfigError::UnsetModuleIndex)?;
    if module_index >= module_slots {
        return Err(StreamConfigError::ModuleIndexOutOfBounds);
    }

    let context_index = usize_index(module.ctx_index, StreamConfigError::UnsetContextIndex)?;
    if context_index >= stream_slots {
        return Err(StreamConfigError::ContextIndexOutOfBounds);
    }

    Ok(ModuleIndexes { context: context_index, module_slots, stream_slots })
}

fn live_module_slot_count() -> usize {
    unsafe { nginx_sys::ngx_max_module }
}

fn live_stream_slot_count() -> usize {
    unsafe { nginx_sys::ngx_stream_max_module }
}

fn live_module_indexes(module: &ngx_module_t) -> Result<ModuleIndexes, StreamConfigError> {
    module_indexes(module, live_module_slot_count(), live_stream_slot_count())
}

unsafe fn conf_slot<T>(
    slots: *mut *mut c_void,
    index: usize,
    slot_count: usize,
) -> Option<NonNull<T>> {
    let slots = NonNull::new(slots)?;
    let slots = unsafe { core::slice::from_raw_parts(slots.as_ptr(), slot_count) };
    let value = *slots.get(index)?;
    NonNull::new(value.cast())
}

fn main_conf_slot<T>(
    slots: *mut *mut c_void,
    module: &ngx_module_t,
) -> Result<Option<NonNull<T>>, StreamConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.stream_slots) })
}

fn server_conf_slot<T>(
    slots: *mut *mut c_void,
    module: &ngx_module_t,
) -> Result<Option<NonNull<T>>, StreamConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.stream_slots) })
}

pub(crate) mod sealed {
    pub trait MainConfSource {}
    pub trait MainConfSourceMut: MainConfSource {}
    pub trait ServerConfSource {}
    pub trait ServerConfSourceMut: ServerConfSource {}
}

/// Source of a Stream module's main configuration.
///
/// This trait is sealed because its implementations carry the nginx-owned slot-array invariant.
/// Use [`StreamModuleMainConf::main_conf`] instead of calling it directly.
pub trait StreamModuleMainConfExt: sealed::MainConfSource {
    /// Resolves a checked typed main-configuration slot.
    #[doc(hidden)]
    fn stream_main_conf<T>(&self, module: &ngx_module_t) -> Result<Option<&T>, StreamConfigError>;
}

/// Exclusive source of a Stream module's main configuration.
pub trait StreamModuleMainConfMutExt: StreamModuleMainConfExt + sealed::MainConfSourceMut {
    /// Resolves a checked exclusive main-configuration slot.
    #[doc(hidden)]
    fn stream_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError>;
}

/// Source of a Stream module's server configuration.
///
/// This trait is sealed because its implementations carry the nginx-owned slot-array invariant.
/// Use [`StreamModuleServerConf::server_conf`] instead of calling it directly.
pub trait StreamModuleServerConfExt: sealed::ServerConfSource {
    /// Resolves a checked typed server-configuration slot.
    #[doc(hidden)]
    fn stream_server_conf<T>(&self, module: &ngx_module_t)
    -> Result<Option<&T>, StreamConfigError>;
}

/// Exclusive source of a Stream module's server configuration.
pub trait StreamModuleServerConfMutExt:
    StreamModuleServerConfExt + sealed::ServerConfSourceMut
{
    /// Resolves a checked exclusive server-configuration slot.
    #[doc(hidden)]
    fn stream_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError>;
}

impl sealed::MainConfSource for ngx_stream_conf_ctx_t {}
impl sealed::MainConfSourceMut for ngx_stream_conf_ctx_t {}
impl sealed::ServerConfSource for ngx_stream_conf_ctx_t {}
impl sealed::ServerConfSourceMut for ngx_stream_conf_ctx_t {}

impl StreamModuleMainConfExt for ngx_stream_conf_ctx_t {
    fn stream_main_conf<T>(&self, module: &ngx_module_t) -> Result<Option<&T>, StreamConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl StreamModuleMainConfMutExt for ngx_stream_conf_ctx_t {
    fn stream_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl StreamModuleServerConfExt for ngx_stream_conf_ctx_t {
    fn stream_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, StreamConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl StreamModuleServerConfMutExt for ngx_stream_conf_ctx_t {
    fn stream_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

fn stream_context(
    cf: &ngx_conf_t,
) -> Result<Option<NonNull<ngx_stream_conf_ctx_t>>, StreamConfigError> {
    if cf.module_type != NGX_STREAM_MODULE as ngx_uint_t {
        return Err(StreamConfigError::WrongConfigurationContext);
    }

    Ok(NonNull::new(cf.ctx.cast()))
}

impl sealed::MainConfSource for ngx_conf_t {}
impl sealed::MainConfSourceMut for ngx_conf_t {}
impl sealed::ServerConfSource for ngx_conf_t {}
impl sealed::ServerConfSourceMut for ngx_conf_t {}

impl StreamModuleMainConfExt for ngx_conf_t {
    fn stream_main_conf<T>(&self, module: &ngx_module_t) -> Result<Option<&T>, StreamConfigError> {
        let Some(context) = stream_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_ref().stream_main_conf(module) }
    }
}

impl StreamModuleMainConfMutExt for ngx_conf_t {
    fn stream_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        let Some(mut context) = stream_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_mut().stream_main_conf_mut(module) }
    }
}

impl StreamModuleServerConfExt for ngx_conf_t {
    fn stream_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, StreamConfigError> {
        let Some(context) = stream_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_ref().stream_server_conf(module) }
    }
}

impl StreamModuleServerConfMutExt for ngx_conf_t {
    fn stream_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        let Some(mut context) = stream_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_mut().stream_server_conf_mut(module) }
    }
}

impl sealed::MainConfSource for ngx_stream_core_srv_conf_t {}
impl sealed::MainConfSourceMut for ngx_stream_core_srv_conf_t {}
impl sealed::ServerConfSource for ngx_stream_core_srv_conf_t {}
impl sealed::ServerConfSourceMut for ngx_stream_core_srv_conf_t {}

impl StreamModuleMainConfExt for ngx_stream_core_srv_conf_t {
    fn stream_main_conf<T>(&self, module: &ngx_module_t) -> Result<Option<&T>, StreamConfigError> {
        let Some(context) = NonNull::new(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().stream_main_conf(module) }
    }
}

impl StreamModuleMainConfMutExt for ngx_stream_core_srv_conf_t {
    fn stream_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        let Some(mut context) = NonNull::new(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().stream_main_conf_mut(module) }
    }
}

impl StreamModuleServerConfExt for ngx_stream_core_srv_conf_t {
    fn stream_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, StreamConfigError> {
        let Some(context) = NonNull::new(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().stream_server_conf(module) }
    }
}

impl StreamModuleServerConfMutExt for ngx_stream_core_srv_conf_t {
    fn stream_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        let Some(mut context) = NonNull::new(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().stream_server_conf_mut(module) }
    }
}

impl sealed::MainConfSource for ngx_stream_session_t {}
impl sealed::MainConfSourceMut for ngx_stream_session_t {}
impl sealed::ServerConfSource for ngx_stream_session_t {}
impl sealed::ServerConfSourceMut for ngx_stream_session_t {}

impl StreamModuleMainConfExt for ngx_stream_session_t {
    fn stream_main_conf<T>(&self, module: &ngx_module_t) -> Result<Option<&T>, StreamConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl StreamModuleMainConfMutExt for ngx_stream_session_t {
    fn stream_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl StreamModuleServerConfExt for ngx_stream_session_t {
    fn stream_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, StreamConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl StreamModuleServerConfMutExt for ngx_stream_session_t {
    fn stream_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl sealed::ServerConfSource for ngx_stream_upstream_srv_conf_t {}
impl sealed::ServerConfSourceMut for ngx_stream_upstream_srv_conf_t {}

impl StreamModuleServerConfExt for ngx_stream_upstream_srv_conf_t {
    fn stream_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, StreamConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl StreamModuleServerConfMutExt for ngx_stream_upstream_srv_conf_t {
    fn stream_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

/// Associates a Stream module with its main-configuration type.
///
/// # Safety
/// `MainConf` must be the main-configuration type stored for `Self::module()`.
pub unsafe trait StreamModuleMainConf: StreamModule {
    /// The module's main-configuration type.
    type MainConf: 'static;

    /// Gets the module's main configuration from a checked nginx-owned source.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::stream::StreamModuleMainConf;
    /// fn escape<M: StreamModuleMainConf>(source: &ngx_conf_t) -> &'static M::MainConf {
    ///     M::main_conf(source).unwrap().unwrap()
    /// }
    /// ```
    fn main_conf(
        source: &impl StreamModuleMainConfExt,
    ) -> Result<Option<&Self::MainConf>, StreamConfigError> {
        source.stream_main_conf(Self::module())
    }

    /// Gets exclusive access to the module's main configuration.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::stream::StreamModuleMainConf;
    /// # fn access<M: StreamModuleMainConf>(cf: &ngx_conf_t) {
    /// let _ = M::main_conf_mut(cf);
    /// # }
    /// ```
    fn main_conf_mut(
        source: &mut impl StreamModuleMainConfMutExt,
    ) -> Result<Option<&mut Self::MainConf>, StreamConfigError> {
        source.stream_main_conf_mut(Self::module())
    }

    /// Resolves configuration from an explicitly selected live cycle.
    ///
    /// # Safety
    /// `cycle` must remain live for the returned borrow. Its `conf_ctx` array must contain the
    /// current `ngx_max_module` entries, and its Stream context must contain exactly
    /// `stream_slot_count` configuration slots. Callers select an old reload cycle explicitly and
    /// provide that cycle's slot count.
    unsafe fn main_conf_from_cycle(
        cycle: &ngx_cycle_t,
        stream_slot_count: usize,
    ) -> Result<Option<&Self::MainConf>, StreamConfigError> {
        let indexes = module_indexes(Self::module(), live_module_slot_count(), stream_slot_count)?;
        let stream_index = usize_index(
            unsafe { nginx_sys::ngx_stream_module.index },
            StreamConfigError::UnsetStreamModuleIndex,
        )?;
        if stream_index >= indexes.module_slots {
            return Err(StreamConfigError::StreamModuleIndexOutOfBounds);
        }

        let Some(contexts) = NonNull::new(cycle.conf_ctx) else {
            return Ok(None);
        };
        let contexts =
            unsafe { core::slice::from_raw_parts(contexts.as_ptr(), indexes.module_slots) };
        let Some(context) = contexts.get(stream_index) else {
            return Ok(None);
        };
        let Some(context) = NonNull::new((*context).cast::<ngx_stream_conf_ctx_t>()) else {
            return Ok(None);
        };
        let context = unsafe { context.as_ref() };
        Ok(unsafe {
            conf_slot(context.main_conf, indexes.context, indexes.stream_slots)
                .map(|configuration| configuration.as_ref())
        })
    }

    /// Runs a closure with the active cycle's main configuration without creating a `'static`
    /// reference.
    ///
    /// # Safety
    /// Call only while nginx keeps its active cycle and Stream configuration alive on the current
    /// worker. The closure must not retain raw configuration pointers after it returns.
    unsafe fn with_active_main_conf<R>(
        f: impl for<'config> FnOnce(&'config Self::MainConf) -> R,
    ) -> Result<Option<R>, StreamConfigError> {
        let Some(cycle) = NonNull::new(unsafe { nginx_sys::ngx_cycle }) else {
            return Ok(None);
        };
        let configuration =
            unsafe { Self::main_conf_from_cycle(cycle.as_ref(), live_stream_slot_count())? };
        Ok(configuration.map(f))
    }
}

/// Associates a Stream module with its server-configuration type.
///
/// # Safety
/// `ServerConf` must be the server-configuration type stored for `Self::module()`.
pub unsafe trait StreamModuleServerConf: StreamModule {
    /// The module's server-configuration type.
    type ServerConf: 'static;

    /// Gets the module's server configuration from a checked nginx-owned source.
    fn server_conf(
        source: &impl StreamModuleServerConfExt,
    ) -> Result<Option<&Self::ServerConf>, StreamConfigError> {
        source.stream_server_conf(Self::module())
    }

    /// Gets exclusive access to the module's server configuration.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::stream::StreamModuleServerConf;
    /// # fn access<M: StreamModuleServerConf>(cf: &ngx_conf_t) {
    /// let _ = M::server_conf_mut(cf);
    /// # }
    /// ```
    fn server_conf_mut(
        source: &mut impl StreamModuleServerConfMutExt,
    ) -> Result<Option<&mut Self::ServerConf>, StreamConfigError> {
        source.stream_server_conf_mut(Self::module())
    }
}

mod core_module {
    use crate::allocator::AllocError;
    use crate::collections::NgxArray;
    use crate::ffi::{
        NGX_LOG_EMERG, ngx_conf_t, ngx_stream_core_main_conf_t, ngx_stream_core_module,
        ngx_stream_core_srv_conf_t, ngx_stream_handler_pt,
    };
    use crate::ngx_conf_log_error;
    use crate::stream::{
        StreamModule, StreamModuleMainConf, StreamModuleServerConf, StreamSessionHandler,
    };

    /// Typed access to `ngx_stream_core_module` configuration.
    pub struct NgxStreamCoreModule;

    unsafe impl StreamModule for NgxStreamCoreModule {
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

    /// Registers a typed handler in its declared Stream phase.
    ///
    /// Call this function from the module's postconfiguration callback.
    pub fn add_phase_handler<H>(cf: &mut ngx_conf_t) -> Result<(), AllocError>
    where
        H: StreamSessionHandler,
    {
        let result = (|| {
            let main = NgxStreamCoreModule::main_conf_mut(cf)
                .map_err(|_| AllocError)?
                .ok_or(AllocError)?;
            let phase = main.phases.get_mut(H::PHASE as usize).ok_or(AllocError)?;
            let handlers = unsafe {
                NgxArray::<ngx_stream_handler_pt>::from_ngx_array_mut(&mut phase.handlers)
            }
            .ok_or(AllocError)?;

            handlers.push(Some(crate::stream::raw_handler::<H>)).map(|_| ())
        })();

        if result.is_err() && !cf.log.is_null() {
            ngx_conf_log_error!(NGX_LOG_EMERG, cf, "failed to register {} handler", H::name(),);
        }

        result
    }
}

pub use core_module::{NgxStreamCoreModule, add_phase_handler};

#[cfg(ngx_feature = "stream_ssl")]
mod ssl {
    use crate::ffi::{ngx_stream_ssl_module, ngx_stream_ssl_srv_conf_t};
    use crate::stream::{StreamModule, StreamModuleServerConf};

    /// Typed access to `ngx_stream_ssl_module` configuration.
    pub struct NgxStreamSslModule;

    unsafe impl StreamModule for NgxStreamSslModule {
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

    unsafe impl StreamModule for NgxStreamUpstreamModule {
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
    #[cfg(feature = "test-link")]
    use core::ffi::c_void;
    #[cfg(feature = "test-link")]
    use core::mem;
    #[cfg(feature = "test-link")]
    use core::ptr;
    #[cfg(feature = "test-link")]
    use std::sync::MutexGuard;

    use super::{StreamConfigError, StreamModuleMainConf, StreamModuleServerConf, module_indexes};
    use crate::ffi::{NGX_STREAM_MODULE, ngx_module_t, ngx_uint_t};
    #[cfg(feature = "test-link")]
    use crate::ffi::{ngx_conf_t, ngx_stream_conf_ctx_t, ngx_stream_core_srv_conf_t};
    use crate::stream::StreamModule;

    fn stream_module(index: ngx_uint_t, context_index: ngx_uint_t) -> ngx_module_t {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_STREAM_MODULE as _;
        module.index = index;
        module.ctx_index = context_index;
        module
    }

    #[test]
    fn stream_module_type_is_required() {
        let module = ngx_module_t::default();

        assert!(matches!(module_indexes(&module, 2, 1), Err(StreamConfigError::WrongModuleType)));
    }

    #[test]
    fn module_index_requires_assignment_and_available_global_slot() {
        let mut module = stream_module(ngx_uint_t::MAX, 0);

        assert!(matches!(module_indexes(&module, 2, 1), Err(StreamConfigError::UnsetModuleIndex)));

        module.index = 2;
        assert!(matches!(
            module_indexes(&module, 2, 1),
            Err(StreamConfigError::ModuleIndexOutOfBounds)
        ));

        module.index = 3;
        assert!(matches!(
            module_indexes(&module, 2, 1),
            Err(StreamConfigError::ModuleIndexOutOfBounds)
        ));

        module.index = 0;
        assert!(module_indexes(&module, 1, 1).is_ok());
    }

    #[test]
    fn context_index_requires_assignment_and_available_stream_slot() {
        let mut module = stream_module(0, ngx_uint_t::MAX);

        assert!(matches!(module_indexes(&module, 1, 1), Err(StreamConfigError::UnsetContextIndex)));

        module.ctx_index = 1;
        assert!(matches!(
            module_indexes(&module, 1, 1),
            Err(StreamConfigError::ContextIndexOutOfBounds)
        ));

        module.ctx_index = 2;
        assert!(matches!(
            module_indexes(&module, 1, 1),
            Err(StreamConfigError::ContextIndexOutOfBounds)
        ));

        module.ctx_index = 0;
        assert!(module_indexes(&module, 1, 1).is_ok());
    }

    fn test_module() -> &'static ngx_module_t {
        Box::leak(Box::new(stream_module(1, 0)))
    }

    fn wrong_type_module() -> &'static ngx_module_t {
        Box::leak(Box::new(ngx_module_t { index: 1, ctx_index: 0, ..ngx_module_t::default() }))
    }

    struct TestStreamModule;

    unsafe impl StreamModule for TestStreamModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl StreamModuleMainConf for TestStreamModule {
        type MainConf = u32;
    }

    unsafe impl StreamModuleServerConf for TestStreamModule {
        type ServerConf = u32;
    }

    struct WrongTypeModule;

    unsafe impl StreamModule for WrongTypeModule {
        fn module() -> &'static ngx_module_t {
            wrong_type_module()
        }
    }

    unsafe impl StreamModuleMainConf for WrongTypeModule {
        type MainConf = u32;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn wrong_module_type_does_not_read_a_stream_configuration_slot() {
        let mut value = 42_u32;
        let mut slots: [*mut c_void; 1] = [(&raw mut value).cast()];
        let context =
            ngx_stream_conf_ctx_t { main_conf: slots.as_mut_ptr(), srv_conf: ptr::null_mut() };

        assert_eq!(WrongTypeModule::main_conf(&context), Err(StreamConfigError::WrongModuleType));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn missing_parser_context_returns_none_and_wrong_context_errors() {
        let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };
        configuration.module_type = NGX_STREAM_MODULE as _;

        assert_eq!(
            TestStreamModule::main_conf(&configuration).map(|value| value.copied()),
            Ok(None)
        );

        configuration.module_type = 0;
        assert_eq!(
            TestStreamModule::main_conf(&configuration),
            Err(StreamConfigError::WrongConfigurationContext)
        );
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn core_server_without_stream_context_returns_none() {
        let server = unsafe { mem::zeroed::<ngx_stream_core_srv_conf_t>() };

        assert_eq!(TestStreamModule::server_conf(&server).map(|value| value.copied()), Ok(None));
    }

    #[cfg(feature = "test-link")]
    struct GlobalState {
        cycle: *mut nginx_sys::ngx_cycle_t,
        max_module: ngx_uint_t,
        stream_max_module: ngx_uint_t,
        stream_module_index: ngx_uint_t,
        stream_core_module_type: ngx_uint_t,
        stream_core_module_index: ngx_uint_t,
        stream_core_module_context_index: ngx_uint_t,
    }

    #[cfg(feature = "test-link")]
    struct StreamGlobals {
        _guard: MutexGuard<'static, ()>,
        previous: GlobalState,
    }

    #[cfg(feature = "test-link")]
    impl StreamGlobals {
        fn new(module_slots: ngx_uint_t, stream_slots: ngx_uint_t) -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let previous = unsafe {
                GlobalState {
                    cycle: nginx_sys::ngx_cycle,
                    max_module: nginx_sys::ngx_max_module,
                    stream_max_module: nginx_sys::ngx_stream_max_module,
                    stream_module_index: (*core::ptr::addr_of!(nginx_sys::ngx_stream_module)).index,
                    stream_core_module_type: (*core::ptr::addr_of!(
                        nginx_sys::ngx_stream_core_module
                    ))
                    .type_,
                    stream_core_module_index: (*core::ptr::addr_of!(
                        nginx_sys::ngx_stream_core_module
                    ))
                    .index,
                    stream_core_module_context_index: (*core::ptr::addr_of!(
                        nginx_sys::ngx_stream_core_module
                    ))
                    .ctx_index,
                }
            };

            unsafe {
                nginx_sys::ngx_cycle = ptr::null_mut();
                nginx_sys::ngx_max_module = module_slots;
                nginx_sys::ngx_stream_max_module = stream_slots;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_module)).index = 0;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).type_ =
                    NGX_STREAM_MODULE as _;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).index = 0;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).ctx_index = 0;
            }

            Self { _guard: guard, previous }
        }

        fn set_active_cycle(&self, cycle: *mut nginx_sys::ngx_cycle_t) {
            unsafe {
                nginx_sys::ngx_cycle = cycle;
            }
        }

        fn set_stream_module_index(&self, index: ngx_uint_t) {
            unsafe {
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_module)).index = index;
            }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for StreamGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_cycle = self.previous.cycle;
                nginx_sys::ngx_max_module = self.previous.max_module;
                nginx_sys::ngx_stream_max_module = self.previous.stream_max_module;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_module)).index =
                    self.previous.stream_module_index;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).type_ =
                    self.previous.stream_core_module_type;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).index =
                    self.previous.stream_core_module_index;
                (*core::ptr::addr_of_mut!(nginx_sys::ngx_stream_core_module)).ctx_index =
                    self.previous.stream_core_module_context_index;
            }
        }
    }

    #[cfg(feature = "test-link")]
    #[path = "phase_tests.rs"]
    mod phase_tests;

    #[cfg(feature = "test-link")]
    #[test]
    fn null_stream_configuration_slots_return_none() {
        let _globals = StreamGlobals::new(2, 1);
        let context =
            ngx_stream_conf_ctx_t { main_conf: ptr::null_mut(), srv_conf: ptr::null_mut() };

        assert_eq!(TestStreamModule::main_conf(&context).map(|value| value.copied()), Ok(None));
        assert_eq!(TestStreamModule::server_conf(&context).map(|value| value.copied()), Ok(None));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn typed_stream_configuration_access_follows_the_source_borrow() {
        let _globals = StreamGlobals::new(2, 1);
        let mut main = 42_u32;
        let mut server = 99_u32;
        let mut main_slots: [*mut c_void; 1] = [(&raw mut main).cast()];
        let mut server_slots: [*mut c_void; 1] = [(&raw mut server).cast()];
        let mut context = ngx_stream_conf_ctx_t {
            main_conf: main_slots.as_mut_ptr(),
            srv_conf: server_slots.as_mut_ptr(),
        };

        assert_eq!(TestStreamModule::main_conf(&context).map(|value| value.copied()), Ok(Some(42)));
        assert_eq!(
            TestStreamModule::server_conf(&context).map(|value| value.copied()),
            Ok(Some(99))
        );

        if let Some(value) = TestStreamModule::main_conf_mut(&mut context).unwrap() {
            *value = 7;
        }
        if let Some(value) = TestStreamModule::server_conf_mut(&mut context).unwrap() {
            *value = 8;
        }

        assert_eq!(main, 7);
        assert_eq!(server, 8);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn cycle_access_keeps_old_and_active_slots_explicit() {
        let globals = StreamGlobals::new(2, 1);

        assert_eq!(unsafe { TestStreamModule::with_active_main_conf(|value| *value) }, Ok(None));
        let empty_cycle = unsafe { mem::zeroed::<nginx_sys::ngx_cycle_t>() };
        assert_eq!(
            unsafe { TestStreamModule::main_conf_from_cycle(&empty_cycle, 1) }
                .map(|value| value.copied()),
            Ok(None)
        );

        let mut old_main = 11_u32;
        let mut old_main_slots: [*mut c_void; 1] = [(&raw mut old_main).cast()];
        let mut old_context = ngx_stream_conf_ctx_t {
            main_conf: old_main_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
        };
        let mut old_contexts: [*mut *mut *mut c_void; 2] =
            [(&raw mut old_context).cast(), ptr::null_mut()];
        let mut old_cycle = unsafe { mem::zeroed::<nginx_sys::ngx_cycle_t>() };
        old_cycle.conf_ctx = old_contexts.as_mut_ptr();

        assert_eq!(
            unsafe { TestStreamModule::main_conf_from_cycle(&old_cycle, 1) }
                .map(|value| value.copied()),
            Ok(Some(11))
        );
        assert_eq!(
            unsafe { TestStreamModule::main_conf_from_cycle(&old_cycle, 0) },
            Err(StreamConfigError::ContextIndexOutOfBounds)
        );

        globals.set_stream_module_index(1);
        assert_eq!(
            unsafe { TestStreamModule::main_conf_from_cycle(&old_cycle, 1) }
                .map(|value| value.copied()),
            Ok(None)
        );
        globals.set_stream_module_index(ngx_uint_t::MAX);
        assert_eq!(
            unsafe { TestStreamModule::main_conf_from_cycle(&old_cycle, 1) },
            Err(StreamConfigError::UnsetStreamModuleIndex)
        );
        globals.set_stream_module_index(2);
        assert_eq!(
            unsafe { TestStreamModule::main_conf_from_cycle(&old_cycle, 1) },
            Err(StreamConfigError::StreamModuleIndexOutOfBounds)
        );
        globals.set_stream_module_index(3);
        assert_eq!(
            unsafe { TestStreamModule::main_conf_from_cycle(&old_cycle, 1) },
            Err(StreamConfigError::StreamModuleIndexOutOfBounds)
        );
        globals.set_stream_module_index(0);

        let mut active_main = 42_u32;
        let mut active_main_slots: [*mut c_void; 1] = [(&raw mut active_main).cast()];
        let mut active_context = ngx_stream_conf_ctx_t {
            main_conf: active_main_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
        };
        let mut active_contexts: [*mut *mut *mut c_void; 2] =
            [(&raw mut active_context).cast(), ptr::null_mut()];
        let mut active_cycle = unsafe { mem::zeroed::<nginx_sys::ngx_cycle_t>() };
        active_cycle.conf_ctx = active_contexts.as_mut_ptr();

        globals.set_active_cycle(&raw mut active_cycle);
        assert_eq!(
            unsafe { TestStreamModule::with_active_main_conf(|value| *value) },
            Ok(Some(42))
        );

        globals.set_active_cycle(&raw mut old_cycle);
        assert_eq!(
            unsafe { TestStreamModule::with_active_main_conf(|value| *value) },
            Ok(Some(11))
        );
    }
}
