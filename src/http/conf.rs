use ::core::ffi::c_void;
use ::core::ptr::NonNull;

use crate::ffi::{
    NGX_HTTP_MODULE, ngx_conf_t, ngx_cycle_t, ngx_http_conf_ctx_t, ngx_http_connection_t,
    ngx_http_core_srv_conf_t, ngx_http_request_t, ngx_http_upstream_srv_conf_t, ngx_module_t,
    ngx_uint_t,
};
use crate::http::HttpModule;

/// Failure while resolving a typed HTTP configuration slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpConfigError {
    /// The module descriptor is not an HTTP module.
    WrongModuleType,
    /// Nginx has not assigned the module's global index.
    UnsetModuleIndex,
    /// Nginx has not assigned the module's HTTP configuration index.
    UnsetContextIndex,
    /// The module's global index is outside the configured module array.
    ModuleIndexOutOfBounds,
    /// The module's HTTP configuration index is outside the configured slot array.
    ContextIndexOutOfBounds,
    /// The configuration parser is not in an HTTP context.
    WrongConfigurationContext,
    /// The HTTP core module does not have a usable global index.
    UnsetHttpModuleIndex,
    /// The HTTP core module index is outside the configured module array.
    HttpModuleIndexOutOfBounds,
}

#[derive(Clone, Copy)]
struct ModuleIndexes {
    context: usize,
    module_slots: usize,
    http_slots: usize,
}

fn usize_index(index: ngx_uint_t, unset: HttpConfigError) -> Result<usize, HttpConfigError> {
    if index == ngx_uint_t::MAX {
        return Err(unset);
    }

    Ok(index)
}

fn module_indexes(
    module: &ngx_module_t,
    module_slots: usize,
    http_slots: usize,
) -> Result<ModuleIndexes, HttpConfigError> {
    if module.type_ != NGX_HTTP_MODULE as ngx_uint_t {
        return Err(HttpConfigError::WrongModuleType);
    }

    let module_index = usize_index(module.index, HttpConfigError::UnsetModuleIndex)?;
    if module_index >= module_slots {
        return Err(HttpConfigError::ModuleIndexOutOfBounds);
    }

    let context_index = usize_index(module.ctx_index, HttpConfigError::UnsetContextIndex)?;
    if context_index >= http_slots {
        return Err(HttpConfigError::ContextIndexOutOfBounds);
    }

    Ok(ModuleIndexes { context: context_index, module_slots, http_slots })
}

fn live_module_slot_count() -> usize {
    unsafe { nginx_sys::ngx_max_module }
}

fn live_http_slot_count() -> usize {
    unsafe { nginx_sys::ngx_http_max_module }
}

fn live_module_indexes(module: &ngx_module_t) -> Result<ModuleIndexes, HttpConfigError> {
    module_indexes(module, live_module_slot_count(), live_http_slot_count())
}

fn checked_pointer<T>(pointer: *mut T) -> Option<NonNull<T>> {
    let pointer = NonNull::new(pointer)?;
    if !pointer.as_ptr().is_aligned() {
        return None;
    }

    Some(pointer)
}

unsafe fn conf_slot<T>(
    slots: *mut *mut c_void,
    index: usize,
    slot_count: usize,
) -> Option<NonNull<T>> {
    let slots = checked_pointer(slots)?;
    let slots = unsafe { ::core::slice::from_raw_parts(slots.as_ptr(), slot_count) };
    let value = *slots.get(index)?;
    checked_pointer(value.cast())
}

fn main_conf_slot<T>(
    slots: *mut *mut c_void,
    module: &ngx_module_t,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.http_slots) })
}

fn server_conf_slot<T>(
    slots: *mut *mut c_void,
    module: &ngx_module_t,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.http_slots) })
}

fn location_conf_slot<T>(
    slots: *mut *mut c_void,
    module: &ngx_module_t,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.http_slots) })
}

pub(crate) mod sealed {
    pub trait MainConfSource {}
    pub trait MainConfSourceMut: MainConfSource {}
    pub trait ServerConfSource {}
    pub trait ServerConfSourceMut: ServerConfSource {}
    pub trait LocationConfSource {}
    pub trait LocationConfSourceMut: LocationConfSource {}
}

/// Source of an HTTP module's main configuration.
///
/// This trait is sealed because its implementations carry the nginx-owned slot-array invariant.
/// Use [`HttpModuleMainConf::main_conf`] instead of calling it directly.
pub trait HttpModuleMainConfExt: sealed::MainConfSource {
    /// Resolves a checked typed main-configuration slot.
    ///
    /// # Safety
    /// `T` must be the main-configuration type stored for `module`.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::{ngx_http_conf_ctx_t, ngx_module_t};
    /// # use ngx::http::HttpModuleMainConfExt;
    /// fn unchecked(source: &ngx_http_conf_ctx_t, module: &ngx_module_t) {
    ///     let _ = source.http_main_conf::<u32>(module);
    /// }
    /// ```
    #[doc(hidden)]
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError>;
}

/// Exclusive source of an HTTP module's main configuration.
pub trait HttpModuleMainConfMutExt: HttpModuleMainConfExt + sealed::MainConfSourceMut {
    /// Resolves a checked exclusive main-configuration slot.
    ///
    /// # Safety
    /// `T` must be the main-configuration type stored for `module`.
    #[doc(hidden)]
    unsafe fn http_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError>;
}

/// Source of an HTTP module's server configuration.
///
/// This trait is sealed because its implementations carry the nginx-owned slot-array invariant.
/// Use [`HttpModuleServerConf::server_conf`] instead of calling it directly.
pub trait HttpModuleServerConfExt: sealed::ServerConfSource {
    /// Resolves a checked typed server-configuration slot.
    ///
    /// # Safety
    /// `T` must be the server-configuration type stored for `module`.
    #[doc(hidden)]
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError>;
}

/// Exclusive source of an HTTP module's server configuration.
pub trait HttpModuleServerConfMutExt:
    HttpModuleServerConfExt + sealed::ServerConfSourceMut
{
    /// Resolves a checked exclusive server-configuration slot.
    ///
    /// # Safety
    /// `T` must be the server-configuration type stored for `module`.
    #[doc(hidden)]
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError>;
}

/// Source of an HTTP module's location configuration.
///
/// This trait is sealed because its implementations carry the nginx-owned slot-array invariant.
/// Use [`HttpModuleLocationConf::location_conf`] instead of calling it directly.
pub trait HttpModuleLocationConfExt: sealed::LocationConfSource {
    /// Resolves a checked typed location-configuration slot.
    ///
    /// # Safety
    /// `T` must be the location-configuration type stored for `module`.
    #[doc(hidden)]
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError>;
}

/// Exclusive source of an HTTP module's location configuration.
pub trait HttpModuleLocationConfMutExt:
    HttpModuleLocationConfExt + sealed::LocationConfSourceMut
{
    /// Resolves a checked exclusive location-configuration slot.
    ///
    /// # Safety
    /// `T` must be the location-configuration type stored for `module`.
    #[doc(hidden)]
    unsafe fn http_location_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError>;
}

impl sealed::MainConfSource for ngx_http_conf_ctx_t {}
impl sealed::MainConfSourceMut for ngx_http_conf_ctx_t {}
impl sealed::ServerConfSource for ngx_http_conf_ctx_t {}
impl sealed::ServerConfSourceMut for ngx_http_conf_ctx_t {}
impl sealed::LocationConfSource for ngx_http_conf_ctx_t {}
impl sealed::LocationConfSourceMut for ngx_http_conf_ctx_t {}

impl HttpModuleMainConfExt for ngx_http_conf_ctx_t {
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl HttpModuleMainConfMutExt for ngx_http_conf_ctx_t {
    unsafe fn http_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl HttpModuleServerConfExt for ngx_http_conf_ctx_t {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl HttpModuleServerConfMutExt for ngx_http_conf_ctx_t {
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl HttpModuleLocationConfExt for ngx_http_conf_ctx_t {
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        Ok(location_conf_slot(self.loc_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl HttpModuleLocationConfMutExt for ngx_http_conf_ctx_t {
    unsafe fn http_location_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        Ok(location_conf_slot(self.loc_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

fn http_context(cf: &ngx_conf_t) -> Result<Option<NonNull<ngx_http_conf_ctx_t>>, HttpConfigError> {
    if cf.module_type != NGX_HTTP_MODULE as ngx_uint_t {
        return Err(HttpConfigError::WrongConfigurationContext);
    }

    Ok(checked_pointer(cf.ctx.cast()))
}

impl sealed::MainConfSource for ngx_conf_t {}
impl sealed::MainConfSourceMut for ngx_conf_t {}
impl sealed::ServerConfSource for ngx_conf_t {}
impl sealed::ServerConfSourceMut for ngx_conf_t {}
impl sealed::LocationConfSource for ngx_conf_t {}
impl sealed::LocationConfSourceMut for ngx_conf_t {}

impl HttpModuleMainConfExt for ngx_conf_t {
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = http_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_main_conf(module) }
    }
}

impl HttpModuleMainConfMutExt for ngx_conf_t {
    unsafe fn http_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = http_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_main_conf_mut(module) }
    }
}

impl HttpModuleServerConfExt for ngx_conf_t {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = http_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_server_conf(module) }
    }
}

impl HttpModuleServerConfMutExt for ngx_conf_t {
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = http_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_server_conf_mut(module) }
    }
}

impl HttpModuleLocationConfExt for ngx_conf_t {
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = http_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_location_conf(module) }
    }
}

impl HttpModuleLocationConfMutExt for ngx_conf_t {
    unsafe fn http_location_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = http_context(self)? else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_location_conf_mut(module) }
    }
}

impl sealed::MainConfSource for ngx_http_connection_t {}
impl sealed::MainConfSourceMut for ngx_http_connection_t {}
impl sealed::ServerConfSource for ngx_http_connection_t {}
impl sealed::ServerConfSourceMut for ngx_http_connection_t {}
impl sealed::LocationConfSource for ngx_http_connection_t {}
impl sealed::LocationConfSourceMut for ngx_http_connection_t {}

impl HttpModuleMainConfExt for ngx_http_connection_t {
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = checked_pointer(self.conf_ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_main_conf(module) }
    }
}

impl HttpModuleMainConfMutExt for ngx_http_connection_t {
    unsafe fn http_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = checked_pointer(self.conf_ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_main_conf_mut(module) }
    }
}

impl HttpModuleServerConfExt for ngx_http_connection_t {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = checked_pointer(self.conf_ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_server_conf(module) }
    }
}

impl HttpModuleServerConfMutExt for ngx_http_connection_t {
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = checked_pointer(self.conf_ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_server_conf_mut(module) }
    }
}

impl HttpModuleLocationConfExt for ngx_http_connection_t {
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = checked_pointer(self.conf_ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_location_conf(module) }
    }
}

impl HttpModuleLocationConfMutExt for ngx_http_connection_t {
    unsafe fn http_location_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = checked_pointer(self.conf_ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_location_conf_mut(module) }
    }
}

impl sealed::MainConfSource for ngx_http_core_srv_conf_t {}
impl sealed::MainConfSourceMut for ngx_http_core_srv_conf_t {}
impl sealed::ServerConfSource for ngx_http_core_srv_conf_t {}
impl sealed::ServerConfSourceMut for ngx_http_core_srv_conf_t {}
impl sealed::LocationConfSource for ngx_http_core_srv_conf_t {}
impl sealed::LocationConfSourceMut for ngx_http_core_srv_conf_t {}

impl HttpModuleMainConfExt for ngx_http_core_srv_conf_t {
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = checked_pointer(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_main_conf(module) }
    }
}

impl HttpModuleMainConfMutExt for ngx_http_core_srv_conf_t {
    unsafe fn http_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = checked_pointer(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_main_conf_mut(module) }
    }
}

impl HttpModuleServerConfExt for ngx_http_core_srv_conf_t {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = checked_pointer(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_server_conf(module) }
    }
}

impl HttpModuleServerConfMutExt for ngx_http_core_srv_conf_t {
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = checked_pointer(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_server_conf_mut(module) }
    }
}

impl HttpModuleLocationConfExt for ngx_http_core_srv_conf_t {
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = checked_pointer(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_ref().http_location_conf(module) }
    }
}

impl HttpModuleLocationConfMutExt for ngx_http_core_srv_conf_t {
    unsafe fn http_location_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(mut context) = checked_pointer(self.ctx) else {
            return Ok(None);
        };
        unsafe { context.as_mut().http_location_conf_mut(module) }
    }
}

impl sealed::MainConfSource for ngx_http_request_t {}
impl sealed::MainConfSourceMut for ngx_http_request_t {}
impl sealed::ServerConfSource for ngx_http_request_t {}
impl sealed::ServerConfSourceMut for ngx_http_request_t {}
impl sealed::LocationConfSource for ngx_http_request_t {}
impl sealed::LocationConfSourceMut for ngx_http_request_t {}

impl HttpModuleMainConfExt for ngx_http_request_t {
    unsafe fn http_main_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl HttpModuleMainConfMutExt for ngx_http_request_t {
    unsafe fn http_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        Ok(main_conf_slot(self.main_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl HttpModuleServerConfExt for ngx_http_request_t {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl HttpModuleServerConfMutExt for ngx_http_request_t {
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl HttpModuleLocationConfExt for ngx_http_request_t {
    unsafe fn http_location_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        Ok(location_conf_slot(self.loc_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl HttpModuleLocationConfMutExt for ngx_http_request_t {
    unsafe fn http_location_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        Ok(location_conf_slot(self.loc_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

impl sealed::ServerConfSource for ngx_http_upstream_srv_conf_t {}
impl sealed::ServerConfSourceMut for ngx_http_upstream_srv_conf_t {}

impl HttpModuleServerConfExt for ngx_http_upstream_srv_conf_t {
    unsafe fn http_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, HttpConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|value| unsafe { value.as_ref() }))
    }
}

impl HttpModuleServerConfMutExt for ngx_http_upstream_srv_conf_t {
    unsafe fn http_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        Ok(server_conf_slot(self.srv_conf, module)?.map(|mut value| unsafe { value.as_mut() }))
    }
}

/// Associates an HTTP module with its main-configuration type.
///
/// # Safety
/// `MainConf` must be the main-configuration type stored for `Self::module()`.
pub unsafe trait HttpModuleMainConf: HttpModule {
    /// The module's main-configuration type.
    type MainConf: 'static;

    /// Gets the module's main configuration from a checked nginx-owned source.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::http::HttpModuleMainConf;
    /// fn escape<M: HttpModuleMainConf>(source: &ngx_conf_t) -> &'static M::MainConf {
    ///     M::main_conf(source).unwrap().unwrap()
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_cycle_t;
    /// # use ngx::http::HttpModuleMainConf;
    /// fn escape_cycle<M: HttpModuleMainConf>(cycle: &ngx_cycle_t) -> &'static M::MainConf {
    ///     unsafe { M::main_conf_from_cycle(cycle, 0).unwrap().unwrap() }
    /// }
    /// ```
    fn main_conf(
        source: &impl HttpModuleMainConfExt,
    ) -> Result<Option<&Self::MainConf>, HttpConfigError> {
        unsafe { source.http_main_conf(Self::module()) }
    }

    /// Gets exclusive access to the module's main configuration.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::http::HttpModuleMainConf;
    /// # fn access<M: HttpModuleMainConf>(cf: &ngx_conf_t) {
    /// let _ = M::main_conf_mut(cf);
    /// # }
    /// ```
    fn main_conf_mut(
        source: &mut impl HttpModuleMainConfMutExt,
    ) -> Result<Option<&mut Self::MainConf>, HttpConfigError> {
        unsafe { source.http_main_conf_mut(Self::module()) }
    }

    /// Resolves configuration from an explicitly selected live cycle.
    ///
    /// # Safety
    /// `cycle` must remain live for the returned borrow. Its `conf_ctx` array must contain the
    /// current `ngx_max_module` entries, and its HTTP context must contain exactly
    /// `http_slot_count` configuration slots. Callers select an old reload cycle explicitly and
    /// provide that cycle's slot count.
    unsafe fn main_conf_from_cycle(
        cycle: &ngx_cycle_t,
        http_slot_count: usize,
    ) -> Result<Option<&Self::MainConf>, HttpConfigError> {
        let indexes = module_indexes(Self::module(), live_module_slot_count(), http_slot_count)?;
        let http_index = usize_index(
            unsafe { nginx_sys::ngx_http_module.index },
            HttpConfigError::UnsetHttpModuleIndex,
        )?;
        if http_index >= indexes.module_slots {
            return Err(HttpConfigError::HttpModuleIndexOutOfBounds);
        }

        let Some(contexts) = checked_pointer(cycle.conf_ctx) else {
            return Ok(None);
        };
        let contexts =
            unsafe { ::core::slice::from_raw_parts(contexts.as_ptr(), indexes.module_slots) };
        let Some(context) = contexts.get(http_index) else {
            return Ok(None);
        };
        let Some(context) = checked_pointer((*context).cast::<ngx_http_conf_ctx_t>()) else {
            return Ok(None);
        };
        let context = unsafe { context.as_ref() };
        Ok(unsafe {
            conf_slot(context.main_conf, indexes.context, indexes.http_slots)
                .map(|configuration| configuration.as_ref())
        })
    }

    /// Runs a closure with the active cycle's main configuration without creating a `'static`
    /// reference.
    ///
    /// # Safety
    /// Call only while nginx keeps its active cycle and HTTP configuration alive on the current
    /// worker. The closure must not retain raw configuration pointers after it returns.
    unsafe fn with_active_main_conf<R>(
        f: impl for<'config> FnOnce(&'config Self::MainConf) -> R,
    ) -> Result<Option<R>, HttpConfigError> {
        let Some(cycle) = checked_pointer(unsafe { nginx_sys::ngx_cycle }) else {
            return Ok(None);
        };
        let configuration =
            unsafe { Self::main_conf_from_cycle(cycle.as_ref(), live_http_slot_count())? };
        Ok(configuration.map(f))
    }
}

/// Associates an HTTP module with its server-configuration type.
///
/// # Safety
/// `ServerConf` must be the server-configuration type stored for `Self::module()`.
pub unsafe trait HttpModuleServerConf: HttpModule {
    /// The module's server-configuration type.
    type ServerConf: 'static;

    /// Gets the module's server configuration from a checked nginx-owned source.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::http::HttpModuleServerConf;
    /// fn escape<M: HttpModuleServerConf>(source: &ngx_conf_t) -> &'static M::ServerConf {
    ///     M::server_conf(source).unwrap().unwrap()
    /// }
    /// ```
    fn server_conf(
        source: &impl HttpModuleServerConfExt,
    ) -> Result<Option<&Self::ServerConf>, HttpConfigError> {
        unsafe { source.http_server_conf(Self::module()) }
    }

    /// Gets exclusive access to the module's server configuration.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::http::HttpModuleServerConf;
    /// # fn access<M: HttpModuleServerConf>(cf: &ngx_conf_t) {
    /// let _ = M::server_conf_mut(cf);
    /// # }
    /// ```
    fn server_conf_mut(
        source: &mut impl HttpModuleServerConfMutExt,
    ) -> Result<Option<&mut Self::ServerConf>, HttpConfigError> {
        unsafe { source.http_server_conf_mut(Self::module()) }
    }
}

/// Associates an HTTP module with its location-configuration type.
///
/// # Safety
/// `LocationConf` must be the location-configuration type stored for `Self::module()`.
pub unsafe trait HttpModuleLocationConf: HttpModule {
    /// The module's location-configuration type.
    type LocationConf: 'static;

    /// Gets the module's location configuration from a checked nginx-owned source.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::http::HttpModuleLocationConf;
    /// fn escape<M: HttpModuleLocationConf>(source: &ngx_conf_t) -> &'static M::LocationConf {
    ///     M::location_conf(source).unwrap().unwrap()
    /// }
    /// ```
    fn location_conf(
        source: &impl HttpModuleLocationConfExt,
    ) -> Result<Option<&Self::LocationConf>, HttpConfigError> {
        unsafe { source.http_location_conf(Self::module()) }
    }

    /// Gets exclusive access to the module's location configuration.
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_conf_t;
    /// # use ngx::http::HttpModuleLocationConf;
    /// # fn access<M: HttpModuleLocationConf>(cf: &ngx_conf_t) {
    /// let _ = M::location_conf_mut(cf);
    /// # }
    /// ```
    fn location_conf_mut(
        source: &mut impl HttpModuleLocationConfMutExt,
    ) -> Result<Option<&mut Self::LocationConf>, HttpConfigError> {
        unsafe { source.http_location_conf_mut(Self::module()) }
    }
}

mod core {
    use crate::allocator::AllocError;
    use crate::{
        collections::NgxArray,
        ffi::{
            ngx_http_core_loc_conf_t, ngx_http_core_main_conf_t, ngx_http_core_module,
            ngx_http_core_srv_conf_t,
        },
        http::{HttpModuleMainConf, HttpRequestHandler},
        ngx_conf_log_error,
    };

    /// Auxiliary structure to access `ngx_http_core_module` configuration.
    pub struct NgxHttpCoreModule;

    unsafe impl crate::http::HttpModule for NgxHttpCoreModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*::core::ptr::addr_of!(ngx_http_core_module) }
        }
    }
    unsafe impl crate::http::HttpModuleMainConf for NgxHttpCoreModule {
        type MainConf = ngx_http_core_main_conf_t;
    }
    unsafe impl crate::http::HttpModuleServerConf for NgxHttpCoreModule {
        type ServerConf = ngx_http_core_srv_conf_t;
    }
    unsafe impl crate::http::HttpModuleLocationConf for NgxHttpCoreModule {
        type LocationConf = ngx_http_core_loc_conf_t;
    }

    /// HTTP phases in which a module can register handlers.
    ///
    /// Internal engine phases do not have handler arrays and are intentionally unavailable.
    ///
    /// ```compile_fail
    /// use ngx::http::HttpPhase;
    ///
    /// let _ = HttpPhase::FindConfig;
    /// ```
    #[repr(usize)]
    pub enum HttpPhase {
        /// Post-read phase
        PostRead = crate::ffi::ngx_http_phases_NGX_HTTP_POST_READ_PHASE as _,
        /// Server rewrite phase
        ServerRewrite = crate::ffi::ngx_http_phases_NGX_HTTP_SERVER_REWRITE_PHASE as _,
        /// Rewrite phase
        Rewrite = crate::ffi::ngx_http_phases_NGX_HTTP_REWRITE_PHASE as _,
        /// Pre-access phase
        Preaccess = crate::ffi::ngx_http_phases_NGX_HTTP_PREACCESS_PHASE as _,
        /// Access phase
        Access = crate::ffi::ngx_http_phases_NGX_HTTP_ACCESS_PHASE as _,
        /// Pre-content phase
        PreContent = crate::ffi::ngx_http_phases_NGX_HTTP_PRECONTENT_PHASE as _,
        /// Content phase
        Content = crate::ffi::ngx_http_phases_NGX_HTTP_CONTENT_PHASE as _,
        /// Log phase
        Log = crate::ffi::ngx_http_phases_NGX_HTTP_LOG_PHASE as _,
    }

    /// Register a request handler for a specified phase.
    /// This function must be called from the module's `postconfiguration()` function.
    pub fn add_phase_handler<H>(cf: &mut nginx_sys::ngx_conf_t) -> Result<(), AllocError>
    where
        H: HttpRequestHandler,
    {
        let result = (|| {
            let main =
                NgxHttpCoreModule::main_conf_mut(cf).map_err(|_| AllocError)?.ok_or(AllocError)?;
            let phase = main.phases.get_mut(H::PHASE as usize).ok_or(AllocError)?;
            let handlers = unsafe {
                NgxArray::<nginx_sys::ngx_http_handler_pt>::from_ngx_array_mut(&mut phase.handlers)
            }
            .ok_or(AllocError)?;

            handlers.push(Some(crate::http::raw_handler::<H>)).map(|_| ())
        })();

        if result.is_err() && !cf.log.is_null() {
            ngx_conf_log_error!(
                nginx_sys::NGX_LOG_EMERG,
                cf,
                "failed to register {} handler",
                H::name(),
            );
        }

        result
    }
}

pub use core::{HttpPhase, NgxHttpCoreModule, add_phase_handler};

#[cfg(ngx_feature = "http_ssl")]
mod ssl {
    use crate::ffi::{ngx_http_ssl_module, ngx_http_ssl_srv_conf_t};

    /// Auxiliary structure to access `ngx_http_ssl_module` configuration.
    pub struct NgxHttpSslModule;

    unsafe impl crate::http::HttpModule for NgxHttpSslModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*::core::ptr::addr_of!(ngx_http_ssl_module) }
        }
    }
    unsafe impl crate::http::HttpModuleServerConf for NgxHttpSslModule {
        type ServerConf = ngx_http_ssl_srv_conf_t;
    }
}
#[cfg(ngx_feature = "http_ssl")]
pub use ssl::NgxHttpSslModule;

mod upstream {
    use crate::ffi::{
        ngx_http_upstream_main_conf_t, ngx_http_upstream_module, ngx_http_upstream_srv_conf_t,
    };

    /// Auxiliary structure to access `ngx_http_upstream_module` configuration.
    pub struct NgxHttpUpstreamModule;

    unsafe impl crate::http::HttpModule for NgxHttpUpstreamModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*::core::ptr::addr_of!(ngx_http_upstream_module) }
        }
    }
    unsafe impl crate::http::HttpModuleMainConf for NgxHttpUpstreamModule {
        type MainConf = ngx_http_upstream_main_conf_t;
    }
    unsafe impl crate::http::HttpModuleServerConf for NgxHttpUpstreamModule {
        type ServerConf = ngx_http_upstream_srv_conf_t;
    }
}

pub use upstream::NgxHttpUpstreamModule;

#[cfg(all(nginx1_25_1, ngx_feature = "http_v2"))]
mod http_v2 {
    use crate::ffi::{ngx_http_v2_module, ngx_http_v2_srv_conf_t};

    /// Auxiliary structure to access `ngx_http_v2_module` configuration.
    pub struct NgxHttpV2Module;

    unsafe impl crate::http::HttpModule for NgxHttpV2Module {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*::core::ptr::addr_of!(ngx_http_v2_module) }
        }
    }
    unsafe impl crate::http::HttpModuleServerConf for NgxHttpV2Module {
        type ServerConf = ngx_http_v2_srv_conf_t;
    }
}
// ngx_http_v2_module was not exposed by default until aefd862a
#[cfg(all(nginx1_25_1, ngx_feature = "http_v2"))]
pub use http_v2::NgxHttpV2Module;

#[cfg(ngx_feature = "http_v3")]
mod http_v3 {
    use crate::ffi::{ngx_http_v3_module, ngx_http_v3_srv_conf_t};

    /// Auxiliary structure to access `ngx_http_v3_module` configuration.
    pub struct NgxHttpV3Module;

    unsafe impl crate::http::HttpModule for NgxHttpV3Module {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*::core::ptr::addr_of!(ngx_http_v3_module) }
        }
    }
    unsafe impl crate::http::HttpModuleServerConf for NgxHttpV3Module {
        type ServerConf = ngx_http_v3_srv_conf_t;
    }
}

#[cfg(ngx_feature = "http_v3")]
pub use http_v3::NgxHttpV3Module;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use ::core::ffi::c_void;
    #[cfg(feature = "test-link")]
    use ::core::mem;
    #[cfg(feature = "test-link")]
    use ::core::ptr;
    use alloc::boxed::Box;
    #[cfg(feature = "test-link")]
    use std::sync::MutexGuard;

    use super::{
        HttpConfigError, HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf,
        module_indexes,
    };
    use crate::ffi::{NGX_HTTP_MODULE, ngx_http_conf_ctx_t, ngx_module_t, ngx_uint_t};
    #[cfg(feature = "test-link")]
    use crate::ffi::{
        ngx_conf_t, ngx_cycle_t, ngx_http_connection_t, ngx_http_core_srv_conf_t,
        ngx_http_request_t, ngx_http_upstream_srv_conf_t,
    };
    use crate::http::HttpModule;

    fn http_module(index: ngx_uint_t, context_index: ngx_uint_t) -> ngx_module_t {
        let mut module = ngx_module_t::default();
        module.type_ = NGX_HTTP_MODULE as _;
        module.index = index;
        module.ctx_index = context_index;
        module
    }

    #[test]
    fn http_module_type_is_required() {
        let module = ngx_module_t::default();

        assert!(matches!(module_indexes(&module, 2, 1), Err(HttpConfigError::WrongModuleType)));
    }

    #[test]
    fn module_index_requires_assignment_and_available_global_slot() {
        let mut module = http_module(ngx_uint_t::MAX, 0);

        assert!(matches!(module_indexes(&module, 2, 1), Err(HttpConfigError::UnsetModuleIndex)));

        module.index = 2;
        assert!(matches!(
            module_indexes(&module, 2, 1),
            Err(HttpConfigError::ModuleIndexOutOfBounds)
        ));

        module.index = 3;
        assert!(matches!(
            module_indexes(&module, 2, 1),
            Err(HttpConfigError::ModuleIndexOutOfBounds)
        ));

        module.index = 0;
        assert!(module_indexes(&module, 1, 1).is_ok());
    }

    #[test]
    fn context_index_requires_assignment_and_available_http_slot() {
        let mut module = http_module(0, ngx_uint_t::MAX);

        assert!(matches!(module_indexes(&module, 1, 1), Err(HttpConfigError::UnsetContextIndex)));

        module.ctx_index = 1;
        assert!(matches!(
            module_indexes(&module, 1, 1),
            Err(HttpConfigError::ContextIndexOutOfBounds)
        ));

        module.ctx_index = 2;
        assert!(matches!(
            module_indexes(&module, 1, 1),
            Err(HttpConfigError::ContextIndexOutOfBounds)
        ));

        module.ctx_index = 0;
        assert!(module_indexes(&module, 1, 1).is_ok());
    }

    fn test_module() -> &'static ngx_module_t {
        Box::leak(Box::new(http_module(1, 0)))
    }

    struct TestHttpModule;

    unsafe impl HttpModule for TestHttpModule {
        fn module() -> &'static ngx_module_t {
            test_module()
        }
    }

    unsafe impl HttpModuleMainConf for TestHttpModule {
        type MainConf = u32;
    }

    unsafe impl HttpModuleServerConf for TestHttpModule {
        type ServerConf = u32;
    }

    unsafe impl HttpModuleLocationConf for TestHttpModule {
        type LocationConf = u32;
    }

    fn wrong_type_module() -> &'static ngx_module_t {
        Box::leak(Box::new(ngx_module_t { index: 0, ctx_index: 0, ..ngx_module_t::default() }))
    }

    struct WrongTypeModule;

    unsafe impl HttpModule for WrongTypeModule {
        fn module() -> &'static ngx_module_t {
            wrong_type_module()
        }
    }

    unsafe impl HttpModuleMainConf for WrongTypeModule {
        type MainConf = u32;
    }

    #[test]
    fn wrong_module_type_does_not_read_a_http_configuration_slot() {
        let mut value = 42_u32;
        let mut slots: [*mut c_void; 1] = [(&raw mut value).cast()];
        let context = ngx_http_conf_ctx_t {
            main_conf: slots.as_mut_ptr(),
            srv_conf: ::core::ptr::null_mut(),
            loc_conf: ::core::ptr::null_mut(),
        };

        assert_eq!(WrongTypeModule::main_conf(&context), Err(HttpConfigError::WrongModuleType));
    }

    #[cfg(feature = "test-link")]
    struct GlobalState {
        cycle: *mut ngx_cycle_t,
        max_module: ngx_uint_t,
        http_max_module: ngx_uint_t,
        http_module_index: ngx_uint_t,
    }

    #[cfg(feature = "test-link")]
    struct HttpGlobals {
        _guard: MutexGuard<'static, ()>,
        previous: GlobalState,
    }

    #[cfg(feature = "test-link")]
    impl HttpGlobals {
        fn new(module_slots: ngx_uint_t, http_slots: ngx_uint_t) -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let previous = unsafe {
                GlobalState {
                    cycle: nginx_sys::ngx_cycle,
                    max_module: nginx_sys::ngx_max_module,
                    http_max_module: nginx_sys::ngx_http_max_module,
                    http_module_index: (*::core::ptr::addr_of!(nginx_sys::ngx_http_module)).index,
                }
            };

            unsafe {
                nginx_sys::ngx_cycle = ptr::null_mut();
                nginx_sys::ngx_max_module = module_slots;
                nginx_sys::ngx_http_max_module = http_slots;
                (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index = 0;
            }

            Self { _guard: guard, previous }
        }

        fn set_active_cycle(&self, cycle: *mut ngx_cycle_t) {
            unsafe {
                nginx_sys::ngx_cycle = cycle;
            }
        }

        fn set_http_module_index(&self, index: ngx_uint_t) {
            unsafe {
                (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index = index;
            }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for HttpGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_cycle = self.previous.cycle;
                nginx_sys::ngx_max_module = self.previous.max_module;
                nginx_sys::ngx_http_max_module = self.previous.http_max_module;
                (*::core::ptr::addr_of_mut!(nginx_sys::ngx_http_module)).index =
                    self.previous.http_module_index;
            }
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn null_and_misaligned_http_configuration_slots_return_none() {
        let _globals = HttpGlobals::new(2, 1);
        let mut context = ngx_http_conf_ctx_t {
            main_conf: ptr::null_mut(),
            srv_conf: ptr::null_mut(),
            loc_conf: ptr::null_mut(),
        };

        assert_eq!(TestHttpModule::main_conf(&context).map(|value| value.copied()), Ok(None));
        assert_eq!(TestHttpModule::server_conf(&context).map(|value| value.copied()), Ok(None));
        assert_eq!(TestHttpModule::location_conf(&context).map(|value| value.copied()), Ok(None));

        context.main_conf = ptr::without_provenance_mut(1);
        context.srv_conf = ptr::without_provenance_mut(1);
        context.loc_conf = ptr::without_provenance_mut(1);
        assert_eq!(TestHttpModule::main_conf(&context).map(|value| value.copied()), Ok(None));
        assert_eq!(TestHttpModule::server_conf(&context).map(|value| value.copied()), Ok(None));
        assert_eq!(TestHttpModule::location_conf(&context).map(|value| value.copied()), Ok(None));

        let mut slots = [ptr::without_provenance_mut::<c_void>(1)];
        context.main_conf = slots.as_mut_ptr();
        context.srv_conf = slots.as_mut_ptr();
        context.loc_conf = slots.as_mut_ptr();
        assert_eq!(TestHttpModule::main_conf(&context).map(|value| value.copied()), Ok(None));
        assert_eq!(TestHttpModule::server_conf(&context).map(|value| value.copied()), Ok(None));
        assert_eq!(TestHttpModule::location_conf(&context).map(|value| value.copied()), Ok(None));

        let mut connection = unsafe { mem::zeroed::<ngx_http_connection_t>() };
        assert_eq!(TestHttpModule::main_conf(&connection).map(|value| value.copied()), Ok(None));
        connection.conf_ctx = ptr::without_provenance_mut(1);
        assert_eq!(TestHttpModule::main_conf(&connection).map(|value| value.copied()), Ok(None));

        let mut core_server = unsafe { mem::zeroed::<ngx_http_core_srv_conf_t>() };
        assert_eq!(TestHttpModule::server_conf(&core_server).map(|value| value.copied()), Ok(None));
        core_server.ctx = ptr::without_provenance_mut(1);
        assert_eq!(TestHttpModule::server_conf(&core_server).map(|value| value.copied()), Ok(None));

        let mut request = unsafe { mem::zeroed::<ngx_http_request_t>() };
        assert_eq!(TestHttpModule::location_conf(&request).map(|value| value.copied()), Ok(None));
        request.loc_conf = ptr::without_provenance_mut(1);
        assert_eq!(TestHttpModule::location_conf(&request).map(|value| value.copied()), Ok(None));

        let mut upstream = unsafe { mem::zeroed::<ngx_http_upstream_srv_conf_t>() };
        assert_eq!(TestHttpModule::server_conf(&upstream).map(|value| value.copied()), Ok(None));
        upstream.srv_conf = ptr::without_provenance_mut(1);
        assert_eq!(TestHttpModule::server_conf(&upstream).map(|value| value.copied()), Ok(None));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn parser_context_requires_http_type_and_checked_context_pointer() {
        let _globals = HttpGlobals::new(2, 1);
        let mut configuration = unsafe { mem::zeroed::<ngx_conf_t>() };

        assert_eq!(
            TestHttpModule::main_conf(&configuration),
            Err(HttpConfigError::WrongConfigurationContext)
        );

        configuration.module_type = NGX_HTTP_MODULE as _;
        assert_eq!(TestHttpModule::main_conf(&configuration).map(|value| value.copied()), Ok(None));
        assert_eq!(
            TestHttpModule::server_conf(&configuration).map(|value| value.copied()),
            Ok(None)
        );
        assert_eq!(
            TestHttpModule::location_conf(&configuration).map(|value| value.copied()),
            Ok(None)
        );

        configuration.ctx = ptr::without_provenance_mut(1);
        assert_eq!(TestHttpModule::main_conf(&configuration).map(|value| value.copied()), Ok(None));
        assert_eq!(
            TestHttpModule::server_conf(&configuration).map(|value| value.copied()),
            Ok(None)
        );
        assert_eq!(
            TestHttpModule::location_conf(&configuration).map(|value| value.copied()),
            Ok(None)
        );
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn typed_http_configuration_access_follows_each_source_borrow() {
        let _globals = HttpGlobals::new(2, 1);
        let mut main = 42_u32;
        let mut server = 99_u32;
        let mut location = 7_u32;
        let mut main_slots: [*mut c_void; 1] = [(&raw mut main).cast()];
        let mut server_slots: [*mut c_void; 1] = [(&raw mut server).cast()];
        let mut location_slots: [*mut c_void; 1] = [(&raw mut location).cast()];
        let mut context = ngx_http_conf_ctx_t {
            main_conf: main_slots.as_mut_ptr(),
            srv_conf: server_slots.as_mut_ptr(),
            loc_conf: location_slots.as_mut_ptr(),
        };

        assert_eq!(TestHttpModule::main_conf(&context).map(|value| value.copied()), Ok(Some(42)));
        assert_eq!(TestHttpModule::server_conf(&context).map(|value| value.copied()), Ok(Some(99)));
        assert_eq!(
            TestHttpModule::location_conf(&context).map(|value| value.copied()),
            Ok(Some(7))
        );

        if let Some(value) = TestHttpModule::main_conf_mut(&mut context).unwrap() {
            *value = 1;
        }
        if let Some(value) = TestHttpModule::server_conf_mut(&mut context).unwrap() {
            *value = 2;
        }
        if let Some(value) = TestHttpModule::location_conf_mut(&mut context).unwrap() {
            *value = 3;
        }

        assert_eq!((main, server, location), (1, 2, 3));

        let mut parser = unsafe { mem::zeroed::<ngx_conf_t>() };
        parser.module_type = NGX_HTTP_MODULE as _;
        parser.ctx = (&raw mut context).cast();
        assert_eq!(TestHttpModule::main_conf(&parser).map(|value| value.copied()), Ok(Some(1)));
        assert_eq!(TestHttpModule::server_conf(&parser).map(|value| value.copied()), Ok(Some(2)));
        assert_eq!(TestHttpModule::location_conf(&parser).map(|value| value.copied()), Ok(Some(3)));
        if let Some(value) = TestHttpModule::main_conf_mut(&mut parser).unwrap() {
            *value = 4;
        }

        let mut connection = unsafe { mem::zeroed::<ngx_http_connection_t>() };
        connection.conf_ctx = &raw mut context;
        assert_eq!(
            TestHttpModule::location_conf(&connection).map(|value| value.copied()),
            Ok(Some(3))
        );
        if let Some(value) = TestHttpModule::location_conf_mut(&mut connection).unwrap() {
            *value = 5;
        }

        let mut core_server = unsafe { mem::zeroed::<ngx_http_core_srv_conf_t>() };
        core_server.ctx = &raw mut context;
        assert_eq!(
            TestHttpModule::server_conf(&core_server).map(|value| value.copied()),
            Ok(Some(2))
        );
        if let Some(value) = TestHttpModule::server_conf_mut(&mut core_server).unwrap() {
            *value = 6;
        }

        let mut request = ngx_http_request_t {
            main_conf: main_slots.as_mut_ptr(),
            srv_conf: server_slots.as_mut_ptr(),
            loc_conf: location_slots.as_mut_ptr(),
            ..unsafe { mem::zeroed() }
        };
        assert_eq!(TestHttpModule::main_conf(&request).map(|value| value.copied()), Ok(Some(4)));
        assert_eq!(TestHttpModule::server_conf(&request).map(|value| value.copied()), Ok(Some(6)));
        assert_eq!(
            TestHttpModule::location_conf(&request).map(|value| value.copied()),
            Ok(Some(5))
        );
        if let Some(value) = TestHttpModule::location_conf_mut(&mut request).unwrap() {
            *value = 7;
        }

        let request = unsafe { crate::http::Request::from_ngx_http_request(&raw mut request) };
        assert_eq!(TestHttpModule::main_conf(request).map(|value| value.copied()), Ok(Some(4)));
        assert_eq!(TestHttpModule::server_conf(request).map(|value| value.copied()), Ok(Some(6)));
        assert_eq!(TestHttpModule::location_conf(request).map(|value| value.copied()), Ok(Some(7)));
        if let Some(value) = TestHttpModule::location_conf_mut(request).unwrap() {
            *value = 8;
        }

        let mut upstream = ngx_http_upstream_srv_conf_t {
            srv_conf: server_slots.as_mut_ptr(),
            ..unsafe { mem::zeroed() }
        };
        assert_eq!(TestHttpModule::server_conf(&upstream).map(|value| value.copied()), Ok(Some(6)));
        if let Some(value) = TestHttpModule::server_conf_mut(&mut upstream).unwrap() {
            *value = 9;
        }

        assert_eq!((main, server, location), (4, 9, 8));
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn cycle_access_keeps_old_and_active_slots_explicit() {
        let globals = HttpGlobals::new(2, 1);

        assert_eq!(unsafe { TestHttpModule::with_active_main_conf(|value| *value) }, Ok(None));
        let empty_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
        assert_eq!(
            unsafe { TestHttpModule::main_conf_from_cycle(&empty_cycle, 1) }
                .map(|value| value.copied()),
            Ok(None)
        );
        let mut misaligned_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
        misaligned_cycle.conf_ctx = ptr::without_provenance_mut(1);
        assert_eq!(
            unsafe { TestHttpModule::main_conf_from_cycle(&misaligned_cycle, 1) }
                .map(|value| value.copied()),
            Ok(None)
        );

        let mut old_main = 11_u32;
        let mut old_slots: [*mut c_void; 1] = [(&raw mut old_main).cast()];
        let mut old_context = ngx_http_conf_ctx_t {
            main_conf: old_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
            loc_conf: ptr::null_mut(),
        };
        let mut old_contexts: [*mut *mut *mut c_void; 2] =
            [(&raw mut old_context).cast(), ptr::null_mut()];
        let mut old_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
        old_cycle.conf_ctx = old_contexts.as_mut_ptr();

        assert_eq!(
            unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) }
                .map(|value| value.copied()),
            Ok(Some(11))
        );
        assert_eq!(
            unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 0) },
            Err(HttpConfigError::ContextIndexOutOfBounds)
        );

        globals.set_http_module_index(1);
        assert_eq!(
            unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) }
                .map(|value| value.copied()),
            Ok(None)
        );
        globals.set_http_module_index(ngx_uint_t::MAX);
        assert_eq!(
            unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) },
            Err(HttpConfigError::UnsetHttpModuleIndex)
        );
        globals.set_http_module_index(2);
        assert_eq!(
            unsafe { TestHttpModule::main_conf_from_cycle(&old_cycle, 1) },
            Err(HttpConfigError::HttpModuleIndexOutOfBounds)
        );
        globals.set_http_module_index(0);

        let mut active_main = 42_u32;
        let mut active_slots: [*mut c_void; 1] = [(&raw mut active_main).cast()];
        let mut active_context = ngx_http_conf_ctx_t {
            main_conf: active_slots.as_mut_ptr(),
            srv_conf: ptr::null_mut(),
            loc_conf: ptr::null_mut(),
        };
        let mut active_contexts: [*mut *mut *mut c_void; 2] =
            [(&raw mut active_context).cast(), ptr::null_mut()];
        let mut active_cycle = unsafe { mem::zeroed::<ngx_cycle_t>() };
        active_cycle.conf_ctx = active_contexts.as_mut_ptr();

        globals.set_active_cycle(&raw mut active_cycle);
        assert_eq!(unsafe { TestHttpModule::with_active_main_conf(|value| *value) }, Ok(Some(42)));

        globals.set_active_cycle(&raw mut old_cycle);
        assert_eq!(unsafe { TestHttpModule::with_active_main_conf(|value| *value) }, Ok(Some(11)));
    }
}
