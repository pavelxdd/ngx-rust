use ::core::ffi::c_void;
use ::core::ptr::NonNull;

use crate::core::ModuleDescriptor;
use crate::ffi::{
    NGX_CORE_MODULE, NGX_HTTP_MODULE, ngx_conf_t, ngx_cycle_t, ngx_http_conf_ctx_t,
    ngx_http_request_t, ngx_http_upstream_srv_conf_t, ngx_uint_t,
};
use crate::http::HttpModule;

/// Failure while resolving a typed HTTP configuration slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpConfigError {
    /// The configuration callback received a null parser pointer.
    NullConfiguration,
    /// The configuration callback received a misaligned parser pointer.
    MisalignedConfiguration,
    /// The parser contains a misaligned HTTP context pointer.
    MisalignedContext,
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
    /// The HTTP core module does not have a usable global index.
    UnsetHttpModuleIndex,
    /// The HTTP core module index is outside the configured module array.
    HttpModuleIndexOutOfBounds,
    /// The global HTTP block module is not an nginx core module.
    WrongHttpModuleType,
}

#[derive(Clone, Copy)]
struct ModuleIndexes {
    context: usize,
    http_slots: usize,
}

fn usize_index(index: ngx_uint_t, unset: HttpConfigError) -> Result<usize, HttpConfigError> {
    if index == ngx_uint_t::MAX {
        return Err(unset);
    }

    Ok(index)
}

fn module_indexes(
    module: ModuleDescriptor,
    module_slots: usize,
    http_slots: usize,
) -> Result<ModuleIndexes, HttpConfigError> {
    let module = unsafe { module.snapshot() };
    if module.module_type != NGX_HTTP_MODULE as ngx_uint_t {
        return Err(HttpConfigError::WrongModuleType);
    }

    let module_index = usize_index(module.index, HttpConfigError::UnsetModuleIndex)?;
    if module_index >= module_slots {
        return Err(HttpConfigError::ModuleIndexOutOfBounds);
    }

    let context_index = usize_index(module.context_index, HttpConfigError::UnsetContextIndex)?;
    if context_index >= http_slots {
        return Err(HttpConfigError::ContextIndexOutOfBounds);
    }

    Ok(ModuleIndexes { context: context_index, http_slots })
}

fn live_module_slot_count() -> usize {
    unsafe { nginx_sys::ngx_max_module }
}

fn live_http_slot_count() -> usize {
    unsafe { nginx_sys::ngx_http_max_module }
}

unsafe fn cycle_http_context(
    cycle: &ngx_cycle_t,
    module_slots: usize,
) -> Result<Option<&ngx_http_conf_ctx_t>, HttpConfigError> {
    let http_module = unsafe {
        ModuleDescriptor::from_raw(&raw mut nginx_sys::ngx_http_module)
            .expect("ngx_http_module descriptor")
            .snapshot()
    };
    if http_module.module_type != NGX_CORE_MODULE as ngx_uint_t {
        return Err(HttpConfigError::WrongHttpModuleType);
    }

    let http_index = usize_index(http_module.index, HttpConfigError::UnsetHttpModuleIndex)?;
    if http_index >= module_slots {
        return Err(HttpConfigError::HttpModuleIndexOutOfBounds);
    }

    let Some(contexts) = checked_pointer(cycle.conf_ctx) else {
        return Ok(None);
    };
    let contexts = unsafe { ::core::slice::from_raw_parts(contexts.as_ptr(), module_slots) };
    let Some(context) = contexts.get(http_index) else {
        return Ok(None);
    };
    let Some(context) = checked_pointer((*context).cast::<ngx_http_conf_ctx_t>()) else {
        return Ok(None);
    };
    Ok(Some(unsafe { context.as_ref() }))
}

unsafe fn main_conf_from_cycle<T>(
    cycle: &ngx_cycle_t,
    module: ModuleDescriptor,
    http_slot_count: usize,
) -> Result<Option<&T>, HttpConfigError> {
    let module_slots = live_module_slot_count();
    let Some(context) = (unsafe { cycle_http_context(cycle, module_slots)? }) else {
        return Ok(None);
    };
    let indexes = module_indexes(module, module_slots, http_slot_count)?;

    Ok(unsafe {
        conf_slot(context.main_conf, indexes.context, indexes.http_slots)
            .map(|configuration| configuration.as_ref())
    })
}

fn live_module_indexes(module: ModuleDescriptor) -> Result<ModuleIndexes, HttpConfigError> {
    module_indexes(module, live_module_slot_count(), live_http_slot_count())
}

pub(crate) fn request_context_index(module: ModuleDescriptor) -> Result<usize, HttpConfigError> {
    Ok(live_module_indexes(module)?.context)
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
    module: ModuleDescriptor,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.http_slots) })
}

pub(crate) fn server_conf_slot<T>(
    slots: *mut *mut c_void,
    module: ModuleDescriptor,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.http_slots) })
}

fn location_conf_slot<T>(
    slots: *mut *mut c_void,
    module: ModuleDescriptor,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    let indexes = live_module_indexes(module)?;
    Ok(unsafe { conf_slot(slots, indexes.context, indexes.http_slots) })
}

/// Checked HTTP configuration parser for one nginx callback invocation.
///
/// The callback-scoped capability cannot be retained after its FFI adapter returns.
///
/// ```compile_fail
/// use core::marker::PhantomData;
/// use core::ptr::NonNull;
/// use ngx::ffi::ngx_conf_t;
/// use ngx::http::HttpConfigurationParser;
///
/// fn forge(raw: NonNull<ngx_conf_t>) -> HttpConfigurationParser<'static> {
///     HttpConfigurationParser {
///         raw,
///         _callback: PhantomData,
///         _not_thread_safe: PhantomData,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_conf_t;
/// use ngx::http::HttpConfigurationParser;
///
/// unsafe fn escape(
///     raw: *mut ngx_conf_t,
/// ) -> &'static mut HttpConfigurationParser<'static> {
///     unsafe { HttpConfigurationParser::with_raw(raw, |parser| parser) }.unwrap()
/// }
/// ```
pub struct HttpConfigurationParser<'callback> {
    raw: NonNull<ngx_conf_t>,
    _callback: ::core::marker::PhantomData<&'callback mut ngx_conf_t>,
    _not_thread_safe: ::core::marker::PhantomData<*mut ()>,
}

#[cfg(test)]
impl<'callback> HttpConfigurationParser<'callback> {
    pub(crate) fn from_test_callback(configuration: &'callback mut ngx_conf_t) -> Self {
        Self {
            raw: NonNull::from(configuration),
            _callback: ::core::marker::PhantomData,
            _not_thread_safe: ::core::marker::PhantomData,
        }
    }
}

impl HttpConfigurationParser<'_> {
    /// Invokes a closure with a checked parser capability that cannot escape the callback.
    ///
    /// # Safety
    ///
    /// `configuration` must point to the live nginx HTTP parser state for this callback. Its
    /// context and configuration slots must remain valid and exclusively mutable until the
    /// closure returns.
    pub unsafe fn with_raw<R>(
        configuration: *mut ngx_conf_t,
        callback: impl for<'scope> FnOnce(&mut HttpConfigurationParser<'scope>) -> R,
    ) -> Result<R, HttpConfigError> {
        let raw = NonNull::new(configuration).ok_or(HttpConfigError::NullConfiguration)?;
        if !configuration.is_aligned() {
            return Err(HttpConfigError::MisalignedConfiguration);
        }

        let mut parser = HttpConfigurationParser {
            raw,
            _callback: ::core::marker::PhantomData,
            _not_thread_safe: ::core::marker::PhantomData,
        };
        Ok(callback(&mut parser))
    }

    fn context(&self) -> Result<Option<NonNull<ngx_http_conf_ctx_t>>, HttpConfigError> {
        let context = unsafe { self.raw.as_ref().ctx.cast::<ngx_http_conf_ctx_t>() };
        let Some(context) = NonNull::new(context) else {
            return Ok(None);
        };
        if !context.as_ptr().is_aligned() {
            return Err(HttpConfigError::MisalignedContext);
        }
        Ok(Some(context))
    }

    fn main_conf<T>(&self, module: ModuleDescriptor) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = self.context()? else {
            return Ok(None);
        };
        Ok(main_conf_slot(unsafe { context.as_ref().main_conf }, module)?
            .map(|value| unsafe { value.as_ref() }))
    }

    fn main_conf_mut<T>(
        &mut self,
        module: ModuleDescriptor,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(context) = self.context()? else {
            return Ok(None);
        };
        Ok(main_conf_slot(unsafe { context.as_ref().main_conf }, module)?
            .map(|mut value| unsafe { value.as_mut() }))
    }

    fn server_conf<T>(&self, module: ModuleDescriptor) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = self.context()? else {
            return Ok(None);
        };
        Ok(server_conf_slot(unsafe { context.as_ref().srv_conf }, module)?
            .map(|value| unsafe { value.as_ref() }))
    }

    fn server_conf_mut<T>(
        &mut self,
        module: ModuleDescriptor,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(context) = self.context()? else {
            return Ok(None);
        };
        Ok(server_conf_slot(unsafe { context.as_ref().srv_conf }, module)?
            .map(|mut value| unsafe { value.as_mut() }))
    }

    fn location_conf<T>(&self, module: ModuleDescriptor) -> Result<Option<&T>, HttpConfigError> {
        let Some(context) = self.context()? else {
            return Ok(None);
        };
        Ok(location_conf_slot(unsafe { context.as_ref().loc_conf }, module)?
            .map(|value| unsafe { value.as_ref() }))
    }

    fn location_conf_mut<T>(
        &mut self,
        module: ModuleDescriptor,
    ) -> Result<Option<&mut T>, HttpConfigError> {
        let Some(context) = self.context()? else {
            return Ok(None);
        };
        Ok(location_conf_slot(unsafe { context.as_ref().loc_conf }, module)?
            .map(|mut value| unsafe { value.as_mut() }))
    }

    /// Returns the native parser pointer for an explicit FFI operation.
    ///
    /// # Safety
    ///
    /// The pointer must not be retained beyond this callback, and the target nginx API must not
    /// violate the parser capability's exclusive access to configuration state.
    pub unsafe fn as_raw(&mut self) -> *mut ngx_conf_t {
        self.raw.as_ptr()
    }
}

pub(crate) fn request_main_conf_slot<T>(
    request: &ngx_http_request_t,
    module: ModuleDescriptor,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    main_conf_slot(request.main_conf, module)
}

pub(crate) fn request_server_conf_slot<T>(
    request: &ngx_http_request_t,
    module: ModuleDescriptor,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    server_conf_slot(request.srv_conf, module)
}

pub(crate) fn request_location_conf_slot<T>(
    request: &ngx_http_request_t,
    module: ModuleDescriptor,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    location_conf_slot(request.loc_conf, module)
}

pub(crate) fn upstream_server_conf_slot<T>(
    upstream: &ngx_http_upstream_srv_conf_t,
    module: ModuleDescriptor,
) -> Result<Option<NonNull<T>>, HttpConfigError> {
    server_conf_slot(upstream.srv_conf, module)
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
    /// # use ngx::http::{HttpConfigurationParser, HttpModuleMainConf};
    /// fn wrong_slot_type<M: HttpModuleMainConf>(parser: &HttpConfigurationParser<'_>) {
    ///     let _: &u8 = M::main_conf(parser).unwrap().unwrap();
    /// }
    /// ```
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
    fn main_conf<'a>(
        parser: &'a HttpConfigurationParser<'_>,
    ) -> Result<Option<&'a Self::MainConf>, HttpConfigError> {
        parser.main_conf(Self::module())
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
    ///
    /// Runtime requests expose configuration only through shared views:
    ///
    /// ```compile_fail
    /// # use ngx::http::{HttpModuleMainConf, RequestRefMut};
    /// # fn access<M: HttpModuleMainConf>(request: &mut RequestRefMut<'_>) {
    /// let _ = M::main_conf_mut(request);
    /// # }
    /// ```
    ///
    /// A live mutable slot borrow prevents a second lifecycle view of the same configuration:
    ///
    /// ```compile_fail
    /// # use ngx::http::{HttpConfigurationParser, HttpModuleMainConf};
    /// # fn alias<M: HttpModuleMainConf>(parser: &mut HttpConfigurationParser<'_>) {
    /// let first = M::main_conf_mut(parser).unwrap();
    /// let second = M::main_conf_mut(parser).unwrap();
    /// let _ = (first, second);
    /// # }
    /// ```
    fn main_conf_mut<'a>(
        parser: &'a mut HttpConfigurationParser<'_>,
    ) -> Result<Option<&'a mut Self::MainConf>, HttpConfigError> {
        parser.main_conf_mut(Self::module())
    }

    /// Resolves shared main configuration from a native HTTP context.
    ///
    /// A raw context, including a copied descriptor, is not a safe configuration source:
    ///
    /// ```compile_fail
    /// # use ngx::ffi::ngx_http_conf_ctx_t;
    /// # use ngx::http::HttpModuleMainConf;
    /// # fn access<M: HttpModuleMainConf>(context: ngx_http_conf_ctx_t) {
    /// let copied = context;
    /// let _ = M::main_conf_from_context(&copied);
    /// # }
    /// ```
    ///
    /// # Safety
    ///
    /// `context` must be the live initialized context selected by nginx for the current callback.
    /// Its slot arrays must remain valid and must contain the current HTTP module slot count.
    unsafe fn main_conf_from_context(
        context: &ngx_http_conf_ctx_t,
    ) -> Result<Option<&Self::MainConf>, HttpConfigError> {
        Ok(main_conf_slot(context.main_conf, Self::module())?
            .map(|value| unsafe { value.as_ref() }))
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
        unsafe { main_conf_from_cycle(cycle, Self::module(), http_slot_count) }
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
    fn server_conf<'a>(
        parser: &'a HttpConfigurationParser<'_>,
    ) -> Result<Option<&'a Self::ServerConf>, HttpConfigError> {
        parser.server_conf(Self::module())
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
    ///
    /// ```compile_fail
    /// # use ngx::http::{HttpModuleServerConf, RequestRefMut};
    /// # fn access<M: HttpModuleServerConf>(request: &mut RequestRefMut<'_>) {
    /// let _ = M::server_conf_mut(request);
    /// # }
    /// ```
    fn server_conf_mut<'a>(
        parser: &'a mut HttpConfigurationParser<'_>,
    ) -> Result<Option<&'a mut Self::ServerConf>, HttpConfigError> {
        parser.server_conf_mut(Self::module())
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
    fn location_conf<'a>(
        parser: &'a HttpConfigurationParser<'_>,
    ) -> Result<Option<&'a Self::LocationConf>, HttpConfigError> {
        parser.location_conf(Self::module())
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
    ///
    /// ```compile_fail
    /// # use ngx::http::{HttpModuleLocationConf, RequestRefMut};
    /// # fn access<M: HttpModuleLocationConf>(request: &mut RequestRefMut<'_>) {
    /// let _ = M::location_conf_mut(request);
    /// # }
    /// ```
    fn location_conf_mut<'a>(
        parser: &'a mut HttpConfigurationParser<'_>,
    ) -> Result<Option<&'a mut Self::LocationConf>, HttpConfigError> {
        parser.location_conf_mut(Self::module())
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
        http::{HttpConfigurationParser, HttpModuleMainConf, HttpRequestHandler},
        ngx_conf_log_error,
    };

    /// Auxiliary structure to access `ngx_http_core_module` configuration.
    pub struct NgxHttpCoreModule;

    unsafe impl crate::http::HttpModule for NgxHttpCoreModule {
        fn module() -> crate::core::ModuleDescriptor {
            unsafe { crate::core::ModuleDescriptor::from_raw(&raw mut ngx_http_core_module) }
                .expect("ngx_http_core_module descriptor")
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
    pub fn add_phase_handler<H>(parser: &mut HttpConfigurationParser<'_>) -> Result<(), AllocError>
    where
        H: HttpRequestHandler,
    {
        let result = (|| {
            let main = NgxHttpCoreModule::main_conf_mut(parser)
                .map_err(|_| AllocError)?
                .ok_or(AllocError)?;
            let phase = main.phases.get_mut(H::PHASE as usize).ok_or(AllocError)?;
            let handlers = unsafe {
                NgxArray::<nginx_sys::ngx_http_handler_pt>::from_ngx_array_mut(&mut phase.handlers)
            }
            .ok_or(AllocError)?;

            handlers.push(Some(crate::http::raw_handler::<H>)).map(|_| ())
        })();

        let cf = unsafe { parser.as_raw() };
        if result.is_err() && !unsafe { (*cf).log }.is_null() {
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
        fn module() -> crate::core::ModuleDescriptor {
            unsafe { crate::core::ModuleDescriptor::from_raw(&raw mut ngx_http_ssl_module) }
                .expect("ngx_http_ssl_module descriptor")
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
        fn module() -> crate::core::ModuleDescriptor {
            unsafe { crate::core::ModuleDescriptor::from_raw(&raw mut ngx_http_upstream_module) }
                .expect("ngx_http_upstream_module descriptor")
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
        fn module() -> crate::core::ModuleDescriptor {
            unsafe { crate::core::ModuleDescriptor::from_raw(&raw mut ngx_http_v2_module) }
                .expect("ngx_http_v2_module descriptor")
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
        fn module() -> crate::core::ModuleDescriptor {
            unsafe { crate::core::ModuleDescriptor::from_raw(&raw mut ngx_http_v3_module) }
                .expect("ngx_http_v3_module descriptor")
        }
    }
    unsafe impl crate::http::HttpModuleServerConf for NgxHttpV3Module {
        type ServerConf = ngx_http_v3_srv_conf_t;
    }
}

#[cfg(ngx_feature = "http_v3")]
pub use http_v3::NgxHttpV3Module;

#[cfg(test)]
#[path = "conf/tests/mod.rs"]
mod tests;
