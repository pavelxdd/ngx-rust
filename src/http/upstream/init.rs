use core::any::TypeId;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::core::{Pool, Status};
use crate::ffi::{
    NGX_LOG_EMERG, ngx_conf_t, ngx_http_upstream_init_pt, ngx_http_upstream_srv_conf_t, ngx_int_t,
};
use crate::http::{HttpConfigError, HttpModuleServerConf};

use super::callback::{HttpUpstreamInitializer, UpstreamCallbackError, UpstreamCallbackSlot};

/// Checked configuration callback view supplied to an upstream initializer.
///
/// ```compile_fail
/// use ngx::http::UpstreamConfiguration;
///
/// fn escape<'a>(
///     configuration: &'a mut UpstreamConfiguration<'_>,
/// ) -> &'static mut UpstreamConfiguration<'static> {
///     configuration
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::UpstreamConfiguration;
///
/// fn duplicate(configuration: UpstreamConfiguration<'_>) {
///     let first = configuration;
///     let second = configuration;
/// }
/// ```
pub struct UpstreamConfiguration<'callback> {
    raw: NonNull<ngx_conf_t>,
    _callback: PhantomData<&'callback mut ngx_conf_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl UpstreamConfiguration<'_> {
    /// # Safety
    ///
    /// `configuration` must point to the live nginx parser state for the callback. Its
    /// configuration pool must not be reset before that pool is destroyed.
    unsafe fn from_raw(configuration: *mut ngx_conf_t) -> Result<Self, UpstreamCallbackError> {
        let raw = NonNull::new(configuration).ok_or(UpstreamCallbackError::NullConfiguration)?;
        if !configuration.is_aligned() {
            return Err(UpstreamCallbackError::MisalignedConfiguration);
        }

        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Returns the nginx configuration pool for copied URL and module data.
    pub fn pool(&self) -> Result<Pool<'_>, UpstreamCallbackError> {
        unsafe { Pool::from_raw(self.raw.as_ref().pool) }
            .ok_or(UpstreamCallbackError::MissingConfigurationPool)
    }

    fn log_failure(&mut self, action: &str, error: &UpstreamCallbackError) {
        if unsafe { self.raw.as_ref().log.is_null() } {
            return;
        }
        crate::ngx_conf_log_error!(
            NGX_LOG_EMERG,
            self.raw.as_ptr(),
            "HTTP upstream {action} failed: {error}"
        );
    }
}

/// Checked upstream server-configuration callback view.
pub struct UpstreamServerConf<'callback> {
    pub(super) raw: NonNull<ngx_http_upstream_srv_conf_t>,
    _callback: PhantomData<&'callback mut ngx_http_upstream_srv_conf_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> UpstreamServerConf<'callback> {
    pub(super) fn from_mut(upstream: &'callback mut ngx_http_upstream_srv_conf_t) -> Self {
        Self { raw: NonNull::from(upstream), _callback: PhantomData, _not_thread_safe: PhantomData }
    }

    pub(super) unsafe fn from_raw(
        upstream: *mut ngx_http_upstream_srv_conf_t,
    ) -> Result<Self, UpstreamCallbackError> {
        let raw = NonNull::new(upstream).ok_or(UpstreamCallbackError::NullUpstream)?;
        if !upstream.is_aligned() {
            return Err(UpstreamCallbackError::MisalignedUpstream);
        }

        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Resolves one typed module server configuration from this upstream configuration.
    pub fn module_conf<M>(&self) -> Result<Option<&M::ServerConf>, HttpConfigError>
    where
        M: HttpModuleServerConf,
    {
        Ok(crate::http::conf::upstream_server_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Resolves one mutable typed module server configuration from this upstream configuration.
    pub fn module_conf_mut<M>(&mut self) -> Result<Option<&mut M::ServerConf>, HttpConfigError>
    where
        M: HttpModuleServerConf,
    {
        Ok(crate::http::conf::upstream_server_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|mut value| unsafe { value.as_mut() }))
    }

    pub(super) fn callback_slot<M>(
        &mut self,
        slot: impl FnOnce(&mut M::ServerConf) -> &mut UpstreamCallbackSlot,
    ) -> Result<NonNull<UpstreamCallbackSlot>, UpstreamCallbackError>
    where
        M: HttpModuleServerConf,
    {
        let configuration = self
            .module_conf_mut::<M>()?
            .ok_or(UpstreamCallbackError::MissingInitializerConfiguration)?;
        Ok(NonNull::from(slot(configuration)))
    }

    fn upstream_slot<H>(&mut self) -> Result<NonNull<UpstreamCallbackSlot>, UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        self.callback_slot::<H::Module>(H::callback_slot)
    }

    fn original_upstream<H>(&mut self) -> Result<OriginalUpstreamInit<H>, UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        let owner = self.raw;
        let slot = self.upstream_slot::<H>()?;
        unsafe { slot.as_ref().original_upstream::<H>(owner) }
    }

    pub(super) fn install_upstream<H>(&mut self) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        let mut owner = self.raw;
        let original = unsafe { owner.as_ref().peer.init_upstream };
        let mut slot = self.upstream_slot::<H>()?;
        unsafe { slot.as_mut().install_upstream::<H>(owner, original)? };
        unsafe { owner.as_mut().peer.init_upstream = Some(raw_init_upstream::<H>) };
        Ok(())
    }

    /// Proves that this configured upstream has a request peer initializer.
    pub fn initialized(&self) -> Result<UpstreamInitialized<'_>, UpstreamCallbackError> {
        if unsafe { self.raw.as_ref().peer.init.is_none() } {
            return Err(UpstreamCallbackError::MissingPeerInitializer);
        }
        Ok(UpstreamInitialized { _upstream: PhantomData })
    }
}

/// Proof that a configured upstream has its mandatory request peer initializer.
///
/// ```compile_fail
/// use core::marker::PhantomData;
/// use ngx::http::UpstreamInitialized;
///
/// fn forge<'a>() -> UpstreamInitialized<'a> {
///     UpstreamInitialized { _upstream: PhantomData }
/// }
/// ```
pub struct UpstreamInitialized<'upstream> {
    _upstream: PhantomData<&'upstream ngx_http_upstream_srv_conf_t>,
}

/// Checked result returned by a saved native upstream initializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamInitStatus {
    /// The native initializer succeeded and installed a request peer initializer.
    Initialized,
    /// The native initializer returned a non-success status.
    Unavailable,
}

/// Result of typed upstream configuration initialization.
pub enum UpstreamInitialization<'upstream> {
    /// The mandatory request peer initializer is installed.
    Initialized(UpstreamInitialized<'upstream>),
    /// Configuration initialization did not succeed.
    Unavailable,
}

/// Owner-typed capability to invoke one saved upstream initializer.
///
/// The installation slot constructs this capability only for its handler and upstream generation.
/// Calling it consumes the capability, so one handler invocation cannot delegate twice.
///
/// ```compile_fail
/// use ngx::http::OriginalUpstreamInit;
///
/// fn forge<H>() -> OriginalUpstreamInit<H> {
///     OriginalUpstreamInit { callback: None, _handler: core::marker::PhantomData }
/// }
/// ```
///
/// ```compile_fail
/// use ngx::http::{OriginalUpstreamInit, UpstreamConfiguration, UpstreamServerConf};
///
/// fn call_twice<H>(
///     original: OriginalUpstreamInit<H>,
///     configuration: &mut UpstreamConfiguration<'_>,
///     upstream: &mut UpstreamServerConf<'_>,
/// ) {
///     let _ = original.call(configuration, upstream);
///     let _ = original.call(configuration, upstream);
/// }
/// ```
pub struct OriginalUpstreamInit<H> {
    pub(super) callback: ngx_http_upstream_init_pt,
    pub(super) _handler: PhantomData<fn() -> H>,
}

impl<H> OriginalUpstreamInit<H> {
    /// Delegates to the saved initializer with its original nginx arguments.
    pub fn call(
        self,
        configuration: &mut UpstreamConfiguration<'_>,
        upstream: &mut UpstreamServerConf<'_>,
    ) -> Result<UpstreamInitStatus, UpstreamCallbackError> {
        let callback = self.callback.ok_or(UpstreamCallbackError::MissingOriginalInitUpstream)?;
        let status = unsafe { callback(configuration.raw.as_ptr(), upstream.raw.as_ptr()) };
        if status != Status::NGX_OK.0 {
            return Ok(UpstreamInitStatus::Unavailable);
        }
        let _ = upstream.initialized()?;
        Ok(UpstreamInitStatus::Initialized)
    }
}

/// Installs a typed HTTP upstream initializer in its module-owned configuration slot.
///
/// Call this from the upstream directive setup after resolving nginx's upstream server
/// configuration. Repeated installation in the same module configuration is rejected before the
/// native callback changes.
pub fn install_upstream_initializer<H>(
    upstream: &mut ngx_http_upstream_srv_conf_t,
) -> Result<(), UpstreamCallbackError>
where
    H: HttpUpstreamInitializer,
{
    UpstreamServerConf::from_mut(upstream).install_upstream::<H>()
}

pub(super) unsafe extern "C" fn raw_init_upstream<H>(
    configuration: *mut ngx_conf_t,
    upstream: *mut ngx_http_upstream_srv_conf_t,
) -> ngx_int_t
where
    H: HttpUpstreamInitializer,
{
    // SAFETY: nginx invokes this initializer with its stable configuration pool.
    let Ok(mut configuration) = (unsafe { UpstreamConfiguration::from_raw(configuration) }) else {
        return Status::NGX_ERROR.0;
    };
    match (|| {
        let mut upstream = unsafe { UpstreamServerConf::from_raw(upstream) }?;
        let original = upstream.original_upstream::<H>()?;
        match H::init(&mut configuration, &mut upstream, original)? {
            UpstreamInitialization::Initialized(_) => Ok(Status::NGX_OK.0),
            UpstreamInitialization::Unavailable => Ok(Status::NGX_ERROR.0),
        }
    })() {
        Ok(status) => status,
        Err(error) => {
            configuration.log_failure("initialization", &error);
            Status::NGX_ERROR.0
        }
    }
}

impl UpstreamCallbackSlot {
    pub(super) fn install_upstream<H>(
        &mut self,
        upstream: NonNull<ngx_http_upstream_srv_conf_t>,
        original: ngx_http_upstream_init_pt,
    ) -> Result<(), UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        if self.upstream.is_some() {
            return Err(UpstreamCallbackError::DuplicateUpstreamInitializer);
        }
        self.upstream = Some(upstream);
        self.upstream_handler = Some(TypeId::of::<H>());
        self.original_upstream = original;
        Ok(())
    }

    pub(super) fn original_upstream<H>(
        &self,
        upstream: NonNull<ngx_http_upstream_srv_conf_t>,
    ) -> Result<OriginalUpstreamInit<H>, UpstreamCallbackError>
    where
        H: HttpUpstreamInitializer,
    {
        if self.upstream != Some(upstream) || self.upstream_handler != Some(TypeId::of::<H>()) {
            return Err(UpstreamCallbackError::ForeignUpstreamInitializer);
        }
        Ok(OriginalUpstreamInit { callback: self.original_upstream, _handler: PhantomData })
    }
}
