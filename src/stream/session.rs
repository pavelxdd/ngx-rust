use core::ffi::c_void;
use core::fmt;
use core::ptr::{self, NonNull};

use super::conf::sealed;
use crate::allocator::AllocError;
use crate::core::{ConnectionError, ConnectionRef, ConnectionRefMut, NgxStr, Pool, Status};
use crate::ffi::{
    NGX_ERROR, NGX_OK, ngx_int_t, ngx_log_t, ngx_module_t, ngx_str_t, ngx_stream_complex_value,
    ngx_stream_complex_value_t, ngx_stream_session_t, ngx_stream_upstream_t,
};
use crate::stream::{
    StreamConfigError, StreamModule, StreamModuleMainConf, StreamModuleMainConfExt,
    StreamModuleMainConfMutExt, StreamModuleServerConf, StreamModuleServerConfExt,
    StreamModuleServerConfMutExt,
};

/// Stream phases in which modules can register handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum StreamPhase {
    /// Immediately after nginx accepts a client connection.
    PostAccept = crate::ffi::ngx_stream_phases_NGX_STREAM_POST_ACCEPT_PHASE as _,
    /// Before access checks.
    Preaccess = crate::ffi::ngx_stream_phases_NGX_STREAM_PREACCESS_PHASE as _,
    /// Access checks.
    Access = crate::ffi::ngx_stream_phases_NGX_STREAM_ACCESS_PHASE as _,
    /// TLS processing.
    Ssl = crate::ffi::ngx_stream_phases_NGX_STREAM_SSL_PHASE as _,
    /// Protocol preread processing.
    Preread = crate::ffi::ngx_stream_phases_NGX_STREAM_PREREAD_PHASE as _,
    /// Session logging.
    Log = crate::ffi::ngx_stream_phases_NGX_STREAM_LOG_PHASE as _,
}

/// Converts a Stream handler result into an nginx status.
pub trait IntoHandlerStatus {
    /// Returns the raw status expected by nginx's Stream phase engine.
    fn into_handler_status(self, session: &Session) -> ngx_int_t;
}

impl<T> IntoHandlerStatus for Option<T>
where
    T: IntoHandlerStatus,
{
    fn into_handler_status(self, session: &Session) -> ngx_int_t {
        self.map(|value| value.into_handler_status(session)).unwrap_or(NGX_ERROR as _)
    }
}

impl<T, E> IntoHandlerStatus for Result<T, E>
where
    T: IntoHandlerStatus,
    E: IntoHandlerStatus,
{
    fn into_handler_status(self, session: &Session) -> ngx_int_t {
        match self {
            Ok(value) => value.into_handler_status(session),
            Err(error) => error.into_handler_status(session),
        }
    }
}

impl IntoHandlerStatus for ngx_int_t {
    fn into_handler_status(self, _session: &Session) -> ngx_int_t {
        self
    }
}

impl IntoHandlerStatus for Status {
    fn into_handler_status(self, _session: &Session) -> ngx_int_t {
        self.0
    }
}

/// A typed Stream phase handler.
pub trait StreamSessionHandler {
    /// Phase in which nginx invokes this handler.
    const PHASE: StreamPhase;
    /// Handler result converted into an nginx status.
    type Output: IntoHandlerStatus;

    /// Handles one active Stream session.
    fn handler(session: &mut Session) -> Self::Output;

    /// Name used when configuration reports a registration failure.
    fn name() -> &'static str {
        core::any::type_name::<Self>()
    }
}

/// C-compatible adapter for a typed Stream phase handler.
///
/// # Safety
/// A non-null `session` must point to a live session that nginx has made exclusively available to
/// the current phase handler. A null pointer returns `NGX_ERROR`.
pub(crate) unsafe extern "C" fn raw_handler<H>(session: *mut ngx_stream_session_t) -> ngx_int_t
where
    H: StreamSessionHandler,
{
    let Some(session) = NonNull::new(session) else {
        return NGX_ERROR as _;
    };
    let session = unsafe { Session::from_ngx_stream_session(session.as_ptr()) };
    H::handler(session).into_handler_status(session)
}

/// Associates one session-context type with a Stream module.
///
/// # Safety
/// The module's session slot must be null or point to an initialized `SessionContext` allocated
/// with a cleanup handler from the session connection's pool. It must remain registered with that
/// pool until removed.
pub unsafe trait StreamModuleSessionContext: StreamModule {
    /// Value stored in the module's per-session context slot.
    type SessionContext: 'static;
}

/// Borrowed high-level view of an nginx Stream session.
#[repr(transparent)]
pub struct Session(ngx_stream_session_t);

impl From<&Session> for *const ngx_stream_session_t {
    fn from(session: &Session) -> Self {
        &raw const session.0
    }
}

impl From<&mut Session> for *mut ngx_stream_session_t {
    fn from(session: &mut Session) -> Self {
        &raw mut session.0
    }
}

impl AsRef<ngx_stream_session_t> for Session {
    fn as_ref(&self) -> &ngx_stream_session_t {
        &self.0
    }
}

impl AsMut<ngx_stream_session_t> for Session {
    fn as_mut(&mut self) -> &mut ngx_stream_session_t {
        &mut self.0
    }
}

impl Session {
    /// Creates an exclusive session view from nginx's raw pointer.
    ///
    /// # Safety
    /// `session` must be non-null, properly aligned, and point to a live `ngx_stream_session_t`.
    /// No other reference to that session may be live for the returned lifetime.
    pub unsafe fn from_ngx_stream_session<'a>(session: *mut ngx_stream_session_t) -> &'a mut Self {
        unsafe { &mut *session.cast::<Self>() }
    }

    /// Creates a shared session view from nginx's raw pointer.
    ///
    /// # Safety
    /// `session` must be non-null, properly aligned, and point to a live `ngx_stream_session_t`.
    /// No mutable reference to that session may be live for the returned lifetime.
    pub unsafe fn from_const_ngx_stream_session<'a>(
        session: *const ngx_stream_session_t,
    ) -> &'a Self {
        unsafe { &*session.cast::<Self>() }
    }

    /// Client connection associated with this session.
    pub fn connection(&self) -> Result<ConnectionRef<'_>, ConnectionError> {
        unsafe { ConnectionRef::from_raw(self.0.connection) }
    }

    /// Exclusive access to the client connection associated with this session.
    pub fn connection_mut(&mut self) -> Result<ConnectionRefMut<'_>, ConnectionError> {
        unsafe { ConnectionRefMut::from_raw(self.0.connection) }
    }

    /// Memory pool owned by the client connection.
    fn pool(&self) -> Option<Pool<'_>> {
        self.connection().ok()?.pool().ok()
    }

    /// Logger associated with the client connection.
    pub fn log(&self) -> *mut ngx_log_t {
        self.connection()
            .ok()
            .and_then(|connection| connection.log().ok().flatten())
            .map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    /// Active upstream state, when nginx has created one.
    pub fn upstream(&self) -> Option<&ngx_stream_upstream_t> {
        unsafe { self.0.upstream.as_ref() }
    }

    /// Exclusive access to active upstream state, when nginx has created one.
    pub fn upstream_mut(&mut self) -> Option<&mut ngx_stream_upstream_t> {
        unsafe { self.0.upstream.as_mut() }
    }

    /// Shared main configuration for module `M`.
    pub fn main_conf<M>(&self) -> Result<Option<&M::MainConf>, StreamConfigError>
    where
        M: StreamModuleMainConf,
    {
        M::main_conf(self)
    }

    /// Shared server configuration for module `M`.
    pub fn server_conf<M>(&self) -> Result<Option<&M::ServerConf>, StreamConfigError>
    where
        M: StreamModuleServerConf,
    {
        M::server_conf(self)
    }

    fn module_context_slot(&self, module: &ngx_module_t) -> Option<NonNull<*mut c_void>> {
        let slots = NonNull::new(self.0.ctx)?;
        Some(unsafe { NonNull::new_unchecked(slots.as_ptr().add(module.ctx_index)) })
    }

    fn module_context_ptr<M>(&self) -> Option<NonNull<M::SessionContext>>
    where
        M: StreamModuleSessionContext,
    {
        let slot = self.module_context_slot(M::module())?;
        NonNull::new(unsafe { *slot.as_ptr() }.cast())
    }

    /// Shared context associated with module `M` for this session.
    pub fn module_context<M>(&self) -> Option<&M::SessionContext>
    where
        M: StreamModuleSessionContext,
    {
        unsafe { Some(self.module_context_ptr::<M>()?.as_ref()) }
    }

    /// Exclusive context associated with module `M` for this session.
    ///
    /// ```compile_fail
    /// # use ngx::stream::{Session, StreamModuleSessionContext};
    /// # fn access<M: StreamModuleSessionContext>(session: &Session) {
    /// let _ = session.module_context_mut::<M>();
    /// # }
    /// ```
    pub fn module_context_mut<M>(&mut self) -> Option<&mut M::SessionContext>
    where
        M: StreamModuleSessionContext,
    {
        unsafe { Some(self.module_context_ptr::<M>()?.as_mut()) }
    }

    /// Returns the module context, inserting a pool-owned value when absent.
    pub fn get_or_insert_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::SessionContext,
    ) -> Result<&mut M::SessionContext, AllocError>
    where
        M: StreamModuleSessionContext,
    {
        let slot = self.module_context_slot(M::module()).ok_or(AllocError)?;
        if let Some(mut context) = NonNull::new(unsafe { *slot.as_ptr() }.cast()) {
            return Ok(unsafe { context.as_mut() });
        }

        let mut context =
            self.pool().ok_or(AllocError)?.allocate_with_cleanup(constructor)?.into_non_null();
        unsafe { *slot.as_ptr() = context.as_ptr().cast() };
        Ok(unsafe { context.as_mut() })
    }

    /// Drops and removes the module context when present.
    pub fn remove_module_context<M>(&mut self) -> Option<()>
    where
        M: StreamModuleSessionContext,
    {
        let pool = self.pool()?;
        let slot = self.module_context_slot(M::module())?;
        let context = NonNull::new(unsafe { *slot.as_ptr() }.cast::<M::SessionContext>())?;
        unsafe { *slot.as_ptr() = core::ptr::null_mut() };

        if unsafe { pool.remove_cleanup(context) } {
            Some(())
        } else {
            unsafe { *slot.as_ptr() = context.as_ptr().cast() };
            None
        }
    }

    /// Evaluates a compiled Stream complex value for this session.
    pub fn complex_value<'a>(
        &'a mut self,
        complex: &ngx_stream_complex_value_t,
    ) -> Option<&'a NgxStr> {
        let mut value = ngx_str_t::default();
        let status = unsafe {
            ngx_stream_complex_value(
                (&raw mut self.0).cast(),
                (complex as *const ngx_stream_complex_value_t).cast_mut(),
                &raw mut value,
            )
        };
        if status != NGX_OK as ngx_int_t {
            return None;
        }
        unsafe { Some(NgxStr::from_ngx_str(value)) }
    }
}

impl sealed::MainConfSource for Session {}
impl sealed::MainConfSourceMut for Session {}
impl sealed::ServerConfSource for Session {}
impl sealed::ServerConfSourceMut for Session {}

impl StreamModuleMainConfExt for Session {
    fn stream_main_conf<T>(&self, module: &ngx_module_t) -> Result<Option<&T>, StreamConfigError> {
        self.0.stream_main_conf(module)
    }
}

impl StreamModuleMainConfMutExt for Session {
    fn stream_main_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        self.0.stream_main_conf_mut(module)
    }
}

impl StreamModuleServerConfExt for Session {
    fn stream_server_conf<T>(
        &self,
        module: &ngx_module_t,
    ) -> Result<Option<&T>, StreamConfigError> {
        self.0.stream_server_conf(module)
    }
}

impl StreamModuleServerConfMutExt for Session {
    fn stream_server_conf_mut<T>(
        &mut self,
        module: &ngx_module_t,
    ) -> Result<Option<&mut T>, StreamConfigError> {
        self.0.stream_server_conf_mut(module)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Session").field("session", &self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    #[cfg(feature = "test-link")]
    extern crate std;

    use alloc::boxed::Box;
    #[cfg(feature = "test-link")]
    use core::ffi::c_void;
    use core::mem::MaybeUninit;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "test-link")]
    use std::sync::MutexGuard;

    #[cfg(feature = "test-link")]
    use super::StreamModuleSessionContext;
    use super::{IntoHandlerStatus, Session, StreamSessionHandler, raw_handler};
    use crate::core::Status;
    use crate::ffi::{NGX_ERROR, NGX_STREAM_OK, ngx_module_t, ngx_stream_session_t};
    #[cfg(feature = "test-link")]
    use crate::ffi::{
        NGX_STREAM_MODULE, ngx_connection_t, ngx_create_pool, ngx_destroy_pool, ngx_log_t,
        ngx_uint_t,
    };
    use crate::stream::{StreamModule, StreamModuleMainConf, StreamModuleServerConf, StreamPhase};

    struct TestContextModule;

    unsafe impl StreamModule for TestContextModule {
        fn module() -> &'static ngx_module_t {
            let mut module = ngx_module_t::default();
            module.type_ = NGX_STREAM_MODULE as _;
            module.index = 0;
            module.ctx_index = 0;
            Box::leak(Box::new(module))
        }
    }

    unsafe impl StreamModuleMainConf for TestContextModule {
        type MainConf = u32;
    }

    unsafe impl StreamModuleServerConf for TestContextModule {
        type ServerConf = u32;
    }

    fn zeroed_session() -> ngx_stream_session_t {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }

    fn session_from(raw: &mut ngx_stream_session_t) -> &mut Session {
        unsafe { Session::from_ngx_stream_session(raw) }
    }

    #[cfg(feature = "test-link")]
    struct StreamGlobals {
        _guard: MutexGuard<'static, ()>,
        max_module: ngx_uint_t,
        stream_max_module: ngx_uint_t,
    }

    #[cfg(feature = "test-link")]
    impl StreamGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            let max_module = unsafe { nginx_sys::ngx_max_module };
            let stream_max_module = unsafe { nginx_sys::ngx_stream_max_module };

            unsafe {
                nginx_sys::ngx_max_module = 1;
                nginx_sys::ngx_stream_max_module = 1;
            }

            Self { _guard: guard, max_module, stream_max_module }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for StreamGlobals {
        fn drop(&mut self) {
            unsafe {
                nginx_sys::ngx_max_module = self.max_module;
                nginx_sys::ngx_stream_max_module = self.stream_max_module;
            }
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn stream_configuration_access_follows_the_session_borrow() {
        let _globals = StreamGlobals::new();
        let mut main = 7_u32;
        let mut server = 8_u32;
        let mut main_conf: [*mut c_void; 1] = [(&raw mut main).cast()];
        let mut server_conf: [*mut c_void; 1] = [(&raw mut server).cast()];
        let mut raw = zeroed_session();
        raw.main_conf = main_conf.as_mut_ptr();
        raw.srv_conf = server_conf.as_mut_ptr();
        let session = session_from(&mut raw);

        assert_eq!(
            session.main_conf::<TestContextModule>().map(|value| value.copied()),
            Ok(Some(7))
        );
        assert_eq!(
            session.server_conf::<TestContextModule>().map(|value| value.copied()),
            Ok(Some(8))
        );
    }

    struct TestHandler;

    impl StreamSessionHandler for TestHandler {
        const PHASE: StreamPhase = StreamPhase::Preread;
        type Output = Status;

        fn handler(session: &mut Session) -> Self::Output {
            session.as_mut().status = NGX_STREAM_OK as _;
            Status::NGX_DECLINED
        }
    }

    static RAW_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct RawHandler;

    impl StreamSessionHandler for RawHandler {
        const PHASE: StreamPhase = StreamPhase::Preread;
        type Output = Status;

        fn handler(session: &mut Session) -> Self::Output {
            RAW_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
            session.as_mut().status = NGX_STREAM_OK as _;
            Status::NGX_DECLINED
        }
    }

    #[test]
    fn typed_handler_mutates_the_session_and_converts_the_result() {
        let mut raw = zeroed_session();
        let session = session_from(&mut raw);

        let status = TestHandler::handler(session).into_handler_status(session);

        assert_eq!(status, Status::NGX_DECLINED.0);
        assert_eq!(raw.status, NGX_STREAM_OK as _);
    }

    #[test]
    fn raw_handler_uses_one_fresh_session_borrow_and_converts_the_status() {
        RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);
        let mut raw = zeroed_session();

        let status = unsafe { raw_handler::<RawHandler>(&raw mut raw) };

        assert_eq!(status, Status::NGX_DECLINED.0);
        assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(raw.status, NGX_STREAM_OK as _);
    }

    #[test]
    fn raw_handler_rejects_a_null_session_without_invoking_the_handler() {
        RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);

        assert_eq!(unsafe { raw_handler::<RawHandler>(ptr::null_mut()) }, NGX_ERROR as _);
        assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handler_result_converts_only_the_selected_branch() {
        let mut raw = zeroed_session();
        let session = session_from(&mut raw);

        assert_eq!(
            Result::<Status, Status>::Ok(Status::NGX_AGAIN).into_handler_status(session),
            Status::NGX_AGAIN.0
        );
        assert_eq!(
            Result::<Status, Status>::Err(Status::NGX_DECLINED).into_handler_status(session),
            Status::NGX_DECLINED.0
        );
        assert_eq!(Option::<Status>::None.into_handler_status(session), NGX_ERROR as _);
    }

    #[cfg(feature = "test-link")]
    static CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    struct TestContext(u32);

    #[cfg(feature = "test-link")]
    impl Drop for TestContext {
        fn drop(&mut self) {
            CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct PoolContextModule;

    #[cfg(feature = "test-link")]
    unsafe impl StreamModule for PoolContextModule {
        fn module() -> &'static ngx_module_t {
            let mut module = ngx_module_t::default();
            module.ctx_index = 0;
            Box::leak(Box::new(module))
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleSessionContext for PoolContextModule {
        type SessionContext = TestContext;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn context_removal_keeps_the_slot_when_the_connection_pool_is_unavailable() {
        let mut context = TestContext(42);
        let context_ptr = (&raw mut context).cast();
        let mut contexts: [*mut c_void; 1] = [context_ptr];
        let mut raw = zeroed_session();
        raw.ctx = contexts.as_mut_ptr();
        let session = session_from(&mut raw);

        assert_eq!(session.remove_module_context::<PoolContextModule>(), None);
        assert_eq!(contexts[0], context_ptr);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn module_context_insertion_and_removal_follow_connection_pool_ownership() {
        CONTEXT_DROPS.store(0, Ordering::Relaxed);
        let mut log = Box::new(unsafe { core::mem::zeroed::<ngx_log_t>() });
        let pool = unsafe { ngx_create_pool(4096, &raw mut *log) };
        assert!(!pool.is_null());
        let mut connection = Box::new(unsafe { core::mem::zeroed::<ngx_connection_t>() });
        connection.pool = pool;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();
        let session = session_from(&mut raw);

        let context = session
            .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
            .unwrap();
        context.0 = 99;
        assert_eq!(session.module_context::<PoolContextModule>().map(|value| value.0), Some(99));
        session.module_context_mut::<PoolContextModule>().unwrap().0 = 100;
        let same = session
            .get_or_insert_module_context_with::<PoolContextModule>(|| unreachable!())
            .unwrap();
        assert_eq!(same.0, 100);
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 0);

        assert_eq!(session.remove_module_context::<PoolContextModule>(), Some(()));
        assert!(session.module_context::<PoolContextModule>().is_none());
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);

        unsafe { ngx_destroy_pool(pool) };
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    }
}
