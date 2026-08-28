use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::pin::Pin;
use core::ptr::NonNull;

use super::conf;
use crate::core::{
    ConnectionError, ConnectionRef, ConnectionRefMut, ModuleDescriptor, Pool, Status,
};
use crate::ffi::{NGX_ERROR, ngx_int_t, ngx_log_t, ngx_stream_session_t};
use crate::stream::{
    StreamConfigError, StreamModule, StreamModuleMainConf, StreamModuleServerConf,
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
    fn into_handler_status(self, session: &Session<'_>) -> ngx_int_t;
}

impl<T> IntoHandlerStatus for Option<T>
where
    T: IntoHandlerStatus,
{
    fn into_handler_status(self, session: &Session<'_>) -> ngx_int_t {
        self.map(|value| value.into_handler_status(session)).unwrap_or(NGX_ERROR as _)
    }
}

impl<T, E> IntoHandlerStatus for Result<T, E>
where
    T: IntoHandlerStatus,
    E: IntoHandlerStatus,
{
    fn into_handler_status(self, session: &Session<'_>) -> ngx_int_t {
        match self {
            Ok(value) => value.into_handler_status(session),
            Err(error) => error.into_handler_status(session),
        }
    }
}

impl IntoHandlerStatus for ngx_int_t {
    fn into_handler_status(self, _session: &Session<'_>) -> ngx_int_t {
        self
    }
}

impl IntoHandlerStatus for Status {
    fn into_handler_status(self, _session: &Session<'_>) -> ngx_int_t {
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
    fn handler(session: &mut Session<'_>) -> Self::Output;

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
    unsafe {
        Session::with_raw(session, |mut session| {
            H::handler(&mut session).into_handler_status(&session)
        })
    }
    .unwrap_or(NGX_ERROR as _)
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

/// Failure returned while creating a checked Stream session view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// The nginx session pointer is null.
    NullSession,
    /// The nginx session pointer does not satisfy `ngx_stream_session_t` alignment.
    MisalignedSession,
}

/// Failure returned while accessing a Stream module session context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionContextError {
    /// The module descriptor does not identify a usable Stream context slot.
    Configuration(StreamConfigError),
    /// Nginx has not installed the session context-slot array.
    MissingSlots,
    /// The session context-slot array does not satisfy pointer alignment.
    MisalignedSlots,
    /// A non-null module context does not satisfy its Rust type's alignment.
    MisalignedContext,
    /// The session connection cannot supply its pool.
    Connection(ConnectionError),
    /// Nginx could not allocate a pool cleanup value.
    Allocation,
}

impl From<StreamConfigError> for SessionContextError {
    fn from(error: StreamConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<ConnectionError> for SessionContextError {
    fn from(error: ConnectionError) -> Self {
        Self::Connection(error)
    }
}

/// Exclusive callback-scoped view of an nginx Stream session.
///
/// ```compile_fail
/// use ngx::stream::Session;
/// use ngx::ffi::ngx_stream_session_t;
///
/// unsafe fn escape(raw: *mut ngx_stream_session_t) -> Session<'static> {
///     unsafe { Session::with_raw(raw, |session| session) }.unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::stream::Session;
/// use ngx::ffi::ngx_stream_session_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *mut ngx_stream_session_t) {
///     let _ = unsafe { Session::with_raw(raw, |session| require_send(session)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ConnectionRef;
/// use ngx::ffi::ngx_stream_session_t;
/// use ngx::stream::Session;
///
/// unsafe fn escape(raw: *mut ngx_stream_session_t) -> ConnectionRef<'static> {
///     unsafe { Session::with_raw(raw, |session| session.connection().unwrap()) }.unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_stream_session_t;
/// use ngx::stream::{Session, StreamModuleMainConf};
///
/// unsafe fn escape<M: StreamModuleMainConf>(raw: *mut ngx_stream_session_t) -> &'static M::MainConf {
///     unsafe { Session::with_raw(raw, |session| session.main_conf::<M>().unwrap().unwrap()) }
///         .unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::ffi::ngx_stream_session_t;
/// use ngx::stream::{Session, StreamModuleSessionContext};
///
/// unsafe fn escape<M: StreamModuleSessionContext>(
///     raw: *mut ngx_stream_session_t,
/// ) -> &'static M::SessionContext {
///     unsafe { Session::with_raw(raw, |session| session.module_context::<M>().unwrap().unwrap()) }
///         .unwrap()
/// }
/// ```
pub struct Session<'callback> {
    raw: NonNull<ngx_stream_session_t>,
    _callback: PhantomData<&'callback mut ngx_stream_session_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl Session<'_> {
    /// Creates a checked exclusive session view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `session` must point to a live initialized nginx session for `'callback`. Its client
    /// connection pool must not be reset before that pool is destroyed. Nginx must make the
    /// session exclusively available for that lifetime, and the view must remain on the owning
    /// event-loop thread.
    pub unsafe fn from_raw(session: *mut ngx_stream_session_t) -> Result<Self, SessionError> {
        let raw = NonNull::new(session).ok_or(SessionError::NullSession)?;
        if !session.is_aligned() {
            return Err(SessionError::MisalignedSession);
        }

        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with a session view that cannot escape the nginx callback through a safe
    /// value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    pub unsafe fn with_raw<R>(
        session: *mut ngx_stream_session_t,
        f: impl for<'scope> FnOnce(Session<'scope>) -> R,
    ) -> Result<R, SessionError> {
        let session = unsafe { Self::from_raw(session) }?;
        Ok(f(session))
    }

    /// Returns the native session pointer for an explicit nginx FFI operation.
    ///
    /// # Safety
    ///
    /// The caller must uphold the target nginx API's aliasing and callback-lifetime requirements.
    pub unsafe fn as_ptr(&self) -> *mut ngx_stream_session_t {
        self.raw.as_ptr()
    }

    /// Client connection associated with this session.
    pub fn connection(&self) -> Result<ConnectionRef<'_>, ConnectionError> {
        unsafe { ConnectionRef::from_raw(self.raw.as_ref().connection) }
    }

    /// Exclusive access to the client connection associated with this session.
    pub fn connection_mut(&mut self) -> Result<ConnectionRefMut<'_>, ConnectionError> {
        unsafe { ConnectionRefMut::from_raw(self.raw.as_ref().connection) }
    }

    /// Memory pool owned by the client connection.
    fn pool(&self) -> Result<Pool<'_>, ConnectionError> {
        self.connection()?.pool()
    }

    /// Logger associated with the client connection.
    pub fn log(&self) -> Result<Option<NonNull<ngx_log_t>>, ConnectionError> {
        self.connection()?.log()
    }

    /// Shared main configuration for module `M`.
    pub fn main_conf<M>(&self) -> Result<Option<&M::MainConf>, StreamConfigError>
    where
        M: StreamModuleMainConf,
    {
        Ok(conf::session_main_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    /// Shared server configuration for module `M`.
    ///
    /// ```compile_fail
    /// # use ngx::stream::{Session, StreamModuleServerConf};
    /// # fn mutable<M: StreamModuleServerConf>(session: &mut Session<'_>) {
    /// let _ = session.server_conf_mut::<M>();
    /// # }
    /// ```
    pub fn server_conf<M>(&self) -> Result<Option<&M::ServerConf>, StreamConfigError>
    where
        M: StreamModuleServerConf,
    {
        Ok(conf::session_server_conf_slot(unsafe { self.raw.as_ref() }, M::module())?
            .map(|value| unsafe { value.as_ref() }))
    }

    fn module_context_slot(
        &self,
        module: ModuleDescriptor,
    ) -> Result<Option<NonNull<*mut c_void>>, SessionContextError> {
        let index = conf::session_context_index(module)?;
        let slots = unsafe { self.raw.as_ref().ctx };
        let Some(slots) = NonNull::new(slots) else {
            return Ok(None);
        };
        if !slots.as_ptr().is_aligned() {
            return Err(SessionContextError::MisalignedSlots);
        }

        Ok(Some(unsafe { NonNull::new_unchecked(slots.as_ptr().add(index)) }))
    }

    fn context_ptr_from_slot<T>(
        slot: NonNull<*mut c_void>,
    ) -> Result<Option<NonNull<T>>, SessionContextError> {
        let Some(context) = NonNull::new(unsafe { (*slot.as_ptr()).cast::<T>() }) else {
            return Ok(None);
        };
        if !context.as_ptr().is_aligned() {
            return Err(SessionContextError::MisalignedContext);
        }

        Ok(Some(context))
    }

    fn module_context_ptr<M>(
        &self,
    ) -> Result<Option<NonNull<M::SessionContext>>, SessionContextError>
    where
        M: StreamModuleSessionContext,
    {
        let Some(slot) = self.module_context_slot(M::module())? else {
            return Ok(None);
        };
        Self::context_ptr_from_slot(slot)
    }

    /// Shared context associated with module `M` for this session.
    pub fn module_context<M>(&self) -> Result<Option<&M::SessionContext>, SessionContextError>
    where
        M: StreamModuleSessionContext,
    {
        Ok(self.module_context_ptr::<M>()?.map(|context| unsafe { context.as_ref() }))
    }

    /// Exclusive access to an explicitly movable context associated with module `M`.
    pub fn module_context_mut<M>(
        &mut self,
    ) -> Result<Option<&mut M::SessionContext>, SessionContextError>
    where
        M: StreamModuleSessionContext,
        M::SessionContext: Unpin,
    {
        Ok(self.module_context_ptr::<M>()?.map(|mut context| unsafe { context.as_mut() }))
    }

    /// Returns pinned exclusive access to a context associated with module `M`.
    pub fn pinned_module_context_mut<M>(
        &mut self,
    ) -> Result<Option<Pin<&mut M::SessionContext>>, SessionContextError>
    where
        M: StreamModuleSessionContext,
    {
        Ok(self
            .module_context_ptr::<M>()?
            .map(|mut context| unsafe { Pin::new_unchecked(context.as_mut()) }))
    }

    /// Returns an explicitly movable module context, inserting a pool-owned value when absent.
    pub fn get_or_insert_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::SessionContext,
    ) -> Result<&mut M::SessionContext, SessionContextError>
    where
        M: StreamModuleSessionContext,
        M::SessionContext: Unpin,
    {
        let slot =
            self.module_context_slot(M::module())?.ok_or(SessionContextError::MissingSlots)?;
        if let Some(mut context) = Self::context_ptr_from_slot(slot)? {
            return Ok(unsafe { context.as_mut() });
        }

        let mut context = self
            .pool()
            .map_err(SessionContextError::Connection)?
            .allocate_with_cleanup(constructor)
            .map_err(|_| SessionContextError::Allocation)?
            .into_non_null();
        unsafe { *slot.as_ptr() = context.as_ptr().cast() };
        Ok(unsafe { context.as_mut() })
    }

    /// Returns a pinned module context, inserting a pool-owned value when absent.
    ///
    /// ```compile_fail
    /// use core::marker::PhantomPinned;
    /// use core::pin::Pin;
    /// use ngx::core::ModuleDescriptor;
    /// use ngx::stream::{Session, StreamModule, StreamModuleSessionContext};
    ///
    /// struct Module;
    /// unsafe impl StreamModule for Module {
    ///     fn module() -> ModuleDescriptor {
    ///         unreachable!()
    ///     }
    /// }
    /// struct Context(PhantomPinned);
    /// unsafe impl StreamModuleSessionContext for Module {
    ///     type SessionContext = Context;
    /// }
    /// fn cannot_move(session: &mut Session<'_>) {
    ///     let context = session
    ///         .get_or_insert_pinned_module_context_with::<Module>(|| Context(PhantomPinned))
    ///         .unwrap();
    ///     let _ = Pin::into_inner(context);
    /// }
    /// ```
    pub fn get_or_insert_pinned_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::SessionContext,
    ) -> Result<Pin<&mut M::SessionContext>, SessionContextError>
    where
        M: StreamModuleSessionContext,
    {
        let slot =
            self.module_context_slot(M::module())?.ok_or(SessionContextError::MissingSlots)?;
        if let Some(mut context) = Self::context_ptr_from_slot(slot)? {
            return Ok(unsafe { Pin::new_unchecked(context.as_mut()) });
        }

        let mut context = self
            .pool()
            .map_err(SessionContextError::Connection)?
            .allocate_with_cleanup(constructor)
            .map_err(|_| SessionContextError::Allocation)?
            .into_non_null();
        unsafe { *slot.as_ptr() = context.as_ptr().cast() };
        Ok(unsafe { Pin::new_unchecked(context.as_mut()) })
    }

    /// Drops and removes the module context when present.
    ///
    /// When an external unsafe caller has already unlinked the cleanup entry, the slot is restored
    /// and this method returns `Ok(None)`.
    pub fn remove_module_context<M>(&mut self) -> Result<Option<()>, SessionContextError>
    where
        M: StreamModuleSessionContext,
    {
        let slot =
            self.module_context_slot(M::module())?.ok_or(SessionContextError::MissingSlots)?;
        let Some(context) = Self::context_ptr_from_slot::<M::SessionContext>(slot)? else {
            return Ok(None);
        };
        let pool = self.pool().map_err(SessionContextError::Connection)?;
        unsafe { *slot.as_ptr() = core::ptr::null_mut() };

        if unsafe { pool.remove_cleanup(context) } {
            Ok(Some(()))
        } else {
            unsafe { *slot.as_ptr() = context.as_ptr().cast() };
            Ok(None)
        }
    }
}

impl fmt::Debug for Session<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Session").field("session", &self.raw).finish()
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
    #[cfg(feature = "test-link")]
    use core::marker::PhantomPinned;
    use core::mem::MaybeUninit;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "test-link")]
    use std::sync::MutexGuard;

    use super::{
        IntoHandlerStatus, Session, SessionContextError, SessionError, StreamModuleSessionContext,
        StreamSessionHandler, raw_handler,
    };
    use crate::core::{ConnectionError, ModuleDescriptor, Status};
    #[cfg(feature = "test-link")]
    use crate::event::{Timer, TimerCallback};
    use crate::ffi::{NGX_ERROR, ngx_module_t, ngx_stream_session_t};
    #[cfg(feature = "test-link")]
    use crate::ffi::{
        NGX_STREAM_MODULE, ngx_connection_t, ngx_create_pool, ngx_current_msec, ngx_destroy_pool,
        ngx_event_expire_timers, ngx_event_timer_init, ngx_log_t, ngx_pool_t, ngx_uint_t,
    };
    #[cfg(feature = "test-link")]
    use crate::log::LogRef;
    use crate::stream::{
        StreamConfigError, StreamModule, StreamModuleMainConf, StreamModuleServerConf, StreamPhase,
    };

    struct TestContextModule;

    unsafe impl StreamModule for TestContextModule {
        fn module() -> ModuleDescriptor {
            let mut module = ngx_module_t::default();
            module.type_ = NGX_STREAM_MODULE as _;
            module.index = 0;
            module.ctx_index = 0;
            ModuleDescriptor::from_test(module)
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

    fn misaligned_session_ptr(storage: &mut [u8]) -> *mut ngx_stream_session_t {
        let alignment = core::mem::align_of::<ngx_stream_session_t>();
        let offset = storage.as_mut_ptr().align_offset(alignment);
        assert!(offset < storage.len());
        unsafe { storage.as_mut_ptr().add(offset + 1).cast() }
    }

    #[test]
    fn session_raw_construction_rejects_null_and_misaligned_pointers() {
        assert!(matches!(
            unsafe { Session::from_raw(ptr::null_mut()) },
            Err(SessionError::NullSession)
        ));

        let mut storage = [0_u8;
            core::mem::size_of::<ngx_stream_session_t>()
                + core::mem::align_of::<ngx_stream_session_t>()];
        let raw = misaligned_session_ptr(&mut storage);
        assert!(matches!(unsafe { Session::from_raw(raw) }, Err(SessionError::MisalignedSession)));
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
        unsafe {
            Session::with_raw(&raw mut raw, |session| {
                assert_eq!(
                    session.main_conf::<TestContextModule>().map(|value| value.copied()),
                    Ok(Some(7))
                );
                assert_eq!(
                    session.server_conf::<TestContextModule>().map(|value| value.copied()),
                    Ok(Some(8))
                );
            })
        }
        .unwrap();
    }

    struct TestHandler;

    impl StreamSessionHandler for TestHandler {
        const PHASE: StreamPhase = StreamPhase::Preread;
        type Output = Status;

        fn handler(_session: &mut Session<'_>) -> Self::Output {
            Status::NGX_DECLINED
        }
    }

    static RAW_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct RawHandler;

    impl StreamSessionHandler for RawHandler {
        const PHASE: StreamPhase = StreamPhase::Preread;
        type Output = Status;

        fn handler(_session: &mut Session<'_>) -> Self::Output {
            RAW_HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
            Status::NGX_DECLINED
        }
    }

    #[test]
    fn typed_handler_converts_the_result() {
        let mut raw = zeroed_session();
        let status = unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                TestHandler::handler(&mut session).into_handler_status(&session)
            })
        }
        .unwrap();

        assert_eq!(status, Status::NGX_DECLINED.0);
    }

    #[test]
    fn raw_handler_uses_one_fresh_session_borrow_and_converts_the_status() {
        RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);
        let mut raw = zeroed_session();

        let status = unsafe { raw_handler::<RawHandler>(&raw mut raw) };

        assert_eq!(status, Status::NGX_DECLINED.0);
        assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn raw_handler_rejects_a_null_session_without_invoking_the_handler() {
        RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);

        assert_eq!(unsafe { raw_handler::<RawHandler>(ptr::null_mut()) }, NGX_ERROR as _);
        assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn raw_handler_rejects_a_misaligned_session_without_invoking_the_handler() {
        RAW_HANDLER_CALLS.store(0, Ordering::Relaxed);
        let mut storage = [0_u8;
            core::mem::size_of::<ngx_stream_session_t>()
                + core::mem::align_of::<ngx_stream_session_t>()];
        let raw = misaligned_session_ptr(&mut storage);

        assert_eq!(unsafe { raw_handler::<RawHandler>(raw) }, NGX_ERROR as _);
        assert_eq!(RAW_HANDLER_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handler_result_converts_only_the_selected_branch() {
        let mut raw = zeroed_session();
        unsafe {
            Session::with_raw(&raw mut raw, |session| {
                assert_eq!(
                    Result::<Status, Status>::Ok(Status::NGX_AGAIN).into_handler_status(&session),
                    Status::NGX_AGAIN.0
                );
                assert_eq!(
                    Result::<Status, Status>::Err(Status::NGX_DECLINED)
                        .into_handler_status(&session),
                    Status::NGX_DECLINED.0
                );
                assert_eq!(Option::<Status>::None.into_handler_status(&session), NGX_ERROR as _);
            })
        }
        .unwrap();
    }

    #[cfg(feature = "test-link")]
    static CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
    }

    #[cfg(feature = "test-link")]
    struct TestContext(u32);

    #[cfg(feature = "test-link")]
    impl Drop for TestContext {
        fn drop(&mut self) {
            CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct TestPool {
        raw: *mut ngx_pool_t,
        _log: Box<ngx_log_t>,
    }

    #[cfg(feature = "test-link")]
    impl TestPool {
        fn new() -> Self {
            let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
            let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!raw.is_null());
            Self { raw, _log: log }
        }
    }

    #[cfg(feature = "test-link")]
    impl Drop for TestPool {
        fn drop(&mut self) {
            unsafe { ngx_destroy_pool(self.raw) };
        }
    }

    #[cfg(feature = "test-link")]
    struct PoolContextModule;

    #[cfg(feature = "test-link")]
    unsafe impl StreamModule for PoolContextModule {
        fn module() -> ModuleDescriptor {
            let mut module = ngx_module_t::default();
            module.type_ = NGX_STREAM_MODULE as _;
            module.index = 0;
            module.ctx_index = 0;
            ModuleDescriptor::from_test(module)
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleSessionContext for PoolContextModule {
        type SessionContext = TestContext;
    }

    #[cfg(feature = "test-link")]
    struct OutOfBoundsContextModule;

    #[cfg(feature = "test-link")]
    unsafe impl StreamModule for OutOfBoundsContextModule {
        fn module() -> ModuleDescriptor {
            let mut module = ngx_module_t::default();
            module.type_ = NGX_STREAM_MODULE as _;
            module.index = 1;
            module.ctx_index = 0;
            ModuleDescriptor::from_test(module)
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleSessionContext for OutOfBoundsContextModule {
        type SessionContext = TestContext;
    }

    #[cfg(feature = "test-link")]
    static PINNED_CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    struct PinnedContext {
        value: u32,
        _pin: PhantomPinned,
    }

    #[cfg(feature = "test-link")]
    impl Drop for PinnedContext {
        fn drop(&mut self) {
            PINNED_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct PinnedContextModule;

    #[cfg(feature = "test-link")]
    unsafe impl StreamModule for PinnedContextModule {
        fn module() -> ModuleDescriptor {
            let mut module = ngx_module_t::default();
            module.type_ = NGX_STREAM_MODULE as _;
            module.index = 0;
            module.ctx_index = 0;
            ModuleDescriptor::from_test(module)
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleSessionContext for PinnedContextModule {
        type SessionContext = PinnedContext;
    }

    #[cfg(feature = "test-link")]
    static TIMER_CONTEXT_DROPS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    static TIMER_CONTEXT_CALLBACKS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "test-link")]
    type TimerContextCallback = for<'callback> fn(TimerCallback<'callback, ()>);

    #[cfg(feature = "test-link")]
    fn timer_context_callback(_timer: TimerCallback<'_, ()>) {
        TIMER_CONTEXT_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "test-link")]
    struct TimerContextDrop;

    #[cfg(feature = "test-link")]
    impl Drop for TimerContextDrop {
        fn drop(&mut self) {
            TIMER_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "test-link")]
    struct TimerContext {
        timer: Timer<'static, (), TimerContextCallback>,
        _drop: TimerContextDrop,
    }

    #[cfg(feature = "test-link")]
    fn static_log_ref() -> LogRef<'static> {
        let log = Box::leak(Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() }));
        unsafe { LogRef::from_raw(log) }.expect("test logger")
    }

    #[cfg(feature = "test-link")]
    struct TimerContextModule;

    #[cfg(feature = "test-link")]
    unsafe impl StreamModule for TimerContextModule {
        fn module() -> ModuleDescriptor {
            let mut module = ngx_module_t::default();
            module.type_ = NGX_STREAM_MODULE as _;
            module.index = 0;
            module.ctx_index = 0;
            ModuleDescriptor::from_test(module)
        }
    }

    #[cfg(feature = "test-link")]
    unsafe impl StreamModuleSessionContext for TimerContextModule {
        type SessionContext = TimerContext;
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn session_access_reports_missing_slots_and_module_index_errors() {
        let _globals = StreamGlobals::new();
        let mut raw = zeroed_session();

        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                assert!(matches!(session.connection(), Err(ConnectionError::NullConnection)));
                assert_eq!(
                    session.main_conf::<TestContextModule>().map(|value| value.copied()),
                    Ok(None)
                );
                assert_eq!(
                    session.server_conf::<TestContextModule>().map(|value| value.copied()),
                    Ok(None)
                );
                assert!(matches!(session.module_context::<PoolContextModule>(), Ok(None)));
                assert!(matches!(
                    session.get_or_insert_module_context_with::<PoolContextModule>(|| {
                        TestContext(42)
                    }),
                    Err(SessionContextError::MissingSlots)
                ));
                assert!(matches!(
                    session.module_context::<OutOfBoundsContextModule>(),
                    Err(SessionContextError::Configuration(
                        StreamConfigError::ModuleIndexOutOfBounds
                    ))
                ));
            })
        }
        .unwrap();
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn context_cleanup_registration_failure_does_not_publish_a_slot() {
        let _globals = StreamGlobals::new();
        let owner = TestPool::new();
        let cleanup = unsafe { (*owner.raw).cleanup };
        unsafe { (*owner.raw).max = 0 };
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();

        for successes in 0..=1 {
            unsafe { ngx_rs_test_fail_allocations_after(successes) };
            let result = unsafe {
                Session::with_raw(&raw mut raw, |mut session| {
                    session
                        .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                        .map(|_| ())
                })
            };
            unsafe { ngx_rs_test_reset_allocation_failures() };

            assert!(matches!(result, Ok(Err(SessionContextError::Allocation))));
            assert!(contexts[0].is_null());
            assert_eq!(unsafe { (*owner.raw).cleanup }, cleanup);
        }
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pinned_context_reuses_its_stable_pool_address() {
        let _globals = StreamGlobals::new();
        PINNED_CONTEXT_DROPS.store(0, Ordering::Relaxed);
        let owner = TestPool::new();
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();

        let address = unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                let address = {
                    let mut context = session
                        .get_or_insert_pinned_module_context_with::<PinnedContextModule>(|| {
                            PinnedContext { value: 42, _pin: PhantomPinned }
                        })
                        .unwrap();
                    let address = NonNull::from(context.as_ref().get_ref()).as_ptr();
                    context.as_mut().get_unchecked_mut().value = 99;
                    address
                };

                let context =
                    session.pinned_module_context_mut::<PinnedContextModule>().unwrap().unwrap();
                assert_eq!(NonNull::from(context.as_ref().get_ref()).as_ptr(), address);
                assert_eq!(context.as_ref().get_ref().value, 99);
                address
            })
        }
        .unwrap();

        assert_eq!(contexts[0], address.cast());
        drop(owner);
        assert_eq!(PINNED_CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn failed_context_cleanup_unlink_restores_the_slot() {
        let _globals = StreamGlobals::new();
        CONTEXT_DROPS.store(0, Ordering::Relaxed);
        let owner = TestPool::new();
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();

        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                session
                    .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                    .unwrap();
            })
        }
        .unwrap();

        let context = contexts[0];
        let cleanup = unsafe { (*owner.raw).cleanup };
        assert!(!cleanup.is_null());
        unsafe {
            (*owner.raw).cleanup = (*cleanup).next;
            (*cleanup).next = ptr::null_mut();
        }

        assert_eq!(
            unsafe {
                Session::with_raw(&raw mut raw, |mut session| {
                    session.remove_module_context::<PoolContextModule>()
                })
            }
            .unwrap()
            .unwrap(),
            None
        );
        assert_eq!(contexts[0], context);

        unsafe {
            (*cleanup).handler = None;
            core::ptr::drop_in_place(context.cast::<TestContext>());
        }
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);

        drop(owner);
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_destroy_cancels_a_pinned_context_timer_before_dropping_its_state() {
        let _globals = StreamGlobals::new();
        unsafe {
            assert_eq!(ngx_event_timer_init(ptr::null_mut()), 0);
            ngx_current_msec = 0;
        }
        TIMER_CONTEXT_DROPS.store(0, Ordering::Relaxed);
        TIMER_CONTEXT_CALLBACKS.store(0, Ordering::Relaxed);
        let owner = TestPool::new();
        let log = static_log_ref();
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();

        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                let mut context = session
                    .get_or_insert_pinned_module_context_with::<TimerContextModule>(|| {
                        let callback: TimerContextCallback = timer_context_callback;
                        TimerContext {
                            timer: Timer::new(log, (), callback),
                            _drop: TimerContextDrop,
                        }
                    })
                    .unwrap();
                let mut timer = context.as_mut().map_unchecked_mut(|context| &mut context.timer);
                timer.as_mut().arm(5).unwrap();
            })
        }
        .unwrap();

        drop(owner);
        assert_eq!(TIMER_CONTEXT_DROPS.load(Ordering::Relaxed), 1);

        unsafe {
            ngx_current_msec = 5;
            ngx_event_expire_timers();
        }
        assert_eq!(TIMER_CONTEXT_CALLBACKS.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn context_removal_keeps_the_slot_when_the_connection_pool_is_unavailable() {
        let _globals = StreamGlobals::new();
        CONTEXT_DROPS.store(0, Ordering::Relaxed);
        let owner = TestPool::new();
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();
        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                session
                    .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                    .unwrap();
            })
        }
        .unwrap();

        let context_ptr = contexts[0];
        raw.connection = ptr::null_mut();
        let result = unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                session.remove_module_context::<PoolContextModule>()
            })
        }
        .unwrap();

        assert!(matches!(
            result,
            Err(SessionContextError::Connection(ConnectionError::NullConnection))
        ));
        assert_eq!(contexts[0], context_ptr);

        raw.connection = &raw mut *connection;
        assert_eq!(
            unsafe {
                Session::with_raw(&raw mut raw, |mut session| {
                    session.remove_module_context::<PoolContextModule>()
                })
            }
            .unwrap()
            .unwrap(),
            Some(())
        );
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn module_context_insertion_and_removal_follow_connection_pool_ownership() {
        let _globals = StreamGlobals::new();
        CONTEXT_DROPS.store(0, Ordering::Relaxed);
        let owner = TestPool::new();
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();
        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                let context = session
                    .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                    .unwrap();
                context.0 = 99;
                assert_eq!(
                    session.module_context::<PoolContextModule>().unwrap().map(|value| value.0),
                    Some(99)
                );
                session.module_context_mut::<PoolContextModule>().unwrap().unwrap().0 = 100;
                let same = session
                    .get_or_insert_module_context_with::<PoolContextModule>(|| unreachable!())
                    .unwrap();
                assert_eq!(same.0, 100);
                assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 0);

                assert_eq!(session.remove_module_context::<PoolContextModule>().unwrap(), Some(()));
                assert!(session.module_context::<PoolContextModule>().unwrap().is_none());
            })
        }
        .unwrap();
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);

        drop(owner);
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "test-link")]
    #[test]
    fn pool_destruction_drops_an_attached_unpinned_context_once() {
        let _globals = StreamGlobals::new();
        CONTEXT_DROPS.store(0, Ordering::Relaxed);
        let owner = TestPool::new();
        let mut connection =
            Box::new(unsafe { MaybeUninit::<ngx_connection_t>::zeroed().assume_init() });
        connection.pool = owner.raw;
        let mut contexts: [*mut c_void; 1] = [ptr::null_mut()];
        let mut raw = zeroed_session();
        raw.connection = &raw mut *connection;
        raw.ctx = contexts.as_mut_ptr();

        unsafe {
            Session::with_raw(&raw mut raw, |mut session| {
                session
                    .get_or_insert_module_context_with::<PoolContextModule>(|| TestContext(42))
                    .unwrap();
            })
        }
        .unwrap();

        assert!(!contexts[0].is_null());
        drop(owner);
        assert_eq!(CONTEXT_DROPS.load(Ordering::Relaxed), 1);
    }
}
