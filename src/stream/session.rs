use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::pin::Pin;
use core::ptr::NonNull;

use super::conf;
use crate::core::{
    ConnectionError, ConnectionRef, ConnectionRefMut, ModuleDescriptor, Pool, Status,
};
use crate::ffi::{NGX_ERROR, ngx_int_t, ngx_stream_session_t};
use crate::log::LogRef;
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
///
/// A handler must not panic; panics terminate the worker process.
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
/// use ngx::ffi::ngx_stream_complex_value_t;
/// use ngx::stream::Session;
///
/// fn reject_raw_complex_value(
///     session: &mut Session<'_>,
///     value: &ngx_stream_complex_value_t,
/// ) {
///     let _ = session.complex_value(value);
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

impl<'callback> Session<'callback> {
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
    ///
    /// ```compile_fail
    /// use ngx::ffi::ngx_stream_session_t;
    /// use ngx::log::LogRef;
    /// use ngx::stream::Session;
    ///
    /// unsafe fn escape(raw: *mut ngx_stream_session_t) -> LogRef<'static> {
    ///     unsafe { Session::with_raw(raw, |session| session.log().unwrap().unwrap()) }.unwrap()
    /// }
    /// ```
    pub fn log(&self) -> Result<Option<LogRef<'callback>>, ConnectionError> {
        let connection =
            unsafe { ConnectionRef::<'callback>::from_raw(self.raw.as_ref().connection) }?;
        connection.log()
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
#[path = "session/tests/mod.rs"]
mod tests;
