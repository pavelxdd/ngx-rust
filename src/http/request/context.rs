use core::convert::Infallible;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::{self, ManuallyDrop};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::core::*;
use crate::ffi::*;
use crate::http::{HttpConfigError, HttpModuleRequestContext, conf};

use super::view::*;

/// Failure returned while accessing a module request-context slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestContextError {
    /// The module descriptor does not identify a usable HTTP context slot.
    Configuration(HttpConfigError),
    /// Nginx has not installed the request context-slot array.
    MissingSlots,
    /// The request context-slot array does not satisfy pointer alignment.
    MisalignedSlots,
    /// A non-null module context does not satisfy its Rust type's alignment.
    MisalignedContext,
    /// The request pool cannot be used for a context operation.
    Request(RequestError),
    /// Nginx could not allocate the context and its cleanup entry.
    Allocation,
    /// The context cleanup was missing when removal was requested.
    MissingCleanup,
}

impl From<HttpConfigError> for RequestContextError {
    fn from(error: HttpConfigError) -> Self {
        Self::Configuration(error)
    }
}

impl From<RequestError> for RequestContextError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// Failure returned while constructing a request module context.
#[derive(Debug, Eq, PartialEq)]
pub enum RequestContextCreateError<E> {
    /// Request or module context state prevented construction.
    Context(RequestContextError),
    /// The caller's context constructor rejected construction.
    Construction(E),
}

impl<E> From<RequestContextError> for RequestContextCreateError<E> {
    fn from(error: RequestContextError) -> Self {
        Self::Context(error)
    }
}

impl<E> From<RequestError> for RequestContextCreateError<E> {
    fn from(error: RequestError) -> Self {
        Self::Context(error.into())
    }
}

impl<E> From<PoolCleanupError<E>> for RequestContextCreateError<E> {
    fn from(error: PoolCleanupError<E>) -> Self {
        match error {
            PoolCleanupError::Allocation => Self::Context(RequestContextError::Allocation),
            PoolCleanupError::Construction(error) => Self::Construction(error),
        }
    }
}

static NEXT_REQUEST_OWNER: AtomicUsize = AtomicUsize::new(1);

#[repr(C)]
pub(super) struct RequestContextRegistry {
    pub(super) first: *mut RequestContextRegistration,
    pub(super) main: NonNull<ngx_http_request_t>,
    pub(super) owner: usize,
    pub(super) generation: u64,
    next_client_body_read_id: u64,
    client_body_read: Option<ClientBodyReadOperation>,
}

#[repr(C)]
struct RequestContextRegistryOwner {
    registry: RequestContextRegistry,
    request_cleanup: ngx_http_cleanup_t,
}

pub(super) type ClientBodyCallback = unsafe extern "C" fn(*mut ngx_http_request_t);

#[derive(Clone, Copy)]
struct ClientBodyReadOperation {
    id: u64,
    generation: u64,
    callback: ClientBodyCallback,
}

pub(super) enum ClientBodyCallbackState {
    Current,
    Stale,
    Missing,
}

#[repr(C)]
pub(super) struct RequestContextRegistration {
    pub(super) registry: NonNull<RequestContextRegistry>,
    pub(super) next: *mut Self,
    pub(super) slot: NonNull<*mut c_void>,
    pub(super) context: NonNull<c_void>,
    pub(super) cancel: unsafe fn(*mut c_void),
    pub(super) active: bool,
}

impl RequestContextRegistry {
    pub(super) fn insert(&mut self, registration: &mut RequestContextRegistration) {
        registration.next = self.first;
        self.first = registration;
    }

    pub(super) fn has_stale(&self) -> bool {
        let mut current = self.first;
        while let Some(registration) = NonNull::new(current) {
            let registration = unsafe { registration.as_ref() };
            if registration.active
                && !ptr::eq(unsafe { *registration.slot.as_ptr() }, registration.context.as_ptr())
            {
                return true;
            }
            current = registration.next;
        }
        false
    }

    fn cancel_stale(&mut self) -> bool {
        let mut cancelled = false;
        let mut current = self.first;
        while let Some(registration) = NonNull::new(current) {
            let registration = unsafe { &mut *registration.as_ptr() };
            let next = registration.next;
            if registration.active
                && !ptr::eq(unsafe { *registration.slot.as_ptr() }, registration.context.as_ptr())
            {
                registration.cancel();
                cancelled = true;
            }
            current = next;
        }
        cancelled
    }

    fn advance_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    fn cancel_all(&mut self) {
        let mut current = self.first;
        while let Some(registration) = NonNull::new(current) {
            let registration = unsafe { &mut *registration.as_ptr() };
            let next = registration.next;
            registration.cancel();
            current = next;
        }
    }
}

impl RequestContextRegistration {
    pub(super) fn cancel(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        unsafe {
            if ptr::eq(*self.slot.as_ptr(), self.context.as_ptr()) {
                *self.slot.as_ptr() = ptr::null_mut();
            }
            (self.cancel)(self.context.as_ptr());
        }
    }

    fn unlink(&mut self) {
        let target = ptr::from_mut(self);
        let mut link = unsafe { &raw mut self.registry.as_mut().first };
        loop {
            let current = unsafe { *link };
            if current.is_null() {
                return;
            }
            if ptr::eq(current, target) {
                unsafe { *link = (*current).next };
                self.next = ptr::null_mut();
                return;
            }
            link = unsafe { &raw mut (*current).next };
        }
    }
}

pub(super) fn request_is_terminated(request: *const ngx_http_request_t) -> bool {
    unsafe { ngx_rs_http_request_terminated(request) != 0 }
}

unsafe extern "C" fn terminate_request_context_registry(data: *mut c_void) {
    let registry = data.cast::<RequestContextRegistry>();
    // Normal completion reaches pool cleanup; early termination must cancel delayed owners first.
    if request_is_terminated(unsafe { (*registry).main.as_ptr() }) {
        unsafe {
            (*registry).client_body_read = None;
            (*registry).cancel_all();
        }
    }
}

unsafe extern "C" fn cleanup_request_context_registry(data: *mut c_void) {
    let registry = data.cast::<RequestContextRegistry>();
    debug_assert!(unsafe { (*registry).first.is_null() });
}

pub(super) fn find_request_context_registry(
    pool: NonNull<ngx_pool_t>,
) -> Option<NonNull<RequestContextRegistry>> {
    let expected = cleanup_request_context_registry as unsafe extern "C" fn(*mut c_void);
    let mut cleanup = unsafe { pool.as_ref().cleanup };
    while let Some(current) = NonNull::new(cleanup) {
        let entry = unsafe { current.as_ref() };
        if entry.handler.is_some_and(|handler| ptr::fn_addr_eq(handler, expected)) {
            let registry = NonNull::new(entry.data.cast::<RequestContextRegistry>())?;
            if registry.as_ptr().is_aligned() {
                return Some(registry);
            }
            return None;
        }
        cleanup = entry.next;
    }
    None
}

pub(super) fn get_or_create_request_context_registry(
    pool: &Pool<'_>,
    mut main: NonNull<ngx_http_request_t>,
) -> Result<(NonNull<RequestContextRegistry>, bool), RequestContextError> {
    let raw = NonNull::new(pool.as_ptr()).expect("checked request pool must have a pointer");
    if let Some(registry) = find_request_context_registry(raw) {
        return Ok((registry, false));
    }

    let identity = NEXT_REQUEST_OWNER
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |owner| owner.checked_add(1))
        .map_err(|_| RequestContextError::Allocation)?;
    let cleanup = NonNull::new(unsafe {
        ngx_pool_cleanup_add(raw.as_ptr(), mem::size_of::<RequestContextRegistryOwner>())
    })
    .ok_or(RequestContextError::Allocation)?;
    let mut owner: NonNull<RequestContextRegistryOwner> =
        NonNull::new(unsafe { cleanup.as_ref().data.cast() })
            .ok_or(RequestContextError::Allocation)?;
    let registry = unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*owner.as_ptr()).registry)) };
    unsafe {
        owner.as_ptr().write(RequestContextRegistryOwner {
            registry: RequestContextRegistry {
                first: ptr::null_mut(),
                main,
                owner: identity,
                generation: 0,
                next_client_body_read_id: 0,
                client_body_read: None,
            },
            request_cleanup: ngx_http_cleanup_t {
                handler: Some(terminate_request_context_registry),
                data: registry.as_ptr().cast(),
                next: main.as_ref().cleanup,
            },
        });
        main.as_mut().cleanup = &raw mut owner.as_mut().request_cleanup;
        (*cleanup.as_ptr()).handler = Some(cleanup_request_context_registry);
    }
    Ok((registry, true))
}

pub(super) fn remove_request_context_registry(
    pool: &Pool<'_>,
    registry: NonNull<RequestContextRegistry>,
    mut main: NonNull<ngx_http_request_t>,
) {
    let owner = registry.cast::<RequestContextRegistryOwner>();
    let request_cleanup = unsafe { ptr::addr_of_mut!((*owner.as_ptr()).request_cleanup) };
    let mut link = unsafe { &raw mut main.as_mut().cleanup };
    loop {
        let current = unsafe { *link };
        if current.is_null() {
            break;
        }
        if ptr::eq(current, request_cleanup) {
            unsafe {
                *link = (*current).next;
                (*current).next = ptr::null_mut();
            }
            break;
        }
        link = unsafe { &raw mut (*current).next };
    }
    debug_assert!(unsafe { pool.remove_cleanup(registry) });
}

pub(super) struct ContextCancellationHold {
    request: NonNull<ngx_http_request_t>,
    main: NonNull<ngx_http_request_t>,
}

impl Drop for ContextCancellationHold {
    fn drop(&mut self) {
        release_request_reference(self.request, self.main);
    }
}

pub(super) fn release_request_reference(
    request: NonNull<ngx_http_request_t>,
    mut main: NonNull<ngx_http_request_t>,
) {
    let main_ref = unsafe { main.as_ref() };
    if main_ref.pool.is_null() {
        return;
    }

    let count = main_ref.count();
    if count > 1 {
        unsafe { main.as_mut().set_count(count - 1) };
    } else if count == 1 && !request_is_terminated(main.as_ptr()) {
        unsafe { ngx_http_finalize_request(request.as_ptr(), NGX_DONE as _) };
    }
}

pub(super) fn retain_request_for_context_cancellation(
    raw: NonNull<ngx_http_request_t>,
) -> Result<Option<ContextCancellationHold>, RequestError> {
    let request = RequestRef { raw, _callback: PhantomData, _not_thread_safe: PhantomData };
    let mut main = request.main_raw()?;
    let count = unsafe { main.as_ref().count() };
    if count == 0 {
        return Ok(None);
    }
    if count == u16::MAX as _ {
        return Err(RequestError::ReferenceCountOverflow);
    }

    // Cancellation and context destructors may release every other request reference. This
    // synchronous owner uses the native lifecycle reserve, not the delayed-operation budget.
    unsafe { main.as_mut().set_count(count + 1) };
    Ok(Some(ContextCancellationHold { request: raw, main }))
}

pub(super) fn cancel_stale_request_contexts(
    raw: NonNull<ngx_http_request_t>,
) -> Result<(), RequestError> {
    let Some(pool) = NonNull::new(unsafe { raw.as_ref().pool }) else {
        return Ok(());
    };
    let Some(mut registry) = find_request_context_registry(pool) else {
        return Ok(());
    };
    let hold = retain_request_for_context_cancellation(raw)?;
    let registry = unsafe { registry.as_mut() };
    if registry.cancel_stale() {
        registry.advance_generation();
    }
    if hold.as_ref().is_some_and(|hold| unsafe { hold.main.as_ref().count() } == 1) {
        return Err(RequestError::MissingPool);
    }
    Ok(())
}

pub(super) fn advance_request_generation(raw: NonNull<ngx_http_request_t>) {
    let Some(pool) = NonNull::new(unsafe { raw.as_ref().pool }) else {
        return;
    };
    let Some(mut registry) = find_request_context_registry(pool) else {
        return;
    };
    unsafe { registry.as_mut().advance_generation() };
}

pub(super) fn take_client_body_read(
    raw: NonNull<ngx_http_request_t>,
    expected: ClientBodyCallback,
) -> ClientBodyCallbackState {
    let Some(pool) = NonNull::new(unsafe { raw.as_ref().pool }) else {
        return ClientBodyCallbackState::Missing;
    };
    let Some(mut registry) = find_request_context_registry(pool) else {
        return ClientBodyCallbackState::Missing;
    };
    let registry = unsafe { registry.as_mut() };
    let Some(operation) = registry.client_body_read.take() else {
        return ClientBodyCallbackState::Missing;
    };
    if !ptr::fn_addr_eq(operation.callback, expected) {
        registry.client_body_read = Some(operation);
        return ClientBodyCallbackState::Missing;
    }
    if operation.generation == registry.generation {
        ClientBodyCallbackState::Current
    } else {
        ClientBodyCallbackState::Stale
    }
}

pub(super) fn clear_client_body_read(
    raw: NonNull<ngx_http_request_t>,
    id: u64,
    expected: ClientBodyCallback,
) {
    let Some(pool) = NonNull::new(unsafe { raw.as_ref().pool }) else {
        return;
    };
    let Some(mut registry) = find_request_context_registry(pool) else {
        return;
    };
    let registry = unsafe { registry.as_mut() };
    if registry.client_body_read.is_some_and(|operation| {
        operation.id == id && ptr::fn_addr_eq(operation.callback, expected)
    }) {
        registry.client_body_read = None;
    }
}

pub(super) fn register_client_body_read(
    raw: NonNull<ngx_http_request_t>,
    callback: ClientBodyCallback,
) -> Result<Option<u64>, RequestContextError> {
    let request = RequestRef { raw, _callback: PhantomData, _not_thread_safe: PhantomData };
    let pool = request.pool()?;
    let main = request.main_raw()?;
    let (mut registry, _) = get_or_create_request_context_registry(&pool, main)?;
    let registry = unsafe { registry.as_mut() };
    if registry.client_body_read.is_some() {
        return Ok(None);
    }
    let id = registry.next_client_body_read_id;
    registry.next_client_body_read_id = id.wrapping_add(1);
    registry.client_body_read =
        Some(ClientBodyReadOperation { id, generation: registry.generation, callback });
    Ok(Some(id))
}

pub(super) fn request_context_generation(
    raw: NonNull<ngx_http_request_t>,
) -> *mut RequestContextRegistration {
    let Some(pool) = NonNull::new(unsafe { raw.as_ref().pool }) else {
        return ptr::null_mut();
    };
    find_request_context_registry(pool)
        .map(|registry| unsafe { registry.as_ref().first })
        .unwrap_or(ptr::null_mut())
}

pub(super) fn cancel_request_context_generation(mut current: *mut RequestContextRegistration) {
    while let Some(registration) = NonNull::new(current) {
        let registration = unsafe { &mut *registration.as_ptr() };
        let next = registration.next;
        registration.cancel();
        current = next;
    }
}

#[repr(C)]
pub(super) struct RequestContextOwner<T> {
    pub(super) context: ManuallyDrop<T>,
    pub(super) registration: RequestContextRegistration,
    pub(super) cleanup: fn(Pin<&mut T>),
}

impl<T> RequestContextOwner<T> {
    pub(super) fn context_ptr(owner: NonNull<Self>) -> NonNull<T> {
        unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*owner.as_ptr()).context).cast()) }
    }
}

pub(super) unsafe fn cancel_request_context<M>(context: *mut c_void)
where
    M: HttpModuleRequestContext,
{
    let context = context.cast::<M::RequestContext>();
    unsafe {
        M::cancel(Pin::new_unchecked(&mut *context));
        ptr::drop_in_place(context);
    }
}

impl<T> Drop for RequestContextOwner<T> {
    fn drop(&mut self) {
        self.registration.unlink();
        if !self.registration.active {
            return;
        }
        self.registration.active = false;
        unsafe {
            if ptr::eq(*self.registration.slot.as_ptr(), self.registration.context.as_ptr()) {
                *self.registration.slot.as_ptr() = ptr::null_mut();
            }
            let mut context = NonNull::new_unchecked(ptr::addr_of_mut!(self.context).cast::<T>());
            (self.cleanup)(Pin::new_unchecked(context.as_mut()));
            ManuallyDrop::drop(&mut self.context);
        }
    }
}

impl<'callback> RequestRef<'callback> {
    fn module_context_slot(
        &self,
        module: ModuleDescriptor,
    ) -> Result<NonNull<*mut c_void>, RequestContextError> {
        let index = conf::request_context_index(module)?;
        let slots = NonNull::new(unsafe { self.raw.as_ref().ctx })
            .ok_or(RequestContextError::MissingSlots)?;
        if !slots.as_ptr().is_aligned() {
            return Err(RequestContextError::MisalignedSlots);
        }

        Ok(unsafe { NonNull::new_unchecked(slots.as_ptr().add(index)) })
    }

    fn context_from_slot<T>(
        slot: NonNull<*mut c_void>,
    ) -> Result<Option<NonNull<T>>, RequestContextError> {
        let Some(context) = NonNull::new(unsafe { (*slot.as_ptr()).cast::<T>() }) else {
            return Ok(None);
        };
        if !context.as_ptr().is_aligned() {
            return Err(RequestContextError::MisalignedContext);
        }

        Ok(Some(context))
    }

    /// Shared context associated with module `M` for this request.
    pub fn module_context<M>(&self) -> Result<Option<&M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let slot = self.module_context_slot(M::module())?;
        Ok(Self::context_from_slot::<M::RequestContext>(slot)?
            .map(|context| unsafe { context.as_ref() }))
    }
}

impl MainRequestRefMut<'_> {
    /// Returns a shared view of the main request.
    pub fn view(&self) -> RequestRef<'_> {
        self.request.view()
    }

    /// Returns exclusive access to a movable context associated with module `M`.
    pub fn module_context_mut<M>(
        &mut self,
    ) -> Result<Option<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
        M::RequestContext: Unpin,
    {
        self.request.module_context_mut::<M>()
    }

    /// Returns pinned exclusive access to a context associated with module `M`.
    pub fn pinned_module_context_mut<M>(
        &mut self,
    ) -> Result<Option<Pin<&mut M::RequestContext>>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        self.request.pinned_module_context_mut::<M>()
    }

    /// Returns a movable main-request context, inserting a pool-owned value when absent.
    pub fn get_or_insert_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<&mut M::RequestContext, RequestContextError>
    where
        M: HttpModuleRequestContext,
        M::RequestContext: Unpin,
    {
        self.request.get_or_insert_module_context_with::<M>(constructor)
    }

    /// Returns a pinned main-request context, inserting a pool-owned value when absent.
    pub fn get_or_insert_pinned_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<Pin<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        self.request.get_or_insert_pinned_module_context_with::<M>(constructor)
    }

    /// Returns a pinned main-request context, using a fallible constructor when absent.
    pub fn try_get_or_insert_pinned_module_context_with<M, E>(
        &mut self,
        constructor: impl FnOnce() -> Result<M::RequestContext, E>,
    ) -> Result<Pin<&mut M::RequestContext>, RequestContextCreateError<E>>
    where
        M: HttpModuleRequestContext,
    {
        self.request.try_get_or_insert_pinned_module_context_with::<M, E>(constructor)
    }

    /// Drops and removes the module context when present.
    pub fn remove_module_context<M>(&mut self) -> Result<bool, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        self.request.remove_module_context::<M>()
    }
}

impl<'callback> RequestRefMut<'callback> {
    /// Verifies that `context` is still published in module `M`'s request slot.
    ///
    /// A mismatch cancels every stale registered context before returning `false`.
    ///
    /// # Safety
    ///
    /// `request` and `context` must identify a live request and one of its registered module
    /// contexts on entry. No reference to `context` may be live. A `false` result means context
    /// cancellation may also have released the request's final retained reference, so neither
    /// pointer may be used afterward.
    pub unsafe fn is_current_module_context<M>(
        request: *mut ngx_http_request_t,
        context: NonNull<M::RequestContext>,
    ) -> Result<bool, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        let raw = checked_request_ptr(request)?;
        let slot = RequestRef { raw, _callback: PhantomData, _not_thread_safe: PhantomData }
            .module_context_slot(M::module())?;
        if ptr::eq(unsafe { *slot.as_ptr() }, context.as_ptr().cast()) {
            return Ok(true);
        }

        match cancel_stale_request_contexts(raw) {
            Ok(()) | Err(RequestError::MissingPool) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Shared context associated with module `M` for this request.
    pub fn module_context<M>(&self) -> Result<Option<&M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        cancel_stale_request_contexts(self.raw)?;
        let slot =
            RequestRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
                .module_context_slot(M::module())?;
        Ok(RequestRef::context_from_slot::<M::RequestContext>(slot)?
            .map(|context| unsafe { context.as_ref() }))
    }

    /// Exclusive access to an explicitly movable context associated with module `M`.
    pub fn module_context_mut<M>(
        &mut self,
    ) -> Result<Option<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
        M::RequestContext: Unpin,
    {
        cancel_stale_request_contexts(self.raw)?;
        let slot = self.view().module_context_slot(M::module())?;
        Ok(RequestRef::context_from_slot::<M::RequestContext>(slot)?
            .map(|mut context| unsafe { context.as_mut() }))
    }

    /// Returns pinned exclusive access to a context associated with module `M`.
    pub fn pinned_module_context_mut<M>(
        &mut self,
    ) -> Result<Option<Pin<&mut M::RequestContext>>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        cancel_stale_request_contexts(self.raw)?;
        let slot = self.view().module_context_slot(M::module())?;
        Ok(RequestRef::context_from_slot::<M::RequestContext>(slot)?
            .map(|mut context| unsafe { Pin::new_unchecked(context.as_mut()) }))
    }

    /// Returns an explicitly movable module context, inserting a pool-owned value when absent.
    pub fn get_or_insert_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<&mut M::RequestContext, RequestContextError>
    where
        M: HttpModuleRequestContext,
        M::RequestContext: Unpin,
    {
        self.get_or_insert_pinned_module_context_with::<M>(constructor).map(Pin::into_inner)
    }

    /// Returns a pinned module context, inserting a pool-owned value when absent.
    ///
    /// The request context slot is published only after the context, its request registry entry,
    /// and its pool cleanup are initialized. Ordinary removal, native slot reset, or request
    /// termination calls [`HttpModuleRequestContext::cancel`] before dropping the value; pool
    /// teardown calls [`HttpModuleRequestContext::cleanup`] instead.
    ///
    /// ```compile_fail
    /// use core::marker::PhantomPinned;
    /// use core::pin::Pin;
    /// use ngx::core::ModuleDescriptor;
    /// use ngx::http::{HttpModule, HttpModuleRequestContext, RequestRefMut};
    ///
    /// struct Module;
    /// unsafe impl HttpModule for Module {
    ///     fn module() -> ModuleDescriptor {
    ///         unreachable!()
    ///     }
    /// }
    /// struct Context(PhantomPinned);
    /// unsafe impl HttpModuleRequestContext for Module {
    ///     type RequestContext = Context;
    /// }
    /// fn cannot_move(request: &mut RequestRefMut<'_>) {
    ///     let context = request
    ///         .get_or_insert_pinned_module_context_with::<Module>(|| Context(PhantomPinned))
    ///         .unwrap();
    ///     let _ = Pin::into_inner(context);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::core::ModuleDescriptor;
    /// use ngx::http::{HttpModule, HttpModuleRequestContext, RequestRef, RequestRefMut};
    ///
    /// struct Module;
    /// unsafe impl HttpModule for Module {
    ///     fn module() -> ModuleDescriptor {
    ///         unreachable!()
    ///     }
    /// }
    /// struct Context<'request> {
    ///     request: RequestRef<'request>,
    /// }
    /// unsafe impl HttpModuleRequestContext for Module {
    ///     type RequestContext = Context<'static>;
    /// }
    /// fn cannot_retain_request<'request>(request: &mut RequestRefMut<'request>) {
    ///     let _ = request.get_or_insert_pinned_module_context_with::<Module>(|| Context {
    ///         request: request.view(),
    ///     });
    /// }
    /// ```
    pub fn get_or_insert_pinned_module_context_with<M>(
        &mut self,
        constructor: impl FnOnce() -> M::RequestContext,
    ) -> Result<Pin<&mut M::RequestContext>, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        match self
            .try_get_or_insert_pinned_module_context_with::<M, Infallible>(|| Ok(constructor()))
        {
            Ok(context) => Ok(context),
            Err(RequestContextCreateError::Context(error)) => Err(error),
            Err(RequestContextCreateError::Construction(error)) => match error {},
        }
    }

    /// Returns a pinned module context, using a fallible constructor when it is absent.
    pub fn try_get_or_insert_pinned_module_context_with<M, E>(
        &mut self,
        constructor: impl FnOnce() -> Result<M::RequestContext, E>,
    ) -> Result<Pin<&mut M::RequestContext>, RequestContextCreateError<E>>
    where
        M: HttpModuleRequestContext,
    {
        cancel_stale_request_contexts(self.raw)?;
        let slot = self.view().module_context_slot(M::module())?;
        if let Some(mut context) = RequestRef::context_from_slot::<M::RequestContext>(slot)? {
            return Ok(unsafe { Pin::new_unchecked(context.as_mut()) });
        }

        let pool = self.pool()?;
        let main = self.view().main_raw()?;
        let (mut registry, registry_created) = get_or_create_request_context_registry(&pool, main)?;
        let owner = match pool.try_allocate_with_cleanup(|| {
            constructor().map(|context| RequestContextOwner {
                context: ManuallyDrop::new(context),
                registration: RequestContextRegistration {
                    registry,
                    next: ptr::null_mut(),
                    slot,
                    context: NonNull::dangling(),
                    cancel: cancel_request_context::<M>,
                    active: true,
                },
                cleanup: M::cleanup,
            })
        }) {
            Ok(owner) => owner.into_non_null(),
            Err(error) => {
                if registry_created {
                    remove_request_context_registry(&pool, registry, main);
                }
                return Err(error.into());
            }
        };
        let mut context = RequestContextOwner::context_ptr(owner);
        unsafe {
            (*owner.as_ptr()).registration.context = context.cast();
            registry.as_mut().insert(&mut (*owner.as_ptr()).registration);
            *slot.as_ptr() = context.as_ptr().cast();
        }
        Ok(unsafe { Pin::new_unchecked(context.as_mut()) })
    }

    /// Drops and removes the module context when present.
    ///
    /// Returns `Ok(false)` when the slot is empty. A missing cleanup restores the original slot
    /// and returns [`RequestContextError::MissingCleanup`].
    pub fn remove_module_context<M>(&mut self) -> Result<bool, RequestContextError>
    where
        M: HttpModuleRequestContext,
    {
        cancel_stale_request_contexts(self.raw)?;
        let pool = self.pool()?;
        let slot = self.view().module_context_slot(M::module())?;
        let Some(context) = RequestRef::context_from_slot::<M::RequestContext>(slot)? else {
            return Ok(false);
        };

        let _hold = retain_request_for_context_cancellation(self.raw)?;
        let owner = context.cast::<RequestContextOwner<M::RequestContext>>();
        if unsafe { pool.remove_cleanup_with(owner, |owner| owner.registration.cancel()) } {
            Ok(true)
        } else {
            Err(RequestContextError::MissingCleanup)
        }
    }
}
