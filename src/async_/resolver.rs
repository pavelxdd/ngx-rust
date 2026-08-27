// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Wrapper for the nginx resolver.
//!
//! See <https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver>.

use alloc::rc::Rc;
use alloc::string::String;
use core::cell::{RefCell, UnsafeCell};
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::num::NonZero;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::slice;
use core::task::{Context, Poll, Waker};

use nginx_sys::{
    NGX_NO_RESOLVER, NGX_RESOLVE_FORMERR, NGX_RESOLVE_NOTIMP, NGX_RESOLVE_NXDOMAIN,
    NGX_RESOLVE_REFUSED, NGX_RESOLVE_SERVFAIL, NGX_RESOLVE_TIMEDOUT,
};

use crate::{
    collections::Vec,
    core::{NgxStr, Pool, Status},
    ffi::{
        ngx_addr_t, ngx_msec_t, ngx_pool_t, ngx_resolve_name, ngx_resolve_start,
        ngx_resolver_ctx_t, ngx_resolver_t, ngx_str_t,
    },
};

/// Error type for all uses of `Resolver`.
#[derive(Debug)]
pub enum Error {
    /// No resolver configured
    NoResolver,
    /// Resolver error, with context of name being resolved
    Resolver(ResolverError, String),
    /// Allocation failed
    AllocationFailed,
    /// Resolution was canceled before it completed
    Canceled,
    /// Unknown internal error while starting name resolution
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::NoResolver => write!(f, "No resolver configured"),
            Error::Resolver(err, context) => write!(f, "{err}: resolving `{context}`"),
            Error::AllocationFailed => write!(f, "Allocation failed"),
            Error::Canceled => write!(f, "Resolution canceled"),
            Error::Internal => write!(f, "Internal error"),
        }
    }
}
impl core::error::Error for Error {}

/// These cases directly reflect the NGX_RESOLVE_ error codes,
/// plus a timeout, and a case for an unknown error where a known
/// NGX_RESOLVE_ should be.
#[derive(Debug)]
pub enum ResolverError {
    /// Format error (NGX_RESOLVE_FORMERR)
    FormErr,
    /// Server failure (NGX_RESOLVE_SERVFAIL)
    ServFail,
    /// Host not found (NGX_RESOLVE_NXDOMAIN)
    NXDomain,
    /// Unimplemented (NGX_RESOLVE_NOTIMP)
    NotImp,
    /// Operation refused (NGX_RESOLVE_REFUSED)
    Refused,
    /// Timed out (NGX_RESOLVE_TIMEDOUT)
    TimedOut,
    /// Unknown NGX_RESOLVE error
    Unknown(isize),
}
impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ResolverError::FormErr => write!(f, "Format error"),
            ResolverError::ServFail => write!(f, "Server Failure"),
            ResolverError::NXDomain => write!(f, "Host not found"),
            ResolverError::NotImp => write!(f, "Unimplemented"),
            ResolverError::Refused => write!(f, "Refused"),
            ResolverError::TimedOut => write!(f, "Timed out"),
            ResolverError::Unknown(code) => write!(f, "Unknown NGX_RESOLVE error {code}"),
        }
    }
}
impl core::error::Error for ResolverError {}

/// Convert from the NGX_RESOLVE_ error codes.
impl From<NonZero<isize>> for ResolverError {
    fn from(code: NonZero<isize>) -> ResolverError {
        match code.get() as u32 {
            NGX_RESOLVE_FORMERR => ResolverError::FormErr,
            NGX_RESOLVE_SERVFAIL => ResolverError::ServFail,
            NGX_RESOLVE_NXDOMAIN => ResolverError::NXDomain,
            NGX_RESOLVE_NOTIMP => ResolverError::NotImp,
            NGX_RESOLVE_REFUSED => ResolverError::Refused,
            NGX_RESOLVE_TIMEDOUT => ResolverError::TimedOut,
            _ => ResolverError::Unknown(code.get()),
        }
    }
}

type Res<'pool> = Result<Vec<ngx_addr_t, Pool<'pool>>, Error>;
type RawRes = Result<RawAddresses, Error>;

/// A wrapper for an ngx_resolver_t which provides an async Rust API.
///
/// A dangling native resolver cannot be introduced through safe code:
///
/// ```compile_fail
/// use core::ptr::NonNull;
/// use ngx::{async_::resolver::Resolver, ffi::ngx_resolver_t};
///
/// let _ = Resolver::from_raw(NonNull::<ngx_resolver_t>::dangling().as_ptr(), 1_000);
/// ```
///
/// Query bytes must come from a valid Rust borrow rather than a raw `ngx_str_t`:
///
/// ```compile_fail
/// use core::ptr::NonNull;
/// use ngx::{
///     async_::resolver::Resolver,
///     core::Pool,
///     ffi::ngx_str_t,
/// };
///
/// fn resolve_dangling(resolver: &Resolver<'_>, pool: &Pool<'_>) {
///     let name = ngx_str_t { len: 1, data: NonNull::<u8>::dangling().as_ptr() };
///     let _ = resolver.resolve_name(&name, pool);
/// }
/// ```
pub struct Resolver<'resolver> {
    resolver: NonNull<ngx_resolver_t>,
    timeout: ngx_msec_t,
    _lifetime: PhantomData<&'resolver UnsafeCell<ngx_resolver_t>>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'resolver> Resolver<'resolver> {
    /// Creates a resolver capability from a native nginx resolver.
    ///
    /// # Safety
    ///
    /// `resolver` must identify a live, properly aligned nginx resolver for `'resolver`, including
    /// its referenced configuration, connections, and logger. The resolver must remain on its
    /// owning event-loop thread. Null and misaligned pointers are rejected.
    pub unsafe fn from_raw(resolver: *mut ngx_resolver_t, timeout: ngx_msec_t) -> Option<Self> {
        let resolver = NonNull::new(resolver)?;
        if !resolver.as_ptr().is_aligned() {
            return None;
        }

        Some(Self { resolver, timeout, _lifetime: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Resolve a name into a set of addresses.
    ///
    /// ```compile_fail
    /// use ngx::{
    ///     async_::resolver::Resolver,
    ///     core::{NgxStr, Pool},
    ///     ffi::ngx_pool_t,
    /// };
    ///
    /// fn escape(resolver: &Resolver<'_>, name: &NgxStr, raw: *mut ngx_pool_t) {
    ///     let _future = unsafe {
    ///         Pool::with_raw(raw, |pool| resolver.resolve_name(name, &pool))
    ///     };
    /// }
    /// ```
    pub async fn resolve_name<'pool>(&self, name: &NgxStr, pool: &Pool<'pool>) -> Res<'pool> {
        Resolution::new(name, NgxStr::from_bytes(&[]), self, pool)?.await
    }

    /// Resolve a service into a set of addresses.
    pub async fn resolve_service<'pool>(
        &self,
        name: &NgxStr,
        service: &NgxStr,
        pool: &Pool<'pool>,
    ) -> Res<'pool> {
        Resolution::new(name, service, self, pool)?.await
    }
}

struct Resolution<'pool> {
    shared: Rc<RefCell<ResolutionShared>>,
    _pool: PhantomData<Pool<'pool>>,
}

impl<'pool> Resolution<'pool> {
    fn new(
        name: &NgxStr,
        service: &NgxStr,
        resolver: &Resolver<'_>,
        pool: &Pool<'pool>,
    ) -> Result<Self, Error> {
        let name = copy_string(name, pool)?;
        let service = copy_string(service, pool)?;
        let pool = NonNull::new(pool.as_ptr()).ok_or(Error::Internal)?;
        let shared = Rc::new(RefCell::new(ResolutionShared::new(pool)));
        let owner_pool = unsafe { Pool::from_raw(pool.as_ptr()) }.ok_or(Error::Internal)?;
        let mut owner = owner_pool
            .allocate_with_cleanup(|| ResolutionOwner::new(Rc::clone(&shared), pool))
            .map_err(|_| Error::AllocationFailed)?;

        let start = match ResolverCtx::start(resolver.resolver, &name, pool) {
            Ok(start) => start,
            Err(error) => {
                let _ = owner.remove();
                return Err(error);
            }
        };

        match start {
            ResolverStart::Quick(result) => {
                let _ = owner.remove();
                shared.borrow_mut().completion = ResolutionCompletion::Ready(result);
            }
            ResolverStart::Context(mut context) => {
                let owner_pointer = owner.as_non_null();
                context.name = name;
                context.service = service;
                context.timeout = resolver.timeout;
                context.set_cancelable(1);
                context.handler = Some(ResolutionOwner::handler);
                context.data = owner_pointer.as_ptr().cast::<c_void>();
                let context_pointer = context.as_ptr();

                {
                    let owner = unsafe { owner.as_pin_mut().get_unchecked_mut() };
                    owner.context = Some(context);
                }
                shared.borrow_mut().owner = Some(owner_pointer);

                // Nginx may call the handler synchronously when a cached result is available.
                // No Rust reference to the pinned owner is live across this call.
                if unsafe { Status(ngx_resolve_name(context_pointer.as_ptr())) }
                    .into_result()
                    .is_err()
                {
                    {
                        let owner = unsafe { owner.as_pin_mut().get_unchecked_mut() };
                        owner.forget_context_after_start_error();
                    }
                    let _ = owner.remove();
                    return Err(Error::Internal);
                }

                let _ = owner.into_non_null();
            }
        }

        Ok(Self { shared, _pool: PhantomData })
    }
}

impl<'pool> core::future::Future for Resolution<'pool> {
    type Output = Res<'pool>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = {
            let mut shared = this.shared.borrow_mut();
            match &mut shared.completion {
                ResolutionCompletion::Pending => {
                    match &mut shared.waker {
                        Some(waker) => waker.clone_from(cx.waker()),
                        None => shared.waker = Some(cx.waker().clone()),
                    }
                    return Poll::Pending;
                }
                ResolutionCompletion::Ready(_) => {
                    let result =
                        match mem::replace(&mut shared.completion, ResolutionCompletion::Taken) {
                            ResolutionCompletion::Ready(result) => result,
                            _ => unreachable!(),
                        };
                    (result, shared.pool)
                }
                ResolutionCompletion::Canceled => return Poll::Ready(Err(Error::Canceled)),
                ResolutionCompletion::Taken => return Poll::Ready(Err(Error::Internal)),
            }
        };

        let (result, pool) = result;
        match result {
            Ok(addresses) => {
                let pool = pool.ok_or(Error::Canceled).and_then(|pool| {
                    unsafe { Pool::from_raw(pool.as_ptr()) }.ok_or(Error::Internal)
                });
                Poll::Ready(pool.map(|pool| unsafe { addresses.into_vec(pool) }))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl Drop for Resolution<'_> {
    fn drop(&mut self) {
        let owner = self.shared.borrow().owner;
        if let Some(mut owner) = owner {
            let _ = unsafe { owner.as_mut() }.cancel();
        }
    }
}

struct ResolutionShared {
    owner: Option<NonNull<ResolutionOwner>>,
    pool: Option<NonNull<ngx_pool_t>>,
    completion: ResolutionCompletion,
    waker: Option<Waker>,
}

impl ResolutionShared {
    fn new(pool: NonNull<ngx_pool_t>) -> Self {
        Self {
            owner: None,
            pool: Some(pool),
            completion: ResolutionCompletion::Pending,
            waker: None,
        }
    }
}

enum ResolutionCompletion {
    Pending,
    Ready(RawRes),
    Canceled,
    Taken,
}

struct ResolutionOwner {
    shared: Rc<RefCell<ResolutionShared>>,
    pool: NonNull<ngx_pool_t>,
    context: Option<ResolverCtx>,
    _pin: PhantomData<core::marker::PhantomPinned>,
}

impl ResolutionOwner {
    fn new(shared: Rc<RefCell<ResolutionShared>>, pool: NonNull<ngx_pool_t>) -> Self {
        Self { shared, pool, context: None, _pin: PhantomData }
    }

    unsafe extern "C" fn handler(context: *mut ngx_resolver_ctx_t) {
        let Some(context) = NonNull::new(context) else {
            return;
        };
        let owner = unsafe { (*context.as_ptr()).data.cast::<ResolutionOwner>() };
        let Some(mut owner) = NonNull::new(owner) else {
            return;
        };

        let waker = unsafe { owner.as_mut() }.complete(context);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn complete(&mut self, context: NonNull<ngx_resolver_ctx_t>) -> Option<Waker> {
        let mut owned = self.context.take()?;
        if !ptr::eq(owned.as_ptr().as_ptr(), context.as_ptr()) {
            self.context = Some(owned);
            return None;
        }

        owned.make_inert();
        // The resolver callback owns this context, and nginx keeps its reported result fields live
        // until ngx_resolve_name_done.
        let result = unsafe { copy_result(&owned, self.pool) };
        let owner = NonNull::from(&*self);
        let waker = {
            let mut shared = self.shared.borrow_mut();
            if shared.owner != Some(owner)
                || !matches!(shared.completion, ResolutionCompletion::Pending)
            {
                None
            } else {
                shared.completion = ResolutionCompletion::Ready(result);
                shared.waker.take()
            }
        };

        drop(owned);
        waker
    }

    fn forget_context_after_start_error(&mut self) {
        if let Some(context) = self.context.take() {
            mem::forget(context);
        }
    }

    fn cancel(&mut self) -> Option<Waker> {
        if let Some(mut context) = self.context.take() {
            context.make_inert();
            drop(context);
        }

        let owner = NonNull::from(&*self);
        let mut shared = self.shared.borrow_mut();
        if shared.owner != Some(owner) {
            return None;
        }

        shared.owner = None;
        shared.pool = None;
        shared.completion = ResolutionCompletion::Canceled;
        shared.waker.take()
    }
}

impl Drop for ResolutionOwner {
    fn drop(&mut self) {
        let waker = self.cancel();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct RawAddresses {
    pool: NonNull<ngx_pool_t>,
    pointer: NonNull<ngx_addr_t>,
    length: usize,
    capacity: usize,
}

impl RawAddresses {
    unsafe fn into_vec(self, pool: Pool<'_>) -> Vec<ngx_addr_t, Pool<'_>> {
        let pointer = self.pointer;
        let length = self.length;
        let capacity = self.capacity;
        mem::forget(self);
        unsafe { Vec::from_raw_parts_in(pointer.as_ptr(), length, capacity, pool) }
    }
}

impl Drop for RawAddresses {
    fn drop(&mut self) {
        if self.capacity != 0 {
            // ResolutionOwner drops completion before nginx releases this pool's large blocks.
            unsafe { nginx_sys::ngx_pfree(self.pool.as_ptr(), self.pointer.as_ptr().cast()) };
        }
    }
}

enum ResolverStart {
    Quick(RawRes),
    Context(ResolverCtx),
}

/// An owned nginx resolver context.
struct ResolverCtx(NonNull<ngx_resolver_ctx_t>);

impl core::ops::Deref for ResolverCtx {
    type Target = ngx_resolver_ctx_t;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this wrapper is always constructed with a valid non-empty resolve context
        unsafe { self.0.as_ref() }
    }
}

impl core::ops::DerefMut for ResolverCtx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this wrapper is always constructed with a valid non-empty resolve context
        unsafe { self.0.as_mut() }
    }
}

impl Drop for ResolverCtx {
    fn drop(&mut self) {
        unsafe {
            nginx_sys::ngx_resolve_name_done(self.0.as_mut());
        }
    }
}

impl ResolverCtx {
    fn start(
        resolver: NonNull<ngx_resolver_t>,
        name: &ngx_str_t,
        pool: NonNull<ngx_pool_t>,
    ) -> Result<ResolverStart, Error> {
        let mut temporary = MaybeUninit::<ngx_resolver_ctx_t>::zeroed();
        unsafe { (*temporary.as_mut_ptr()).name = *name };
        let ctx = unsafe { ngx_resolve_start(resolver.as_ptr(), temporary.as_mut_ptr()) };
        if ctx == NGX_NO_RESOLVER {
            return Err(Error::NoResolver);
        }
        let ctx = NonNull::new(ctx).ok_or(Error::AllocationFailed)?;
        if ptr::eq(ctx.as_ptr(), temporary.as_mut_ptr()) {
            let result = unsafe { copy_result(&*temporary.as_ptr(), pool) };
            unsafe { nginx_sys::ngx_resolve_name_done(temporary.as_mut_ptr()) };
            return Ok(ResolverStart::Quick(result));
        }

        Ok(ResolverStart::Context(Self(ctx)))
    }

    fn as_ptr(&self) -> NonNull<ngx_resolver_ctx_t> {
        self.0
    }

    fn make_inert(&mut self) {
        self.data = ptr::null_mut();
        self.handler = None;
    }
}

/// # Safety
///
/// The native result pointers reachable from `context` must remain readable for their reported
/// lengths until this function returns, and `pool` must identify the live resolution pool.
unsafe fn copy_result(context: &ngx_resolver_ctx_t, pool: NonNull<ngx_pool_t>) -> RawRes {
    if let Some(error) = NonZero::new(context.state) {
        let name = String::from_utf8_lossy(unsafe { checked_bytes(&context.name) }?).into_owned();
        return Err(Error::Resolver(ResolverError::from(error), name));
    }

    let count = context.naddrs;
    let addresses = unsafe { checked_slice(context.addrs, count) }?;
    let raw_pool = pool;
    let pool = unsafe { Pool::from_raw(raw_pool.as_ptr()) }.ok_or(Error::Internal)?;
    let mut copied = Vec::new_in(pool.clone());
    copied.try_reserve_exact(addresses.len()).map_err(|_| Error::AllocationFailed)?;

    for address in addresses {
        copied.push(unsafe { copy_resolved_addr(address, &pool) }?);
    }

    let (pointer, length, capacity, _) = copied.into_raw_parts_with_alloc();
    let pointer = NonNull::new(pointer).ok_or(Error::Internal)?;
    Ok(RawAddresses { pool: raw_pool, pointer, length, capacity })
}

/// # Safety
///
/// A non-empty range must be aligned, initialized, and readable for `length` elements throughout
/// `'a`.
unsafe fn checked_slice<'a, T>(pointer: *const T, length: usize) -> Result<&'a [T], Error> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null()
        || (mem::size_of::<T>() != 0 && length > isize::MAX as usize / mem::size_of::<T>())
    {
        return Err(Error::Internal);
    }

    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

/// # Safety
///
/// A non-empty native string must remain readable for its reported length through the returned
/// borrow.
unsafe fn checked_bytes(value: &ngx_str_t) -> Result<&[u8], Error> {
    unsafe { checked_slice(value.data.cast_const(), value.len) }
}

fn copy_string(value: &NgxStr, pool: &Pool<'_>) -> Result<ngx_str_t, Error> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Ok(ngx_str_t::empty());
    }

    unsafe { ngx_str_t::from_bytes(pool.as_ptr(), bytes) }.ok_or(Error::AllocationFailed)
}

/// # Safety
///
/// Native address and name storage must remain readable for their reported lengths until copied.
unsafe fn copy_resolved_addr(
    addr: &nginx_sys::ngx_resolver_addr_t,
    pool: &Pool<'_>,
) -> Result<ngx_addr_t, Error> {
    let socklen = usize::try_from(addr.socklen).map_err(|_| Error::Internal)?;
    if socklen < mem::size_of::<libc::sa_family_t>()
        || socklen > mem::size_of::<libc::sockaddr_storage>()
    {
        return Err(Error::Internal);
    }

    let source = NonNull::new(addr.sockaddr.cast::<u8>()).ok_or(Error::Internal)?;
    let target = NonNull::new(pool.alloc(socklen).cast::<u8>()).ok_or(Error::AllocationFailed)?;
    unsafe { ptr::copy_nonoverlapping(source.as_ptr(), target.as_ptr(), socklen) };
    let bytes = unsafe { checked_bytes(&addr.name) }?;
    let name = if bytes.is_empty() {
        ngx_str_t::empty()
    } else {
        unsafe { ngx_str_t::from_bytes(pool.as_ptr(), bytes) }.ok_or(Error::AllocationFailed)?
    };

    Ok(ngx_addr_t { sockaddr: target.as_ptr().cast(), socklen: addr.socklen, name })
}

#[cfg(all(test, feature = "test-link"))]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::cell::{Cell, RefCell};
    use core::ffi::c_void;
    use core::future::Future;
    use core::marker::PhantomData;
    use core::mem::{self, MaybeUninit};
    use core::pin::Pin;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use std::sync::MutexGuard;

    use nginx_sys::{
        NGX_OK, NGX_RESOLVE_NXDOMAIN, NGX_RESOLVE_TIMEDOUT, ngx_create_pool, ngx_destroy_pool,
        ngx_log_t, ngx_pool_t, ngx_resolver_addr_t, ngx_resolver_ctx_t, ngx_resolver_t, ngx_str_t,
        ngx_uint_t,
    };

    use super::*;

    struct TestPool {
        raw: Cell<*mut ngx_pool_t>,
        _log: Box<ngx_log_t>,
    }

    impl TestPool {
        fn new() -> Self {
            let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
            let raw = unsafe { ngx_create_pool(4096, &raw mut *log) };
            assert!(!raw.is_null());
            Self { raw: Cell::new(raw), _log: log }
        }

        fn handle(&self) -> Pool<'_> {
            unsafe { Pool::from_raw(self.raw.get()) }.unwrap()
        }

        fn destroy(&self) {
            let raw = self.raw.replace(core::ptr::null_mut());
            if !raw.is_null() {
                unsafe { ngx_destroy_pool(raw) };
            }
        }
    }

    impl Drop for TestPool {
        fn drop(&mut self) {
            self.destroy();
        }
    }

    unsafe extern "C" {
        fn ngx_rs_test_fail_allocations_after(successes: ngx_uint_t);
        fn ngx_rs_test_reset_allocation_failures();
        fn ngx_rs_test_reset_resolve_name_done_count();
        fn ngx_rs_test_resolve_name_done_count() -> ngx_uint_t;
    }

    struct ResolverGlobals {
        _guard: MutexGuard<'static, ()>,
    }

    impl ResolverGlobals {
        fn new() -> Self {
            let guard = crate::TEST_NGINX_GLOBALS.lock().unwrap_or_else(|error| error.into_inner());
            unsafe {
                ngx_rs_test_reset_allocation_failures();
                ngx_rs_test_reset_resolve_name_done_count();
            }
            Self { _guard: guard }
        }

        fn done_count(&self) -> usize {
            unsafe { ngx_rs_test_resolve_name_done_count() as usize }
        }
    }

    impl Drop for ResolverGlobals {
        fn drop(&mut self) {
            unsafe { ngx_rs_test_reset_allocation_failures() };
        }
    }

    struct TestResolver {
        raw: Box<ngx_resolver_t>,
        _log: Box<ngx_log_t>,
    }

    impl TestResolver {
        fn new() -> Self {
            let mut log = Box::new(unsafe { MaybeUninit::<ngx_log_t>::zeroed().assume_init() });
            let mut raw =
                Box::new(unsafe { MaybeUninit::<ngx_resolver_t>::zeroed().assume_init() });
            raw.log = &raw mut *log;
            Self { raw, _log: log }
        }

        fn with_connection() -> Self {
            let mut resolver = Self::new();
            resolver.raw.connections.nelts = 1;
            resolver
        }

        fn resolver(&mut self) -> Resolver<'_> {
            unsafe { Resolver::from_raw(&raw mut *self.raw, 1_000) }.unwrap()
        }
    }

    fn pending_resolution<'pool>(
        pool: &Pool<'pool>,
        configure: impl FnOnce(&mut ngx_resolver_ctx_t),
        test: impl FnOnce(&mut Resolution<'pool>, &mut ngx_resolver_ctx_t),
    ) {
        let mut resolver = TestResolver::new();
        let mut context =
            Box::new(unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() });
        context.resolver = &raw mut *resolver.raw;
        context.set_quick(1);
        configure(&mut context);

        let raw_pool = NonNull::new(pool.as_ptr()).unwrap();
        let shared = Rc::new(RefCell::new(ResolutionShared::new(raw_pool)));
        let mut owner = pool
            .allocate_with_cleanup(|| ResolutionOwner::new(Rc::clone(&shared), raw_pool))
            .unwrap();
        let owner_pointer = owner.as_non_null();
        context.handler = Some(ResolutionOwner::handler);
        context.data = owner_pointer.as_ptr().cast::<c_void>();
        {
            let state = unsafe { owner.as_pin_mut().get_unchecked_mut() };
            state.context = Some(ResolverCtx(NonNull::from(&mut *context)));
        }
        shared.borrow_mut().owner = Some(owner_pointer);
        let mut resolution = Resolution { shared, _pool: PhantomData };
        let _ = owner.into_non_null();

        test(&mut resolution, &mut context);

        drop(resolution);
        drop(context);
        drop(resolver);
    }

    fn poll_resolution<'pool>(
        resolution: &mut Resolution<'pool>,
        waker: &Waker,
    ) -> Poll<Res<'pool>> {
        let mut context = Context::from_waker(waker);
        Pin::new(resolution).poll(&mut context)
    }

    fn canceled_resolution<'pool>() -> Resolution<'pool> {
        Resolution {
            shared: Rc::new(RefCell::new(ResolutionShared {
                owner: None,
                pool: None,
                completion: ResolutionCompletion::Canceled,
                waker: None,
            })),
            _pool: PhantomData,
        }
    }

    fn leave_pool_bytes(pool: &Pool<'_>, bytes: usize) {
        let raw = pool.as_ptr();
        let available = unsafe { (*raw).d.end.offset_from((*raw).d.last) as usize };
        assert!(available > bytes);
        assert!(!pool.alloc_unaligned(available - bytes).is_null());
    }

    struct CountWaker(Arc<AtomicUsize>);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct CancelWaker {
        resolution: AtomicPtr<c_void>,
    }

    impl CancelWaker {
        fn cancel(&self) {
            let pointer = self.resolution.swap(ptr::null_mut(), Ordering::Relaxed);
            if pointer.is_null() {
                return;
            }

            // The resolver invokes this test waker synchronously on the same thread, after its
            // shared borrow has ended. The pointer is consumed before the test can return.
            unsafe {
                let resolution = &mut *pointer.cast::<Resolution<'static>>();
                let pending = mem::replace(resolution, canceled_resolution());
                drop(pending);
            }
        }
    }

    impl Wake for CancelWaker {
        fn wake(self: Arc<Self>) {
            self.cancel();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.cancel();
        }
    }

    #[test]
    fn resolver_factory_rejects_null_and_misaligned_native_owners() {
        assert!(unsafe { Resolver::from_raw(ptr::null_mut(), 1_000) }.is_none());

        let mut resolver = MaybeUninit::<ngx_resolver_t>::uninit();
        let misaligned = unsafe { resolver.as_mut_ptr().cast::<u8>().add(1).cast() };
        assert!(unsafe { Resolver::from_raw(misaligned, 1_000) }.is_none());
    }

    #[test]
    fn numeric_name_resolves_without_a_configured_dns_server() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut raw_resolver = TestResolver::new();
        let resolver = raw_resolver.resolver();
        let name = NgxStr::from_bytes(b"127.0.0.1");
        let mut resolution = core::pin::pin!(resolver.resolve_name(name, &pool));
        let mut context = Context::from_waker(Waker::noop());

        match resolution.as_mut().poll(&mut context) {
            Poll::Ready(Ok(addresses)) => {
                assert_eq!(addresses.len(), 1);
                assert_eq!(
                    addresses[0].socklen as usize,
                    core::mem::size_of::<libc::sockaddr_in>()
                );
            }
            Poll::Ready(Err(error)) => panic!("numeric resolution failed: {error}"),
            Poll::Pending => panic!("numeric resolution did not complete synchronously"),
        }
        assert_eq!(globals.done_count(), 1);
    }

    #[test]
    fn no_resolver_returns_without_creating_a_native_context() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut raw_resolver = TestResolver::new();
        let resolver = raw_resolver.resolver();
        let name = NgxStr::from_bytes(b"example.test");
        let mut resolution = core::pin::pin!(resolver.resolve_name(name, &pool));
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            resolution.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::NoResolver))
        ));
        assert_eq!(globals.done_count(), 0);
    }

    #[test]
    fn dropping_unpolled_resolution_does_not_start_a_native_context() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut raw_resolver = TestResolver::with_connection();
        let resolver = raw_resolver.resolver();
        let name = NgxStr::from_bytes(b"example.test");

        drop(resolver.resolve_name(name, &pool));
        assert_eq!(globals.done_count(), 0);
    }

    #[test]
    fn native_context_allocation_failure_releases_owner_without_done() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut raw_resolver = TestResolver::with_connection();
        let resolver = raw_resolver.resolver();
        let name = NgxStr::from_bytes(b"example.test");
        unsafe { ngx_rs_test_fail_allocations_after(0) };
        let mut resolution = core::pin::pin!(resolver.resolve_name(name, &pool));
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            resolution.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::AllocationFailed))
        ));
        assert_eq!(globals.done_count(), 0);
    }

    #[test]
    fn owner_cleanup_allocation_failure_does_not_start_resolution() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        leave_pool_bytes(&pool, 8);
        let mut raw_resolver = TestResolver::new();
        let resolver = raw_resolver.resolver();
        let name = NgxStr::from_bytes(b"x");
        unsafe { ngx_rs_test_fail_allocations_after(0) };
        let mut resolution = core::pin::pin!(resolver.resolve_name(name, &pool));
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            resolution.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::AllocationFailed))
        ));
        assert_eq!(globals.done_count(), 0);
    }

    #[test]
    fn native_start_error_forgets_consumed_context_without_done() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut raw_resolver = TestResolver::with_connection();
        let resolver = raw_resolver.resolver();
        let name = NgxStr::from_bytes(b"example.test");
        let service = NgxStr::from_bytes(b"https");
        unsafe { ngx_rs_test_fail_allocations_after(1) };
        let mut resolution = core::pin::pin!(resolver.resolve_service(name, service, &pool));
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            resolution.as_mut().poll(&mut context),
            Poll::Ready(Err(Error::Internal))
        ));
        assert_eq!(globals.done_count(), 0);
    }

    #[test]
    fn vector_copy_allocation_failure_finishes_native_context_once() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut sockaddr = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        sockaddr.sin_family = libc::AF_INET as _;
        let native_address = ngx_resolver_addr_t {
            sockaddr: core::ptr::from_mut(&mut sockaddr).cast(),
            socklen: mem::size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t::empty(),
            priority: 0,
            weight: 0,
        };
        let mut native_addresses = alloc::vec![native_address; 1_024];
        let native_addresses_pointer = native_addresses.as_mut_ptr();
        let native_addresses_length = native_addresses.len();

        pending_resolution(
            &pool,
            |context| {
                context.state = NGX_OK as _;
                context.naddrs = native_addresses_length as _;
                context.addrs = native_addresses_pointer;
            },
            |resolution, context| {
                unsafe { ngx_rs_test_fail_allocations_after(0) };
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
                assert!(matches!(
                    poll_resolution(resolution, Waker::noop()),
                    Poll::Ready(Err(Error::AllocationFailed))
                ));
            },
        );
    }

    #[test]
    fn dropping_ready_large_result_releases_its_pool_allocation() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut sockaddr = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        sockaddr.sin_family = libc::AF_INET as _;
        let native_address = ngx_resolver_addr_t {
            sockaddr: core::ptr::from_mut(&mut sockaddr).cast(),
            socklen: mem::size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t::empty(),
            priority: 0,
            weight: 0,
        };
        let mut native_addresses = alloc::vec![native_address; 1_024];
        let native_addresses_pointer = native_addresses.as_mut_ptr();
        let native_addresses_length = native_addresses.len();

        pending_resolution(
            &pool,
            |context| {
                context.state = NGX_OK as _;
                context.naddrs = native_addresses_length as _;
                context.addrs = native_addresses_pointer;
            },
            |resolution, context| {
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
                let large = unsafe { (*pool.as_ptr()).large };
                assert!(!large.is_null());
                assert!(!(unsafe { (*large).alloc }).is_null());

                let ready = mem::replace(resolution, canceled_resolution());
                drop(ready);
                assert!((unsafe { (*large).alloc }).is_null());
            },
        );
    }

    #[test]
    fn sockaddr_copy_allocation_failure_finishes_native_context_once() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut sockaddr = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        sockaddr.sin_family = libc::AF_INET as _;
        let native_address = ngx_resolver_addr_t {
            sockaddr: core::ptr::from_mut(&mut sockaddr).cast(),
            socklen: mem::size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t::empty(),
            priority: 0,
            weight: 0,
        };
        let mut native_addresses = [native_address];
        let native_addresses_pointer = native_addresses.as_mut_ptr();

        pending_resolution(
            &pool,
            |context| {
                context.state = NGX_OK as _;
                context.naddrs = 1;
                context.addrs = native_addresses_pointer;
            },
            |resolution, context| {
                leave_pool_bytes(
                    &pool,
                    mem::size_of::<ngx_addr_t>() + mem::align_of::<ngx_addr_t>(),
                );
                unsafe { ngx_rs_test_fail_allocations_after(0) };
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
                assert!(matches!(
                    poll_resolution(resolution, Waker::noop()),
                    Poll::Ready(Err(Error::AllocationFailed))
                ));
            },
        );
    }

    #[test]
    fn address_name_copy_allocation_failure_finishes_native_context_once() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut sockaddr = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        sockaddr.sin_family = libc::AF_INET as _;
        let mut name = [b'n'; 128];
        let name_pointer = name.as_mut_ptr();
        let name_length = name.len();
        let native_address = ngx_resolver_addr_t {
            sockaddr: core::ptr::from_mut(&mut sockaddr).cast(),
            socklen: mem::size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t { data: name_pointer, len: name_length },
            priority: 0,
            weight: 0,
        };
        let mut native_addresses = [native_address];
        let native_addresses_pointer = native_addresses.as_mut_ptr();

        pending_resolution(
            &pool,
            |context| {
                context.state = NGX_OK as _;
                context.naddrs = 1;
                context.addrs = native_addresses_pointer;
            },
            |resolution, context| {
                leave_pool_bytes(
                    &pool,
                    mem::size_of::<ngx_addr_t>()
                        + mem::align_of::<ngx_addr_t>()
                        + mem::size_of::<libc::sockaddr_in>()
                        + mem::align_of::<libc::sockaddr_in>(),
                );
                unsafe { ngx_rs_test_fail_allocations_after(0) };
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
                assert!(matches!(
                    poll_resolution(resolution, Waker::noop()),
                    Poll::Ready(Err(Error::AllocationFailed))
                ));
            },
        );
    }

    #[test]
    fn delayed_result_replaces_waker_and_copies_multiple_addresses() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut first_sockaddr =
            unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        first_sockaddr.sin_family = libc::AF_INET as _;
        first_sockaddr.sin_port = 8443_u16.to_be();
        first_sockaddr.sin_addr = libc::in_addr { s_addr: u32::from_be_bytes([192, 0, 2, 1]) };
        let mut second_sockaddr =
            unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        second_sockaddr.sin_family = libc::AF_INET as _;
        second_sockaddr.sin_port = 5353_u16.to_be();
        second_sockaddr.sin_addr = libc::in_addr { s_addr: u32::from_be_bytes([198, 51, 100, 2]) };
        let first_sockaddr_copy = unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(&first_sockaddr).cast::<u8>(),
                mem::size_of::<libc::sockaddr_in>(),
            )
            .to_vec()
        };
        let second_sockaddr_copy = unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(&second_sockaddr).cast::<u8>(),
                mem::size_of::<libc::sockaddr_in>(),
            )
            .to_vec()
        };
        let mut first_name = *b"first.example";
        let mut second_name = *b"second.example";
        let first_sockaddr_pointer = core::ptr::from_mut(&mut first_sockaddr).cast();
        let second_sockaddr_pointer = core::ptr::from_mut(&mut second_sockaddr).cast();
        let first_name_pointer = first_name.as_mut_ptr();
        let second_name_pointer = second_name.as_mut_ptr();
        let mut native_addresses = [
            ngx_resolver_addr_t {
                sockaddr: first_sockaddr_pointer,
                socklen: mem::size_of::<libc::sockaddr_in>() as _,
                name: ngx_str_t { data: first_name_pointer, len: first_name.len() },
                priority: 0,
                weight: 0,
            },
            ngx_resolver_addr_t {
                sockaddr: second_sockaddr_pointer,
                socklen: mem::size_of::<libc::sockaddr_in>() as _,
                name: ngx_str_t { data: second_name_pointer, len: second_name.len() },
                priority: 0,
                weight: 0,
            },
        ];
        let native_addresses_pointer = native_addresses.as_mut_ptr();

        pending_resolution(
            &pool,
            |context| {
                context.state = NGX_OK as _;
                context.naddrs = native_addresses.len() as _;
                context.addrs = native_addresses_pointer;
            },
            |resolution, context| {
                let first_wakes = Arc::new(AtomicUsize::new(0));
                let second_wakes = Arc::new(AtomicUsize::new(0));
                let first_waker = Waker::from(Arc::new(CountWaker(Arc::clone(&first_wakes))));
                let second_waker = Waker::from(Arc::new(CountWaker(Arc::clone(&second_wakes))));

                assert!(matches!(poll_resolution(resolution, &first_waker), Poll::Pending));
                assert!(matches!(poll_resolution(resolution, &second_waker), Poll::Pending));

                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(first_wakes.load(Ordering::Relaxed), 0);
                assert_eq!(second_wakes.load(Ordering::Relaxed), 1);
                assert_eq!(globals.done_count(), 1);

                first_sockaddr.sin_port = 0;
                second_sockaddr.sin_port = 0;
                first_name.fill(b'x');
                second_name.fill(b'x');

                let addresses = match poll_resolution(resolution, &second_waker) {
                    Poll::Ready(Ok(addresses)) => addresses,
                    Poll::Ready(Err(error)) => panic!("resolution failed: {error}"),
                    Poll::Pending => panic!("resolution remained pending after callback"),
                };
                assert_eq!(addresses.len(), 2);
                assert_eq!(
                    unsafe {
                        core::slice::from_raw_parts(
                            addresses[0].sockaddr.cast::<u8>(),
                            addresses[0].socklen as usize,
                        )
                    },
                    first_sockaddr_copy
                );
                assert_eq!(
                    unsafe {
                        core::slice::from_raw_parts(
                            addresses[1].sockaddr.cast::<u8>(),
                            addresses[1].socklen as usize,
                        )
                    },
                    second_sockaddr_copy
                );
                assert_eq!(unsafe { checked_bytes(&addresses[0].name) }.unwrap(), b"first.example");
                assert_eq!(
                    unsafe { checked_bytes(&addresses[1].name) }.unwrap(),
                    b"second.example"
                );

                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);

                drop(addresses);
                let taken = mem::replace(resolution, canceled_resolution());
                drop(taken);
                assert_eq!(globals.done_count(), 1);
            },
        );
        assert_eq!(globals.done_count(), 1);
    }

    #[test]
    fn callback_before_first_poll_returns_an_empty_address_list() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |context| {
                context.state = NGX_OK as _;
                context.naddrs = 0;
                context.addrs = ptr::null_mut();
            },
            |resolution, context| {
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);

                match poll_resolution(resolution, Waker::noop()) {
                    Poll::Ready(Ok(addresses)) => assert!(addresses.is_empty()),
                    Poll::Ready(Err(error)) => panic!("resolution failed: {error}"),
                    Poll::Pending => panic!("empty result remained pending"),
                }
            },
        );
    }

    #[test]
    fn nxdomain_callback_copies_name_and_finishes_once() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let mut name = *b"missing.example";
        let name_pointer = name.as_mut_ptr();
        let name_length = name.len();

        pending_resolution(
            &pool,
            |context| {
                context.state = NGX_RESOLVE_NXDOMAIN as _;
                context.name = ngx_str_t { data: name_pointer, len: name_length };
            },
            |resolution, context| {
                unsafe { ResolutionOwner::handler(context) };
                name.fill(b'x');
                assert_eq!(globals.done_count(), 1);

                match poll_resolution(resolution, Waker::noop()) {
                    Poll::Ready(Err(Error::Resolver(ResolverError::NXDomain, name))) => {
                        assert_eq!(name, "missing.example");
                    }
                    Poll::Ready(Err(error)) => panic!("unexpected resolution error: {error}"),
                    Poll::Ready(Ok(_)) => panic!("NXDOMAIN returned addresses"),
                    Poll::Pending => panic!("NXDOMAIN remained pending"),
                }

                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
            },
        );
    }

    #[test]
    fn timeout_callback_wakes_and_finishes_once() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |context| context.state = NGX_RESOLVE_TIMEDOUT as _,
            |resolution, context| {
                let wakes = Arc::new(AtomicUsize::new(0));
                let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));
                assert!(matches!(poll_resolution(resolution, &waker), Poll::Pending));

                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(wakes.load(Ordering::Relaxed), 1);
                assert_eq!(globals.done_count(), 1);

                assert!(matches!(
                    poll_resolution(resolution, &waker),
                    Poll::Ready(Err(Error::Resolver(ResolverError::TimedOut, _)))
                ));
            },
        );
    }

    #[test]
    fn malformed_native_result_fields_return_internal_error() {
        let _globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();
        let raw_pool = NonNull::new(pool.as_ptr()).unwrap();

        let mut context = unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() };
        context.state = NGX_OK as _;
        context.naddrs = 1;
        context.addrs = ptr::null_mut();
        assert!(matches!(unsafe { copy_result(&context, raw_pool) }, Err(Error::Internal)));

        let mut address = unsafe { MaybeUninit::<ngx_resolver_addr_t>::zeroed().assume_init() };
        let mut context = unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() };
        context.state = NGX_OK as _;
        context.naddrs = 1;
        context.addrs = core::ptr::from_mut(&mut address);
        assert!(matches!(unsafe { copy_result(&context, raw_pool) }, Err(Error::Internal)));

        let mut oversized = [0_u8; mem::size_of::<libc::sockaddr_storage>() + 1];
        let address = ngx_resolver_addr_t {
            sockaddr: oversized.as_mut_ptr().cast(),
            socklen: oversized.len() as _,
            name: ngx_str_t::empty(),
            priority: 0,
            weight: 0,
        };
        let mut context = unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() };
        context.state = NGX_OK as _;
        context.naddrs = 1;
        context.addrs = core::ptr::from_ref(&address).cast_mut();
        assert!(matches!(unsafe { copy_result(&context, raw_pool) }, Err(Error::Internal)));

        let address = ngx_resolver_addr_t {
            sockaddr: ptr::null_mut(),
            socklen: mem::size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t::empty(),
            priority: 0,
            weight: 0,
        };
        let mut context = unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() };
        context.state = NGX_OK as _;
        context.naddrs = 1;
        context.addrs = core::ptr::from_ref(&address).cast_mut();
        assert!(matches!(unsafe { copy_result(&context, raw_pool) }, Err(Error::Internal)));

        let mut sockaddr = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        let address = ngx_resolver_addr_t {
            sockaddr: core::ptr::from_mut(&mut sockaddr).cast(),
            socklen: mem::size_of::<libc::sockaddr_in>() as _,
            name: ngx_str_t { data: ptr::null_mut(), len: 1 },
            priority: 0,
            weight: 0,
        };
        let mut context = unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() };
        context.state = NGX_OK as _;
        context.naddrs = 1;
        context.addrs = core::ptr::from_ref(&address).cast_mut();
        assert!(matches!(unsafe { copy_result(&context, raw_pool) }, Err(Error::Internal)));

        let mut context = unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() };
        context.state = NGX_RESOLVE_NXDOMAIN as _;
        context.name = ngx_str_t { data: ptr::null_mut(), len: 1 };
        assert!(matches!(unsafe { copy_result(&context, raw_pool) }, Err(Error::Internal)));

        let mut context = unsafe { MaybeUninit::<ngx_resolver_ctx_t>::zeroed().assume_init() };
        context.state = NGX_OK as _;
        context.naddrs = usize::MAX as ngx_uint_t;
        context.addrs = NonNull::<ngx_resolver_addr_t>::dangling().as_ptr();
        assert!(matches!(unsafe { copy_result(&context, raw_pool) }, Err(Error::Internal)));
    }

    #[test]
    fn dropping_pending_resolution_cancels_once_before_callback() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |_| {},
            |resolution, context| {
                let wakes = Arc::new(AtomicUsize::new(0));
                let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));
                assert!(matches!(poll_resolution(resolution, &waker), Poll::Pending));

                let pending = mem::replace(resolution, canceled_resolution());
                drop(pending);
                assert_eq!(wakes.load(Ordering::Relaxed), 0);
                assert!(context.data.is_null());
                assert!(context.handler.is_none());
                assert_eq!(globals.done_count(), 1);

                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
                assert!(matches!(
                    poll_resolution(resolution, &waker),
                    Poll::Ready(Err(Error::Canceled))
                ));
            },
        );
    }

    #[test]
    fn waker_can_cancel_resolution_during_callback() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |_| {},
            |resolution, context| {
                let cancel_waker = Arc::new(CancelWaker {
                    resolution: AtomicPtr::new(core::ptr::from_mut(resolution).cast()),
                });
                let waker = Waker::from(Arc::clone(&cancel_waker));
                assert!(matches!(poll_resolution(resolution, &waker), Poll::Pending));

                unsafe { ResolutionOwner::handler(context) };
                assert!(context.data.is_null());
                assert_eq!(globals.done_count(), 1);
                assert!(matches!(
                    poll_resolution(resolution, Waker::noop()),
                    Poll::Ready(Err(Error::Canceled))
                ));
            },
        );
    }

    #[test]
    fn dropping_ready_resolution_does_not_complete_twice() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |_| {},
            |resolution, context| {
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);

                let ready = mem::replace(resolution, canceled_resolution());
                drop(ready);
                assert_eq!(globals.done_count(), 1);

                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
            },
        );
    }

    #[test]
    fn pool_cleanup_cancels_pending_resolution_once() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |_| {},
            |resolution, context| {
                let wakes = Arc::new(AtomicUsize::new(0));
                let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));
                assert!(matches!(poll_resolution(resolution, &waker), Poll::Pending));

                owner.destroy();
                assert!(context.data.is_null());
                assert_eq!(wakes.load(Ordering::Relaxed), 1);
                assert_eq!(globals.done_count(), 1);

                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
                assert!(matches!(
                    poll_resolution(resolution, &waker),
                    Poll::Ready(Err(Error::Canceled))
                ));
            },
        );
    }

    #[test]
    fn pool_cleanup_waker_can_drop_the_resolution_reentrantly() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |_| {},
            |resolution, context| {
                let cancel_waker = Arc::new(CancelWaker {
                    resolution: AtomicPtr::new(core::ptr::from_mut(resolution).cast()),
                });
                let waker = Waker::from(Arc::clone(&cancel_waker));
                assert!(matches!(poll_resolution(resolution, &waker), Poll::Pending));

                owner.destroy();
                assert!(cancel_waker.resolution.load(Ordering::Relaxed).is_null());
                assert!(context.data.is_null());
                assert_eq!(globals.done_count(), 1);
                assert!(matches!(
                    poll_resolution(resolution, Waker::noop()),
                    Poll::Ready(Err(Error::Canceled))
                ));
            },
        );
    }

    #[test]
    fn pool_cleanup_discards_ready_result_without_second_done() {
        let globals = ResolverGlobals::new();
        let owner = TestPool::new();
        let pool = owner.handle();

        pending_resolution(
            &pool,
            |_| {},
            |resolution, context| {
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);

                owner.destroy();
                assert!(matches!(
                    poll_resolution(resolution, Waker::noop()),
                    Poll::Ready(Err(Error::Canceled))
                ));
                unsafe { ResolutionOwner::handler(context) };
                assert_eq!(globals.done_count(), 1);
            },
        );
    }
}
