//! Owned nginx posted events.

use core::marker::{PhantomData, PhantomPinned};
use core::mem;
use core::pin::Pin;
use core::ptr;

use crate::allocator::AllocError;
use crate::core::{Pool, PoolValue};
use crate::ffi::{
    ngx_delete_posted_event, ngx_event_t, ngx_post_event, ngx_posted_events, ngx_posted_next_events,
};
use crate::log::LogRef;
use crate::ngx_container_of;

use super::{EventRef, PostedQueue};

static POSTED_EVENT_IDENT: [usize; 1] = [0];

/// Failure returned while posting a [`PostedEvent`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostedEventError {
    /// The event has been shut down and cannot be posted again.
    Shutdown,
}

/// Pinned owner of an nginx posted event and its callback state.
///
/// ```compile_fail
/// use ngx::event::{PostedEvent, PostedQueue};
/// use ngx::log::LogRef;
///
/// fn cannot_post_from_safe_code(log: LogRef<'_>) {
///     let mut event = Box::pin(PostedEvent::new(log, (), |_| {}));
///     event.as_mut().post(PostedQueue::Normal).unwrap();
/// }
/// ```
///
/// A posted event must be pinned before it can be posted, canceled, or shut down. Rust-owned
/// events are canceled by [`Drop`]; use [`allocate_in_pool`](Self::allocate_in_pool) for a
/// pool-owned event so its cleanup is registered before it can be posted.
///
/// ```compile_fail
/// use core::pin::Pin;
/// use ngx::event::{PostedEvent, PostedQueue};
/// use ngx::log::LogRef;
///
/// fn cannot_move_after_post(log: LogRef<'_>) {
///     let mut event = Box::pin(PostedEvent::new(log, (), |_| {}));
///     event.as_mut().post(PostedQueue::Normal).unwrap();
///     let _event = Pin::into_inner(event);
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::PostedEvent;
/// use ngx::log::LogRef;
///
/// fn cannot_retain_callback_state(log: LogRef<'_>) {
///     let mut escaped: Option<&mut u8> = None;
///     let _event = PostedEvent::new(log, 0_u8, |mut event| {
///         escaped = Some(event.state_mut());
///     });
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::PostedEvent;
/// use ngx::log::LogRef;
///
/// fn cannot_move_to_another_thread(log: LogRef<'_>) {
///     let event = PostedEvent::new(log, (), |_| {});
///     std::thread::spawn(move || drop(event));
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::{PostedEvent, PostedEventCallback};
/// use ngx::log::LogRef;
///
/// type Callback = for<'callback> fn(PostedEventCallback<'callback, ()>);
///
/// fn callback(_: PostedEventCallback<'_, ()>) {}
///
/// fn cannot_outlive_logger<'log>(
///     log: LogRef<'log>,
/// ) -> PostedEvent<'static, (), Callback> {
///     PostedEvent::new(log, (), callback as Callback)
/// }
/// ```
pub struct PostedEvent<'log, T, F> {
    event: ngx_event_t,
    state: mem::ManuallyDrop<T>,
    callback: mem::ManuallyDrop<F>,
    stopped: bool,
    callback_alive: *mut bool,
    _log: PhantomData<LogRef<'log>>,
    _pin: PhantomPinned,
    _not_thread_safe: PhantomData<*mut ()>,
}

/// Callback-scoped access to a posted event's state and queue controls.
///
/// A value is created for each posted-event callback and cannot safely outlive that callback.
pub struct PostedEventCallback<'callback, T> {
    control: &'callback mut PostedEventCallbackControl,
    state: &'callback mut T,
}

struct PostedEventCallbackControl {
    posted: bool,
    stopped: bool,
    action: PostedEventCallbackAction,
}

enum PostedEventCallbackAction {
    None,
    Cancel,
    Post(PostedQueue),
}

impl<'log, T, F> PostedEvent<'log, T, F>
where
    F: for<'callback> FnMut(PostedEventCallback<'callback, T>),
{
    /// Creates an event that has not been posted or shut down.
    ///
    /// The returned event must be pinned before calling [`post`](Self::post),
    /// [`cancel`](Self::cancel), or [`shutdown`](Self::shutdown).
    pub fn new(log: LogRef<'log>, state: T, callback: F) -> Self {
        let mut event = unsafe { mem::zeroed::<ngx_event_t>() };
        event.data = (&raw const POSTED_EVENT_IDENT).cast_mut().cast();
        event.handler = Some(posted_event_handler::<T, F>);
        event.log = log.as_ptr();

        Self {
            event,
            state: mem::ManuallyDrop::new(state),
            callback: mem::ManuallyDrop::new(callback),
            stopped: false,
            callback_alive: ptr::null_mut(),
            _log: PhantomData,
            _pin: PhantomPinned,
            _not_thread_safe: PhantomData,
        }
    }

    /// Returns the event state outside a callback without mutable access.
    pub fn state(&self) -> &T {
        &self.state
    }

    /// Returns whether nginx has this event on a posted-event queue.
    pub fn is_posted(&self) -> bool {
        self.event.posted() != 0
    }

    /// Returns whether this event has been shut down permanently.
    pub fn is_shutdown(&self) -> bool {
        self.stopped
    }

    /// Posts this event to the selected nginx queue.
    ///
    /// Returns `Ok(false)` when nginx has already queued the event. Foreign threads must use
    /// [`notify`] instead.
    ///
    /// # Safety
    ///
    /// This must run on the initialized nginx event-loop thread that owns the posted queues.
    pub unsafe fn post(
        mut self: Pin<&mut Self>,
        queue: PostedQueue,
    ) -> Result<bool, PostedEventError> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        post_owned_event(&mut this.event, this.stopped, queue)
    }

    /// Removes this event from its posted queue when it is queued.
    ///
    /// Returns whether a queue entry was removed. Repeated cancellation is harmless.
    pub fn cancel(mut self: Pin<&mut Self>) -> bool {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        cancel_owned_event(&mut this.event)
    }

    /// Permanently stops this event and cancels a pending queue entry.
    ///
    /// Returns whether a queue entry was removed. Repeated shutdown is harmless.
    pub fn shutdown(mut self: Pin<&mut Self>) -> bool {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        this.stopped = true;
        cancel_owned_event(&mut this.event)
    }
}

impl<T, F> PostedEvent<'static, T, F>
where
    T: 'static,
    F: for<'callback> FnMut(PostedEventCallback<'callback, T>) + 'static,
{
    /// Allocates a pinned posted event in an nginx pool and registers its destructor first.
    ///
    /// The returned [`PoolValue`] retains the stable address and pool cleanup. Its event is posted
    /// through [`PoolValue::as_pin_mut`].
    ///
    /// # Safety
    ///
    /// `log` must remain live and usable on its owning event-loop thread until the pool destroys
    /// this event or [`PoolValue::remove`] removes it.
    pub unsafe fn allocate_in_pool<'pool>(
        pool: &Pool<'pool>,
        log: LogRef<'_>,
        state: T,
        callback: F,
    ) -> Result<PoolValue<'pool, Self>, AllocError> {
        let log = unsafe { LogRef::from_raw(log.as_ptr()) }.expect("validated event logger");
        pool.allocate_with_cleanup(|| Self::new(log, state, callback))
    }
}

impl<T> PostedEventCallback<'_, T> {
    /// Returns the callback-scoped event state.
    pub fn state(&self) -> &T {
        self.state
    }

    /// Returns mutable event state for this callback only.
    pub fn state_mut(&mut self) -> &mut T {
        self.state
    }

    /// Returns whether nginx has this event on a posted-event queue.
    pub fn is_posted(&self) -> bool {
        self.control.posted
    }

    /// Returns whether this event has been shut down permanently.
    pub fn is_shutdown(&self) -> bool {
        self.control.stopped
    }

    /// Posts this event to the selected nginx queue.
    ///
    /// Returns `Ok(false)` when nginx has already queued the event.
    pub fn post(&mut self, queue: PostedQueue) -> Result<bool, PostedEventError> {
        if self.control.stopped {
            return Err(PostedEventError::Shutdown);
        }
        if self.control.posted {
            return Ok(false);
        }

        self.control.posted = true;
        self.control.action = PostedEventCallbackAction::Post(queue);
        Ok(true)
    }

    /// Removes this event from its posted queue when it is queued.
    ///
    /// Returns whether a queue entry was removed. Repeated cancellation is harmless.
    pub fn cancel(&mut self) -> bool {
        if !self.control.posted {
            return false;
        }

        self.control.posted = false;
        self.control.action = PostedEventCallbackAction::Cancel;
        true
    }

    /// Permanently stops this event and cancels a pending queue entry.
    ///
    /// Returns whether a queue entry was removed. Repeated shutdown is harmless.
    pub fn shutdown(&mut self) -> bool {
        self.control.stopped = true;
        self.cancel()
    }
}

fn post_owned_event(
    event: &mut ngx_event_t,
    stopped: bool,
    queue: PostedQueue,
) -> Result<bool, PostedEventError> {
    if stopped {
        return Err(PostedEventError::Shutdown);
    }
    if event.posted() != 0 {
        return Ok(false);
    }

    unsafe {
        let queue = match queue {
            PostedQueue::Normal => &raw mut ngx_posted_events,
            PostedQueue::Next => &raw mut ngx_posted_next_events,
        };
        ngx_post_event(event, queue);
    }
    Ok(true)
}

fn cancel_owned_event(event: &mut ngx_event_t) -> bool {
    if event.posted() == 0 {
        return false;
    }

    unsafe { ngx_delete_posted_event(event) };
    true
}

unsafe extern "C" fn posted_event_handler<T, F>(raw: *mut ngx_event_t)
where
    F: for<'callback> FnMut(PostedEventCallback<'callback, T>),
{
    let Ok(event) = (unsafe { EventRef::from_raw(raw) }) else {
        return;
    };
    let posted = ngx_container_of!(event.as_ptr(), PostedEvent<'_, T, F>, event);
    let mut control = PostedEventCallbackControl {
        posted: event.is_posted(),
        stopped: unsafe { (*posted).stopped },
        action: PostedEventCallbackAction::None,
    };

    // Keep callback-owned values outside the allocation so reentrant Drop cannot invalidate them.
    let mut alive = true;
    unsafe { (*posted).callback_alive = &raw mut alive };
    let mut callback = unsafe { ptr::read(&raw const (*posted).callback) };
    let mut state = unsafe { ptr::read(&raw const (*posted).state) };

    (*callback)(PostedEventCallback { control: &mut control, state: &mut state });

    if !alive {
        unsafe {
            mem::ManuallyDrop::drop(&mut state);
            mem::ManuallyDrop::drop(&mut callback);
        }
        return;
    }

    let posted = unsafe { &mut *posted };
    posted.callback_alive = ptr::null_mut();
    unsafe {
        ptr::write(&raw mut posted.callback, callback);
        ptr::write(&raw mut posted.state, state);
    }
    posted.stopped = control.stopped;
    match control.action {
        PostedEventCallbackAction::None => {}
        PostedEventCallbackAction::Cancel => {
            cancel_owned_event(&mut posted.event);
        }
        PostedEventCallbackAction::Post(queue) => {
            let _ = post_owned_event(&mut posted.event, posted.stopped, queue);
        }
    }
}

impl<T, F> Drop for PostedEvent<'_, T, F> {
    fn drop(&mut self) {
        if !self.callback_alive.is_null() {
            // The active handler owns the moved state and callback until it returns.
            unsafe { *self.callback_alive = false };
            cancel_owned_event(&mut self.event);
            return;
        }

        cancel_owned_event(&mut self.event);
        unsafe {
            mem::ManuallyDrop::drop(&mut self.state);
            mem::ManuallyDrop::drop(&mut self.callback);
        }
    }
}
