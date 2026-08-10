use core::cell::{Cell, RefCell};
use core::error;
use core::fmt;
use core::future::Future;
use core::marker::{PhantomData, PhantomPinned};
use core::mem;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use crate::event::{
    EventPeerConnection, EventPeerConnectionError, EventPeerConnectionState, Timer, TimerCallback,
};
use crate::ffi::{
    NGX_OK, ngx_connection_t, ngx_event_handler_pt, ngx_event_t, ngx_handle_read_event,
    ngx_handle_write_event, ngx_msec_int_t, ngx_msec_t,
};

const MILLISECONDS_PER_SECOND: u128 = 1_000;
const NANOSECONDS_PER_MILLISECOND: u32 = 1_000_000;
const TIMER_DURATION_MAX_MILLISECONDS: u128 = ngx_msec_int_t::MAX as u128;

std::thread_local! {
    static EVENT_WAITERS: Cell<*mut ReadinessState> = const { Cell::new(ptr::null_mut()) };
}

fn duration_to_milliseconds_ceil(duration: Duration) -> u128 {
    let milliseconds = u128::from(duration.as_secs()) * MILLISECONDS_PER_SECOND
        + u128::from(duration.subsec_millis());

    if duration.subsec_nanos() % NANOSECONDS_PER_MILLISECOND == 0 {
        milliseconds
    } else {
        milliseconds + 1
    }
}

fn timeout_step(remaining: u128) -> Option<(u128, ngx_msec_t)> {
    let milliseconds = (remaining != 0).then(|| remaining.min(TIMER_DURATION_MAX_MILLISECONDS))?;
    let timeout =
        ngx_msec_t::try_from(milliseconds).expect("signed nginx timer bound must fit ngx_msec_t");

    Some((milliseconds, timeout))
}

/// Readiness delivered by an [`EventReadiness`] future.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    /// The peer read event is ready.
    Read,
    /// The peer write event is ready.
    Write,
    /// A pending nonblocking peer connection completed successfully.
    Connect,
}

/// Failure while waiting for peer readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessError {
    /// The optional timeout elapsed.
    Timeout,
    /// The peer reached end of file.
    EndOfFile,
    /// nginx reported a connection or selected event error.
    Connection,
    /// The selected event already has a timer owned by another handler.
    TimerActive,
    /// A second readiness owner attempted to wait for the same native event.
    AlreadyWaiting,
    /// nginx rejected native readiness registration.
    EventRegistration,
    /// The peer connection or connect completion operation failed.
    Peer(EventPeerConnectionError),
}

impl From<EventPeerConnectionError> for ReadinessError {
    fn from(error: EventPeerConnectionError) -> Self {
        Self::Peer(error)
    }
}

impl fmt::Display for ReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("event peer readiness timed out"),
            Self::EndOfFile => formatter.write_str("event peer reached end of file"),
            Self::Connection => formatter.write_str("event peer reported a connection error"),
            Self::TimerActive => {
                formatter.write_str("event peer readiness event already has an active timer")
            }
            Self::AlreadyWaiting => {
                formatter.write_str("event peer readiness event already has a waiter")
            }
            Self::EventRegistration => {
                formatter.write_str("nginx rejected event peer readiness registration")
            }
            Self::Peer(error) => write!(formatter, "event peer readiness failed: {error}"),
        }
    }
}

impl error::Error for ReadinessError {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WaitKind {
    Read,
    Write,
    Connect,
}

impl WaitKind {
    fn uses_write_event(self) -> bool {
        matches!(self, Self::Write | Self::Connect)
    }

    fn readiness(self) -> Readiness {
        match self {
            Self::Read => Readiness::Read,
            Self::Write => Readiness::Write,
            Self::Connect => Readiness::Connect,
        }
    }
}

struct WakerState {
    waker: RefCell<Option<Waker>>,
}

impl WakerState {
    fn new() -> Self {
        Self { waker: RefCell::new(None) }
    }

    fn replace(&self, waker: &Waker) {
        let mut current = self.waker.borrow_mut();
        match current.as_mut() {
            Some(current) => current.clone_from(waker),
            None => *current = Some(waker.clone()),
        }
    }

    fn wake(&self) {
        let waker = self.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn clear(&self) {
        self.waker.borrow_mut().take();
    }
}

struct ReadinessState {
    waker: WakerState,
    event: Cell<*mut ngx_event_t>,
    next: Cell<*mut ReadinessState>,
}

impl ReadinessState {
    fn new() -> Self {
        Self {
            waker: WakerState::new(),
            event: Cell::new(ptr::null_mut()),
            next: Cell::new(ptr::null_mut()),
        }
    }
}

struct ReadinessTimerState {
    waker: WakerState,
}

impl ReadinessTimerState {
    fn new() -> Self {
        Self { waker: WakerState::new() }
    }
}

type ReadinessTimerCallback = for<'callback> fn(TimerCallback<'callback, ReadinessTimerState>);

fn readiness_timer_callback(timer: TimerCallback<'_, ReadinessTimerState>) {
    timer.state().waker.wake();
}

fn register_waiter(event: NonNull<ngx_event_t>, state: NonNull<ReadinessState>) -> bool {
    EVENT_WAITERS.with(|head| {
        let mut current = head.get();
        while let Some(current_state) = NonNull::new(current) {
            let current_ref = unsafe { current_state.as_ref() };
            if ptr::eq(current_ref.event.get(), event.as_ptr()) {
                return false;
            }
            current = current_ref.next.get();
        }

        let state_ref = unsafe { state.as_ref() };
        state_ref.event.set(event.as_ptr());
        state_ref.next.set(head.get());
        head.set(state.as_ptr());
        true
    })
}

fn unregister_waiter(event: NonNull<ngx_event_t>, state: NonNull<ReadinessState>) {
    EVENT_WAITERS.with(|head| {
        let mut previous: *mut ReadinessState = ptr::null_mut();
        let mut current = head.get();

        while let Some(current_state) = NonNull::new(current) {
            let current_ref = unsafe { current_state.as_ref() };
            if current == state.as_ptr() {
                let next = current_ref.next.get();
                if previous.is_null() {
                    head.set(next);
                } else {
                    unsafe { (*previous).next.set(next) };
                }
                current_ref.event.set(ptr::null_mut());
                current_ref.next.set(ptr::null_mut());
                return;
            }

            previous = current;
            current = current_ref.next.get();
        }

        let state_ref = unsafe { state.as_ref() };
        if ptr::eq(state_ref.event.get(), event.as_ptr()) {
            state_ref.event.set(ptr::null_mut());
            state_ref.next.set(ptr::null_mut());
        }
    });
}

unsafe extern "C" fn readiness_handler(raw: *mut ngx_event_t) {
    let Some(event) = NonNull::new(raw) else {
        return;
    };

    let mut current = EVENT_WAITERS.with(Cell::get);
    while let Some(state) = NonNull::new(current) {
        let state_ref = unsafe { state.as_ref() };
        if ptr::eq(state_ref.event.get(), event.as_ptr()) {
            state_ref.waker.wake();
            return;
        }
        current = state_ref.next.get();
    }
}

fn same_handler(
    actual: ngx_event_handler_pt,
    expected: unsafe extern "C" fn(*mut ngx_event_t),
) -> bool {
    matches!(actual, Some(actual) if core::ptr::fn_addr_eq(actual, expected))
}

/// Future that exclusively waits for one read, write, or pending-connect event.
///
/// The future keeps a mutable borrow of its peer connection, so safe code cannot start another
/// read, write, connect, close, or keepalive transfer operation until it is completed or dropped.
/// It never performs socket I/O or closes the peer. Unsafe code that closes the native peer while
/// this future exists must first stop native callbacks and drop the future.
///
/// ```compile_fail
/// use ngx::event::EventPeerConnection;
///
/// fn reject(mut connection: EventPeerConnection<'_>) {
///     let read = connection.wait_read(None);
///     let write = connection.wait_write(None);
///     drop((read, write));
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::EventPeerConnection;
///
/// fn reject(mut connection: EventPeerConnection<'_>) {
///     let wait = connection.wait_read(None);
///     let keepalive = connection.into_keepalive();
///     drop((wait, keepalive));
/// }
/// ```
///
/// ```compile_fail
/// use ngx::event::EventPeerConnection;
///
/// fn require_send<T: Send>(_: T) {}
///
/// fn reject(mut connection: EventPeerConnection<'_>) {
///     require_send(connection.wait_read(None));
/// }
/// ```
#[must_use = "futures do nothing unless polled or awaited"]
pub struct EventReadiness<'connection, 'address> {
    connection: &'connection mut EventPeerConnection<'address>,
    kind: WaitKind,
    timeout_remaining: Option<u128>,
    timeout_armed: u128,
    timer: Timer<ReadinessTimerState, ReadinessTimerCallback>,
    event: Option<NonNull<ngx_event_t>>,
    saved_handler: Option<ngx_event_handler_pt>,
    state: ReadinessState,
    _pin: PhantomPinned,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'connection, 'address> EventReadiness<'connection, 'address> {
    fn new(
        connection: &'connection mut EventPeerConnection<'address>,
        kind: WaitKind,
        timeout: Option<Duration>,
    ) -> Self {
        let log = connection.readiness_log();
        Self {
            connection,
            kind,
            timeout_remaining: timeout.map(duration_to_milliseconds_ceil),
            timeout_armed: 0,
            timer: Timer::new(
                log,
                ReadinessTimerState::new(),
                readiness_timer_callback as ReadinessTimerCallback,
            ),
            event: None,
            saved_handler: None,
            state: ReadinessState::new(),
            _pin: PhantomPinned,
            _not_thread_safe: PhantomData,
        }
    }

    fn state_pointer(&mut self) -> NonNull<ReadinessState> {
        NonNull::from(&mut self.state)
    }

    fn timeout_result(&mut self) -> Option<ReadinessError> {
        let remaining = self.timeout_remaining.as_mut()?;
        if *remaining == 0 {
            return Some(ReadinessError::Timeout);
        }
        let mut timer = unsafe { Pin::new_unchecked(&mut self.timer) };
        if !timer.as_mut().take_timeout() {
            return None;
        }

        let armed = mem::take(&mut self.timeout_armed);
        *remaining = remaining
            .checked_sub(armed)
            .expect("readiness timer expiry must match the armed timeout step");
        (*remaining == 0).then_some(ReadinessError::Timeout)
    }

    fn event_result(
        &mut self,
        connection: NonNull<ngx_connection_t>,
        event: NonNull<ngx_event_t>,
    ) -> Option<Result<Readiness, ReadinessError>> {
        let ready = unsafe {
            let connection = connection.as_ref();
            let event = event.as_ref();
            if event.timedout() != 0 {
                return Some(Err(ReadinessError::Timeout));
            }
            if connection.error() != 0 || event.error() != 0 {
                return Some(Err(ReadinessError::Connection));
            }
            if event.eof() != 0 {
                return Some(Err(ReadinessError::EndOfFile));
            }
            event.ready() != 0
        };

        if self.kind == WaitKind::Connect
            && self.connection.state() != EventPeerConnectionState::Pending
        {
            return Some(Ok(Readiness::Connect));
        }

        if !ready {
            return None;
        }

        if self.kind == WaitKind::Connect
            && self.connection.state() == EventPeerConnectionState::Pending
        {
            return Some(
                self.connection.complete_connect().map(|()| Readiness::Connect).map_err(Into::into),
            );
        }

        Some(Ok(self.kind.readiness()))
    }

    fn install(&mut self, event: NonNull<ngx_event_t>) -> Result<(), ReadinessError> {
        if unsafe { event.as_ref().timer_set() != 0 } {
            return Err(ReadinessError::TimerActive);
        }

        let state = self.state_pointer();
        if !register_waiter(event, state) {
            return Err(ReadinessError::AlreadyWaiting);
        }

        let saved_handler = unsafe { event.as_ref().handler };
        unsafe { event.as_ptr().as_mut().unwrap().handler = Some(readiness_handler) };
        self.event = Some(event);
        self.saved_handler = Some(saved_handler);

        let status = unsafe {
            if self.kind.uses_write_event() {
                ngx_handle_write_event(event.as_ptr(), 0)
            } else {
                ngx_handle_read_event(event.as_ptr(), 0)
            }
        };
        if status == NGX_OK as _ { Ok(()) } else { Err(ReadinessError::EventRegistration) }
    }

    fn arm_timeout(&mut self) {
        let Some(remaining) = self.timeout_remaining else {
            return;
        };
        if self.timer.is_armed() {
            return;
        }

        let Some((milliseconds, timeout)) = timeout_step(remaining) else {
            return;
        };
        self.timeout_armed = milliseconds;
        let mut timer = unsafe { Pin::new_unchecked(&mut self.timer) };
        timer.as_mut().set_cancelable(true);
        timer.as_mut().arm(timeout).expect("readiness timer was checked unarmed before arming");
    }

    fn finish(&mut self) {
        let mut timer = unsafe { Pin::new_unchecked(&mut self.timer) };
        timer.as_mut().cancel();
        timer.as_ref().get_ref().state().waker.clear();
        self.state.waker.clear();

        let Some(event) = self.event.take() else {
            return;
        };

        let state = self.state_pointer();
        unregister_waiter(event, state);
        if same_handler(unsafe { event.as_ref().handler }, readiness_handler) {
            unsafe {
                event.as_ptr().as_mut().unwrap().handler = self.saved_handler.take().unwrap_or(None)
            };
        } else {
            self.saved_handler.take();
        }
    }
}

impl Future for EventReadiness<'_, '_> {
    type Output = Result<Readiness, ReadinessError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        let (connection, event) =
            match this.connection.readiness_parts(this.kind.uses_write_event()) {
                Ok(parts) => parts,
                Err(error) => {
                    this.finish();
                    return Poll::Ready(Err(error.into()));
                }
            };
        if let Some(result) = this.event_result(connection, event) {
            this.finish();
            return Poll::Ready(result);
        }

        if let Some(error) = this.timeout_result() {
            this.finish();
            return Poll::Ready(Err(error));
        }

        this.state.waker.replace(cx.waker());
        this.timer.state().waker.replace(cx.waker());
        if this.event.is_none() {
            if let Err(error) = this.install(event) {
                this.finish();
                return Poll::Ready(Err(error));
            }
        }

        if let Some(result) = this.event_result(connection, event) {
            this.finish();
            return Poll::Ready(result);
        }

        this.arm_timeout();
        Poll::Pending
    }
}

impl Drop for EventReadiness<'_, '_> {
    fn drop(&mut self) {
        self.finish();
    }
}

impl<'address> EventPeerConnection<'address> {
    /// Waits for the peer read event, optionally bounded by an nginx timer.
    pub fn wait_read(&mut self, timeout: Option<Duration>) -> EventReadiness<'_, 'address> {
        EventReadiness::new(self, WaitKind::Read, timeout)
    }

    /// Waits for the peer write event, optionally bounded by an nginx timer.
    pub fn wait_write(&mut self, timeout: Option<Duration>) -> EventReadiness<'_, 'address> {
        EventReadiness::new(self, WaitKind::Write, timeout)
    }

    /// Waits for a pending nonblocking peer connection and validates `SO_ERROR` on readiness.
    pub fn wait_connect(&mut self, timeout: Option<Duration>) -> EventReadiness<'_, 'address> {
        EventReadiness::new(self, WaitKind::Connect, timeout)
    }
}
