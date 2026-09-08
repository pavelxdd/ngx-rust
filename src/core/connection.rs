mod address;
mod proxy_protocol;

pub use address::*;
pub use proxy_protocol::*;

use core::ffi::c_int;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::core::{
    BufferError, BufferMut, BufferRef, ChainError, ChainMut, Pool, PoolBuffer, Status,
};
use crate::event::{EventError, EventRef};
use crate::ffi::{
    NGX_AGAIN, NGX_ERROR, ngx_buf_t, ngx_chain_t, ngx_connection_local_sockaddr, ngx_connection_t,
    ngx_listening_t, off_t,
};
use crate::log::LogRef;

use proxy_protocol::connection_proxy_protocol;

/// Failure returned while validating a native nginx connection view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionError {
    /// The connection pointer is null.
    NullConnection,
    /// The connection pointer does not satisfy `ngx_connection_t` alignment.
    MisalignedConnection,
    /// The connection has no memory pool.
    MissingPool,
    /// The connection pool pointer does not satisfy `ngx_pool_t` alignment.
    MisalignedPool,
    /// The connection has no listening socket.
    MissingListener,
    /// The listening socket pointer does not satisfy `ngx_listening_t` alignment.
    MisalignedListener,
    /// The connection logger pointer does not satisfy `ngx_log_t` alignment.
    MisalignedLog,
    /// The connection sent-byte counter cannot be represented as an unsigned value.
    NegativeBytesSent,
    /// The connection or listener has an unsupported socket type.
    UnsupportedSocketType(c_int),
    /// A socket address is invalid.
    Address(SocketAddressError),
    /// A buffer is invalid.
    Buffer(BufferError),
    /// An event pointer is invalid.
    Event(EventError),
    /// A replacement buffer belongs to a different nginx pool.
    ForeignPool,
}

/// Result of one native connection receive operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionReadResult {
    /// The connection received this many bytes.
    Data(usize),
    /// The connection reached end of file.
    EndOfFile,
    /// The native connection would block before receiving data.
    Again,
}

/// Result of one native connection send operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionWriteResult {
    /// The connection sent this many bytes.
    Written(usize),
    /// The native connection would block before sending data.
    Again,
}

/// Result of one native chain send operation.
#[derive(Debug)]
pub enum ConnectionChainWriteResult<'chain> {
    /// Nginx consumed the complete input chain.
    Complete,
    /// Nginx left this tail unsent for a later writable event.
    Pending(ChainMut<'chain>),
}

impl ConnectionChainWriteResult<'_> {
    /// Transfers the nullable unsent native chain head to its pool-owning caller.
    pub fn into_raw(self) -> *mut ngx_chain_t {
        match self {
            Self::Complete => ptr::null_mut(),
            Self::Pending(chain) => chain.as_ptr(),
        }
    }
}

/// Failure returned by one native chain send operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionChainWriteError {
    /// The byte limit is negative.
    InvalidLimit,
    /// The connection has no chain-send callback.
    MissingSendChain,
    /// Nginx returned its chain error sentinel.
    SendChainFailed,
    /// Nginx returned a tail that does not belong to the input chain.
    UnexpectedTail,
    /// Nginx returned an invalid unsent chain tail.
    Chain(ChainError),
}

/// Failure returned by one native connection I/O operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionIoError {
    /// The connection has no receive callback.
    MissingReceive,
    /// The connection has no send callback.
    MissingSend,
    /// The native receive callback failed.
    ReceiveFailed,
    /// The native send callback failed.
    SendFailed,
    /// The native receive callback reported more bytes than fit in the supplied output.
    ReceiveTooLarge,
    /// The native send callback reported more bytes than the supplied input.
    SendTooLarge,
}

impl From<BufferError> for ConnectionError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

impl From<ChainError> for ConnectionChainWriteError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<EventError> for ConnectionError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

/// A configured socket type supported by nginx connection APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketType {
    /// A byte-stream socket.
    Stream,
    /// A datagram socket.
    Datagram,
}

impl SocketType {
    /// Parses an nginx native socket type.
    pub fn from_raw(raw: c_int) -> Result<Self, ConnectionError> {
        socket_type(raw)
    }
}

/// Shared callback-scoped access to an nginx connection.
///
/// ```compile_fail
/// use ngx::core::ConnectionRef;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *const ngx_connection_t) {
///     let _ = unsafe { ConnectionRef::with_raw(raw, |connection| require_send(connection)) };
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ConnectionRef;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_sync<T: Sync>(_: &T) {}
/// unsafe fn reject(raw: *const ngx_connection_t) {
///     let _ = unsafe { ConnectionRef::with_raw(raw, |connection| require_sync(&connection)) };
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionRef<'callback> {
    raw: NonNull<ngx_connection_t>,
    _callback: PhantomData<&'callback ngx_connection_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> ConnectionRef<'callback> {
    /// Creates a checked shared connection view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `connection` must point to a live initialized nginx connection for `'callback`. Its memory
    /// pool must not be reset before that pool is destroyed. Nginx must not mutably access the
    /// connection while this shared view exists, and the view must remain on its owning event-loop
    /// thread.
    pub unsafe fn from_raw(connection: *const ngx_connection_t) -> Result<Self, ConnectionError> {
        let raw = checked_connection_ptr(connection)?;
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with a shared view that cannot escape the nginx callback through a safe
    /// value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// use ngx::core::ConnectionRef;
    /// use ngx::ffi::ngx_connection_t;
    ///
    /// unsafe fn escape(raw: *const ngx_connection_t) -> ConnectionRef<'static> {
    ///     unsafe { ConnectionRef::with_raw(raw, |connection| connection) }.unwrap()
    /// }
    /// ```
    pub unsafe fn with_raw<R>(
        connection: *const ngx_connection_t,
        f: impl for<'scope> FnOnce(ConnectionRef<'scope>) -> R,
    ) -> Result<R, ConnectionError> {
        let connection = unsafe { Self::from_raw(connection) }?;
        Ok(f(connection))
    }

    /// Returns the wrapped native connection pointer for FFI interoperation.
    ///
    /// # Safety
    ///
    /// The caller must not use the pointer to create an aliasing mutable Rust view, outlive this
    /// callback, move access to another thread, or violate any ownership represented by this view.
    pub unsafe fn as_ptr(&self) -> *const ngx_connection_t {
        self.raw.as_ptr()
    }

    /// Returns the connection memory pool.
    pub fn pool(&self) -> Result<Pool<'callback>, ConnectionError> {
        connection_pool(self.raw)
    }

    /// Returns the connection logger when nginx configured one.
    ///
    /// ```compile_fail
    /// use ngx::core::ConnectionRef;
    /// use ngx::ffi::ngx_connection_t;
    /// use ngx::log::LogRef;
    ///
    /// unsafe fn escape(raw: *const ngx_connection_t) -> LogRef<'static> {
    ///     unsafe { ConnectionRef::with_raw(raw, |connection| connection.log().unwrap().unwrap()) }
    ///         .unwrap()
    /// }
    /// ```
    pub fn log(&self) -> Result<Option<LogRef<'callback>>, ConnectionError> {
        // SAFETY: this checked connection owner keeps its logger live for `'callback`.
        unsafe { connection_log(self.raw) }
    }

    /// Returns the client connection's sent-byte counter.
    pub fn bytes_sent(&self) -> Result<u64, ConnectionError> {
        u64::try_from(unsafe { self.raw.as_ref().sent })
            .map_err(|_| ConnectionError::NegativeBytesSent)
    }

    /// Returns the configured socket type.
    pub fn socket_type(&self) -> Result<SocketType, ConnectionError> {
        connection_socket_type(self.raw)
    }

    /// Returns the listener that accepted this connection.
    pub fn listener(&self) -> Result<ListenerRef<'callback>, ConnectionError> {
        connection_listener(self.raw)
    }

    /// Returns the checked peer address.
    pub fn peer_address(&self) -> Result<SocketAddress<'callback>, ConnectionError> {
        connection_peer_address(self.raw)
    }

    /// Returns the checked local address recorded by nginx.
    pub fn local_address(&self) -> Result<SocketAddress<'callback>, ConnectionError> {
        connection_local_address(self.raw)
    }

    /// Returns configured PROXY protocol metadata when nginx attached it.
    pub fn proxy_protocol(
        &self,
    ) -> Result<Option<ProxyProtocolRef<'callback>>, ProxyProtocolError> {
        connection_proxy_protocol(self.raw)
    }

    /// Returns the active input buffer when nginx has installed one.
    ///
    /// ```compile_fail
    /// use ngx::core::{BufferRef, ConnectionRef};
    /// use ngx::ffi::ngx_connection_t;
    ///
    /// unsafe fn escape(raw: *const ngx_connection_t) -> BufferRef<'static> {
    ///     unsafe { ConnectionRef::with_raw(raw, |connection| connection.buffer().unwrap().unwrap()) }
    ///         .unwrap()
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use ngx::core::ConnectionRef;
    /// use ngx::ffi::ngx_connection_t;
    ///
    /// fn require_send<T: Send>(_: T) {}
    /// unsafe fn reject(raw: *const ngx_connection_t) {
    ///     let _ = unsafe {
    ///         ConnectionRef::with_raw(raw, |connection| require_send(connection.buffer().unwrap().unwrap()))
    ///     };
    /// }
    /// ```
    pub fn buffer(&self) -> Result<Option<BufferRef<'callback>>, ConnectionError> {
        connection_buffer(self.raw)
    }
}

/// Exclusive callback-scoped access to an nginx connection.
///
/// ```compile_fail
/// use ngx::core::ConnectionRefMut;
/// use ngx::event::EventRef;
/// use ngx::ffi::ngx_connection_t;
///
/// unsafe fn escape(raw: *mut ngx_connection_t) -> EventRef<'static> {
///     unsafe { ConnectionRefMut::with_raw(raw, |mut connection| connection.read_event().unwrap()) }
///         .unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ConnectionRefMut;
/// use ngx::ffi::ngx_connection_t;
///
/// fn require_send<T: Send>(_: T) {}
/// unsafe fn reject(raw: *mut ngx_connection_t) {
///     let _ = unsafe {
///         ConnectionRefMut::with_raw(raw, |mut connection| require_send(connection.read_event().unwrap()))
///     };
/// }
/// ```
pub struct ConnectionRefMut<'callback> {
    raw: NonNull<ngx_connection_t>,
    _callback: PhantomData<&'callback mut ngx_connection_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> ConnectionRefMut<'callback> {
    /// Creates a checked exclusive connection view from an nginx callback pointer.
    ///
    /// # Safety
    ///
    /// `connection` must point to a live initialized nginx connection for `'callback`. Its memory
    /// pool must not be reset before that pool is destroyed. No other mutable or shared Rust view
    /// may exist for the same connection, and the view must remain on its owning event-loop thread.
    pub unsafe fn from_raw(connection: *mut ngx_connection_t) -> Result<Self, ConnectionError> {
        let raw = checked_connection_ptr(connection)?;
        Ok(Self { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Invokes a closure with an exclusive view that cannot escape the nginx callback through a
    /// safe value.
    ///
    /// # Safety
    ///
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    pub unsafe fn with_raw<R>(
        connection: *mut ngx_connection_t,
        f: impl for<'scope> FnOnce(ConnectionRefMut<'scope>) -> R,
    ) -> Result<R, ConnectionError> {
        let connection = unsafe { Self::from_raw(connection) }?;
        Ok(f(connection))
    }

    /// Returns the wrapped native connection pointer for FFI interoperation.
    ///
    /// # Safety
    ///
    /// The caller must not use the pointer to create an aliasing Rust view, outlive this callback,
    /// move access to another thread, or violate any ownership represented by this exclusive view.
    pub unsafe fn as_ptr(&mut self) -> *mut ngx_connection_t {
        self.raw.as_ptr()
    }

    /// Returns a shared reborrow of this connection.
    pub fn view(&self) -> ConnectionRef<'_> {
        ConnectionRef { raw: self.raw, _callback: PhantomData, _not_thread_safe: PhantomData }
    }

    /// Returns the connection memory pool.
    pub fn pool(&self) -> Result<Pool<'callback>, ConnectionError> {
        connection_pool(self.raw)
    }

    /// Returns the connection logger when nginx configured one.
    pub fn log(&self) -> Result<Option<LogRef<'callback>>, ConnectionError> {
        // SAFETY: this checked connection owner keeps its logger live for `'callback`.
        unsafe { connection_log(self.raw) }
    }

    /// Returns the client connection's sent-byte counter.
    pub fn bytes_sent(&self) -> Result<u64, ConnectionError> {
        self.view().bytes_sent()
    }

    /// Receives bytes through nginx's configured connection callback.
    ///
    /// A zero return is end-of-file for streams and an empty message for datagrams.
    pub fn receive(
        &mut self,
        output: &mut [u8],
    ) -> Result<ConnectionReadResult, ConnectionIoError> {
        if output.is_empty() {
            return Ok(ConnectionReadResult::Data(0));
        }

        let receive = unsafe { self.raw.as_ref().recv }.ok_or(ConnectionIoError::MissingReceive)?;
        let result = unsafe { receive(self.raw.as_ptr(), output.as_mut_ptr(), output.len()) };
        if result > 0 {
            let received = result as usize;
            return (received <= output.len())
                .then_some(ConnectionReadResult::Data(received))
                .ok_or(ConnectionIoError::ReceiveTooLarge);
        }
        if result == 0 {
            return Ok(if unsafe { self.raw.as_ref().type_ } == libc::SOCK_DGRAM {
                ConnectionReadResult::Data(0)
            } else {
                ConnectionReadResult::EndOfFile
            });
        }
        if result == NGX_AGAIN as _ {
            return Ok(ConnectionReadResult::Again);
        }

        Err(ConnectionIoError::ReceiveFailed)
    }

    /// Sends bytes through nginx's configured connection callback.
    ///
    /// Empty streams complete locally, while empty datagrams reach the native callback.
    pub fn send(&mut self, input: &[u8]) -> Result<ConnectionWriteResult, ConnectionIoError> {
        if input.is_empty() && unsafe { self.raw.as_ref().type_ } != libc::SOCK_DGRAM {
            return Ok(ConnectionWriteResult::Written(0));
        }

        let send = unsafe { self.raw.as_ref().send }.ok_or(ConnectionIoError::MissingSend)?;
        let result = unsafe { send(self.raw.as_ptr(), input.as_ptr().cast_mut(), input.len()) };
        if result >= 0 {
            let written = result as usize;
            return (written <= input.len())
                .then_some(ConnectionWriteResult::Written(written))
                .ok_or(ConnectionIoError::SendTooLarge);
        }
        if result == NGX_AGAIN as _ {
            return Ok(ConnectionWriteResult::Again);
        }

        Err(ConnectionIoError::SendFailed)
    }

    /// Sends a chain through nginx and returns the unconsumed tail, if any.
    ///
    /// Nginx may advance the chain's buffer cursors, so the input is exclusive. A zero limit is
    /// unlimited; negative limits are rejected before invoking nginx.
    ///
    /// # Safety
    /// Every chain link, buffer descriptor, and selected memory or file resource must remain valid
    /// and exclusively owned until nginx completes or cancels any asynchronous send started by
    /// this call. Dropping a pending result does not cancel native sendfile work.
    pub unsafe fn send_chain<'chain>(
        &mut self,
        input: ChainMut<'chain>,
        limit: off_t,
    ) -> Result<ConnectionChainWriteResult<'chain>, ConnectionChainWriteError> {
        if limit < 0 {
            return Err(ConnectionChainWriteError::InvalidLimit);
        }

        let send_chain = unsafe { self.raw.as_ref().send_chain }
            .ok_or(ConnectionChainWriteError::MissingSendChain)?;
        let tail = unsafe { send_chain(self.raw.as_ptr(), input.as_ptr(), limit) };
        if tail == ptr::without_provenance_mut(NGX_ERROR as usize) {
            return Err(ConnectionChainWriteError::SendChainFailed);
        }
        if tail.is_null() {
            return Ok(ConnectionChainWriteResult::Complete);
        }
        if !input.contains_link(tail) {
            return Err(ConnectionChainWriteError::UnexpectedTail);
        }

        let tail = unsafe { ChainMut::from_raw(tail) }?;
        Ok(ConnectionChainWriteResult::Pending(tail))
    }

    /// Returns the configured socket type.
    pub fn socket_type(&self) -> Result<SocketType, ConnectionError> {
        connection_socket_type(self.raw)
    }

    /// Returns the listener that accepted this connection.
    pub fn listener(&self) -> Result<ListenerRef<'_>, ConnectionError> {
        connection_listener(self.raw)
    }

    /// Returns the checked peer address.
    pub fn peer_address(&self) -> Result<SocketAddress<'_>, ConnectionError> {
        connection_peer_address(self.raw)
    }

    /// Returns the checked local address recorded by nginx.
    pub fn local_address(&self) -> Result<SocketAddress<'_>, ConnectionError> {
        connection_local_address(self.raw)
    }

    /// Populates the local address through nginx when it was not resolved at accept time.
    ///
    /// Nginx may allocate the refreshed address from this connection's pool.
    pub fn refresh_local_address(&mut self) -> Result<(), Status> {
        Status(unsafe { ngx_connection_local_sockaddr(self.raw.as_ptr(), ptr::null_mut(), 0) })
            .into_result()
    }

    /// Returns configured PROXY protocol metadata when nginx attached it.
    pub fn proxy_protocol(&self) -> Result<Option<ProxyProtocolRef<'_>>, ProxyProtocolError> {
        connection_proxy_protocol(self.raw)
    }

    /// Returns the active input buffer when nginx has installed one.
    pub fn buffer(&self) -> Result<Option<BufferRef<'_>>, ConnectionError> {
        connection_buffer(self.raw)
    }

    /// Returns exclusive access to the active input buffer when nginx has installed one.
    pub fn buffer_mut(&mut self) -> Result<Option<BufferMut<'_>>, ConnectionError> {
        let buffer = unsafe { self.raw.as_ref().buffer };
        if buffer.is_null() {
            return Ok(None);
        }
        unsafe { BufferMut::from_raw(buffer) }.map(Some).map_err(ConnectionError::Buffer)
    }

    /// Permanently installs a descriptor owned by this connection's pool.
    pub fn replace_buffer(&mut self, buffer: PoolBuffer<'callback>) -> Result<(), ConnectionError> {
        if !ptr::eq(self.pool()?.as_ptr(), buffer.pool_ptr()) {
            return Err(ConnectionError::ForeignPool);
        }
        unsafe { self.raw.as_mut().buffer = buffer.into_non_null().as_ptr() };
        Ok(())
    }

    /// Copies validated metadata into this connection's pool and attaches it atomically.
    pub fn attach_proxy_protocol(
        &mut self,
        metadata: ProxyProtocolBuilder<'_>,
    ) -> Result<(), ProxyProtocolError> {
        metadata.attach(self)
    }

    /// Temporarily installs a caller-owned synchronous buffer descriptor.
    pub fn swap_buffer<'connection, 'scratch>(
        &'connection mut self,
        scratch: &'scratch mut ngx_buf_t,
    ) -> Result<BufferSwap<'connection, 'callback, 'scratch>, ConnectionError> {
        let scratch = NonNull::from(scratch);
        let scratch_view =
            unsafe { BufferMut::from_raw(scratch.as_ptr()) }.map_err(ConnectionError::Buffer)?;
        scratch_view.view().kind().map_err(ConnectionError::Buffer)?;
        scratch_view.view().has_space().map_err(ConnectionError::Buffer)?;
        let original = unsafe { self.raw.as_ref().buffer };
        unsafe { self.raw.as_mut().buffer = scratch.as_ptr() };
        Ok(BufferSwap { connection: self, original, scratch, _scratch: PhantomData })
    }

    /// Returns exclusive access to the connection read event.
    pub fn read_event(&mut self) -> Result<EventRef<'_>, ConnectionError> {
        unsafe { EventRef::from_raw(self.raw.as_ref().read) }.map_err(ConnectionError::Event)
    }

    /// Returns exclusive access to the connection write event.
    pub fn write_event(&mut self) -> Result<EventRef<'_>, ConnectionError> {
        unsafe { EventRef::from_raw(self.raw.as_ref().write) }.map_err(ConnectionError::Event)
    }
}

/// A synchronous buffer-pointer swap that restores the original connection state on drop.
pub struct BufferSwap<'connection, 'callback, 'scratch> {
    connection: &'connection mut ConnectionRefMut<'callback>,
    original: *mut ngx_buf_t,
    scratch: NonNull<ngx_buf_t>,
    _scratch: PhantomData<&'scratch mut ngx_buf_t>,
}

impl<'callback> BufferSwap<'_, 'callback, '_> {
    /// Returns the temporary buffer as a checked shared view.
    pub fn buffer(&self) -> Result<BufferRef<'_>, ConnectionError> {
        unsafe { BufferRef::from_raw(self.scratch.as_ptr()) }.map_err(ConnectionError::Buffer)
    }

    /// Returns the temporary buffer as a checked exclusive view.
    pub fn buffer_mut(&mut self) -> Result<BufferMut<'_>, ConnectionError> {
        unsafe { BufferMut::from_raw(self.scratch.as_ptr()) }.map_err(ConnectionError::Buffer)
    }

    /// Replaces the buffer visible through the connection until this swap ends.
    pub fn replace_buffer(&mut self, buffer: PoolBuffer<'callback>) -> Result<(), ConnectionError> {
        self.connection.replace_buffer(buffer)
    }

    /// Copies the currently installed descriptor into the caller-owned scratch descriptor.
    ///
    /// Call this before the guard ends when an nginx callback must publish its final buffer range
    /// through the caller's synchronous scratch descriptor.
    pub fn copy_current_to_scratch(&mut self) -> Result<(), ConnectionError> {
        let current = unsafe { self.connection.raw.as_ref().buffer };
        let current = unsafe { BufferRef::from_raw(current) }.map_err(ConnectionError::Buffer)?;
        current.kind().map_err(ConnectionError::Buffer)?;
        current.has_space().map_err(ConnectionError::Buffer)?;
        unsafe { ptr::copy(current.as_ptr(), self.scratch.as_ptr(), 1) };
        Ok(())
    }
}

impl Drop for BufferSwap<'_, '_, '_> {
    fn drop(&mut self) {
        unsafe { self.connection.raw.as_mut().buffer = self.original };
    }
}

/// Callback-scoped access to an nginx listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerRef<'callback> {
    raw: NonNull<ngx_listening_t>,
    _callback: PhantomData<&'callback ngx_listening_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'callback> ListenerRef<'callback> {
    /// Returns the configured listener socket type.
    pub fn socket_type(&self) -> Result<SocketType, ConnectionError> {
        socket_type(unsafe { self.raw.as_ref().type_ })
    }

    /// Returns the checked listener address.
    pub fn address(&self) -> Result<SocketAddress<'callback>, ConnectionError> {
        let listener = unsafe { self.raw.as_ref() };
        unsafe { parse_socket_address(listener.sockaddr, listener.socklen) }
            .map_err(ConnectionError::Address)
    }
}

fn checked_connection_ptr(
    connection: *const ngx_connection_t,
) -> Result<NonNull<ngx_connection_t>, ConnectionError> {
    let raw = NonNull::new(connection.cast_mut()).ok_or(ConnectionError::NullConnection)?;
    if !connection.is_aligned() {
        return Err(ConnectionError::MisalignedConnection);
    }
    Ok(raw)
}

fn connection_pool<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<Pool<'callback>, ConnectionError> {
    let pool = unsafe { connection.as_ref().pool };
    if pool.is_null() {
        return Err(ConnectionError::MissingPool);
    }
    if !pool.is_aligned() {
        return Err(ConnectionError::MisalignedPool);
    }
    unsafe { Pool::from_raw(pool) }.ok_or(ConnectionError::MisalignedPool)
}

// SAFETY: the connection logger must remain live for `'log`.
unsafe fn connection_log<'log>(
    connection: NonNull<ngx_connection_t>,
) -> Result<Option<LogRef<'log>>, ConnectionError> {
    let log = unsafe { connection.as_ref().log };
    if log.is_null() {
        return Ok(None);
    }
    unsafe { LogRef::from_raw(log) }.map(Some).ok_or(ConnectionError::MisalignedLog)
}

fn connection_socket_type(
    connection: NonNull<ngx_connection_t>,
) -> Result<SocketType, ConnectionError> {
    socket_type(unsafe { connection.as_ref().type_ })
}

fn connection_listener<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<ListenerRef<'callback>, ConnectionError> {
    let listener = unsafe { connection.as_ref().listening };
    let raw = NonNull::new(listener).ok_or(ConnectionError::MissingListener)?;
    if !listener.is_aligned() {
        return Err(ConnectionError::MisalignedListener);
    }
    Ok(ListenerRef { raw, _callback: PhantomData, _not_thread_safe: PhantomData })
}

fn connection_peer_address<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<SocketAddress<'callback>, ConnectionError> {
    let connection = unsafe { connection.as_ref() };
    unsafe { parse_socket_address(connection.sockaddr, connection.socklen) }
        .map_err(ConnectionError::Address)
}

fn connection_local_address<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<SocketAddress<'callback>, ConnectionError> {
    let connection = unsafe { connection.as_ref() };
    unsafe { parse_socket_address(connection.local_sockaddr, connection.local_socklen) }
        .map_err(ConnectionError::Address)
}

fn connection_buffer<'callback>(
    connection: NonNull<ngx_connection_t>,
) -> Result<Option<BufferRef<'callback>>, ConnectionError> {
    let buffer = unsafe { connection.as_ref().buffer };
    if buffer.is_null() {
        return Ok(None);
    }
    unsafe { BufferRef::from_raw(buffer) }.map(Some).map_err(ConnectionError::Buffer)
}

fn socket_type(raw: c_int) -> Result<SocketType, ConnectionError> {
    match raw {
        libc::SOCK_STREAM => Ok(SocketType::Stream),
        libc::SOCK_DGRAM => Ok(SocketType::Datagram),
        _ => Err(ConnectionError::UnsupportedSocketType(raw)),
    }
}

#[cfg(test)]
#[path = "connection/tests.rs"]
mod tests;
