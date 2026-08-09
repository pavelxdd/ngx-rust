use core::alloc::Layout;
use core::error;
use core::ffi::CStr;
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};
use core::slice;

use crate::allocator::Allocator;
use crate::core::{
    NgxStr, Pool, SocketAddress, SocketAddressError, SocketPort, Status, parse_socket_address,
};
use crate::ffi::{ngx_addr_t, ngx_str_t, ngx_url_t};

/// Failure while parsing or viewing a configured upstream URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamUrlViewError {
    /// The parsed URL has a nonempty string with no backing bytes.
    MissingStringData,
    /// Nginx reported more addresses than can fit in the process address space.
    AddressCountOverflow,
    /// The parsed URL has addresses but no address array.
    MissingAddresses,
    /// The parsed address array does not satisfy `ngx_addr_t` alignment.
    MisalignedAddresses,
    /// A selected native socket address is invalid.
    SocketAddress(SocketAddressError),
}

impl fmt::Display for UpstreamUrlViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStringData => formatter.write_str("upstream URL string has no data"),
            Self::AddressCountOverflow => {
                formatter.write_str("upstream URL address count is too large")
            }
            Self::MissingAddresses => formatter.write_str("upstream URL has no address array"),
            Self::MisalignedAddresses => {
                formatter.write_str("upstream URL address array is misaligned")
            }
            Self::SocketAddress(_) => formatter.write_str("upstream URL has an invalid address"),
        }
    }
}

impl error::Error for UpstreamUrlViewError {}

impl From<SocketAddressError> for UpstreamUrlViewError {
    fn from(error: SocketAddressError) -> Self {
        Self::SocketAddress(error)
    }
}

/// Error text emitted by nginx while parsing a configured upstream URL.
pub struct UpstreamUrlMessage<'pool> {
    data: NonNull<u8>,
    len: usize,
    _pool: PhantomData<&'pool Pool<'pool>>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl UpstreamUrlMessage<'_> {
    /// Returns the pool-owned nginx parser message bytes.
    pub fn as_bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }

        unsafe { slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}

impl fmt::Debug for UpstreamUrlMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("UpstreamUrlMessage").field(&self.as_bytes()).finish()
    }
}

/// Failure while parsing an upstream URL through nginx.
#[derive(Debug)]
pub enum UpstreamUrlParseError<'pool> {
    /// nginx cannot parse an empty URL input.
    EmptyInput,
    /// The configuration pool could not retain URL input or parser diagnostics.
    Allocation,
    /// nginx rejected the URL and supplied a pool-owned diagnostic.
    Invalid(UpstreamUrlMessage<'pool>),
    /// nginx rejected the URL without a parser diagnostic.
    Native,
}

impl fmt::Display for UpstreamUrlParseError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => formatter.write_str("upstream URL is empty"),
            Self::Allocation => formatter.write_str("failed to allocate upstream URL data"),
            Self::Invalid(message) => {
                formatter.write_str("nginx rejected upstream URL: ")?;
                match core::str::from_utf8(message.as_bytes()) {
                    Ok(message) => formatter.write_str(message),
                    Err(_) => formatter.write_str("invalid"),
                }
            }
            Self::Native => formatter.write_str("nginx rejected upstream URL"),
        }
    }
}

impl error::Error for UpstreamUrlParseError<'_> {}

/// Whether nginx used the URL's configured default port or an explicit authority port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamPort {
    /// The authority omitted its port and nginx used the supplied default.
    Default(SocketPort),
    /// The authority contained an explicit port.
    Explicit(SocketPort),
}

impl UpstreamPort {
    /// Returns the port in host and network byte order.
    pub fn value(self) -> SocketPort {
        match self {
            Self::Default(port) | Self::Explicit(port) => port,
        }
    }
}

/// Parsed URL retained by the nginx configuration pool.
///
/// The value owns no memory itself: nginx retains its input, native result, addresses, and parser
/// diagnostics in the configuration pool supplied to [`parse`](Self::parse).
///
/// ```compile_fail
/// use ngx::core::Pool;
/// use ngx::http::ConfiguredUpstreamUrl;
///
/// fn escape<'pool>(pool: Pool<'pool>) -> ConfiguredUpstreamUrl<'static> {
///     ConfiguredUpstreamUrl::parse(pool, b"127.0.0.1", 80).unwrap()
/// }
/// ```
pub struct ConfiguredUpstreamUrl<'pool> {
    raw: NonNull<ngx_url_t>,
    _pool: PhantomData<&'pool Pool<'pool>>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl<'pool> ConfiguredUpstreamUrl<'pool> {
    /// Copies and parses one upstream URL with nginx's configured URL parser.
    ///
    /// `default_port` is used only when the authority omits a port. DNS resolution follows nginx's
    /// configured parser behavior and is not refreshed by this wrapper.
    pub fn parse(
        pool: Pool<'pool>,
        input: &[u8],
        default_port: u16,
    ) -> Result<Self, UpstreamUrlParseError<'pool>> {
        if input.is_empty() {
            return Err(UpstreamUrlParseError::EmptyInput);
        }

        let input = copy_pool_bytes(&pool, input).map_err(|_| UpstreamUrlParseError::Allocation)?;
        let raw = NonNull::new(pool.calloc_type::<ngx_url_t>())
            .ok_or(UpstreamUrlParseError::Allocation)?;

        unsafe {
            (*raw.as_ptr()).url = ngx_str_t { len: input.len, data: input.data.as_ptr() };
            (*raw.as_ptr()).default_port = default_port as _;
        }

        if unsafe { crate::ffi::ngx_parse_url(pool.as_ptr(), raw.as_ptr()) } == Status::NGX_OK.0 {
            return Ok(Self { raw, _pool: PhantomData, _not_thread_safe: PhantomData });
        }

        let error = unsafe { raw.as_ref().err };
        if error.is_null() {
            return Err(UpstreamUrlParseError::Native);
        }

        let error = unsafe { CStr::from_ptr(error) }.to_bytes();
        let error = copy_pool_bytes(&pool, error).map_err(|_| UpstreamUrlParseError::Allocation)?;
        Err(UpstreamUrlParseError::Invalid(UpstreamUrlMessage {
            data: error.data,
            len: error.len,
            _pool: PhantomData,
            _not_thread_safe: PhantomData,
        }))
    }

    /// Returns the copied authority bytes nginx parsed.
    pub fn input(&self) -> Result<&[u8], UpstreamUrlViewError> {
        let raw = unsafe { self.raw.as_ref() };
        checked_url_bytes(&raw.url)
    }

    /// Returns the parsed hostname or Unix-domain socket path bytes.
    pub fn host(&self) -> Result<&NgxStr, UpstreamUrlViewError> {
        let raw = unsafe { self.raw.as_ref() };
        checked_url_string(&raw.host)
    }

    /// Returns the parsed URL port provenance for Internet addresses.
    pub fn port(&self) -> Option<UpstreamPort> {
        let raw = unsafe { self.raw.as_ref() };
        #[cfg(unix)]
        if raw.family == libc::AF_UNIX {
            return None;
        }

        let port = SocketPort::from_host_order(raw.port as u16);
        if raw.no_port() != 0 {
            Some(UpstreamPort::Default(port))
        } else {
            Some(UpstreamPort::Explicit(port))
        }
    }

    /// Returns the checked selected addresses nginx resolved for this URL.
    pub fn addresses(&self) -> Result<UpstreamAddresses<'_>, UpstreamUrlViewError> {
        let raw = unsafe { self.raw.as_ref() };
        let len =
            usize::try_from(raw.naddrs).map_err(|_| UpstreamUrlViewError::AddressCountOverflow)?;
        let Some(bytes) = mem::size_of::<ngx_addr_t>().checked_mul(len) else {
            return Err(UpstreamUrlViewError::AddressCountOverflow);
        };
        if bytes > isize::MAX as usize {
            return Err(UpstreamUrlViewError::AddressCountOverflow);
        }
        if len == 0 {
            return Ok(UpstreamAddresses { raw: None, len: 0, _url: PhantomData });
        }

        let raw = NonNull::new(raw.addrs).ok_or(UpstreamUrlViewError::MissingAddresses)?;
        if !raw.as_ptr().is_aligned() {
            return Err(UpstreamUrlViewError::MisalignedAddresses);
        }

        Ok(UpstreamAddresses { raw: Some(raw), len, _url: PhantomData })
    }
}

#[derive(Clone, Copy)]
struct PoolBytes {
    data: NonNull<u8>,
    len: usize,
}

fn copy_pool_bytes(pool: &Pool<'_>, bytes: &[u8]) -> Result<PoolBytes, ()> {
    if bytes.is_empty() {
        return Ok(PoolBytes { data: NonNull::dangling(), len: 0 });
    }

    let layout = Layout::array::<u8>(bytes.len()).map_err(|_| ())?;
    let data = pool.allocate(layout).map_err(|_| ())?.cast::<u8>();
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), data.as_ptr(), bytes.len()) };
    Ok(PoolBytes { data, len: bytes.len() })
}

fn checked_url_bytes(value: &ngx_str_t) -> Result<&[u8], UpstreamUrlViewError> {
    if value.len == 0 {
        return Ok(&[]);
    }

    let data = NonNull::new(value.data).ok_or(UpstreamUrlViewError::MissingStringData)?;
    Ok(unsafe { slice::from_raw_parts(data.as_ptr(), value.len) })
}

fn checked_url_string(value: &ngx_str_t) -> Result<&NgxStr, UpstreamUrlViewError> {
    Ok(NgxStr::from_bytes(checked_url_bytes(value)?))
}

/// Checked addresses selected by nginx for one configured upstream URL.
#[derive(Clone, Copy)]
pub struct UpstreamAddresses<'url> {
    raw: Option<NonNull<ngx_addr_t>>,
    len: usize,
    _url: PhantomData<&'url ngx_addr_t>,
}

impl<'url> UpstreamAddresses<'url> {
    /// Returns the number of selected addresses.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether nginx selected no addresses, for example for a no-resolve URL.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns one checked selected address by index.
    pub fn get(&self, index: usize) -> Option<UpstreamAddress<'url>> {
        if index >= self.len {
            return None;
        }

        let raw = unsafe { NonNull::new_unchecked(self.raw?.as_ptr().add(index)) };
        Some(UpstreamAddress { raw, _url: PhantomData, _not_thread_safe: PhantomData })
    }

    /// Iterates over the selected addresses in nginx's resolution order.
    pub fn iter(&self) -> UpstreamAddressIter<'url> {
        UpstreamAddressIter { addresses: *self, index: 0 }
    }
}

/// Iterator over [`UpstreamAddresses`].
pub struct UpstreamAddressIter<'url> {
    addresses: UpstreamAddresses<'url>,
    index: usize,
}

impl<'url> Iterator for UpstreamAddressIter<'url> {
    type Item = UpstreamAddress<'url>;

    fn next(&mut self) -> Option<Self::Item> {
        let address = self.addresses.get(self.index)?;
        self.index += 1;
        Some(address)
    }
}

/// One checked address selected by nginx for a configured upstream URL.
#[derive(Clone, Copy)]
pub struct UpstreamAddress<'url> {
    raw: NonNull<ngx_addr_t>,
    _url: PhantomData<&'url ngx_addr_t>,
    _not_thread_safe: PhantomData<*mut ()>,
}

impl UpstreamAddress<'_> {
    /// Returns nginx's formatted address name.
    pub fn name(&self) -> Result<&NgxStr, UpstreamUrlViewError> {
        let raw = unsafe { self.raw.as_ref() };
        checked_url_string(&raw.name)
    }

    /// Returns the selected native socket address as a checked generic address view.
    pub fn socket_address(&self) -> Result<SocketAddress<'_>, UpstreamUrlViewError> {
        let raw = unsafe { self.raw.as_ref() };
        unsafe { parse_socket_address(raw.sockaddr, raw.socklen) }.map_err(Into::into)
    }
}

#[cfg(all(test, feature = "test-link"))]
#[path = "url/tests.rs"]
mod tests;
