use core::{error, fmt, str::FromStr};

use crate::ffi::*;

use super::view::{RequestRef, RequestRefMut};

/// A possible error value when converting `Method`
pub struct InvalidMethod {
    _priv: (),
}

/// Request method verb
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Method(MethodInner);

impl Method {
    /// UNKNOWN
    pub const UNKNOWN: Method = Method(MethodInner::Unknown);

    /// GET
    pub const GET: Method = Method(MethodInner::Get);

    /// HEAD
    pub const HEAD: Method = Method(MethodInner::Head);

    /// POST
    pub const POST: Method = Method(MethodInner::Post);

    /// PUT
    pub const PUT: Method = Method(MethodInner::Put);

    /// DELETE
    pub const DELETE: Method = Method(MethodInner::Delete);

    /// MKCOL
    pub const MKCOL: Method = Method(MethodInner::Mkcol);

    /// COPY
    pub const COPY: Method = Method(MethodInner::Copy);

    /// MOVE
    pub const MOVE: Method = Method(MethodInner::Move);

    /// OPTIONS
    pub const OPTIONS: Method = Method(MethodInner::Options);

    /// PROPFIND
    pub const PROPFIND: Method = Method(MethodInner::Propfind);

    /// PROPPATCH
    pub const PROPPATCH: Method = Method(MethodInner::Proppatch);

    /// LOCK
    pub const LOCK: Method = Method(MethodInner::Lock);

    /// UNLOCK
    pub const UNLOCK: Method = Method(MethodInner::Unlock);

    /// PATCH
    pub const PATCH: Method = Method(MethodInner::Patch);

    /// TRACE
    pub const TRACE: Method = Method(MethodInner::Trace);

    /// CONNECT
    pub const CONNECT: Method = Method(MethodInner::Connect);

    /// Convert a Method to a &str.
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            MethodInner::Unknown => "UNKNOWN",
            MethodInner::Get => "GET",
            MethodInner::Head => "HEAD",
            MethodInner::Post => "POST",
            MethodInner::Put => "PUT",
            MethodInner::Delete => "DELETE",
            MethodInner::Mkcol => "MKCOL",
            MethodInner::Copy => "COPY",
            MethodInner::Move => "MOVE",
            MethodInner::Options => "OPTIONS",
            MethodInner::Propfind => "PROPFIND",
            MethodInner::Proppatch => "PROPPATCH",
            MethodInner::Lock => "LOCK",
            MethodInner::Unlock => "UNLOCK",
            MethodInner::Patch => "PATCH",
            MethodInner::Trace => "TRACE",
            MethodInner::Connect => "CONNECT",
        }
    }

    fn from_bytes(t: &[u8]) -> Result<Method, InvalidMethod> {
        match t {
            b"GET" => Ok(Self::GET),
            b"HEAD" => Ok(Self::HEAD),
            b"POST" => Ok(Self::POST),
            b"PUT" => Ok(Self::PUT),
            b"DELETE" => Ok(Self::DELETE),
            b"MKCOL" => Ok(Self::MKCOL),
            b"COPY" => Ok(Self::COPY),
            b"MOVE" => Ok(Self::MOVE),
            b"OPTIONS" => Ok(Self::OPTIONS),
            b"PROPFIND" => Ok(Self::PROPFIND),
            b"PROPPATCH" => Ok(Self::PROPPATCH),
            b"LOCK" => Ok(Self::LOCK),
            b"UNLOCK" => Ok(Self::UNLOCK),
            b"PATCH" => Ok(Self::PATCH),
            b"TRACE" => Ok(Self::TRACE),
            b"CONNECT" => Ok(Self::CONNECT),
            _ => Err(InvalidMethod::new()),
        }
    }

    pub(super) fn from_ngx(t: ngx_uint_t) -> Method {
        let t = t as _;
        match t {
            crate::ffi::NGX_HTTP_GET => Method(MethodInner::Get),
            crate::ffi::NGX_HTTP_HEAD => Method(MethodInner::Head),
            crate::ffi::NGX_HTTP_POST => Method(MethodInner::Post),
            crate::ffi::NGX_HTTP_PUT => Method(MethodInner::Put),
            crate::ffi::NGX_HTTP_DELETE => Method(MethodInner::Delete),
            crate::ffi::NGX_HTTP_MKCOL => Method(MethodInner::Mkcol),
            crate::ffi::NGX_HTTP_COPY => Method(MethodInner::Copy),
            crate::ffi::NGX_HTTP_MOVE => Method(MethodInner::Move),
            crate::ffi::NGX_HTTP_OPTIONS => Method(MethodInner::Options),
            crate::ffi::NGX_HTTP_PROPFIND => Method(MethodInner::Propfind),
            crate::ffi::NGX_HTTP_PROPPATCH => Method(MethodInner::Proppatch),
            crate::ffi::NGX_HTTP_LOCK => Method(MethodInner::Lock),
            crate::ffi::NGX_HTTP_UNLOCK => Method(MethodInner::Unlock),
            crate::ffi::NGX_HTTP_PATCH => Method(MethodInner::Patch),
            crate::ffi::NGX_HTTP_TRACE => Method(MethodInner::Trace),
            #[cfg(nginx1_21_1)]
            crate::ffi::NGX_HTTP_CONNECT => Method(MethodInner::Connect),
            _ => Method(MethodInner::Unknown),
        }
    }
}

impl AsRef<str> for Method {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'a> PartialEq<&'a Method> for Method {
    #[inline]
    fn eq(&self, other: &&'a Method) -> bool {
        self == *other
    }
}

impl PartialEq<Method> for &Method {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        *self == other
    }
}

impl PartialEq<str> for Method {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<Method> for str {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        self == other.as_ref()
    }
}

impl<'a> PartialEq<&'a str> for Method {
    #[inline]
    fn eq(&self, other: &&'a str) -> bool {
        self.as_ref() == *other
    }
}

impl PartialEq<Method> for &str {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        *self == other.as_ref()
    }
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl fmt::Display for Method {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.as_ref())
    }
}

impl<'a> From<&'a Method> for Method {
    #[inline]
    fn from(t: &'a Method) -> Self {
        t.clone()
    }
}

impl<'a> TryFrom<&'a [u8]> for Method {
    type Error = InvalidMethod;

    #[inline]
    fn try_from(t: &'a [u8]) -> Result<Self, Self::Error> {
        Method::from_bytes(t)
    }
}

impl<'a> TryFrom<&'a str> for Method {
    type Error = InvalidMethod;

    #[inline]
    fn try_from(t: &'a str) -> Result<Self, Self::Error> {
        TryFrom::try_from(t.as_bytes())
    }
}

impl FromStr for Method {
    type Err = InvalidMethod;

    #[inline]
    fn from_str(t: &str) -> Result<Self, Self::Err> {
        TryFrom::try_from(t)
    }
}

impl InvalidMethod {
    fn new() -> InvalidMethod {
        InvalidMethod { _priv: () }
    }
}

impl fmt::Debug for InvalidMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("InvalidMethod")
            // skip _priv noise
            .finish()
    }
}

impl fmt::Display for InvalidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid HTTP method")
    }
}

impl error::Error for InvalidMethod {}

#[derive(Clone, PartialEq, Eq, Hash)]
enum MethodInner {
    Unknown,
    Get,
    Head,
    Post,
    Put,
    Delete,
    Mkcol,
    Copy,
    Move,
    Options,
    Propfind,
    Proppatch,
    Lock,
    Unlock,
    Patch,
    Trace,
    Connect,
}

impl<'callback> RequestRef<'callback> {
    /// Request method verb.
    pub fn method(&self) -> Method {
        Method::from_ngx(unsafe { self.raw.as_ref().method })
    }
}

impl<'callback> RequestRefMut<'callback> {
    /// Request method verb.
    pub fn method(&self) -> Method {
        self.view().method()
    }
}
