use ::core::cmp;
use ::core::fmt;
use ::core::hash;
use ::core::ptr;
use ::core::slice;
use ::core::str;

use crate::bindings::{ngx_pool_t, ngx_str_t};
use crate::detail;

impl ngx_str_t {
    /// Returns the contents of this `ngx_str_t` as a byte slice.
    ///
    /// The returned slice will **not** contain the optional nul terminator that `ngx_str_t.data`
    /// may have.
    ///
    /// The slice borrows the `ngx_str_t`; it cannot be created from an owned value with an
    /// unrelated lifetime.
    ///
    /// ```compile_fail
    /// use nginx_sys::ngx_str_t;
    ///
    /// fn into_static(value: ngx_str_t) -> &'static [u8] {
    ///     value.into()
    /// }
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        if self.is_empty() {
            &[]
        } else {
            // SAFETY: `ngx_str_t` with non-zero len must contain a valid correctly aligned pointer
            unsafe { slice::from_raw_parts(self.data, self.len) }
        }
    }

    /// Returns the contents of this `ngx_str_t` as a mutable byte slice.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        if self.is_empty() {
            &mut []
        } else {
            // SAFETY: `ngx_str_t` with non-zero len must contain a valid correctly aligned pointer
            unsafe { slice::from_raw_parts_mut(self.data, self.len) }
        }
    }

    /// Returns `true` if the string has a length of 0.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the contents of this `ngx_str_t` a string slice (`&str`) if
    /// the contents are utf-8 encoded.
    ///
    /// # Returns
    /// A string slice (`&str`) representing the nginx string, or else a
    /// Utf8Error.
    pub fn to_str(&self) -> Result<&str, str::Utf8Error> {
        str::from_utf8(self.as_bytes())
    }

    /// Creates an empty `ngx_str_t` instance.
    ///
    /// This method replaces the `ngx_null_string` C macro.
    pub const fn empty() -> Self {
        ngx_str_t { len: 0, data: ptr::null_mut() }
    }

    /// Create an `ngx_str_t` instance from a byte slice.
    ///
    /// # Safety
    ///
    /// The caller must provide a valid pointer to a memory pool.
    pub unsafe fn from_bytes(pool: *mut ngx_pool_t, src: &[u8]) -> Option<Self> {
        unsafe { detail::bytes_to_uchar(pool, src).map(|data| Self { data, len: src.len() }) }
    }

    /// Create an `ngx_str_t` instance from a string slice (`&str`).
    ///
    /// # Arguments
    ///
    /// * `pool` - A pointer to the nginx memory pool (`ngx_pool_t`).
    /// * `data` - The string slice from which to create the nginx string.
    ///
    /// # Safety
    /// This function is marked as unsafe because it accepts a raw pointer argument. There is no
    /// way to know if `pool` is pointing to valid memory. The caller must provide a valid pool to
    /// avoid indeterminate behavior.
    ///
    /// # Returns
    /// An `ngx_str_t` instance representing the given string slice, or `None` if allocation fails.
    pub unsafe fn from_str(pool: *mut ngx_pool_t, data: &str) -> Option<Self> {
        let len = data.len();
        unsafe { detail::str_to_uchar(pool, data).map(|data| ngx_str_t { data, len }) }
    }

    /// Divides one `ngx_str_t` into two at an index.
    ///
    /// # Safety
    ///
    /// The results will reference the original string; be wary of the ownership and lifetime.
    pub fn split_at(&self, mid: usize) -> Option<(ngx_str_t, ngx_str_t)> {
        if mid > self.len {
            return None;
        }

        Some((
            ngx_str_t { data: self.data, len: mid },
            ngx_str_t { data: unsafe { self.data.add(mid) }, len: self.len - mid },
        ))
    }

    /// Returns an `ngx_str_t` with the prefix removed.
    ///
    /// If the string starts with the byte sequence `prefix`, returns the substring after the
    /// prefix, wrapped in `Some`. The resulting substring can be empty.
    ///
    /// # Safety
    ///
    /// The result will reference the original string; be wary of the ownership and lifetime.
    ///
    /// The method is not marked as `unsafe` as everything it does is possible via safe interfaces.
    pub fn strip_prefix(&self, prefix: impl AsRef<[u8]>) -> Option<ngx_str_t> {
        let prefix = prefix.as_ref();
        if self.as_bytes().starts_with(prefix) {
            self.split_at(prefix.len()).map(|x| x.1)
        } else {
            None
        }
    }

    /// Returns an `ngx_str_t` with the suffix removed.
    ///
    /// If the string ends with the byte sequence `suffix`, returns the substring before the
    /// suffix, wrapped in `Some`. The resulting substring can be empty.
    ///
    /// # Safety
    ///
    /// The result will reference the original string; be wary of the ownership and lifetime.
    ///
    /// The method is not marked as `unsafe` as everything it does is possible via safe interfaces.
    pub fn strip_suffix(&self, suffix: impl AsRef<[u8]>) -> Option<ngx_str_t> {
        let suffix = suffix.as_ref();
        if self.as_bytes().ends_with(suffix) {
            self.split_at(self.len - suffix.len()).map(|x| x.0)
        } else {
            None
        }
    }
}

impl AsRef<[u8]> for ngx_str_t {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for ngx_str_t {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_bytes_mut()
    }
}

impl Default for ngx_str_t {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for ngx_str_t {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        detail::display_bytes(f, self.as_bytes())
    }
}

impl hash::Hash for ngx_str_t {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state)
    }
}

impl PartialEq for ngx_str_t {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(self.as_bytes(), other.as_bytes())
    }
}

impl Eq for ngx_str_t {}

impl PartialOrd<Self> for ngx_str_t {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ngx_str_t {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        Ord::cmp(self.as_bytes(), other.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_pool_allocation_is_fallible() {
        let _: unsafe fn(*mut ngx_pool_t, &str) -> Option<*mut crate::u_char> =
            detail::str_to_uchar;
        let _: unsafe fn(*mut ngx_pool_t, &str) -> Option<ngx_str_t> = ngx_str_t::from_str;
    }

    #[test]
    fn ngx_str_prefix() {
        let s = "key=value";
        let s = ngx_str_t { data: s.as_ptr().cast_mut(), len: s.len() };

        assert_eq!(
            s.strip_prefix("key=").as_ref().map(ngx_str_t::as_bytes),
            Some("value".as_bytes())
        );

        assert_eq!(s.strip_prefix("test"), None);

        assert_eq!(
            s.strip_suffix("value").as_ref().map(ngx_str_t::as_bytes),
            Some("key=".as_bytes())
        );

        assert_eq!(s.strip_suffix("test"), None);
    }
}
