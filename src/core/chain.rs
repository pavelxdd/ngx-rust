use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use nginx_sys::{ngx_alloc_chain_link, ngx_buf_t, ngx_chain_t};

use crate::core::{BufferError, BufferMut, BufferRef, Pool, PoolBuffer};

impl<'pool> Pool<'pool> {
    /// Starts an empty pool-owned chain builder.
    pub fn chain(&self) -> PoolChain<'pool> {
        PoolChain { head: None, tail: None, pool: self.clone() }
    }
}

/// Failure returned while validating or extending an nginx chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    /// A chain node has a null buffer pointer.
    NullBuffer,
    /// A chain node pointer is misaligned.
    MisalignedLink,
    /// A buffer in the chain is invalid.
    Buffer(BufferError),
    /// Nginx could not allocate a chain node.
    Allocation,
    /// The aggregate chain size overflowed `usize`.
    Overflow,
}

impl From<BufferError> for ChainError {
    fn from(error: BufferError) -> Self {
        Self::Buffer(error)
    }
}

/// Shared callback-scoped access to a nullable nginx chain.
#[derive(Clone, Copy, Debug)]
pub struct ChainRef<'chain> {
    head: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain ngx_chain_t>,
}

impl<'chain> ChainRef<'chain> {
    /// Creates a shared view over a nullable nginx chain.
    ///
    /// # Safety
    /// Every non-null link and buffer must remain readable for `'chain`; links must be aligned,
    /// form a terminating acyclic list, and not be mutably accessed for that lifetime. Every
    /// buffer must also satisfy [`BufferRef::from_raw`].
    pub unsafe fn from_raw(head: *mut ngx_chain_t) -> Result<Self, ChainError> {
        check_chain_ptr(head)?;
        Ok(Self { head, _lifetime: PhantomData })
    }

    /// Invokes a closure with a chain view that cannot escape through a safe value.
    ///
    /// # Safety
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// # use ngx::core::ChainRef;
    /// # use ngx::ffi::ngx_chain_t;
    /// # fn escape(raw: *mut ngx_chain_t) {
    /// let _chain = unsafe { ChainRef::with_raw(raw, |chain| chain) };
    /// # }
    /// ```
    pub unsafe fn with_raw<R>(
        head: *mut ngx_chain_t,
        f: impl for<'scope> FnOnce(ChainRef<'scope>) -> R,
    ) -> Result<R, ChainError> {
        let chain = unsafe { ChainRef::from_raw(head) }?;
        Ok(f(chain))
    }

    /// Iterates over checked buffer links in order.
    pub fn iter(self) -> ChainIter<'chain> {
        ChainIter { next: self.head, _lifetime: PhantomData }
    }

    /// Returns the checked sum of all nginx-visible buffer sizes.
    pub fn len(self) -> Result<usize, ChainError> {
        self.iter().try_fold(0usize, |total, buffer| {
            let len = buffer?.len().map_err(ChainError::Buffer)?;
            total.checked_add(len).ok_or(ChainError::Overflow)
        })
    }

    /// Returns whether the chain has no nginx-visible bytes.
    pub fn is_empty(self) -> Result<bool, ChainError> {
        self.len().map(|len| len == 0)
    }
}

/// Exclusive callback-scoped access to a nullable nginx chain.
#[derive(Debug)]
pub struct ChainMut<'chain> {
    head: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain mut ngx_chain_t>,
}

impl<'chain> ChainMut<'chain> {
    /// Creates an exclusive view over a nullable nginx chain.
    ///
    /// # Safety
    /// Every non-null link and buffer must remain valid and exclusively accessible for `'chain`;
    /// links must be aligned and form a terminating acyclic list, and buffer pointers must not
    /// alias each other. Every buffer must also satisfy [`BufferMut::from_raw`].
    pub unsafe fn from_raw(head: *mut ngx_chain_t) -> Result<Self, ChainError> {
        check_chain_ptr(head)?;
        Ok(Self { head, _lifetime: PhantomData })
    }

    /// Invokes a closure with an exclusive chain view that cannot escape through a safe value.
    ///
    /// # Safety
    /// The same requirements as [`from_raw`](Self::from_raw) apply for the closure call.
    ///
    /// ```compile_fail
    /// # use ngx::core::ChainMut;
    /// # use ngx::ffi::ngx_chain_t;
    /// # fn escape(raw: *mut ngx_chain_t) {
    /// let _chain = unsafe { ChainMut::with_raw(raw, |chain| chain) };
    /// # }
    /// ```
    pub unsafe fn with_raw<R>(
        head: *mut ngx_chain_t,
        f: impl for<'scope> FnOnce(ChainMut<'scope>) -> R,
    ) -> Result<R, ChainError> {
        let chain = unsafe { ChainMut::from_raw(head) }?;
        Ok(f(chain))
    }

    /// Iterates over shared checked buffer views without consuming this exclusive chain handle.
    pub fn iter(&self) -> ChainIter<'_> {
        ChainIter { next: self.head, _lifetime: PhantomData }
    }

    /// Iterates over exclusive checked buffer views in order.
    pub fn into_iter_mut(self) -> ChainIterMut<'chain> {
        ChainIterMut { next: self.head, _lifetime: PhantomData }
    }

    /// Appends `suffix` before passing the combined chain to an nginx output filter.
    ///
    /// The appended raw links remain connected after `f` returns because an nginx output filter
    /// may retain the chain when it returns `NGX_AGAIN`. Both input handles are consumed, and the
    /// combined callback-scoped handle cannot escape through a safe return value.
    /// # Safety
    ///
    /// `suffix` must remain valid for as long as the output filter can retain the combined chain.
    /// This is normally true for an nginx output-filter input chain, whose links remain valid
    /// after the callback returns `NGX_AGAIN`.
    pub unsafe fn append_for_output_filter<'suffix, R>(
        self,
        suffix: ChainMut<'suffix>,
        f: impl for<'scope> FnOnce(ChainMut<'scope>) -> R,
    ) -> Result<R, ChainError> {
        let Some(mut tail) = self.tail()? else {
            return unsafe { Self::with_raw(suffix.head, f) };
        };
        if suffix.head.is_null() {
            return unsafe { Self::with_raw(self.head, f) };
        }

        unsafe { tail.as_mut().next = suffix.head };
        unsafe { Self::with_raw(self.head, f) }
    }

    pub(crate) fn as_ptr(&self) -> *mut ngx_chain_t {
        self.head
    }

    pub(crate) fn contains_link(&self, target: *mut ngx_chain_t) -> bool {
        let mut link = self.head;
        while !link.is_null() {
            if ptr::eq(link, target) {
                return true;
            }
            link = unsafe { (*link).next };
        }
        false
    }

    fn tail(&self) -> Result<Option<NonNull<ngx_chain_t>>, ChainError> {
        let mut current = NonNull::new(self.head);
        while let Some(link) = current {
            if !link.as_ptr().is_aligned() {
                return Err(ChainError::MisalignedLink);
            }
            let next = unsafe { link.as_ref().next };
            if next.is_null() {
                return Ok(Some(link));
            }
            if !next.is_aligned() {
                return Err(ChainError::MisalignedLink);
            }
            current = NonNull::new(next);
        }
        Ok(None)
    }
}

/// Checked shared nginx chain iterator.
pub struct ChainIter<'chain> {
    next: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain ngx_chain_t>,
}

impl<'chain> Iterator for ChainIter<'chain> {
    type Item = Result<BufferRef<'chain>, ChainError>;

    fn next(&mut self) -> Option<Self::Item> {
        let link = NonNull::new(self.next)?;
        if !self.next.is_aligned() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::MisalignedLink));
        }
        let link = unsafe { link.as_ref() };
        self.next = link.next;
        if link.buf.is_null() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::NullBuffer));
        }
        Some(unsafe { BufferRef::from_raw(link.buf) }.map_err(ChainError::Buffer))
    }
}

/// Checked exclusive nginx chain iterator.
pub struct ChainIterMut<'chain> {
    next: *mut ngx_chain_t,
    _lifetime: PhantomData<&'chain mut ngx_chain_t>,
}

impl<'chain> Iterator for ChainIterMut<'chain> {
    type Item = Result<BufferMut<'chain>, ChainError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut link = NonNull::new(self.next)?;
        if !self.next.is_aligned() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::MisalignedLink));
        }
        let link = unsafe { link.as_mut() };
        self.next = link.next;
        if link.buf.is_null() {
            self.next = ptr::null_mut();
            return Some(Err(ChainError::NullBuffer));
        }
        Some(unsafe { BufferMut::from_raw(link.buf) }.map_err(ChainError::Buffer))
    }
}

/// Pool-owned nginx chain builder with explicit head and tail ownership.
#[derive(Debug)]
pub struct PoolChain<'pool> {
    head: Option<NonNull<ngx_chain_t>>,
    tail: Option<NonNull<ngx_chain_t>>,
    pool: Pool<'pool>,
}

impl<'pool> PoolChain<'pool> {
    /// Appends one pool-owned buffer at the current tail.
    pub fn append(&mut self, buffer: PoolBuffer<'pool>) -> Result<(), ChainError> {
        if !ptr::eq(self.pool.as_ptr(), buffer.pool_ptr()) {
            return Err(ChainError::Buffer(BufferError::ForeignPool));
        }
        self.append_raw(buffer.into_non_null())
    }

    /// Appends every fully prepared link from `candidate` and leaves it empty.
    ///
    /// The candidate remains unchanged when it belongs to a different pool.
    pub fn append_chain(&mut self, candidate: &mut PoolChain<'pool>) -> Result<(), ChainError> {
        if !ptr::eq(self.pool.as_ptr(), candidate.pool.as_ptr()) {
            return Err(ChainError::Buffer(BufferError::ForeignPool));
        }

        debug_assert_eq!(candidate.head.is_some(), candidate.tail.is_some());
        let Some((head, tail)) = candidate.head.zip(candidate.tail) else {
            return Ok(());
        };

        if let Some(mut output_tail) = self.tail {
            unsafe { output_tail.as_mut().next = head.as_ptr() };
        } else {
            self.head = Some(head);
        }
        self.tail = Some(tail);
        candidate.head = None;
        candidate.tail = None;
        Ok(())
    }

    /// Iterates over the current chain in append order.
    pub fn iter(&self) -> ChainIter<'_> {
        ChainIter { next: self.head_ptr(), _lifetime: PhantomData }
    }

    pub(crate) fn belongs_to(&self, pool: &Pool<'_>) -> bool {
        ptr::eq(self.pool.as_ptr(), pool.as_ptr())
    }

    /// Transfers the nullable chain head while the pool retains all storage.
    pub fn into_raw(self) -> *mut ngx_chain_t {
        self.head_ptr()
    }

    /// Transfers the nullable chain endpoints while the pool retains all storage.
    ///
    /// A request-pool context can retain the endpoints and append another fully prepared chain
    /// without walking raw links again.
    pub fn into_raw_parts(self) -> (*mut ngx_chain_t, *mut ngx_chain_t) {
        (self.head_ptr(), self.tail.map_or(ptr::null_mut(), NonNull::as_ptr))
    }

    fn append_raw(&mut self, buffer: NonNull<ngx_buf_t>) -> Result<(), ChainError> {
        let mut link = NonNull::new(unsafe { ngx_alloc_chain_link(self.pool.as_ptr()) })
            .ok_or(ChainError::Allocation)?;
        unsafe {
            link.as_mut().buf = buffer.as_ptr();
            link.as_mut().next = ptr::null_mut();
        }

        if let Some(mut tail) = self.tail {
            unsafe { tail.as_mut().next = link.as_ptr() };
        } else {
            self.head = Some(link);
        }
        self.tail = Some(link);
        Ok(())
    }

    fn head_ptr(&self) -> *mut ngx_chain_t {
        self.head.map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    #[cfg(test)]
    fn tail_ptr(&self) -> *mut ngx_chain_t {
        self.tail.map_or(ptr::null_mut(), NonNull::as_ptr)
    }
}

fn check_chain_ptr(chain: *mut ngx_chain_t) -> Result<(), ChainError> {
    if !chain.is_null() && !chain.is_aligned() {
        return Err(ChainError::MisalignedLink);
    }
    Ok(())
}

#[cfg(test)]
#[path = "chain/tests.rs"]
mod tests;
