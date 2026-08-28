use core::ptr::NonNull;

use crate::ffi::{ngx_module_t, ngx_uint_t};

/// Opaque identity of a native nginx module descriptor.
///
/// The handle does not create a Rust reference to the descriptor because nginx mutates module
/// metadata during startup and dynamic loading.
///
/// ```compile_fail
/// use ngx::core::ModuleDescriptor;
/// use ngx::ffi::ngx_module_t;
///
/// fn forge(raw: *mut ngx_module_t) -> ModuleDescriptor {
///     ModuleDescriptor::from_raw(raw).unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use ngx::core::ModuleDescriptor;
///
/// fn index(module: ModuleDescriptor) -> usize {
///     module.index as usize
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct ModuleDescriptor {
    raw: NonNull<ngx_module_t>,
}

impl ModuleDescriptor {
    /// Creates an opaque handle to a native module descriptor.
    ///
    /// # Safety
    ///
    /// `raw` must identify the caller's real nginx module descriptor and remain allocated until
    /// process exit. Nginx may mutate the descriptor according to its module lifecycle.
    pub unsafe fn from_raw(raw: *mut ngx_module_t) -> Option<Self> {
        let raw = NonNull::new(raw)?;
        if !raw.as_ptr().is_aligned() {
            return None;
        }
        Some(Self { raw })
    }

    #[cfg(test)]
    pub(crate) fn from_test(module: ngx_module_t) -> Self {
        unsafe { Self::from_raw(alloc::boxed::Box::into_raw(alloc::boxed::Box::new(module))) }
            .unwrap()
    }

    /// Returns the native descriptor pointer for explicit FFI operations or identity comparison.
    pub const fn as_ptr(self) -> *mut ngx_module_t {
        self.raw.as_ptr()
    }

    /// Copies initialized fields needed for configuration slot lookup.
    ///
    /// # Safety
    ///
    /// Nginx must have initialized the module and context indexes, and must not mutate these fields
    /// concurrently with this read.
    pub(crate) unsafe fn snapshot(self) -> ModuleDescriptorSnapshot {
        let raw = self.raw.as_ptr();
        ModuleDescriptorSnapshot {
            module_type: unsafe { core::ptr::addr_of!((*raw).type_).read() },
            index: unsafe { core::ptr::addr_of!((*raw).index).read() },
            context_index: unsafe { core::ptr::addr_of!((*raw).ctx_index).read() },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ModuleDescriptorSnapshot {
    pub(crate) module_type: ngx_uint_t,
    pub(crate) index: ngx_uint_t,
    pub(crate) context_index: ngx_uint_t,
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use core::ptr;

    use super::ModuleDescriptor;
    use crate::ffi::ngx_module_t;

    #[test]
    fn descriptor_rejects_invalid_pointers() {
        assert!(unsafe { ModuleDescriptor::from_raw(ptr::null_mut()) }.is_none());
        assert!(unsafe { ModuleDescriptor::from_raw(ptr::without_provenance_mut(1)) }.is_none());
    }

    #[test]
    fn snapshot_reads_the_initialized_native_state() {
        let raw = Box::into_raw(Box::new(ngx_module_t::default()));
        let descriptor = unsafe { ModuleDescriptor::from_raw(raw) }.unwrap();
        unsafe {
            (*raw).type_ = 7;
            (*raw).index = 11;
            (*raw).ctx_index = 13;
        }

        let snapshot = unsafe { descriptor.snapshot() };
        assert_eq!(snapshot.module_type, 7);
        assert_eq!(snapshot.index, 11);
        assert_eq!(snapshot.context_index, 13);
    }
}
