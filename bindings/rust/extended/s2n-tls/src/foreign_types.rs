use std::{cell::UnsafeCell, marker::PhantomData};

/// Define a type that represents ownership of the underlying s2n-tls type.
///
/// For example, `define_owned_type(ExternalPsk, s2n_psk)` will produce the
/// following struct.
/// ```
/// use std::ptr::NonNull;
///
/// #[derive(Debug)]
/// pub struct ExternalPsk {
///     ptr: NonNull<s2n_tls_sys::s2n_psk>
/// }
/// ```
/// Drop must be manually implemented on this type.
macro_rules! define_owned_type {
    ($(#[$meta:meta])* $struct_name:ident, $inner_type:ty) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $struct_name {
            ptr: std::ptr::NonNull<$inner_type>,
        }

        unsafe impl Send for $struct_name {}
        unsafe impl Sync for $struct_name {}

        impl $struct_name {
            /// Creates a new instance of the struct from a raw pointer.
            ///
            /// # Safety
            /// The caller must ensure the pointer is valid and non-null.
            pub fn from_s2n_ptr(ptr: std::ptr::NonNull<$inner_type>) -> Self {
                Self { ptr }
            }

            /// Access the underlying pointer.
            pub fn as_s2n_ptr(&self) -> *const $inner_type {
                self.ptr.as_ptr() as *const $inner_type
            }

            /// Access the underlying pointer.
            pub fn as_s2n_ptr_mut(&self) -> *mut $inner_type {
                self.ptr.as_ptr()
            }
        }
    };
}

// This opaque definition is borrowed from the foreign-types crate
// https://github.com/sfackler/foreign-types/blob/393f6ab5a5dc66b8a8e2d6d880b1ff80b6a7edc2/foreign-types-shared/src/lib.rs#L14
// This type acts as if it owns a *mutable pointer to a zero sized type, where
// that type may implement un-synchronized interior mutability.
#[derive(Debug)]
pub(crate) struct Opaque(PhantomData<UnsafeCell<*mut ()>>);

/// Define a type that represents a reference to the underlying s2n-tls type. This
/// type should not have an associated drop implementation.
///
/// Ref Types can be used to ergonomically return a reference from a function.
/// The lifetime of the ref will automatically be tied to the lifetime of the
/// surrounding function.
macro_rules! define_ref_type {
    ($(#[$meta:meta])* $struct_name:ident, $inner_type:ty) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $struct_name(crate::foreign_types::Opaque);

        impl crate::foreign_types::S2NRef for $struct_name {
            type ForeignType = $inner_type;
        }
    };
}

/// SAFETY: both Self and Self::ForeignType must be zero sized.
pub(crate) trait S2NRef: Sized {
    /// e.g. s2n_tls_sys::api::s2n_offered_psk_list
    type ForeignType: Sized;

    fn from_s2n_ptr_mut<'a>(ptr: *mut Self::ForeignType) -> &'a mut Self {
        unsafe { &mut *(ptr as *mut Self) }
    }

    fn from_s2n_ptr<'a>(ptr: *const Self::ForeignType) -> &'a Self {
        unsafe { &*(ptr as *const Self) }
    }

    fn as_s2n_ptr_mut(&mut self) -> *mut Self::ForeignType {
        self.as_s2n_ptr() as *mut Self::ForeignType
    }

    fn as_s2n_ptr(&self) -> *const Self::ForeignType {
        self as *const Self as *const Self::ForeignType
    }
}

pub(crate) use {define_owned_type, define_ref_type};
