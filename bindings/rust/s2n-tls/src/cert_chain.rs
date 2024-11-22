// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{error::{Error, Fallible}, ffi_traits::Opaque};
use s2n_tls_sys::*;
use std::{
    marker::PhantomData, ops::Deref, ptr::{self, NonNull}
};

/// A CertificateChain represents a chain of X.509 certificates.
pub struct CertificateChain {
    ptr: NonNull<s2n_cert_chain_and_key>,
}

impl CertificateChain {
    /// This allocates a new certificate chain from s2n.
    pub(crate) fn new() -> Result<CertificateChain, Error> {
        unsafe {
            let ptr = s2n_cert_chain_and_key_new().into_result()?;
            Ok(CertificateChain {
                ptr,
            })
        }
    }
}

impl Deref for CertificateChain {
    type Target = CertificateChainRef;

    fn deref(&self) -> &Self::Target {
        CertificateChainRef::from_s2n_ptr(unsafe {self.ptr.as_ref()})

    }
}

impl Drop for CertificateChain {
    fn drop(&mut self) {
        // ignore failures since there's not much we can do about it
        unsafe {
            let _ = s2n_cert_chain_and_key_free(self.ptr.as_ptr()).into_result();
        }
    }
}

pub struct CertificateChainRef(Opaque);

impl CertificateChainRef {

    pub fn iter(&self) -> CertificateChainIter {
        CertificateChainIter {
            idx: 0,
            // Cache the length as it's O(n) to compute it, the chain is stored as a linked list.
            // It shouldn't change while we have access to the iterator.
            len: self.len(),
            chain: self,
        }
    }

    /// Return the length of this certificate chain.
    ///
    /// Note that the underyling API currently traverses a linked list, so this is a relatively
    /// expensive API to call.
    pub fn len(&self) -> usize {
        let mut length: u32 = 0;
        let res =
            unsafe { s2n_cert_chain_get_length(self.as_const_s2n_ptr(), &mut length).into_result() };
        if res.is_err() {
            // Errors should only happen on empty chains (we guarantee that `ptr` is a valid chain).
            return 0;
        }
        // u32 should always fit into usize on the platforms we support.
        length.try_into().unwrap()
    }

    /// Check if the certificate chain has any certificates.
    ///
    /// Note that the underyling API currently traverses a linked list, so this is a relatively
    /// expensive API to call.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn from_s2n_ptr(ptr: &s2n_cert_chain_and_key) -> &Self {
        // SAFETY: casting *s2n_client_hello <-> *ClientHello: For repr(Rust),
        // repr(packed(N)), repr(align(N)), and repr(C) structs: if all fields of a
        // struct have size 0, then the struct has size 0.
        // https://rust-lang.github.io/unsafe-code-guidelines/layout/structs-and-tuples.html#zero-sized-structs
        unsafe { &*(ptr as *const _ as *const _) }
    }
    pub(crate) fn as_s2n_ptr(&mut self) -> *mut s2n_cert_chain_and_key {
        self as *const _ as *mut _
    }

    pub(crate) fn as_const_s2n_ptr(&self) -> *const s2n_cert_chain_and_key {
        self as *const _ as *const _
    }
}

// # Safety
//
// s2n_cert_chain_and_key objects can be sent across threads.
unsafe impl Send for CertificateChain {}

pub struct CertificateChainIter<'a> {
    idx: u32,
    len: usize,
    chain: &'a CertificateChainRef,
}

impl<'a> Iterator for CertificateChainIter<'a> {
    type Item = Result<&'a CertificateRef, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.idx;
        // u32 fits into usize on platforms we support.
        if usize::try_from(idx).unwrap() >= self.len {
            return None;
        }
        self.idx += 1;
        let mut out = ptr::null_mut();
        unsafe {
            if let Err(e) =
                s2n_cert_chain_get_cert(self.chain.as_const_s2n_ptr(), &mut out, idx).into_result()
            {
                return Some(Err(e));
            }
        }
        let out = match NonNull::new(out) {
            Some(out) => out,
            None => return Some(Err(Error::INVALID_INPUT)),
        };
        Some(Ok(CertificateRef::from_s2n_ptr(unsafe { out.as_ref() })))
    }
}

pub struct CertificateRef(Opaque);

impl CertificateRef {
    pub(crate) fn as_const_s2n_ptr(&self) -> *const s2n_cert {
        self as *const _ as *const _
    }

    pub(crate) fn from_s2n_ptr(ptr: &s2n_cert) -> &Self {
        unsafe { &*(ptr as *const _ as *const _) }
    }

    pub fn der(&self) -> Result<&[u8], Error> {
        unsafe {
            let mut buffer = ptr::null();
            let mut length = 0;
            s2n_cert_get_der(self.as_const_s2n_ptr(), &mut buffer, &mut length).into_result()?;
            let length = usize::try_from(length).map_err(|_| Error::INVALID_INPUT)?;

            Ok(std::slice::from_raw_parts(buffer, length))
        }
    }
}

// # Safety
//
// Certificates just reference data in the chain, so share the Send-ness of the chain.
unsafe impl Send for CertificateRef {}
