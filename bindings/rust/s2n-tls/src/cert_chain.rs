// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Fallible};
use s2n_tls_sys::*;
use std::{
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::Arc,
};

struct CertificateChainHandle(pub NonNull<s2n_cert_chain_and_key>);

impl Drop for CertificateChainHandle {
    fn drop(&mut self) {
        // ignore failures since there's not much we can do about it
        unsafe {
            let _ = s2n_cert_chain_and_key_free(self.0.as_ptr()).into_result();
        }
    }
}

/// A CertificateChain represents a chain of X.509 certificates.
///
/// Certificate chains are internally reference counted and are cheaply cloneable.
#[derive(Clone)]
pub struct CertificateChain<'a> {
    ptr: Arc<CertificateChainHandle>,
    _lifetime: PhantomData<&'a s2n_cert_chain_and_key>,
}

impl CertificateChain<'_> {
    pub fn load_pems(cert: &[u8], key: &[u8]) -> Result<CertificateChain<'static>, Error> {
        let mut chain = Self::allocate_owned()?;
        unsafe {
            s2n_cert_chain_and_key_load_pem_bytes(
                chain.as_mut_ptr().as_ptr(),
                cert.as_ptr() as *mut _,
                cert.len() as u32,
                key.as_ptr() as *mut _,
                key.len() as u32,
            )
            .into_result()
        }?;

        Ok(chain)
    }

    /// This allocates a new certificate chain from s2n.
    pub(crate) fn allocate_owned() -> Result<CertificateChain<'static>, Error> {
        unsafe {
            let ptr = s2n_cert_chain_and_key_new().into_result()?;
            Ok(CertificateChain {
                ptr: Arc::new(CertificateChainHandle(ptr)),
                _lifetime: PhantomData,
            })
        }
    }

    pub(crate) unsafe fn from_ptr_reference<'a>(
        ptr: NonNull<s2n_cert_chain_and_key>,
    ) -> CertificateChain<'a> {
        let handle = Arc::new(CertificateChainHandle(ptr));

        // This is a reference. When this CertificateChain goes out of scope, the
        // data must not be freed. We have to manually increment the reference
        // count to allow for the "reference" held by the s2n_connection.
        let clone_to_increment_refcount = Arc::clone(&handle);
        std::mem::forget(clone_to_increment_refcount);
        // handle & owning struct
        debug_assert_eq!(Arc::strong_count(&handle), 2);

        CertificateChain {
            ptr: handle,
            _lifetime: PhantomData,
        }
    }

    pub fn iter(&self) -> CertificateChainIter<'_> {
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
            unsafe { s2n_cert_chain_get_length(self.ptr.0.as_ptr(), &mut length).into_result() };
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

    pub(crate) fn as_mut_ptr(&mut self) -> NonNull<s2n_cert_chain_and_key> {
        self.ptr.0
    }

    pub(crate) fn as_ptr(&self) -> *const s2n_cert_chain_and_key {
        self.ptr.0.as_ptr() as *const _
    }
}

// # Safety
//
// s2n_cert_chain_and_key objects can be sent across threads.
unsafe impl Send for CertificateChain<'_> {}
unsafe impl Sync for CertificateChain<'_> {}

pub struct CertificateChainIter<'a> {
    idx: u32,
    len: usize,
    chain: &'a CertificateChain<'a>,
}

impl<'a> Iterator for CertificateChainIter<'a> {
    type Item = Result<Certificate<'a>, Error>;

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
                s2n_cert_chain_get_cert(self.chain.ptr.0.as_ptr(), &mut out, idx).into_result()
            {
                return Some(Err(e));
            }
        }
        let out = match NonNull::new(out) {
            Some(out) => out,
            None => return Some(Err(Error::INVALID_INPUT)),
        };
        Some(Ok(Certificate {
            chain: PhantomData,
            certificate: out,
        }))
    }
}

pub struct Certificate<'a> {
    // The chain owns the memory for this certificate.
    chain: PhantomData<&'a CertificateChain<'a>>,

    certificate: NonNull<s2n_cert>,
}

impl<'a> Certificate<'a> {
    pub fn der(&self) -> Result<&[u8], Error> {
        unsafe {
            let mut buffer = ptr::null();
            let mut length = 0;
            s2n_cert_get_der(self.certificate.as_ptr(), &mut buffer, &mut length).into_result()?;
            let length = usize::try_from(length).map_err(|_| Error::INVALID_INPUT)?;

            Ok(std::slice::from_raw_parts(buffer, length))
        }
    }
}

// # Safety
//
// Certificates just reference data in the chain, so share the Send-ness of the chain.
unsafe impl Send for Certificate<'_> {}

#[cfg(test)]
mod tests {
    use crate::{
        config,
        security::{Policy, DEFAULT_TLS13},
        testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler, TestPair},
    };

    use super::*;

    #[test]
    fn ref_counts() -> Result<(), crate::error::Error> {
        let cert = CertKeyPair::default();

        let chain = CertificateChain::load_pems(cert.cert(), cert.key())?;
        assert_eq!(Arc::strong_count(&chain.ptr), 1);

        let mut list = Vec::new();
        for _ in 0..10 {
            list.push(chain.clone());
        }
        assert_eq!(Arc::strong_count(&chain.ptr), 1 + 10);
        drop(list);
        assert_eq!(Arc::strong_count(&chain.ptr), 1);

        Ok(())
    }

    #[test]
    fn sanity_check() -> Result<(), crate::error::Error> {
        let cert = CertKeyPair::default();

        {
            let mut server = config::Builder::new();
            server.set_security_policy(&DEFAULT_TLS13)?;
            server.load_pem(cert.cert(), cert.key())?;

            let mut client = config::Builder::new();
            client.set_security_policy(&DEFAULT_TLS13)?;
            client.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
            client.trust_pem(cert.cert())?;

            let mut pair = TestPair::from_configs(&client.build()?, &server.build()?);

            pair.handshake().unwrap();
        }

        Ok(())
    }

    #[test]
    fn config_drop() -> Result<(), crate::error::Error> {
        let cert = CertKeyPair::default();

        let chain = CertificateChain::load_pems(cert.cert(), cert.key())?;

        // cert on a single config
        {
            let mut server = config::Builder::new();
            server.set_security_policy(&DEFAULT_TLS13)?;
            server.add_to_store(chain.clone())?;
            server.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
            server.trust_pem(cert.cert())?;

            // after being added, the reference count should have increased
            assert_eq!(Arc::strong_count(&chain.ptr), 2);

            let mut pair = TestPair::from_config(&server.build()?);
            assert!(pair.handshake().is_ok());

            assert_eq!(Arc::strong_count(&chain.ptr), 2);
        }
        // after the config goes out of scope and is dropped, the ref count should
        // decrement
        assert_eq!(Arc::strong_count(&chain.ptr), 1);
        {
            
        // cert on a single config
        {
            let mut server = config::Builder::new();
            server.set_security_policy(&DEFAULT_TLS13)?;
            server.add_to_store(chain.clone())?;
            server.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
            server.trust_pem(cert.cert())?;

            // after being added, the reference count should have increased
            assert_eq!(Arc::strong_count(&chain.ptr), 2);

            let mut pair = TestPair::from_config(&server.build()?);
            assert!(pair.handshake().is_ok());

            assert_eq!(Arc::strong_count(&chain.ptr), 2);
        }
        }


        Ok(())
    }
}
