// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::UnsafeCell,
    ops::Deref,
    ptr::{addr_of_mut, NonNull},
};

use crate::{
    connection::Connection,
    enums::PskHmac,
    error::{Error, ErrorType, Fallible},
};
use s2n_tls_sys::*;

#[derive(Debug)]
pub struct Builder {
    psk: ExternalPsk,
    has_identity: bool,
    has_secret: bool,
    has_hmac: bool,
}

impl Builder {
    pub fn new() -> Result<Self, crate::error::Error> {
        crate::init::init();
        let psk = ExternalPsk::allocate()?;
        Ok(Self {
            psk,
            has_identity: false,
            has_secret: false,
            has_hmac: false,
        })
    }

    pub fn with_identity(&mut self, identity: &[u8]) -> Result<&mut Self, crate::error::Error> {
        let identity_length = identity.len().try_into().map_err(|_| {
            Error::bindings(
                ErrorType::UsageError,
                "invalid psk identity",
                "The identity must be no longer than u16::MAX",
            )
        })?;
        unsafe {
            s2n_psk_set_identity(
                self.psk.as_s2n_ptr_mut(),
                identity.as_ptr(),
                identity_length,
            )
            .into_result()
        }?;
        self.has_identity = true;
        Ok(self)
    }

    pub fn with_secret(&mut self, secret: &[u8]) -> Result<&mut Self, crate::error::Error> {
        let secret_length = secret.len().try_into().map_err(|_| {
            Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "The secret must be no longer than u16::MAX",
            )
        })?;

        // This check would ideally be in the C code, but would be a backwards
        // incompatible change.
        //= https://www.rfc-editor.org/rfc/rfc9257.html#section-6
        //# Each PSK ... MUST be at least 128 bits long
        if secret_length < (128 / 8) {
            return Err(Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "PSK secret must be at least 128 bits",
            ));
        }
        // There are a number of application level errors that might result in an
        // all-zero secret accidentally getting used. Error if that happens.
        if secret.iter().all(|b| *b == 0) {
            return Err(Error::bindings(
                ErrorType::UsageError,
                "invalid psk secret",
                "PSK secret must not be all zeros",
            ));
        }
        unsafe {
            s2n_psk_set_secret(self.psk.as_s2n_ptr_mut(), secret.as_ptr(), secret_length)
                .into_result()
        }?;
        self.has_secret = true;
        Ok(self)
    }

    pub fn with_hmac(&mut self, hmac: PskHmac) -> Result<&mut Self, crate::error::Error> {
        unsafe { s2n_psk_set_hmac(self.psk.as_s2n_ptr_mut(), hmac.try_into()?).into_result() }?;
        self.has_hmac = true;
        Ok(self)
    }

    pub fn build(self) -> Result<ExternalPsk, crate::error::Error> {
        if !self.has_identity {
            Err(Error::bindings(
                crate::error::ErrorType::UsageError,
                "invalid psk",
                "You must set an identity using `with_identity`",
            ))
        } else if !self.has_secret {
            Err(Error::bindings(
                crate::error::ErrorType::UsageError,
                "invalid psk",
                "You must set a secret using `with_secret`",
            ))
        } else if !self.has_hmac {
            Err(Error::bindings(
                crate::error::ErrorType::UsageError,
                "invalid psk",
                "You must set an hmac `with_hmac`",
            ))
        } else {
            Ok(self.psk)
        }
    }
}

/// ExternalPsk represents an out-of-band pre-shared key.
///
/// If two peers already have some mechanism to securely exchange secrets, then
/// they can use ExternalPSKs to authenticate rather than certificates.
#[derive(Debug)]
pub struct ExternalPsk {
    ptr: NonNull<s2n_psk>,
}

unsafe impl Send for ExternalPsk {}
unsafe impl Sync for ExternalPsk {}

impl ExternalPsk {
    fn allocate() -> Result<Self, crate::error::Error> {
        let psk = unsafe { s2n_external_psk_new().into_result() }?;
        Ok(Self { ptr: psk })
    }

    pub(crate) fn as_s2n_ptr_mut(&mut self) -> *mut s2n_psk {
        self.ptr.as_ptr()
    }

    pub(crate) fn as_s2n_ptr(&self) -> *const s2n_psk {
        self.ptr.as_ptr() as *const s2n_psk
    }

    pub fn builder() -> Result<Builder, crate::error::Error> {
        Builder::new()
    }
}

impl Drop for ExternalPsk {
    fn drop(&mut self) {
        let mut external_psk: *mut s2n_psk = self.ptr.as_ptr();

        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_psk_free(std::ptr::addr_of_mut!(external_psk)).into_result() };
    }
}

pub(crate) struct OfferedPskListRef(s2n_offered_psk_list);

impl OfferedPskListRef {
    fn from_s2n_ptr_mut(ptr: &mut s2n_offered_psk_list) -> &mut Self {
        unsafe { &mut *(ptr as *mut s2n_offered_psk_list as *mut Self) }
    }

    fn as_s2n_ptr_mut(&mut self) -> *mut s2n_offered_psk_list {
        self.as_s2n_ptr() as *mut s2n_offered_psk_list
    }

    fn as_s2n_ptr(&self) -> *const s2n_offered_psk_list {
        self as *const OfferedPskListRef as *const s2n_offered_psk_list
    }

    fn has_next(&self) -> bool {
        unsafe { s2n_offered_psk_list_has_next(self.as_s2n_ptr()) }
    }

    fn next(&mut self, psk: &mut OfferedPsk) -> Result<(), crate::error::Error> {
        let psk_ptr = psk.as_s2n_ptr() as *mut s2n_offered_psk;
        unsafe { s2n_offered_psk_list_next(self.as_s2n_ptr_mut(), psk_ptr).into_result() }?;
        Ok(())
    }

    pub(crate) fn choose_psk(&mut self, psk: &OfferedPsk) -> Result<(), crate::error::Error> {
        let mut_psk = psk.as_s2n_ptr() as *mut s2n_offered_psk;
        unsafe { s2n_offered_psk_list_choose_psk(self.as_s2n_ptr_mut(), mut_psk).into_result()? };
        Ok(())
    }

    pub(crate) fn reread(&mut self) -> Result<(), crate::error::Error> {
        unsafe { s2n_offered_psk_list_reread(self.as_s2n_ptr_mut()).into_result() }?;
        Ok(())
    }
}

pub struct OfferedPskCursor<'callback> {
    pub(crate) psk: OfferedPsk,
    pub(crate) list: &'callback mut OfferedPskListRef,
}

impl<'callback> OfferedPskCursor<'callback> {
    /// Advance the cursor, returning the currently selected PSK.
    pub fn advance<'item>(&'item mut self) -> Option<&'item OfferedPsk> {
        if !self.list.has_next() {
            return None;
        } else {
            // TODO: fix the panic
            self.list.next(&mut self.psk).unwrap();
            Some(&self.psk)
        }
    }

    /// Choose the currently selected PSK to negotiate with.
    pub fn choose_current_psk(self) -> Result<(), crate::error::Error> {
        self.list.choose_psk(&self.psk)
    }

    pub fn rewind(&mut self) -> Result<(), crate::error::Error> {
        self.list.reread()?;
        Ok(())
    }
}

pub struct OfferedPsk {
    ptr: NonNull<s2n_offered_psk>,
}

impl Deref for OfferedPsk {
    type Target = OfferedPskRef;

    fn deref(&self) -> &Self::Target {
        OfferedPskRef::from_s2n_ptr_mut(self.ptr.as_ptr())
    }
}

impl Drop for OfferedPsk {
    fn drop(&mut self) {
        let mut s2n_ptr = self.ptr.as_ptr();
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_offered_psk_free(std::ptr::addr_of_mut!(s2n_ptr)).into_result() };
    }
}

impl OfferedPsk {
    pub(crate) fn allocate() -> Result<Self, crate::error::Error> {
        let ptr = unsafe { s2n_offered_psk_new().into_result() }?;
        Ok(Self { ptr })
    }
}

pub struct OfferedPskRef {
    _opaque: (),
}

impl OfferedPskRef {
    fn from_s2n_ptr_mut<'a>(ptr: *mut s2n_offered_psk) -> &'a mut Self {
        unsafe { &mut *(ptr as *mut Self) }
    }

    fn as_s2n_ptr(&self) -> *const s2n_offered_psk {
        self as *const Self as *const s2n_offered_psk
    }

    pub fn identity(&self) -> Result<&[u8], crate::error::Error> {
        let mut identity_buffer: *mut u8 = std::ptr::null::<u8>() as *mut u8;
        let mut size = 0;
        unsafe {
            s2n_offered_psk_get_identity(
                self.as_s2n_ptr(),
                addr_of_mut!(identity_buffer),
                &mut size,
            )
            .into_result()?
        };
        Ok(unsafe { std::slice::from_raw_parts(identity_buffer, size as usize) })
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::ErrorSource, testing::TestPair};

    use super::*;

    #[test]
    /// `identity`, `secret`, and `hmac` are all required fields. If any of them
    /// aren't set, then `psk.build()` operation should fail.
    fn build_errors() -> Result<(), crate::error::Error> {
        const PERMUTATIONS: u8 = 0b111;

        for bitfield in 0..PERMUTATIONS {
            let mut psk = Builder::new()?;
            if bitfield & 0b001 != 0 {
                psk.with_identity(b"Alice")?;
            }
            if bitfield & 0b010 != 0 {
                psk.with_secret(b"Rabbits don't actually jump. They instead push the world down")?;
            }
            if bitfield & 0b100 != 0 {
                psk.with_hmac(PskHmac::SHA384)?;
            }
            assert!(psk.build().is_err());
        }
        Ok(())
    }

    #[test]
    //= https://www.rfc-editor.org/rfc/rfc9257.html#section-6
    //= type=test
    //# Each PSK ... MUST be at least 128 bits long
    fn psk_secret_must_be_at_least_128_bits() -> Result<(), crate::error::Error> {
        // 120 bit key
        let secret = vec![5; 15];

        let mut psk = Builder::new()?;
        let err = psk.with_secret(&secret).unwrap_err();
        assert_eq!(err.source(), ErrorSource::Bindings);
        assert_eq!(err.kind(), ErrorType::UsageError);
        assert_eq!(err.name(), "invalid psk secret");
        assert_eq!(err.message(), "PSK secret must be at least 128 bits");
        Ok(())
    }

    fn test_psk() -> ExternalPsk {
        let mut builder = ExternalPsk::builder().unwrap();
        builder.with_identity(b"alice").unwrap();
        builder.with_secret(b"contrary to popular belief, the moon is flour, not cheese").unwrap();
        builder.with_hmac(PskHmac::SHA384).unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn psk_handshake() -> Result<(), crate::error::Error> {
        let psk = test_psk();
        let mut config = crate::config::Config::builder();
        config.set_security_policy(&crate::security::DEFAULT_TLS13)?;
        let config = config.build()?;
        let mut test_pair = TestPair::from_config(&config);
        test_pair.client.append_psk(&psk)?;
        test_pair.server.append_psk(&psk)?;
        assert!(test_pair.handshake().is_ok());
        Ok(())
    }
}
