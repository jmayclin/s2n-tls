// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Fallible};
use s2n_tls_sys::*;
use std::{fmt, marker::PhantomData, ptr::NonNull};

const PSK_SECRET_BAD_LENGTH: &str = "PSK secret of inappropriate size";
const PSK_SECRET_TOO_SMALL: &str = "PSK secret must be at least 128 bits";
const PSK_IDENTITY_BAD_LENGTH: &str = "PSK identity of inappropriate size";

/// ExternalPsk represents an out-of-band pre-shared key. If two peers already have some
/// secret communication mechanism, then they can use ExternalPsks to authenticate rather
/// than certificates.
/// Invariants: an ExternalPsk contains no null pointers, and it's identity and material
/// are both valid values.
pub struct ExternalPsk(s2n_psk);

impl ExternalPsk {
    pub fn new(identity: &[u8], secret: &[u8]) -> Result<Box<Self>, Error> {
        let psk = ExternalPskBuilder::new()?
            .set_identity(identity)?
            .set_secret(secret)?;
        Ok(psk)
    }

    /// `wipe` will reuse the current PSK allocation, but change the identity and
    /// secret values. This is used in the PSK callback as we iterate over values
    /// in a list.
    fn wipe(psk: Box<Self>) -> ExternalPskBuilder<NeedsIdentity> {
        let psk_ptr = Box::into_raw(psk) as *mut s2n_psk;

        // safety: An ExternalPsk is guaranteed to be well formed, so it is safe
        // to assume that the ExternalPsk is not null
        let psk_ptr = NonNull::new(psk_ptr).unwrap();
        psk_ptr.into()
    }
}

struct NeedsIdentity;
struct NeedsSecret;

/// This builder is used to enforce the invariant that an External PSK always has
/// a valid identity and length set.
struct ExternalPskBuilder<T> {
    psk: NonNull<s2n_psk>,
    // This is used to indicate the "type state". E.g. What properties still
    // need to be set to ensure a valid PSK?
    marker: PhantomData<T>,
}

impl From<NonNull<s2n_psk>> for ExternalPskBuilder<NeedsIdentity> {
    fn from(psk: NonNull<s2n_psk>) -> Self {
        Self {
            psk,
            marker: PhantomData::<NeedsIdentity>,
        }
    }
}

impl ExternalPskBuilder<NeedsIdentity> {
    fn new() -> Result<Self, Error> {
        crate::init::init();
        let psk = unsafe { s2n_external_psk_new().into_result()? };
        Ok(ExternalPskBuilder::<NeedsIdentity> {
            psk,
            marker: PhantomData::<NeedsIdentity>,
        })
    }

    fn set_identity(self, identity: &[u8]) -> Result<ExternalPskBuilder<NeedsSecret>, Error> {
        let identity_length = identity
            .len()
            .try_into()
            .map_err(|_| Error::application(PSK_IDENTITY_BAD_LENGTH.into()))?;

        unsafe {
            s2n_psk_set_identity(self.psk.as_ptr(), identity.as_ptr(), identity_length)
                .into_result()?
        };

        Ok(ExternalPskBuilder {
            psk: self.psk,
            marker: PhantomData::<NeedsSecret>,
        })
    }
}

impl ExternalPskBuilder<NeedsSecret> {
    fn set_secret(self, secret: &[u8]) -> Result<Box<ExternalPsk>, Error> {
        let secret_length = secret
            .len()
            .try_into()
            .map_err(|_| Error::application(PSK_SECRET_BAD_LENGTH.into()))?;

        // https://www.rfc-editor.org/rfc/rfc9257.html#section-6
        // Each PSK ... MUST be at least 128 bits long
        // this check would ideally be in the C code, but would be a backwards incompatible change
        if secret_length < (128 / 8) {
            return Err(Error::application(PSK_SECRET_TOO_SMALL.into()));
        }

        unsafe {
            s2n_psk_set_secret(self.psk.as_ptr(), secret.as_ptr(), secret_length).into_result()?
        };

        let psk = self.psk.as_ptr() as *mut ExternalPsk;
        unsafe { Ok(Box::from_raw(psk)) }
    }
}

impl Drop for ExternalPsk {
    fn drop(&mut self) {
        let mut external_psk: *mut s2n_psk = &mut self.0;
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_psk_free(std::ptr::addr_of_mut!(external_psk)).into_result() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let psk =
            ExternalPsk::new("bob".as_bytes(), "hehe i am a very secret value".as_bytes()).unwrap();
        drop(psk);
    }
}
