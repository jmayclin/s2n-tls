// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Fallible};
use s2n_tls_sys::*;
use std::fmt;

pub struct ExternalPsk(s2n_psk);

impl ExternalPsk {
    pub fn new(identity: &[u8], secret: &[u8]) -> Result<Box<Self>, Error> {
        let psk = unsafe {
            let psk = s2n_external_psk_new().into_result()?;

            let secret_length = secret
                .len()
                .try_into()
                .map_err(|e| Error::application("PSK secret of inappropriate size".into()))?;

            // https://www.rfc-editor.org/rfc/rfc9257.html#section-6
            // Each PSK ... MUST be at least 128 bits long
            // this check would ideally be in the C code, but would be a backwards incompatible change
            if secret_length < 16 {
                return Err(Error::application("PSK secret must be at least 128 bits".into()));
            }
            s2n_psk_set_secret(psk.as_ptr(), secret.as_ptr(), secret_length).into_result()?;

            let identity_length = identity
                .len()
                .try_into()
                .map_err(|e| Error::application("PSK identity of inappropriate size".into()))?;

            s2n_psk_set_identity(psk.as_ptr(), identity.as_ptr(), identity_length).into_result()?;

            psk
        };

        let psk = psk.as_ptr() as *mut ExternalPsk;
        unsafe { Ok(Box::from_raw(psk)) }
    }
}

impl Drop for ExternalPsk {
    fn drop(&mut self) {
        let mut external_psk: *mut s2n_psk = &mut self.0;
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe {
            s2n_psk_free(std::ptr::addr_of_mut!(external_psk)).into_result()
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let psk = ExternalPsk::new("bob".as_bytes(), "hehe i am a very secret value".as_bytes()).unwrap();
        drop(psk);
    }
}
