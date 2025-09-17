// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::PrefixedBlob,
    KeyArn, AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN, PSK_IDENTITY_VALIDITY,
};
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM_SIV},
    digest::{self, digest},
    hkdf,
    hmac::Key,
    rand::SecureRandom,
};
use aws_sdk_kms::{primitives::Blob, types::MacAlgorithmSpec, Client};
use s2n_tls::error::Error as S2NError;
use std::{
    fmt::Debug,
    hash::Hash,
    io::ErrorKind,
    time::{Duration, SystemTime},
};
const SHA384_DIGEST_SIZE: usize = 48;
const EPOCH_DURATION: Duration = Duration::from_secs(3_600 * 24);

// V1 was used for an earlier KMS data-key based solution
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum PskVersion {
    V2 = 2,
}

impl EncodeValue for PskVersion {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        let byte = *self as u8;
        buffer.encode_value(&byte)?;
        Ok(())
    }
}

impl DecodeValue for PskVersion {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, buffer) = u8::decode_from(buffer)?;
        match value {
            2 => Ok((Self::V2, buffer)),
            _ => Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("{value} is not a valid KmsPskFormat"),
            )),
        }
    }
}

const SESSION_NAME_LENGTH: usize = 16;
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EpochSecret {
    /// the key epoch, which is the number of days elapsed since the unix epoch
    pub key_arn: KeyArn,
    pub key_epoch: u64,
    pub secret: Vec<u8>,
}

impl Debug for EpochSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochSecret")
            .field("key_arn", &self.key_arn)
            .field("key_epoch", &self.key_epoch)
            .field("secret", &"<REDACTED>")
            .finish()
    }
}

impl EpochSecret {
    pub async fn fetch_epoch_secret(
        kms_client: &Client,
        key_arn: &KeyArn,
        key_epoch: u64,
    ) -> anyhow::Result<Self> {
        let mac_output = kms_client
            .generate_mac()
            .key_id(key_arn.clone())
            .mac_algorithm(MacAlgorithmSpec::HmacSha384)
            .message(Blob::new(key_epoch.to_be_bytes()))
            .send()
            .await?;

        let secret = match mac_output.mac {
            Some(mac) => mac.into_inner(),
            // the KMS documentation implies that the ciphertext and plaintext
            // fields are required, although the SDK does not model them as such
            // https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html#API_GenerateMac_ResponseSyntax
            None => anyhow::bail!("failed to retrieve the Mac from the GenerateMac operation"),
        };

        println!("fetched epoch secret: {}, {}, {}", key_arn, key_epoch, hex::encode(&secret));

        Ok(Self {
            key_arn: key_arn.clone(),
            key_epoch,
            secret,
        })
    }

    #[cfg(test)]
    pub fn test_constructor(key_arn: KeyArn, key_epoch: u64, secret: Vec<u8>) -> Self {
        Self {
            key_arn,
            key_epoch,
            secret,
        }
    }

    pub fn current_epoch() -> u64 {
        // SAFETY: this method will panic if the current system clock is set to
        // a time before the unix epoch. This is not a recoverable error, so we
        // panic
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("expected system time to be after UNIX epoch");
        now.as_secs() / (3_600 * 24)
    }

    pub fn new_connection_psk(&self) -> Result<s2n_tls::psk::Psk, S2NError> {
        let session_name = {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let mut session_name = [0; SESSION_NAME_LENGTH];
            // TODO: no unwrap
            rng.fill(&mut session_name).unwrap();
            session_name
        };
        println!("new connection psk session: {}", hex::encode(session_name));

        let identity = PskIdentity::new(&session_name, self).unwrap();
        let secret = self.new_psk_secret(&session_name);
        Self::psk_from_parts(identity, secret)
    }

    pub(crate) fn new_psk_secret(&self, session_name: &[u8]) -> Vec<u8> {
        let null_salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]);
        let pseudo_random_key = null_salt.extract(&self.secret);
        // TODO: no unwrap
        let binding = [session_name];
        let session_secret = pseudo_random_key
            .expand(&binding, hkdf::HKDF_SHA384.hmac_algorithm())
            .unwrap();
        let mut session_secret_bytes = vec![0; SHA384_DIGEST_SIZE];
        session_secret.fill(&mut session_secret_bytes).unwrap();
        session_secret_bytes
    }

    pub(crate) fn psk_from_parts(
        identity: PskIdentity,
        secret: Vec<u8>,
    ) -> Result<s2n_tls::psk::Psk, S2NError> {
        let mut psk = s2n_tls::psk::Psk::builder()?;
        psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
        psk.set_identity(&identity.encode_to_vec().unwrap())?;
        psk.set_secret(&secret)?;
        Ok(psk.build()?)
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct PskIdentity {
    version: PskVersion,
    /// the key epoch that was used to derive the daily secret
    pub key_epoch: u64,
    /// the session name used to derive session specific keys
    pub session_name: PrefixedBlob<u16>,
    /// a value indicating the KMS key arn that was used
    kms_key_binder: PrefixedBlob<u16>,
}

impl Debug for PskIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PskIdentity")
            .field("version", &self.version)
            .field("key_epoch", &self.key_epoch)
            .field("session_name", &hex::encode(self.session_name.blob()))
            .field("kms_key_binder", &hex::encode(self.kms_key_binder.blob()))
            .finish()
    }
}

impl EncodeValue for PskIdentity {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.version)?;
        buffer.encode_value(&self.key_epoch)?;
        buffer.encode_value(&self.session_name)?;
        buffer.encode_value(&self.kms_key_binder)?;
        Ok(())
    }
}

impl DecodeValue for PskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (version, buffer) = buffer.decode_value()?;
        let (key_epoch, buffer) = buffer.decode_value()?;
        let (session_name, buffer) = buffer.decode_value()?;
        let (kms_key_binder, buffer) = buffer.decode_value()?;

        let value = Self {
            version,
            key_epoch,
            session_name,
            kms_key_binder,
        };

        Ok((value, buffer))
    }
}

impl PskIdentity {
    /// Create a PskIdentity
    ///
    /// * `ciphertext_data_key`: The ciphertext returned from the KMS generateDataKey
    ///   API.
    /// * `obfuscation_key`: The key that will be used to obfuscate the ciphertext,
    ///   preventing any details about the ciphertext from being on the wire.
    pub fn new(session_name: &[u8], daily_secret: &EpochSecret) -> anyhow::Result<Self> {
        let kms_key_binder = Self::obfuscate_kms_arn(session_name, daily_secret);
        let kms_key_binder = PrefixedBlob::new(kms_key_binder)?;
        let session_name = PrefixedBlob::new(session_name.to_vec())?;
        Ok(Self {
            version: PskVersion::V2,
            key_epoch: daily_secret.key_epoch,
            session_name,
            kms_key_binder,
        })
    }

    fn obfuscate_kms_arn(session_name: &[u8], daily_secret: &EpochSecret) -> Vec<u8> {
        let mut ctx = digest::Context::new(&digest::SHA384);
        ctx.update(&daily_secret.secret);
        ctx.update(session_name);
        ctx.update(daily_secret.key_arn.as_bytes());
        let kms_key_binder = ctx.finish();
        kms_key_binder.as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// serializing and deserializing a PSK Identity should result in the same struct
    #[test]
    fn round_trip() {
        let test_epoch_secret: EpochSecret =
            EpochSecret::test_constructor("a key arn".to_owned(), 15, vec![0, 1, 2, 3, 4]);

        let identity = PskIdentity::new(b"a session name", &test_epoch_secret).unwrap();
        let serialized_identity = identity.encode_to_vec().unwrap();

        let (deserialized_identity, remaining) =
            PskIdentity::decode_from(&serialized_identity).unwrap();
        assert!(remaining.is_empty());

        assert_eq!(deserialized_identity, identity);
    }

    // /// The encoded PSK Identity from the 0.0.1 version of the library was checked
    // /// in. If we ever fail to deserialize this STOP! You are about to make a
    // /// breaking change. You must find a way to make your change backwards
    // /// compatible.
    // #[test]
    // fn backwards_compatibility() {
    //     const ENCODED_IDENTITY: &[u8] = include_bytes!("../resources/psk_identity.bin");
    //     const CIPHERTEXT: &[u8] = b"this is a test KMS ciphertext";

    //     let (deserialized_identity, remaining) =
    //         PskIdentity::decode_from(ENCODED_IDENTITY).unwrap();
    //     assert!(remaining.is_empty());

    //     // The API is deliberately designed to make it difficult to avoid checking
    //     // the age of the PSK. This is still a useful test because age validation
    //     // happens after parsing everything. As long as we are seeing the age
    //     // error, then there is a high degree of confidence that there are no
    //     // backwards incompatible changes.
    //     let too_old_err = deserialized_identity
    //         .deobfuscate_datakey(&[CONSTANT_OBFUSCATION_KEY.clone()])
    //         .unwrap_err();

    //     // e.g. "too old: PSK age was 1762.201972884s, but must be less than 60s"
    //     assert!(too_old_err.to_string().contains("too old: PSK age was"));
    // }
}
