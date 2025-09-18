// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::PrefixedBlob,
    KeyArn,
};
use aws_lc_rs::{
    digest::{self},
    hkdf,
    rand::SecureRandom,
};
use aws_sdk_kms::{primitives::Blob, types::MacAlgorithmSpec, Client};
use s2n_tls::error::Error as S2NError;
use std::{fmt::Debug, hash::Hash, io::ErrorKind, time::Duration};
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

    pub fn new_connection_psk(&self) -> Result<s2n_tls::psk::Psk, S2NError> {
        let session_name = {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let mut session_name = [0; SESSION_NAME_LENGTH];
            rng.fill(&mut session_name)
                .map_err(|_| S2NError::application("failed to create session name".into()))?;
            session_name
        };

        let identity =
            PskIdentity::new(&session_name, self).map_err(|e| S2NError::application(e.into()))?;
        let secret = self.new_psk_secret(&session_name)?;
        Self::psk_from_parts(identity, secret)
    }

    pub fn new_psk_secret(&self, session_name: &[u8]) -> Result<Vec<u8>, S2NError> {
        let null_salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]);
        let pseudo_random_key = null_salt.extract(&self.secret);
        let binding = [session_name];
        let session_secret = pseudo_random_key
            .expand(&binding, hkdf::HKDF_SHA384.hmac_algorithm())
            .map_err(|_| S2NError::application("PSK secret HKDF failed".into()))?;
        let mut session_secret_bytes = vec![0; SHA384_DIGEST_SIZE];
        session_secret
            .fill(&mut session_secret_bytes)
            .map_err(|_| S2NError::application("failed to extract key material".into()))?;
        Ok(session_secret_bytes)
    }

    pub fn psk_from_parts(
        identity: PskIdentity,
        secret: Vec<u8>,
    ) -> Result<s2n_tls::psk::Psk, S2NError> {
        let identity_bytes = identity.encode_to_vec().map_err(|e| {
            S2NError::application(format!("unable to encode PSK identity: {e:?}").into())
        })?;
        let mut psk = s2n_tls::psk::Psk::builder()?;
        psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
        psk.set_identity(&identity_bytes)?;
        psk.set_secret(&secret)?;
        psk.build()
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
    use std::time::Instant;

    use super::*;

    fn test_epoch_secret() -> EpochSecret {
EpochSecret::test_constructor(
            "arn:1234:abcd".to_owned(),
            123_456,
            b"secret material bytes".to_vec(),
        )
    }

    /// serializing and deserializing a PSK Identity should result in the same struct
    #[test]
    fn round_trip() {
        let identity = PskIdentity::new(b"a session name", &test_epoch_secret()).unwrap();
        let serialized_identity = identity.encode_to_vec().unwrap();

        let (deserialized_identity, remaining) =
            PskIdentity::decode_from(&serialized_identity).unwrap();
        assert!(remaining.is_empty());

        assert_eq!(deserialized_identity, identity);
    }

    /// The encoded PSK Identity from the 0.0.1 version of the library was checked
    /// in. If we ever fail to deserialize this STOP! You are about to make a
    /// breaking change. You must find a way to make your change backwards
    /// compatible.
    #[test]
    fn backwards_compatibility() {
        const ENCODED_IDENTITY: &[u8] = include_bytes!("../resources/psk_identity.bin");
        const SESSION_NAME: &[u8] = b"psk session name";

        let identity = PskIdentity::new(SESSION_NAME, &test_epoch_secret()).unwrap();

        let deserialized_identity = PskIdentity::decode_from_exact(ENCODED_IDENTITY).unwrap();
        assert_eq!(deserialized_identity, identity);
    }

    /// This is a very simple benchmark checking the cost of PSK Identity derivation
    /// We use this setup because it allows us to keep the EpochSecret struct private
    #[test]
    fn psk_derivation_cost() {
        let start = Instant::now();
        for i in 0_u64..1_000_000 {
            let identity = PskIdentity::new(&i.to_be_bytes(), &test_epoch_secret()).unwrap();
        }
        let elapsed = start.elapsed();
        println!("total time: {:?}, per derivation: {:?}", elapsed, elapsed / 1_000_000);
    }
}
