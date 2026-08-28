// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Construction of the kernel `crypto_info` byte layouts.
//!
//! These mirror `struct tls12_crypto_info_aes_gcm_128` /
//! `struct tls12_crypto_info_aes_gcm_256` from `<linux/tls.h>` and are passed
//! directly to `setsockopt(SOL_TLS, TLS_TX | TLS_RX, ...)`.
//!
//! The C struct is:
//! ```c
//! struct tls_crypto_info { __u16 version; __u16 cipher_type; };
//! struct tls12_crypto_info_aes_gcm_128 {
//!     struct tls_crypto_info info;
//!     unsigned char iv[8];
//!     unsigned char key[16];
//!     unsigned char salt[4];
//!     unsigned char rec_seq[8];
//! };
//! ```
//! (AES-256 is identical except `key` is 32 bytes.)
//!
//! `version` and `cipher_type` are `__u16` read by the kernel as host-order
//! integers, so they are encoded in **native** byte order. The remaining
//! fields are raw bytes.
//!
//! Field derivation (matching `crypto/s2n_aead_cipher_aes_gcm.c`):
//! - TLS1.2 GCM: `salt` = the 4-byte implicit/fixed IV; `iv` = sequence number;
//!   `rec_seq` = sequence number.
//! - TLS1.3 GCM: the 12-byte fixed IV is split `salt` = first 4 bytes,
//!   `iv` = last 8 bytes; `rec_seq` = sequence number.

use crate::protocol::serialization::{AeadAlgorithm, ProtocolVersion};
use crate::Error;

/// `TLS_1_2_VERSION` from `<linux/tls.h>` (0x0303).
const TLS_1_2_VERSION: u16 = 0x0303;
/// `TLS_1_3_VERSION` from `<linux/tls.h>` (0x0304).
const TLS_1_3_VERSION: u16 = 0x0304;

/// `TLS_CIPHER_AES_GCM_128` from `<linux/tls.h>`.
const TLS_CIPHER_AES_GCM_128: u16 = 51;
/// `TLS_CIPHER_AES_GCM_256` from `<linux/tls.h>`.
const TLS_CIPHER_AES_GCM_256: u16 = 52;

/// Kernel field sizes (identical across AES-128 and AES-256 except the key).
const IV_SIZE: usize = 8;
const SALT_SIZE: usize = 4;
const REC_SEQ_SIZE: usize = 8;

/// A `setsockopt(SOL_TLS, ...)`-ready `crypto_info` byte buffer.
///
/// Deliberately does not derive `Debug` printing of contents, since it embeds
/// the record key.
pub struct CryptoInfo {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for CryptoInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoInfo")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl CryptoInfo {
    /// The raw bytes to pass as the `optval` of `setsockopt`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build the `crypto_info` for a single direction.
    ///
    /// `key` is the derived AEAD key, `fixed_iv` is the derived fixed IV (4
    /// bytes for TLS1.2, 12 bytes for TLS1.3), and `sequence_number` is the
    /// 8-byte record sequence number for this direction.
    pub fn build(
        protocol_version: ProtocolVersion,
        aead: AeadAlgorithm,
        key: &[u8],
        fixed_iv: &[u8],
        sequence_number: &[u8; REC_SEQ_SIZE],
    ) -> Result<Self, Error> {
        let key_size = aead.key_len();
        if key.len() != key_size {
            return Err(Error::Crypto("derived key has unexpected length"));
        }

        let (version, cipher_type) = match (protocol_version, aead) {
            (ProtocolVersion::Tls12, AeadAlgorithm::Aes128Gcm) => {
                (TLS_1_2_VERSION, TLS_CIPHER_AES_GCM_128)
            }
            (ProtocolVersion::Tls12, AeadAlgorithm::Aes256Gcm) => {
                (TLS_1_2_VERSION, TLS_CIPHER_AES_GCM_256)
            }
            (ProtocolVersion::Tls13, AeadAlgorithm::Aes128Gcm) => {
                (TLS_1_3_VERSION, TLS_CIPHER_AES_GCM_128)
            }
            (ProtocolVersion::Tls13, AeadAlgorithm::Aes256Gcm) => {
                (TLS_1_3_VERSION, TLS_CIPHER_AES_GCM_256)
            }
        };

        // Derive the kernel `iv` (8 bytes) and `salt` (4 bytes) fields.
        let (iv_field, salt_field): ([u8; IV_SIZE], [u8; SALT_SIZE]) = match protocol_version {
            ProtocolVersion::Tls12 => {
                // salt = 4-byte fixed IV; iv = sequence number.
                if fixed_iv.len() != SALT_SIZE {
                    return Err(Error::Crypto("TLS1.2 fixed IV must be 4 bytes"));
                }
                let mut salt = [0u8; SALT_SIZE];
                salt.copy_from_slice(fixed_iv);
                (*sequence_number, salt)
            }
            ProtocolVersion::Tls13 => {
                // 12-byte fixed IV split: salt = first 4, iv = last 8.
                if fixed_iv.len() != SALT_SIZE + IV_SIZE {
                    return Err(Error::Crypto("TLS1.3 fixed IV must be 12 bytes"));
                }
                let mut salt = [0u8; SALT_SIZE];
                salt.copy_from_slice(&fixed_iv[..SALT_SIZE]);
                let mut iv = [0u8; IV_SIZE];
                iv.copy_from_slice(&fixed_iv[SALT_SIZE..]);
                (iv, salt)
            }
        };

        let mut bytes = Vec::with_capacity(4 + IV_SIZE + key_size + SALT_SIZE + REC_SEQ_SIZE);
        // struct tls_crypto_info: version, cipher_type (native-endian u16).
        bytes.extend_from_slice(&version.to_ne_bytes());
        bytes.extend_from_slice(&cipher_type.to_ne_bytes());
        // iv, key, salt, rec_seq (raw bytes).
        bytes.extend_from_slice(&iv_field);
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&salt_field);
        bytes.extend_from_slice(sequence_number);

        Ok(CryptoInfo { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Field offsets within the serialized struct.
    const OFF_VERSION: usize = 0;
    const OFF_CIPHER: usize = 2;
    const OFF_IV: usize = 4;
    const OFF_KEY: usize = OFF_IV + IV_SIZE;

    fn build(
        version: ProtocolVersion,
        aead: AeadAlgorithm,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, [u8; 8]) {
        let key = vec![0xAAu8; aead.key_len()];
        let fixed_iv = match version {
            ProtocolVersion::Tls12 => vec![0x11u8; 4],
            ProtocolVersion::Tls13 => (0..12u8).collect(),
        };
        let seq = [1, 2, 3, 4, 5, 6, 7, 8];
        let info = CryptoInfo::build(version, aead, &key, &fixed_iv, &seq).unwrap();
        (info.as_bytes().to_vec(), key, fixed_iv, seq)
    }

    fn expected_total_len(aead: AeadAlgorithm) -> usize {
        4 + IV_SIZE + aead.key_len() + SALT_SIZE + REC_SEQ_SIZE
    }

    #[test]
    fn all_four_combinations_have_expected_size() {
        for version in [ProtocolVersion::Tls12, ProtocolVersion::Tls13] {
            for aead in [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm] {
                let (bytes, ..) = build(version, aead);
                assert_eq!(
                    bytes.len(),
                    expected_total_len(aead),
                    "version {version:?} aead {aead:?}"
                );
            }
        }
    }

    #[test]
    fn sizes_match_kernel_struct_constants() {
        // sizeof(struct tls12_crypto_info_aes_gcm_128) == 40
        // sizeof(struct tls12_crypto_info_aes_gcm_256) == 56
        assert_eq!(expected_total_len(AeadAlgorithm::Aes128Gcm), 40);
        assert_eq!(expected_total_len(AeadAlgorithm::Aes256Gcm), 56);
    }

    #[test]
    fn version_and_cipher_tags() {
        let (bytes, ..) = build(ProtocolVersion::Tls12, AeadAlgorithm::Aes128Gcm);
        assert_eq!(
            &bytes[OFF_VERSION..OFF_VERSION + 2],
            &TLS_1_2_VERSION.to_ne_bytes()
        );
        assert_eq!(
            &bytes[OFF_CIPHER..OFF_CIPHER + 2],
            &TLS_CIPHER_AES_GCM_128.to_ne_bytes()
        );

        let (bytes, ..) = build(ProtocolVersion::Tls13, AeadAlgorithm::Aes256Gcm);
        assert_eq!(
            &bytes[OFF_VERSION..OFF_VERSION + 2],
            &TLS_1_3_VERSION.to_ne_bytes()
        );
        assert_eq!(
            &bytes[OFF_CIPHER..OFF_CIPHER + 2],
            &TLS_CIPHER_AES_GCM_256.to_ne_bytes()
        );
    }

    #[test]
    fn tls12_iv_is_seq_salt_is_fixed_iv() {
        let (bytes, key, fixed_iv, seq) = build(ProtocolVersion::Tls12, AeadAlgorithm::Aes128Gcm);
        let off_salt = OFF_KEY + key.len();
        let off_rec_seq = off_salt + SALT_SIZE;

        // iv == sequence number
        assert_eq!(&bytes[OFF_IV..OFF_IV + IV_SIZE], &seq);
        // key
        assert_eq!(&bytes[OFF_KEY..off_salt], &key[..]);
        // salt == fixed IV
        assert_eq!(&bytes[off_salt..off_rec_seq], &fixed_iv[..]);
        // rec_seq == sequence number
        assert_eq!(&bytes[off_rec_seq..off_rec_seq + REC_SEQ_SIZE], &seq);
    }

    #[test]
    fn tls13_iv_split_salt_and_iv() {
        let (bytes, key, fixed_iv, seq) = build(ProtocolVersion::Tls13, AeadAlgorithm::Aes256Gcm);
        let off_salt = OFF_KEY + key.len();
        let off_rec_seq = off_salt + SALT_SIZE;

        // iv == last 8 bytes of the 12-byte fixed IV
        assert_eq!(&bytes[OFF_IV..OFF_IV + IV_SIZE], &fixed_iv[SALT_SIZE..]);
        // salt == first 4 bytes of the fixed IV
        assert_eq!(&bytes[off_salt..off_rec_seq], &fixed_iv[..SALT_SIZE]);
        // rec_seq == sequence number
        assert_eq!(&bytes[off_rec_seq..off_rec_seq + REC_SEQ_SIZE], &seq);
    }

    #[test]
    fn rejects_wrong_key_length() {
        let short_key = vec![0u8; 8];
        let err = CryptoInfo::build(
            ProtocolVersion::Tls13,
            AeadAlgorithm::Aes128Gcm,
            &short_key,
            &[0u8; 12],
            &[0u8; 8],
        )
        .unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn rejects_wrong_fixed_iv_length() {
        // TLS1.3 requires a 12-byte fixed IV.
        let key = vec![0u8; 16];
        let err = CryptoInfo::build(
            ProtocolVersion::Tls13,
            AeadAlgorithm::Aes128Gcm,
            &key,
            &[0u8; 4],
            &[0u8; 8],
        )
        .unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }
}
