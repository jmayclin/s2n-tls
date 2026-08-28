// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Re-derivation of record keys and fixed IVs from serialized secrets.
//!
//! The serialized connection blob stores *secrets*, not record keys. To program
//! the kernel we must re-derive the AEAD keys and fixed IVs, exactly as s2n-tls
//! does when it enables kTLS:
//!
//! - TLS1.2 (`tls/s2n_prf.c`): the PRF "key expansion" over the master secret
//!   with seed `server_random || client_random`, producing (for an AEAD suite
//!   with no MAC) `client_key || server_key || client_iv || server_iv`, where
//!   each IV is the 4-byte implicit/fixed IV.
//! - TLS1.3 (`tls/s2n_tls13_key_schedule.c`): per-direction
//!   `HKDF-Expand-Label(secret, "key", "", key_len)` and
//!   `HKDF-Expand-Label(secret, "iv", "", 12)`.
//!
//! Derivation is expressed in terms of client/server roles (mirroring s2n-tls's
//! `s2n_key_material`). Mapping a role to the kernel TX/RX direction is the
//! responsibility of the caller, since it depends on the connection's mode
//! (client vs server), which is not part of the serialized blob.

use aws_lc_rs::{hkdf, tls_prf};

use crate::protocol::serialization::{
    HashAlgorithm, ProtocolVersion, Secrets, SerializedConnection,
};
use crate::Error;

/// The TLS1.3 fixed IV length (bytes). Both AES-GCM and ChaCha20 use 12.
pub const TLS13_FIXED_IV_LEN: usize = 12;
/// The TLS1.2 AEAD implicit (fixed) IV length (bytes). This is the GCM salt.
pub const TLS12_FIXED_IV_LEN: usize = 4;

/// Record keys and fixed IVs for both roles.
///
/// `client_*` is the key material the client uses to *write* (and the server
/// uses to *read*); `server_*` is the reverse.
#[derive(Clone)]
pub struct DerivedKeys {
    /// Client write key.
    pub client_key: Vec<u8>,
    /// Server write key.
    pub server_key: Vec<u8>,
    /// Client fixed IV (4 bytes for TLS1.2, 12 for TLS1.3).
    pub client_iv: Vec<u8>,
    /// Server fixed IV (4 bytes for TLS1.2, 12 for TLS1.3).
    pub server_iv: Vec<u8>,
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret key material. Only lengths.
        f.debug_struct("DerivedKeys")
            .field("key_len", &self.client_key.len())
            .field("iv_len", &self.client_iv.len())
            .finish()
    }
}

impl DerivedKeys {
    /// Derive record keys and fixed IVs from a parsed serialized connection.
    pub fn derive(conn: &SerializedConnection) -> Result<Self, Error> {
        let key_len = conn.cipher_suite.aead().key_len();
        match (&conn.secrets, conn.protocol_version) {
            (
                Secrets::Tls12 {
                    master_secret,
                    client_random,
                    server_random,
                },
                ProtocolVersion::Tls12,
            ) => derive_tls12(
                master_secret,
                client_random,
                server_random,
                conn.cipher_suite.hash(),
                key_len,
            ),
            (
                Secrets::Tls13 {
                    client_application_secret,
                    server_application_secret,
                    ..
                },
                ProtocolVersion::Tls13,
            ) => derive_tls13(
                client_application_secret,
                server_application_secret,
                conn.cipher_suite.hash(),
                key_len,
            ),
            _ => Err(Error::InvalidSerialization(
                "protocol version and secrets variant disagree",
            )),
        }
    }
}

fn tls12_prf_algorithm(hash: HashAlgorithm) -> &'static tls_prf::Algorithm {
    match hash {
        HashAlgorithm::Sha256 => &tls_prf::P_SHA256,
        HashAlgorithm::Sha384 => &tls_prf::P_SHA384,
    }
}

/// TLS1.2 "key expansion" PRF. See `s2n_prf_generate_key_material`.
fn derive_tls12(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    hash: HashAlgorithm,
    key_len: usize,
) -> Result<DerivedKeys, Error> {
    // AEAD suites have no MAC key. The key block layout is:
    //   client_key || server_key || client_iv || server_iv
    // where the IV is the 4-byte implicit (fixed) IV.
    let block_len = key_len * 2 + TLS12_FIXED_IV_LEN * 2;

    let secret = tls_prf::Secret::new(tls12_prf_algorithm(hash), master_secret)
        .map_err(|_| Error::Crypto("invalid master secret for PRF"))?;

    // The seed is server_random || client_random (note the order).
    let block = secret
        .derive_with_seed_concatination(b"key expansion", server_random, client_random, block_len)
        .map_err(|_| Error::Crypto("TLS1.2 PRF derivation failed"))?;
    let block = block.as_ref();

    let (client_key, rest) = block.split_at(key_len);
    let (server_key, rest) = rest.split_at(key_len);
    let (client_iv, server_iv) = rest.split_at(TLS12_FIXED_IV_LEN);

    Ok(DerivedKeys {
        client_key: client_key.to_vec(),
        server_key: server_key.to_vec(),
        client_iv: client_iv.to_vec(),
        server_iv: server_iv.to_vec(),
    })
}

/// TLS1.3 traffic key derivation. See `s2n_tls13_key_schedule_get_keying_material`.
fn derive_tls13(
    client_application_secret: &[u8],
    server_application_secret: &[u8],
    hash: HashAlgorithm,
    key_len: usize,
) -> Result<DerivedKeys, Error> {
    let (client_key, client_iv) = tls13_key_and_iv(client_application_secret, hash, key_len)?;
    let (server_key, server_iv) = tls13_key_and_iv(server_application_secret, hash, key_len)?;
    Ok(DerivedKeys {
        client_key,
        server_key,
        client_iv,
        server_iv,
    })
}

fn hkdf_algorithm(hash: HashAlgorithm) -> hkdf::Algorithm {
    match hash {
        HashAlgorithm::Sha256 => hkdf::HKDF_SHA256,
        HashAlgorithm::Sha384 => hkdf::HKDF_SHA384,
    }
}

fn tls13_key_and_iv(
    secret: &[u8],
    hash: HashAlgorithm,
    key_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let key = hkdf_expand_label(secret, hash, b"key", key_len)?;
    let iv = hkdf_expand_label(secret, hash, b"iv", TLS13_FIXED_IV_LEN)?;
    Ok((key, iv))
}

/// `HKDF-Expand-Label` per RFC 8446 section 7.1, with an empty context.
///
/// ```text
/// HkdfLabel = u16(length)
///           || u8(len("tls13 " + label)) || "tls13 " || label
///           || u8(len(context))          || context
/// ```
fn hkdf_expand_label(
    secret: &[u8],
    hash: HashAlgorithm,
    label: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, Error> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let full_label_len = LABEL_PREFIX.len() + label.len();
    if full_label_len > 255 || out_len > u16::MAX as usize {
        return Err(Error::Crypto("HKDF label or length out of range"));
    }

    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    // Empty context: single zero-length byte.
    info.push(0);

    let prk = hkdf::Prk::new_less_safe(hkdf_algorithm(hash), secret);
    let info_slices: [&[u8]; 1] = [&info];
    let okm = prk
        .expand(&info_slices, OutLen(out_len))
        .map_err(|_| Error::Crypto("HKDF-Expand-Label failed"))?;

    let mut out = vec![0u8; out_len];
    okm.fill(&mut out)
        .map_err(|_| Error::Crypto("HKDF-Expand-Label fill failed"))?;
    Ok(out)
}

/// A [`hkdf::KeyType`] wrapper for an arbitrary output length.
struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8448 section 3, "server application_traffic_secret_0" and the
    /// AES-128-GCM key/iv derived from it via HKDF-Expand-Label. This pins our
    /// HkdfLabel encoding and expansion to a published test vector.
    /// See https://www.rfc-editor.org/rfc/rfc8448#section-3
    #[test]
    fn tls13_hkdf_expand_label_rfc8448() {
        let secret = hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");

        let key = hkdf_expand_label(&secret, HashAlgorithm::Sha256, b"key", 16).unwrap();
        let iv = hkdf_expand_label(&secret, HashAlgorithm::Sha256, b"iv", 12).unwrap();

        assert_eq!(key, hex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56"));
        assert_eq!(iv, hex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84"));
    }

    /// RFC 8448 section 3, "client application_traffic_secret_0" key/iv.
    #[test]
    fn tls13_hkdf_expand_label_rfc8448_client() {
        let secret =
            hex("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5");

        let key = hkdf_expand_label(&secret, HashAlgorithm::Sha256, b"key", 16).unwrap();
        let iv = hkdf_expand_label(&secret, HashAlgorithm::Sha256, b"iv", 12).unwrap();

        assert_eq!(key, hex("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51"));
        assert_eq!(iv, hex("5b 78 92 3d ee 08 57 90 33 e5 23 d9"));
    }

    /// The TLS1.2 PRF key block must have the expected structure: two keys of
    /// `key_len` and two 4-byte fixed IVs. This is a self-consistency /
    /// shape test; end-to-end correctness is verified against the kernel in the
    /// integration tests.
    #[test]
    fn tls12_key_block_shape() {
        let master = vec![0x0b; 48];
        let client_random = vec![0x11; 32];
        let server_random = vec![0x22; 32];

        for (hash, key_len) in [(HashAlgorithm::Sha256, 16), (HashAlgorithm::Sha384, 32)] {
            let keys =
                derive_tls12(&master, &client_random, &server_random, hash, key_len).unwrap();
            assert_eq!(keys.client_key.len(), key_len);
            assert_eq!(keys.server_key.len(), key_len);
            assert_eq!(keys.client_iv.len(), TLS12_FIXED_IV_LEN);
            assert_eq!(keys.server_iv.len(), TLS12_FIXED_IV_LEN);
            // Client and server keys must differ.
            assert_ne!(keys.client_key, keys.server_key);
        }
    }
}
