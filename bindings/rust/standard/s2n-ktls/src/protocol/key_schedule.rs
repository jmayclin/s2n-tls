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

use aws_lc_rs::hkdf;

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

        match &conn.secrets {
            Secrets::Tls12(secret) => {
                debug_assert_eq!(conn.protocol_version, ProtocolVersion::Tls12);
                secret.derive_tls12(conn.cipher_suite.hash(), key_len)
            }
            Secrets::Tls13(secret) => {
                debug_assert_eq!(conn.protocol_version, ProtocolVersion::Tls13);
                secret.derive_tls13(conn.cipher_suite.hash(), key_len)
            }
        }
    }
}

/// The current TLS 1.3 application traffic secrets, tracked across key updates.
///
/// The serialized connection blob only carries the *initial* application
/// traffic secrets. In TLS 1.3, either peer may send a `KeyUpdate` message at
/// any point after the handshake, deriving a new traffic secret for the
/// direction it writes with:
///
/// ```text
/// application_traffic_secret_N+1 =
///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
/// ```
///
/// Because that derivation is fully deterministic, `s2n-ktls` can maintain its
/// own copy of each direction's current secret and advance it whenever a key
/// update occurs, then re-derive the record key/IV and re-program the kernel.
/// This is what lets the crate handle key updates with **no runtime dependency
/// on s2n-tls**.
#[derive(Clone)]
pub struct TrafficSecrets {
    hash: HashAlgorithm,
    key_len: usize,
    /// The current client application traffic secret.
    client_secret: Vec<u8>,
    /// The current server application traffic secret.
    server_secret: Vec<u8>,
}

impl std::fmt::Debug for TrafficSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret material. Only lengths and parameters.
        f.debug_struct("TrafficSecrets")
            .field("hash", &self.hash)
            .field("key_len", &self.key_len)
            .field("secret_len", &self.client_secret.len())
            .finish()
    }
}

/// Which side's traffic secret to advance / derive keys for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRole {
    /// The client's write secret (the client encrypts, the server decrypts).
    Client,
    /// The server's write secret (the server encrypts, the client decrypts).
    Server,
}

impl TrafficSecrets {
    /// Capture the initial TLS 1.3 traffic secrets from a serialized connection.
    ///
    /// Returns `None` for a TLS 1.2 connection, which has no notion of a
    /// `KeyUpdate` and therefore does not need secret tracking.
    pub fn from_serialized(conn: &SerializedConnection) -> Option<Self> {
        match &conn.secrets {
            Secrets::Tls13(secret) => Some(TrafficSecrets {
                hash: conn.cipher_suite.hash(),
                key_len: conn.cipher_suite.aead().key_len(),
                client_secret: secret.client_application_secret.clone(),
                server_secret: secret.server_application_secret.clone(),
            }),
            Secrets::Tls12(_) => None,
        }
    }

    /// Advance the traffic secret for `role` to its next generation, applying
    /// the `"traffic upd"` derivation. This mirrors what the peer does when it
    /// sends a `KeyUpdate` (for a receiving role) or what we do when we send one
    /// (for a sending role).
    pub fn advance(&mut self, role: SecretRole) -> Result<(), Error> {
        let secret = match role {
            SecretRole::Client => &mut self.client_secret,
            SecretRole::Server => &mut self.server_secret,
        };
        *secret = tls13_update_traffic_secret(secret, self.hash)?;
        Ok(())
    }

    /// Derive the current record key and 12-byte fixed IV for `role`.
    pub fn derive_key_and_iv(&self, role: SecretRole) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let secret = match role {
            SecretRole::Client => &self.client_secret,
            SecretRole::Server => &self.server_secret,
        };
        tls13_derive_key_and_iv(secret, self.hash, self.key_len)
    }
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

/// Derive the AEAD key and 12-byte fixed IV from a single TLS 1.3 traffic
/// secret.
///
/// This is the per-direction primitive used both for the initial keys and
/// after a key update, when only one direction's secret has changed.
pub fn tls13_derive_key_and_iv(
    secret: &[u8],
    hash: HashAlgorithm,
    key_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    tls13_key_and_iv(secret, hash, key_len)
}

/// Advance a TLS 1.3 application traffic secret for a key update.
///
/// Per RFC 8446 section 7.2:
/// ```text
/// application_traffic_secret_N+1 =
///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
/// ```
///
/// This matches s2n-tls's `s2n_tls13_update_application_traffic_secret`
/// (`crypto/s2n_tls13_keys.c`), which uses the `"traffic upd"` label. Because
/// the derivation is fully deterministic, `s2n-ktls` can advance the secret and
/// re-program the kernel without any help from s2n-tls.
pub fn tls13_update_traffic_secret(secret: &[u8], hash: HashAlgorithm) -> Result<Vec<u8>, Error> {
    hkdf_expand_label(secret, hash, b"traffic upd", hash.digest_len())
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

    /// The `"traffic upd"` key update derivation, pinned against the vector in
    /// s2n-tls's `s2n_tls13_keys_test.c` (originally from OpenSSL's `s_client`
    /// KeyUpdate implementation, using `TLS_AES_256_GCM_SHA384`).
    #[test]
    fn tls13_update_traffic_secret_vector() {
        let application_secret = hex("4bc28934ddd802b00f479e14a72d7725dab45d32b3b145f29\
             e4c5b56677560eb5236b168c71c5c75aa52f3e20ee89bfb");
        let expected = hex("ee85dd54781bd4d8a100589a9fe6ac9a3797b811e977f549cd\
             531be2441d7c63e2b9729d145c11d84af35957727565a4");

        let updated =
            tls13_update_traffic_secret(&application_secret, HashAlgorithm::Sha384).unwrap();
        assert_eq!(updated, expected);
    }

    /// The TLS1.2 PRF key block must have the expected structure: two keys of
    /// `key_len` and two 4-byte fixed IVs. This is a self-consistency /
    /// shape test; end-to-end correctness is verified against the kernel in the
    /// integration tests.
    #[test]
    fn tls12_key_block_shape() {
        use crate::protocol::serialization::Tls12Secret;

        let master = vec![0x0b; 48];
        let client_random = vec![0x11; 32];
        let server_random = vec![0x22; 32];

        for (hash, key_len) in [(HashAlgorithm::Sha256, 16), (HashAlgorithm::Sha384, 32)] {
            let keys = Tls12Secret {
                master_secret: master.clone().try_into().unwrap(),
                client_random: client_random.clone().try_into().unwrap(),
                server_random: server_random.clone().try_into().unwrap(),
            }
            .derive_tls12(hash, key_len)
            .unwrap();
            assert_eq!(keys.client_key.len(), key_len);
            assert_eq!(keys.server_key.len(), key_len);
            assert_eq!(keys.client_iv.len(), TLS12_FIXED_IV_LEN);
            assert_eq!(keys.server_iv.len(), TLS12_FIXED_IV_LEN);
            // Client and server keys must differ.
            assert_ne!(keys.client_key, keys.server_key);
        }
    }
}
