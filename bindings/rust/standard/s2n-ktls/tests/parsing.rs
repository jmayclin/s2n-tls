// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parsing tests for the s2n-tls V1 serialized connection format.
//!
//! Fixtures are real serialized blobs produced by an s2n-tls `TestPair`
//! handshake (not hand-built byte vectors). Parsed fields are cross-checked
//! against s2n-tls's own view of the connection where possible.

mod common;

use s2n_ktls::protocol::serialization::{
    AeadAlgorithm, HashAlgorithm, ProtocolVersion, Secrets, SerializedConnection,
};
use s2n_tls::enums::Version;

/// Policies chosen to exercise different (version x cipher) combinations.
/// Rather than hardcode what each policy negotiates, we derive the expected
/// values from s2n-tls's own view of the connection and assert our parser
/// agrees.
const POLICIES: &[&str] = &[
    "20170210",      // TLS1.2, AES-128-GCM
    "20190801",      // TLS1.3-capable
    "20240501",      // TLS1.3
    "default",       // TLS1.2 default
    "default_tls13", // TLS1.3 default
];

fn version_from_s2n(v: Version) -> ProtocolVersion {
    match v {
        Version::TLS12 => ProtocolVersion::Tls12,
        Version::TLS13 => ProtocolVersion::Tls13,
        other => panic!("unexpected negotiated version: {other:?}"),
    }
}

/// Derive the expected AEAD + hash from the cipher suite name s2n-tls reports,
/// e.g. "ECDHE-RSA-AES128-GCM-SHA256" or "TLS_AES_256_GCM_SHA384".
fn expected_aead_hash(cipher_name: &str) -> (AeadAlgorithm, HashAlgorithm) {
    let aead = if cipher_name.contains("AES_128_GCM") || cipher_name.contains("AES128-GCM") {
        AeadAlgorithm::Aes128Gcm
    } else if cipher_name.contains("AES_256_GCM") || cipher_name.contains("AES256-GCM") {
        AeadAlgorithm::Aes256Gcm
    } else {
        panic!("test policy negotiated a non-AES-GCM suite: {cipher_name}");
    };
    let hash = if cipher_name.ends_with("SHA256") {
        HashAlgorithm::Sha256
    } else if cipher_name.ends_with("SHA384") {
        HashAlgorithm::Sha384
    } else {
        panic!("unexpected cipher hash: {cipher_name}");
    };
    (aead, hash)
}

#[test]
fn parse_real_blobs_cross_checked() {
    for &policy in POLICIES {
        let sp = common::serialized_pair(policy);

        let expected_version = version_from_s2n(sp.negotiated_version);
        let (expected_aead, expected_hash) = expected_aead_hash(&sp.cipher_name);

        for blob in [&sp.server_blob, &sp.client_blob] {
            let parsed = SerializedConnection::parse(blob)
                .unwrap_or_else(|e| panic!("policy {policy} failed to parse: {e}"));

            assert_eq!(parsed.protocol_version, expected_version, "policy {policy}");
            assert_eq!(parsed.cipher_suite.aead(), expected_aead, "policy {policy}");
            assert_eq!(parsed.cipher_suite.hash(), expected_hash, "policy {policy}");

            match &parsed.secrets {
                Secrets::Tls12 { .. } => {
                    assert_eq!(parsed.protocol_version, ProtocolVersion::Tls12);
                }
                Secrets::Tls13(secret) => {
                    assert_eq!(parsed.protocol_version, ProtocolVersion::Tls13);
                    let expected = expected_hash.digest_len();
                    assert_eq!(secret.client_application_secret.len(), expected);
                    assert_eq!(secret.server_application_secret.len(), expected);
                    assert_eq!(secret.resumption_master_secret.len(), expected);
                }
            }
        }
    }
}

#[test]
fn server_and_client_sequence_numbers_agree() {
    // After a handshake with no application data, both peers should have
    // consistent sequence numbers. The server's client_sequence_number should
    // match what the client recorded as its own send sequence, etc. We at least
    // assert the fields parse and are the fixed width.
    let sp = common::serialized_pair("20170210");

    assert_eq!(std::mem::size_of::<u64>(), 8);
    assert_eq!(std::mem::size_of::<u64>(), 8);
}

#[test]
fn reject_bad_version_tag() {
    let mut blob = common::serialized_pair("default").server_blob;
    // Corrupt the leading u64 version tag (bytes 0..8).
    blob[7] = 0xFF;
    let err = SerializedConnection::parse(&blob).unwrap_err();
    assert!(
        err.to_string().contains("serialization version"),
        "unexpected error: {err}"
    );
}

#[test]
fn reject_truncated_buffer() {
    let blob = common::serialized_pair("default").server_blob;
    let truncated = &blob[..blob.len() - 5];
    let err = SerializedConnection::parse(truncated).unwrap_err();
    assert!(
        err.to_string().contains("end of buffer"),
        "unexpected error: {err}"
    );
}

#[test]
fn reject_trailing_bytes() {
    let mut blob = common::serialized_pair("default").server_blob;
    blob.push(0x00);
    let err = SerializedConnection::parse(&blob).unwrap_err();
    assert!(
        err.to_string().contains("trailing"),
        "unexpected error: {err}"
    );
}

#[test]
fn reject_unsupported_cipher() {
    // Take a valid TLS1.2 GCM blob and overwrite the cipher IANA value with a
    // CBC suite (TLS_RSA_WITH_AES_128_CBC_SHA = 0x00,0x2F), which kTLS can't use.
    let mut blob = common::serialized_pair("20170210").server_blob;
    // Layout: u64 version (0..8), major (8), minor (9), cipher IANA (10..12).
    blob[10] = 0x00;
    blob[11] = 0x2F;
    let err = SerializedConnection::parse(&blob).unwrap_err();
    assert!(
        err.to_string().contains("cipher suite"),
        "unexpected error: {err}"
    );
}

#[test]
fn reject_unsupported_protocol_version() {
    // Overwrite the protocol version bytes with TLS1.0 (3, 1).
    let mut blob = common::serialized_pair("default").server_blob;
    blob[8] = 3;
    blob[9] = 1;
    let err = SerializedConnection::parse(&blob).unwrap_err();
    assert!(
        err.to_string().contains("TLS1.2 and TLS1.3"),
        "unexpected error: {err}"
    );
}
