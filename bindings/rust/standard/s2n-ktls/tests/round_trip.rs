// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Round-trip tests: parsing a real serialized blob and re-emitting it must
//! reproduce the original bytes exactly, and reported lengths must match.

mod common;

use s2n_ktls::protocol::serialization::SerializedConnection;

const POLICIES: &[&str] = &[
    "20170210",      // TLS1.2, AES-128-GCM
    "20190801",      // TLS1.3-capable
    "20240501",      // TLS1.3
    "default",       // TLS1.2 default
    "default_tls13", // TLS1.3 default
];

#[test]
fn round_trip_reproduces_original_bytes() {
    for &policy in POLICIES {
        let sp = common::serialized_pair(policy);

        for blob in [&sp.server_blob, &sp.client_blob] {
            let parsed = SerializedConnection::parse(blob)
                .unwrap_or_else(|e| panic!("policy {policy} failed to parse: {e}"));

            let reemitted = parsed.to_vec();
            assert_eq!(
                &reemitted, blob,
                "policy {policy}: re-emitted bytes differ from original"
            );
        }
    }
}

#[test]
fn serialization_length_matches_actual() {
    for &policy in POLICIES {
        let sp = common::serialized_pair(policy);

        for blob in [&sp.server_blob, &sp.client_blob] {
            let parsed = SerializedConnection::parse(blob).unwrap();
            assert_eq!(
                parsed.serialization_length(),
                blob.len(),
                "policy {policy}: serialization_length disagrees with real blob length"
            );
        }
    }
}

#[test]
fn serialization_length_matches_c_formula() {
    // Cross-check against the C size constants:
    //   FIXED = 8 (version) + 2 (protocol) + 2 (cipher) + 8 + 8 (seq) + 2 (frag) = 30
    //   TLS1.2: FIXED + 48 (master) + 32 + 32 (randoms) = 142
    //   TLS1.3 SHA-256: FIXED + 32 * 3 = 126
    //   TLS1.3 SHA-384: FIXED + 48 * 3 = 174
    use s2n_tls::enums::Version;

    for &policy in POLICIES {
        let sp = common::serialized_pair(policy);
        let parsed = SerializedConnection::parse(&sp.server_blob).unwrap();
        let len = parsed.serialization_length();

        match sp.negotiated_version {
            Version::TLS12 => assert_eq!(len, 142, "policy {policy} TLS1.2 size"),
            Version::TLS13 => {
                // 126 for SHA-256 suites, 174 for SHA-384 suites.
                assert!(
                    len == 126 || len == 174,
                    "policy {policy} TLS1.3 unexpected size {len}"
                );
            }
            other => panic!("unexpected version {other:?}"),
        }
    }
}
