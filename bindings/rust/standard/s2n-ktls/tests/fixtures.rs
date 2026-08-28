// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Smoke test proving that s2n-tls (a dev-dependency) can produce real
//! serialized connection blobs via `TestPair`. Later tasks consume these blobs
//! as parser fixtures.

mod common;

#[test]
fn testpair_produces_serialized_blob() {
    // "default" negotiates TLS1.2; "default_tls13" negotiates TLS1.3.
    for policy in ["default", "default_tls13"] {
        let pair = common::serialized_pair(policy);
        // The V1 fixed header alone is 8 + 2 + 2 + 8 + 8 + 2 = 30 bytes, and
        // every supported config appends secrets on top of that.
        assert!(
            pair.server_blob.len() > 30,
            "serialized blob for {policy} unexpectedly small: {} bytes",
            pair.server_blob.len()
        );
        println!(
            "{policy}: serialized blob is {} bytes",
            pair.server_blob.len()
        );
    }
}
