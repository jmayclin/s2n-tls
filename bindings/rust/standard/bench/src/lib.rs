// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
pub mod openssl;
pub mod openssl_extension;
pub mod rustls;
pub mod s2n_tls;
// Although these are integration tests, we deliberately avoid the "integration"
// provided in the default repo setup, because it will run tests in serial rather
// than parallel/
// https://matklad.github.io/2021/02/27/delete-cargo-integration-tests.html
#[cfg(test)]
mod tests;

pub use crate::{
    harness::{
        get_cert_path, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode, PemType, SigType,
        TlsConnPair, TlsConnection,
    },
    openssl::OpenSslConnection,
    rustls::RustlsConnection,
    s2n_tls::S2NConnection,
};

// controls profiler frequency for flamegraph generation in benchmarks
pub const PROFILER_FREQUENCY: i32 = 100;
