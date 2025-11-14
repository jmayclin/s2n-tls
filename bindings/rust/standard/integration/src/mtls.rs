// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use openssl::ssl::SslContextBuilder;
use rustls::ClientConfig;
use s2n_tls::enums::ClientAuthType;
use std::{sync::Arc, thread::sleep, time::Duration};
use tls_harness::{
    cohort::{
        rustls::RustlsConfigBuilder, OpenSslConnection, RustlsConfig, RustlsConnection, S2NConfig,
        S2NConnection,
    },
    harness::{read_to_bytes, TlsConfigBuilder, TlsConfigBuilderPair},
    PemType, SigType, TlsConnPair,
};

/// The byte threshold at which records switch from small to large
const RESIZE_THRESHOLD: usize = 16_000;
/// Maximum size for small records during ramp-up (single Ethernet frame limit)
const SMALL_RECORD_MAX: usize = 1_500;
/// Total application data size (chosen so the final record is always more than small size)
const APP_DATA_SIZE: usize = 100_000;
/// Duration of inactivity before resetting to small records
const TIMEOUT_THRESHOLD: Duration = Duration::from_secs(1);

/// Tests s2n-tls dynamic record sizing behavior.
///
/// This test explicitly validates the s2n_connection_set_dynamic_record_threshold() method
/// by configuring the threshold and validating the three phases of dynamic record sizing:
/// 1. Initial ramp-up: small records until threshold, then large records
/// 2. Steady state: all large records  
/// 3. Post-timeout ramp-up: small records again after timeout, then large records
#[test]
fn rustls_client_mtls() {
    let mut pair: TlsConnPair<RustlsConnection, S2NConnection> = {
        let mut server_config = s2n_tls::config::Builder::new();
        server_config.set_chain(SigType::Rsa2048);
        server_config
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap();
        server_config.with_system_certs(false).unwrap();
        server_config
            .trust_pem(&read_to_bytes(PemType::CACert, SigType::Rsa2048))
            .unwrap();
        let server_config = server_config.build().unwrap();
        let server_config = S2NConfig::from(server_config);

        let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(RustlsConfig::get_root_cert_store(SigType::Rsa2048))
            .with_client_auth_cert(
                RustlsConfig::get_cert_chain(PemType::ClientCertChain, SigType::Rsa2048),
                RustlsConfig::get_key(PemType::ClientKey, SigType::Rsa2048),
            )
            .unwrap();
        let client_config: RustlsConfig = client_config.into();

        let mut configs =
            TlsConfigBuilderPair::<RustlsConfigBuilder, s2n_tls::config::Builder>::default();
        configs
            .server
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap();
        TlsConnPair::from_configs(&client_config, &server_config)
    };

    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();
}
