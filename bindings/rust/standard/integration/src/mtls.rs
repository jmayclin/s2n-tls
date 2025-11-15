// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use openssl::ssl::SslContextBuilder;
use rustls::ClientConfig;
use s2n_tls::{
    callbacks::{CertValidationCallbackSync, CertValidationInfo},
    connection::Connection,
    enums::ClientAuthType,
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};
use tls_harness::{
    cohort::{
        rustls::RustlsConfigBuilder, OpenSslConnection, RustlsConfig, RustlsConnection, S2NConfig,
        S2NConnection,
    },
    harness::{read_to_bytes, TlsConfigBuilder, TlsConfigBuilderPair},
    PemType, SigType, TlsConnPair,
};

/// Total application data size (chosen so the final record is always more than small size)
const APP_DATA_SIZE: usize = 100_000;

#[test]
fn mtls_basic() {
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
use s2n_tls::error::Error as S2NError;

#[derive(Debug, Default)]
struct SyncCallback {
    invoked: Arc<AtomicU64>,
    /// this is the number of time that the callback must be polled before it returns successfully
    required_invokes: u64,
}

impl SyncCallback {
    fn new(required_invokes: u64) -> Self {
        Self {
            invoked: Default::default(),
            required_invokes,
        }
    }
}

impl CertValidationCallbackSync for SyncCallback {
    fn handle_validation(&self, conn: &mut Connection, info: &mut CertValidationInfo) {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        println!("cert validation invoked");
        if self.invoked.load(Ordering::SeqCst) == self.required_invokes {
            info.accept().unwrap();
        }
    }
}

#[test]
fn mtls_with_cert_verify() {
    let callback = SyncCallback::new(1);
    let callback_handle = Arc::clone(&callback.invoked);
    let mut pair: TlsConnPair<RustlsConnection, S2NConnection> = {
        let server_config = {
            let mut server_config = s2n_tls::config::Builder::new();
            server_config.set_chain(SigType::Rsa2048);
            server_config
                .set_client_auth_type(ClientAuthType::Required)
                .unwrap()
                .with_system_certs(false)
                .unwrap()
                .trust_pem(&read_to_bytes(PemType::CACert, SigType::Rsa2048))
                .unwrap()
                .set_cert_validation_callback_sync(callback)
                .unwrap();
            let server_config = server_config.build().unwrap();
            S2NConfig::from(server_config)
        };

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
    assert_eq!(callback_handle.load(Ordering::SeqCst), 0);

    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();

    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);
}

#[test]
fn mtls_with_async_cert_verify() {
    let callback = SyncCallback::new(2);
    let callback_handle = Arc::clone(&callback.invoked);
    let mut pair: TlsConnPair<RustlsConnection, S2NConnection> = {
        let server_config = {
            let mut server_config = s2n_tls::config::Builder::new();
            server_config.set_chain(SigType::Rsa2048);
            server_config
                .set_client_auth_type(ClientAuthType::Required)
                .unwrap()
                .with_system_certs(false)
                .unwrap()
                .trust_pem(&read_to_bytes(PemType::CACert, SigType::Rsa2048))
                .unwrap()
                .set_cert_validation_callback_sync(callback)
                .unwrap();
            let server_config = server_config.build().unwrap();
            S2NConfig::from(server_config)
        };

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
    assert_eq!(callback_handle.load(Ordering::SeqCst), 0);
    pair.io.enable_recording();

    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();

    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);
}
