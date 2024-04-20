// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB};
use s2n_tls::{config::Config, security::{DEFAULT, DEFAULT_TLS13}};

use std::error::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{ClientTLS, ServerTLS};

pub struct S2NShim;

impl std::fmt::Display for S2NShim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s2n-tls")
    }
}

fn actually_implementing_renegotiate_in_the_rust_bindings_is_too_much() {
    tracing::info!("responding to the renegotiate request");
    // etc
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientTLS<T> for S2NShim {
    type Config = s2n_tls::config::Config;
    type Connector = s2n_tls_tokio::TlsConnector;
    type Stream = s2n_tls_tokio::TlsStream<T>;

    fn get_client_config(
        test: common::InteropTest,
        ca_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn Error>> {
        if test == InteropTest::ServerInitiatedReneg {
            let mut config = Config::builder();
            // renegotiation must use TLS 1.2
            config.set_security_policy(&DEFAULT)?;
            config.trust_pem(ca_pem)?;

            config.set_renegotiate_callback(actually_implementing_renegotiate_in_the_rust_bindings_is_too_much);
            return Ok(Some(config.build()?));
        } 
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.trust_pem(ca_pem)?;
        Ok(Some(config.build()?))
    }

    fn connector(config: Self::Config) -> Self::Connector {
        s2n_tls_tokio::TlsConnector::new(config)
    }

    async fn connect(
        client: &Self::Connector,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn Error + Send + Sync>> {
        Ok(client.connect("localhost", transport_stream).await?)
    }

    async fn handle_server_initiated_reneg(
        stream: &mut Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // write the initial greeting
        stream.write_all(CLIENT_GREETING.as_bytes()).await?;

        // the server sends the renegotiate request after receiving the client greeting
        stream.as_mut().renegotiate_wipe();
        stream.renegotiate().await?;

        stream.write_all(CLIENT_FINISHED.as_bytes()).await?;
        Ok(())
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> ServerTLS<T> for S2NShim {
    type Config = s2n_tls::config::Config;
    type Acceptor = s2n_tls_tokio::TlsAcceptor;
    type Stream = s2n_tls_tokio::TlsStream<T>;

    fn get_server_config(
        _test: InteropTest,
        cert_pem_path: &str,
        key_pem_path: &str,
    ) -> Result<Option<s2n_tls::config::Config>, Box<dyn Error>> {
        let cert_pem = std::fs::read(cert_pem_path)?;
        let key_pem = std::fs::read(key_pem_path)?;
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.load_pem(&cert_pem, &key_pem)?;
        Ok(Some(config.build()?))
    }

    fn acceptor(config: Self::Config) -> Self::Acceptor {
        s2n_tls_tokio::TlsAcceptor::new(config)
    }

    async fn accept(
        server: &Self::Acceptor,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn Error + Send + Sync>> {
        Ok(server.accept(transport_stream).await?)
    }

    async fn handle_large_data_download_with_frequent_key_updates(
        stream: &mut Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::info!("waiting for client greeting");
        let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
        stream.read_exact(&mut server_greeting_buffer).await?;
        assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

        let mut data_buffer = vec![0; 1_000_000];
        // for each GB
        for i in 0..LARGE_DATA_DOWNLOAD_GB {
            // send a key update with each gigabyte
            stream
                .as_mut()
                .request_key_update(s2n_tls::enums::PeerKeyUpdate::KeyUpdateNotRequested)?;
            if i % 10 == 0 {
                tracing::info!(
                    "GB sent: {}, key updates: {:?}",
                    i,
                    stream.as_ref().key_update_counts()?
                );
            }
            data_buffer[0] = (i % u8::MAX as u64) as u8;
            for j in 0..1_000 {
                tracing::trace!("{}-{}", i, j);
                stream.write_all(&data_buffer).await?;
            }
        }

        let (send, _recv) = stream.as_ref().key_update_counts()?;
        assert!(send > 0);
        Ok(())
    }
}
