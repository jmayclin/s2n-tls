// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This lint warns that async function in trait are especially likely to unexpected 
// breaking changes because of the type inference on the future bounds. We are not
// concerned about breaking API changes since this is an internal crate, and the
// ergonomic benefits of "async fn" significantly outweigh the stability concerns.
//
// However in cases where the additional "async" syntax isn't useful, we prefer 
// "impl Future" syntax for the more readable compiler errors that it provides.
#![allow(async_fn_in_trait)]

use std::{error::Error, fmt::Debug};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB, SERVER_GREETING};

pub mod rustls_shim;
pub mod s2n_tls_shim;

/// The ServerTLS trait is intended to allow for shared code between s2n-tls, rustls,
/// and openssl. All of these TLS implementations have relatively similar API shapes
/// which this trait attempts to abstract over.
pub trait ServerTLS<T> {
    type Config;
    type Acceptor: Clone + Send + 'static;
    // the Stream is generic to allow for Turmoil test usage
    type Stream: Send + AsyncRead + AsyncWrite + Debug + Unpin;

    fn get_server_config(
        test: InteropTest,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn Error>>;
    fn acceptor(config: Self::Config) -> Self::Acceptor;

    fn accept(
        server: &Self::Acceptor,
        transport_stream: T,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;

    /// `handle_server_connection` provide the generic "handle connection" functionality.
    /// It will automatically implement correct application behavior for tests that
    /// don't require any implementation specific apis. This include "Handshake",
    /// "Greeting", and "LargeDataDownload". 
    async fn handle_server_connection(
        test: InteropTest,
        mut stream: Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::info!("Executing the {:?} scenario", test);
        match test {
            InteropTest::Handshake => {
                /* no application data exchange in the handshake case */
            }
            InteropTest::Greeting => {
                let mut client_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                stream.read(&mut client_greeting_buffer).await?;
                assert_eq!(client_greeting_buffer, CLIENT_GREETING.as_bytes());

                stream.write_all(SERVER_GREETING.as_bytes()).await?;
            }
            InteropTest::LargeDataDownload => {
                let mut client_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                stream.read(&mut client_greeting_buffer).await?;
                assert_eq!(client_greeting_buffer, CLIENT_GREETING.as_bytes());

                let mut data_buffer = vec![0; 1_000_000];
                // for each GB
                for i in 0..LARGE_DATA_DOWNLOAD_GB {
                    if i % 10 == 0 {
                        tracing::info!("GB sent: {}", i);
                    }
                    data_buffer[0] = (i % u8::MAX as u64) as u8;
                    for _ in 0..1_000 {
                        stream.write_all(&data_buffer).await?;
                    }
                }
            }
            InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
                Self::handle_large_data_download_with_frequent_key_updates(&mut stream).await?;
            }
        }
        // Don't assert on a successful close behavior, since s2n-tls bindings
        // do not support a graceful close behavior.
        // https://github.com/aws/s2n-tls/issues/4488
        let res = stream.shutdown().await;
        tracing::debug!("TLS Shutdown result {:?}", res);
        Ok(())
    }

    /// If server supports the "large_data_download_forced_key_update" scenario, it should implement this method.
    /// The method should *not* handle the shutdown of the stream. It should only handle the writing of application
    /// messages and the sending of the key updates.
    async fn handle_large_data_download_with_frequent_key_updates(
        _stream: &mut Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("unimplemented".into())
    }
}

pub trait ClientTLS<T> {
    type Config;
    type Connector: Clone + Send + 'static;
    type Stream: Send + AsyncRead + AsyncWrite + Debug + Unpin;

    fn get_client_config(
        test: InteropTest,
        ca_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn Error>>;

    fn connector(config: Self::Config) -> Self::Connector;

    fn connect(
        client: &Self::Connector,
        transport_stream: T,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;

    async fn handle_client_connection(
        test: InteropTest,
        mut stream: Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match test {
            InteropTest::Handshake => {
                tracing::info!("Client executing handshake scenario") /* no data exchange in the handshake case */
            }
            InteropTest::Greeting => {
                stream.write_all(CLIENT_GREETING.as_bytes()).await?;

                let mut server_greeting_buffer = vec![0; SERVER_GREETING.as_bytes().len()];
                stream.read_exact(&mut server_greeting_buffer).await?;
                assert_eq!(server_greeting_buffer, SERVER_GREETING.as_bytes());
            }
            InteropTest::LargeDataDownload
            | InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
                stream.write_all(CLIENT_GREETING.as_bytes()).await?;

                let mut recv_buffer = vec![0; 1_000_000];
                for i in 0..LARGE_DATA_DOWNLOAD_GB {
                    let tag = (i % u8::MAX as u64) as u8;
                    // 1_000 Mb in a Gb
                    for _ in 0..1_000 {
                        stream.read_exact(&mut recv_buffer).await?;
                        assert_eq!(recv_buffer[0], tag);
                    }
                }
            }
        }
        tracing::info!("client is shutting down");
        let shutdown_result = stream.shutdown().await;
        if let Err(e) = shutdown_result {
            // Don't assert on a successful close behavior, since s2n-tls bindings
            // do not support a graceful close behavior.
            // https://github.com/aws/s2n-tls/issues/4488
            // value: Os { code: 107, kind: NotConnected, message: "Transport endpoint is not connected" }
            if let Some(107) = e.raw_os_error() {
                tracing::error!("Ignoring TCP Close Error, returning success: {}", e);
                return Ok(());
            }
            return Err(Box::new(e));
        }
        Ok(())
    }
}
