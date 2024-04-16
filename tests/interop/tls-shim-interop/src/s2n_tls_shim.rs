use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB, SERVER_GREETING};
use s2n_tls::{config::Config, security::DEFAULT_TLS13};

use std::error::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{ClientTLS, ServerTLS};
use async_trait::async_trait;

pub struct ShimS2nTls;

impl std::fmt::Display for ShimS2nTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s2n-tls")
    }
}

// T is generally a tokio::TcpStream or a turmoil::TcpStream
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientTLS<T> for ShimS2nTls {
    type Config = s2n_tls::config::Config;
    type Connector = s2n_tls_tokio::TlsConnector;
    type Stream = s2n_tls_tokio::TlsStream<T>;

    fn get_client_config(
        _test: common::InteropTest,
        ca_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn Error>> {
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

    // async fn handle_client_connection(
    //     test: InteropTest,
    //     mut stream: Self::Stream,
    // ) -> Result<(), Box<dyn Error + Send + Sync>> {
    //     match test {
    //         InteropTest::Handshake => { /* no data exchange in the handshake case */ }
    //         InteropTest::Greeting => {
    //             let mut server_greeting_buffer = vec![0; SERVER_GREETING.as_bytes().len()];
    //             stream.write_all(CLIENT_GREETING.as_bytes()).await?;
    //             stream.read_exact(&mut server_greeting_buffer).await?;
    //             assert_eq!(server_greeting_buffer, SERVER_GREETING.as_bytes());
    //         }
    //         InteropTest::LargeDataDownload => todo!(),
    //         InteropTest::LargeDataDownloadWithFrequentKeyUpdates => todo!(),
    //     }
    //     stream.shutdown().await?;
    //     Ok(())
    // }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> ServerTLS<T> for ShimS2nTls {
    type Config = s2n_tls::config::Config;
    type Acceptor = s2n_tls_tokio::TlsAcceptor;
    type Stream = s2n_tls_tokio::TlsStream<T>;

    fn get_server_config(
        _test: InteropTest,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Option<s2n_tls::config::Config>, Box<dyn Error>> {
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.load_pem(cert_pem, key_pem)?;
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

    // async fn handle_large_data_download_with_frequent_key_updates(_stream: &mut Self::Stream) -> Result<(), Box<dyn Error + Send + Sync>> {
    //     Err("not implemented".into())
    // }

    // async fn handle_server_connection(
    //     test: InteropTest,
    //     mut stream: Self::Stream,
    // ) -> Result<(), Box<dyn Error + Send + Sync>> {
    //     match test {
    //         InteropTest::Handshake => {
    //             tracing::info!("server executing the handshake scenario"); /* no data exchange in the handshake case */
    //         }
    //         InteropTest::Greeting => {
    //             tracing::info!("server executing the greeting scenario");
    //             let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
    //             tracing::info!("reading the data");
    //             stream.read(&mut server_greeting_buffer).await?;
    //             tracing::info!("asserting equal");
    //             assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

    //             stream.write_all(SERVER_GREETING.as_bytes()).await?;
    //         }
    //         InteropTest::LargeDataDownload => {
    //             tracing::info!("waiting for client greeting");
    //             let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
    //             stream.read_exact(&mut server_greeting_buffer).await?;
    //             assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());
    //             let mut data_buffer = vec![0; 1_000_000];
    //             // for each GB
    //             for i in 0..LARGE_DATA_DOWNLOAD_GB {
    //                 if i % 10 == 0 {
    //                     tracing::info!(
    //                         "GB sent: {}, key updates: {:?}",
    //                         i,
    //                         stream.as_ref().key_update_counts()?
    //                     );
    //                 }
    //                 data_buffer[0] = (i % u8::MAX as u64) as u8;
    //                 for j in 0..1_000 {
    //                     tracing::trace!("{}-{}", i, j);
    //                     stream.write_all(&data_buffer).await?;
    //                 }
    //             }

    //             let (send, _recv) = stream.as_ref().key_update_counts()?;
    //             assert!(send > 0);
    //         }
    //         InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
    //             tracing::info!("waiting for client greeting");
    //             let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
    //             stream.read_exact(&mut server_greeting_buffer).await?;
    //             assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

    //             let mut data_buffer = vec![0; 1_000_000];
    //             // for each GB
    //             for i in 0..LARGE_DATA_DOWNLOAD_GB {
    //                 // send a key update with each gigabyte
    //                 stream
    //                     .as_mut()
    //                     .request_key_update(s2n_tls::enums::PeerKeyUpdate::KeyUpdateNotRequested)?;
    //                 if i % 10 == 0 {
    //                     tracing::info!(
    //                         "GB sent: {}, key updates: {:?}",
    //                         i,
    //                         stream.as_ref().key_update_counts()?
    //                     );
    //                 }
    //                 data_buffer[0] = (i % u8::MAX as u64) as u8;
    //                 for j in 0..1_000 {
    //                     tracing::trace!("{}-{}", i, j);
    //                     stream.write_all(&data_buffer).await?;
    //                 }
    //             }

    //             let (send, _recv) = stream.as_ref().key_update_counts()?;
    //             assert!(send > 0);
    //         }
    //     }
    //     let res = stream.shutdown().await;
    //     tracing::info!("the result of the tls shutdown was {:?}", res);
    //     Ok(())
    // }

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
