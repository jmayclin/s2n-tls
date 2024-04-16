use std::{error::Error, fmt::Debug};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use async_trait::async_trait;

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB, SERVER_GREETING};

pub mod rustls_shim;
pub mod s2n_tls_shim;

pub trait ServerTLS<T> {
    type Config;
    // `'static` means that the Acceptor types contains no references which have a lifetime
    // shorter than `'static`. This is a bit of a lie, which I should fix later.
    type Acceptor: Clone + Send + 'static;
    type Stream: Send + AsyncRead + AsyncWrite + Debug + Unpin;

    fn get_server_config(
        test: InteropTest,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn Error>>;
    fn acceptor(config: Self::Config) -> Self::Acceptor;

    // rather than using an async function, using an explicit impl Future. This
    // the async fn (Future) will violently resist implementing Send
    fn accept(
        server: &Self::Acceptor,
        transport_stream: T,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;

    // fn handle_server_connection(
    //     test: InteropTest,
    //     stream: Self::Stream,
    // ) -> impl std::future::Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send;

    async fn handle_server_connection(
        test: InteropTest,
        mut stream: Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match test {
            InteropTest::Handshake => {
                /* no application data exchange in the handshake case */
                tracing::info!("server executing the handshake scenario");
            }
            InteropTest::Greeting => {
                let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                stream.read(&mut server_greeting_buffer).await?;
                assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

                stream.write_all(SERVER_GREETING.as_bytes()).await?;
            }
            InteropTest::LargeDataDownload => {
                tracing::info!("waiting for client greeting");
                let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                stream.read_exact(&mut server_greeting_buffer).await?;
                assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());
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
                // tracing::info!("waiting for client greeting");
                // let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                // stream.read_exact(&mut server_greeting_buffer).await?;
                // assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

                // let mut data_buffer = vec![0; 1_000_000];
                // // for each GB
                // for i in 0..LARGE_DATA_DOWNLOAD_GB {
                //     // send a key update with each gigabyte
                //     stream
                //         .as_mut()
                //         .request_key_update(s2n_tls::enums::PeerKeyUpdate::KeyUpdateNotRequested)?;
                //     if i % 10 == 0 {
                //         tracing::info!(
                //             "GB sent: {}, key updates: {:?}",
                //             i,
                //             stream.as_ref().key_update_counts()?
                //         );
                //     }
                //     data_buffer[0] = (i % u8::MAX as u64) as u8;
                //     for j in 0..1_000 {
                //         tracing::trace!("{}-{}", i, j);
                //         stream.write_all(&data_buffer).await?;
                //     }
                // }

                // let (send, _recv) = stream.as_ref().key_update_counts()?;
                // assert!(send > 0);
            }
        }
        let res = stream.shutdown().await;
        tracing::info!("the result of the tls shutdown was {:?}", res);
        Ok(())
    }

    /// If server's support the "large_data_download_forced_key_update" scenario, they should implement this method. 
    /// The method should *not* handle the shutdown of the stream. It should only handle the writing of application 
    /// messages and the sending of the key updates.
    fn handle_large_data_download_with_frequent_key_updates(_stream: &mut Self::Stream) -> impl std::future::Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send;
}

pub trait ClientTLS<T> {
    type Config;
    // `'static` means that the Acceptor types contains no references which have a lifetime
    // shorter than `'static`. This is a bit of a lie, which I should fix later.
    type Connector: Clone + Send + 'static;
    type Stream: Send + AsyncRead + AsyncWrite + Debug + Unpin;

    fn get_client_config(
        test: InteropTest,
        ca_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn Error>>;

    fn connector(config: Self::Config) -> Self::Connector;

    // rather than using an async function, using an explicit impl Future. This
    // the async fn (Future) will violently resist implementing Send
    fn connect(
        client: &Self::Connector,
        transport_stream: T,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;

    // fn handle_client_connection(
    //     test: InteropTest,
    //     stream: Self::Stream,
    // ) -> impl std::future::Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send;

    /// This is essentially the event loop, and will be invoked once on each stream
    /// that is yielded form the the `connect` method. Generally implementors should
    /// prefer to implement the individual method overrides rather than overriding
    /// the entire event loop.
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
        //sleep(std::time::Duration::from_secs(1)).await;
        let shutdown_result = stream.shutdown().await;
        if let Err(e) = shutdown_result {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
