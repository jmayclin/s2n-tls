use clap::Parser;
use s2n_tls::{config::Config, enums::Mode, pool::ConfigPoolBuilder, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::{
    env,
    error::Error,
    fmt::Debug,
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream}, time::sleep,
};

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB, SERVER_GREETING};

pub mod s2n_tls_shim;
pub mod rustls_shim;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub trait InteropServerConfig {
    fn get_server_config(test: InteropTest) -> Self;
}



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
    
    fn handle_server_connection(
        test: InteropTest,
        stream: Self::Stream,
    ) -> impl std::future::Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send;
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
            InteropTest::Handshake => { tracing::info!("Client executing handshake scenario")/* no data exchange in the handshake case */ }
            InteropTest::Greeting => {
                stream.write_all(CLIENT_GREETING.as_bytes()).await?;
                
                let mut server_greeting_buffer = vec![0; SERVER_GREETING.as_bytes().len()];
                stream.read_exact(&mut server_greeting_buffer).await?;
                assert_eq!(server_greeting_buffer, SERVER_GREETING.as_bytes());
            }
            InteropTest::LargeDataDownload => {
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
            },
            InteropTest::LargeDataDownloadWithFrequentKeyUpdates => todo!(),
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
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
