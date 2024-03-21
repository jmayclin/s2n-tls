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
    net::{TcpListener, TcpSocket, TcpStream},
};

use common::InteropTest;

pub mod s2n_tls_shim;
pub mod rustls_shim;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}


pub trait ServerTLS {
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
        transport_stream: tokio::net::TcpStream,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;
    
    fn handle_server_connection(
        test: InteropTest,
        stream: Self::Stream,
    ) -> impl std::future::Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send;
}

pub trait ClientTLS {
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
        transport_stream: tokio::net::TcpStream,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;
    
    fn handle_client_connection(
        test: InteropTest,
        stream: Self::Stream,
    ) -> impl std::future::Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send;
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
