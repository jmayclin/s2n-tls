use clap::Parser;
use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB, SERVER_GREETING};
use s2n_tls::{config::Config, enums::Mode, pool::ConfigPoolBuilder, security::{DEFAULT, DEFAULT_TLS13}};
use s2n_tls_tokio::TlsAcceptor;
use std::{
    env, error::Error, fmt::{format, Debug}, fs, net::{Ipv4Addr, SocketAddr, SocketAddrV4}, path::Display, pin::Pin, time::Duration
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    time::sleep,
};

use crate::{ClientTLS, ServerTLS};

pub struct ShimS2nTls;

impl std::fmt::Display for ShimS2nTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s2n-tls")
    }
}

// T is generally a tokio::TcpStream or a turmoil::TcpStream
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientTLS<T> for ShimS2nTls
{
    type Config = s2n_tls::config::Config;
    type Connector = s2n_tls_tokio::TlsConnector;
    type Stream = s2n_tls_tokio::TlsStream<T>;

    fn get_client_config(
        test: common::InteropTest,
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
        test: InteropTest,
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

    async fn handle_server_connection(
        test: InteropTest,
        mut stream: Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match test {
            InteropTest::Handshake => { println!("server executing the handshake scenario");/* no data exchange in the handshake case */ },
            InteropTest::Greeting => {
                tracing::info!("server executing the greeting scenario");
                let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                tracing::info!("reading the data");
                stream.read(&mut server_greeting_buffer).await?;
                tracing::info!("asserting equal");
                assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());
                
                stream.write_all(SERVER_GREETING.as_bytes()).await?;
            },
            InteropTest::LargeDataDownload => {
                let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                stream.read_exact(&mut server_greeting_buffer).await?;
                assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

                let mut data_buffer = vec![0; 1_000_000];
                // for each GB
                for i in 0..LARGE_DATA_DOWNLOAD_GB {
                    data_buffer[0] = (i % u8::MAX as u64) as u8;
                    for _ in 0..1_000 {
                        stream.write_all(&data_buffer).await?;
                    }
                }
            },
            InteropTest::LargeDataDownloadWithFrequentKeyUpdates => todo!(),
        }
        //stream.shutdown().await?;
        //let mut read_buffer = vec![0; "gimme data".as_bytes().len()];
        //tls.read_exact(&mut read_buffer).await?;
        //assert_eq!(&read_buffer, "gimme data".as_bytes());
        // let target = 100; // Gb
        //                   //let allowed_records = (target * GB / 8_192) as u64; // 8_192 is default s2n record size;
        //                   //tls.as_mut().set_encryption_limit(allowed_records).unwrap();
        // println!("{:#?}", tls);

        // // read in the initial message
        // let mut buffer = vec![0x56; 1_000_000];
        // let read = tls.read(buffer.as_mut_slice()).await.unwrap();

        // assert_eq!(read, "gimme data".len());
        // assert_eq!(&buffer[0..read], "gimme data".as_bytes());
        // println!("the java client said hello to me. Nice fellow");

        // // write 200 Gb to client
        // for i in 0..(200 * 1_000) {
        //     //let update = tls.as_ref().key_updates().unwrap();
        //     if i % (25 * 1_000) == 0 {
        //         //tls.as_mut().request_key_update(s2n_tls::enums::PeerKeyUpdate::KeyUpdateNotRequested).unwrap();
        //     }
        //     //println!("writing mb {}, send and recv updates: {:?}", i, update);
        //     tls.write_all(&buffer).await.unwrap();
        // }

        // tls.write_all("thats all for now folks".as_bytes())
        //     .await
        //     .unwrap();

        // don't assert, because things are silly and it sometimes breaks
        let res = stream.shutdown().await;
        println!("the result of the tls shutdown was {:?}", res);
        Ok(())
    }
    
}
