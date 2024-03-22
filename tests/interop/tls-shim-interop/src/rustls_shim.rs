use std::{fmt::{Debug, Display}, io::BufReader, sync::Arc};

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB, SERVER_GREETING};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::TcpStream};
use tokio_rustls::{rustls::{self, pki_types}, TlsConnector};

use crate::ClientTLS;

pub struct RustlsShim;

impl Display for RustlsShim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rustls")
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> ClientTLS<T> for RustlsShim {
    type Config = Arc<tokio_rustls::rustls::ClientConfig>;
    type Connector = tokio_rustls::TlsConnector;
    type Stream = tokio_rustls::client::TlsStream<T>;

    fn get_client_config(
        test: common::InteropTest,
        ca_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn std::error::Error>> {
        if test == InteropTest::LargeDataDownloadWithFrequentKeyUpdates {
            return Ok(None);
        }
        
        let mut root_store = rustls::RootCertStore::empty();

        //let certs = rustls_pemfile::certs(&mut BufReader::new(ca_pem)).collect();
        let mut buffered_cert = BufReader::new(ca_pem);
        let root_cert = rustls_pemfile::certs(&mut buffered_cert).next().unwrap().unwrap();

        root_store.add(root_cert).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Some(Arc::new(config)))
    }

    fn connector(config: Self::Config) -> Self::Connector {
        TlsConnector::from(config)
    }

    async fn connect(
        client: &Self::Connector,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn std::error::Error + Send + Sync>> {
        let domain = "localhost";
        let server_name = pki_types::ServerName::try_from(domain)?;
        Ok(client.connect(server_name, transport_stream).await?)
    }

    // async fn handle_client_connection(
    //     test: InteropTest,
    //     mut stream: Self::Stream,
    // ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     match test {
    //         InteropTest::Handshake => {/* no data exchange in the handshake case */},
    //         InteropTest::Greeting => {
    //             let mut server_greeting_buffer = vec![0; SERVER_GREETING.as_bytes().len()];
    //             stream.write_all(CLIENT_GREETING.as_bytes()).await?;
    //             stream.read_exact(&mut server_greeting_buffer).await?;
    //             assert_eq!(server_greeting_buffer, SERVER_GREETING.as_bytes());
    //         },
    //         InteropTest::LargeDataDownload => {
    //             stream.write_all(CLIENT_GREETING.as_bytes()).await?;

    //             let mut recv_buffer = vec![0; 1_000_000];
    //             for i in 0..LARGE_DATA_DOWNLOAD_GB {
    //                 let tag = (i % u8::MAX as u64) as u8;
    //                 // 1_000 Mb in a Gb
    //                 for _ in 0..1_000 {
    //                     stream.read_exact(&mut recv_buffer).await?;
    //                     assert_eq!(recv_buffer[0], tag);
    //                 }
    //             }
    //         },
    //         InteropTest::LargeDataDownloadWithFrequentKeyUpdates => todo!(),
    //     }
    //     stream.shutdown().await?;
    //     Ok(())
    // }
    
}
