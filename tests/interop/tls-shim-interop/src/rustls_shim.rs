use std::{io::BufReader, sync::Arc};

use common::{InteropTest, CLIENT_GREETING, SERVER_GREETING};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tokio_rustls::{rustls::{self, pki_types}, TlsConnector};

use crate::ClientTLS;

pub struct RustlsShim;

impl ClientTLS for RustlsShim {
    type Config = Arc<tokio_rustls::rustls::ClientConfig>;

    type Connector = tokio_rustls::TlsConnector;

    type Stream = tokio_rustls::client::TlsStream<TcpStream>;

    fn get_client_config(
        test: common::InteropTest,
        ca_pem: &[u8],
    ) -> Result<Option<Self::Config>, Box<dyn std::error::Error>> {
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
        transport_stream: tokio::net::TcpStream,
    ) -> Result<Self::Stream, Box<dyn std::error::Error + Send + Sync>> {
        let domain = "localhost";
        let server_name = pki_types::ServerName::try_from(domain)?;
        Ok(client.connect(server_name, transport_stream).await?)
    }

    async fn handle_client_connection(
        test: InteropTest,
        mut stream: Self::Stream,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match test {
            InteropTest::Handshake => {/* no data exchange in the handshake case */},
            InteropTest::Greeting => {
                let mut server_greeting_buffer = vec![0; SERVER_GREETING.as_bytes().len()];
                stream.write_all(CLIENT_GREETING.as_bytes()).await?;
                stream.read_exact(&mut server_greeting_buffer).await?;
                assert_eq!(server_greeting_buffer, SERVER_GREETING.as_bytes());
            },
            InteropTest::LargeDataDownload => todo!(),
            InteropTest::LargeDataDownloadWithFrequentKeyUpdates => todo!(),
        }
        stream.shutdown().await?;
        Ok(())
    }
}
