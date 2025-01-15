use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::Arc,
};

use aws_lc_rs::rand::SecureRandom;
use s2n_tls::{
    callbacks::{ConnectionFuture, MonotonicClock, PskSelectionCallback},
    config::{Config, ConnectionInitializer},
    connection::Connection,
    enums::PskMode,
    error::Error,
    psk::ExternalPsk,
    security,
};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

const PORT: u16 = 1738;

const KEY_SIZE: usize = 1024;

#[derive(Clone)]
pub struct PskStore {
    // mapping from identity -> key material
    keys: Arc<HashMap<u64, Vec<u8>>>,
}

impl PskStore {
    pub fn new(size: u64) -> Self {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mut keys = HashMap::new();
        for i in 0..size {
            let identity = i;
            let mut material = vec![0; KEY_SIZE];
            rng.fill(&mut material).unwrap();
            //let psk = ExternalPsk::new(&identity.to_ne_bytes(), &material).unwrap();
            keys.insert(identity, material);
        }
        PskStore {
            keys: Arc::new(keys),
        }
    }

    pub fn get(&self, identity: u64) -> Option<Box<ExternalPsk>> {
        self.keys
            .get(&identity)
            .map(|key| ExternalPsk::new(&identity.to_ne_bytes(), key).unwrap())
    }
}

/// used by the server to load all of the PSKs onto a connection
impl ConnectionInitializer for PskStore {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
        for (identity, _psk) in self.keys.iter() {
            let psk = self.get(*identity).unwrap();
            connection.append_psk(&psk)?;
        }
        Ok(None)
    }
}

impl PskSelectionCallback for PskStore {
    fn choose_psk(&self, conn: &mut Connection, mut psk_list: s2n_tls::callbacks::OfferedPskList) {
        tracing::debug!("doing psk selection");
        while let Some(offered_psk) = psk_list.next() {
            let identity = offered_psk.identity().unwrap();
            let identity = u64::from_ne_bytes(identity[0..8].try_into().expect("unexpected"));
            if let Some(matched_psk) = self.get(identity) {
                conn.append_psk(&matched_psk).unwrap();
                tracing::info!("chose a psk");
                psk_list.choose_offered_psk(offered_psk).unwrap();
                return;
            }
        }
        tracing::warn!("no suitable psk found");
    }
}

// new type pattern to implement the ConnectionInitializer on an external type
pub struct ClientPsk {
    psk: Box<ExternalPsk>,
}

impl From<Box<ExternalPsk>> for ClientPsk {
    fn from(value: Box<ExternalPsk>) -> Self {
        ClientPsk { psk: value }
    }
}

/// used by the client to load a single psk onto the connection
impl ConnectionInitializer for ClientPsk {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
        connection.append_psk(&self.psk)?;
        Ok(None)
    }
}

// a server using simpler PSK setup, only supporting 2 different PSKs. Since there
// is a small number of PSKs, we directly load each of them onto the connection
// using the `ConnectionInitializer` trait implemented on `PskStore`.
pub async fn small_server(psk_store: PskStore) -> Result<(), Box<dyn Send + Sync + std::error::Error>> {
    let mut config = s2n_tls::config::Config::builder();
    config
        .set_security_policy(&security::DEFAULT_TLS13)?
        .set_psk_mode(PskMode::External)?
        .set_connection_initializer(psk_store)?;

    let server = TlsAcceptor::new(config.build()?);
    let listener =
        tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

    loop {
        let server_clone = server.clone();
        let (stream, _peer_addr) = listener.accept().await?;
        tokio::spawn(async move {
            tracing::trace!("spawning new task to handle client");
            let mut tls = server_clone.accept(stream).await.unwrap();

            let mut identity = vec![0; tls.as_ref().negotiated_psk_identity_length().unwrap()];
            tls.as_ref().negotiated_psk_identity(&mut identity).unwrap();
            tracing::info!("the server selected {:?}", identity);

            tls.write_all(b"hello client").await.unwrap();
            // wait for client to shutdown. After the client shuts down its side
            // of the connection, 0 will be returned
            let read = tls.read(&mut [0]).await.unwrap();
            assert_eq!(read, 0);

            tls.shutdown().await.unwrap();
        });
    }
}

// a server using a more complex PSK setup, supporting thousands of different
// psks. Because of the large number, we only load them onto the connection at
// the prompting of a PskSelectionCallback on the PskStore.
pub async fn big_server(psk_store: PskStore) -> Result<(), Box<dyn Send + Sync + std::error::Error>> {
    let mut config = s2n_tls::config::Config::builder();
    config
        .set_security_policy(&security::DEFAULT_TLS13)?
        .set_psk_mode(PskMode::External)?
        .set_psk_selection_callback(psk_store)?;

    let server = TlsAcceptor::new(config.build()?);
    let listener =
        tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

    loop {
        let server_clone = server.clone();
        let (stream, _peer_addr) = listener.accept().await?;
        tokio::spawn(async move {
            tracing::info!("spawning new task to handle client");
            let mut tls = server_clone.accept(stream).await.unwrap();

            let mut identity = vec![0; tls.as_ref().negotiated_psk_identity_length().unwrap()];
            tls.as_ref().negotiated_psk_identity(&mut identity).unwrap();
            tracing::info!("the server selected {:?}", identity);

            tls.write_all(b"hello client").await.unwrap();
            // wait for client to shutdown. After the client shuts down its side
            // of the connection, 0 will be returned
            let read = tls.read(&mut [0]).await.unwrap();
            assert_eq!(read, 0);

            tls.shutdown().await.unwrap();
        });
    }
}
// This server manages a large number of PSKs. Instead of appending them all onto
// the connection, we do the PSK selection ourselves using the more advanced PSK
// methods.
// async fn big_server(psk_store: PskStore) -> Result<(), Box<dyn std::error::Error>> {

// }

pub async fn client(client_psk: ClientPsk) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::builder();
    config.set_security_policy(&security::DEFAULT_TLS13)?;
    config.set_connection_initializer(client_psk)?;

    // Create the TlsConnector based on the configuration.
    let client = TlsConnector::new(config.build()?);

    // Connect to the server.
    let stream = TcpStream::connect(("localhost", PORT)).await?;
    let mut tls = client.connect("localhost", stream).await?;
    println!("{:#?}", tls);

    let mut data_from_server = vec![0; b"hello client".len()];
    tls.read_exact(&mut data_from_server).await?;
    assert_eq!(data_from_server, b"hello client");

    tls.shutdown().await?;

    // generally we will see a 0 length read complete successfully, however there
    // is a possibility that the server's RST reaches the socket before we try the
    // 0 length read, in which case an error is returned. Therefore we can not
    // always expect a successful read here.
    let _ = tls.read(&mut [0]).await;

    Ok(())
}

#[cfg(test)]
mod simulation {
    use std::{
        sync::{Once},
        time::Duration,
    };

    use tracing::Level;

    use super::*;

    // These variables control how many PSKs are used in each scenario
    const FEW_KEY_SCENARIO: u64 = 2;
    const MANY_KEY_SCENARIO: u64 = 10_000;

    // This is not useful the majority of the time (in ci), but it's valuable
    // enough and tedious enough to write that we leave the functionality here,
    // but turned off.
    const LOGGING_ENABLED: bool = true;

    static LOGGER_INIT: Once = Once::new();

    fn setup_logging() {
        LOGGER_INIT.call_once(|| {
            if !LOGGING_ENABLED {
                return;
            }
            tracing_subscriber::fmt::fmt()
                .with_max_level(Level::TRACE)
                .with_line_number(true)
                .init();
            tracing::info!("logging is enabled");
        });
    }

    /// This simulation shows how PSK's might be used when there is only a small
    /// number of keys. Keys can be directly added to the connection with
    /// `conn.append_psk(...)`.
    #[tokio::test]
    async fn few_keys_example() -> Result<(), Box<dyn std::error::Error>> {
        setup_logging();

        let psk_store = PskStore::new(FEW_KEY_SCENARIO);

        // this is us doing out "out of band" sharing. We are ensuring that the
        // clients & servers will have shared keys.
        let client_1_psk = psk_store.get(0).unwrap().into();
        let client_2_psk = psk_store.get(1).unwrap().into();

        // this client will fail to connect, because the PSK that it is offering
        // is not known to the server
        let client_3_psk = ExternalPsk::new(b"not a known psk", b"123456928374928734123123")
            .unwrap()
            .into();

        let server = tokio::spawn(async {
            small_server(psk_store).await
        });

        // sim.host("server", move || {
        //     // this clone isn't generally necessary for servers, but Turmoil might
        //     // restart the server, and so we need to be able to call this closure
        //     // multiple times
        //     let psk_clone = psk_store.clone();
        //     small_server(psk_clone)
        // });
        tokio::spawn(async {
            assert!(client(client_1_psk).await.is_ok());
        });
        tokio::spawn(async {
            assert!(client(client_2_psk).await.is_ok());
        });
        tokio::spawn(async {
            assert!(client(client_3_psk).await.is_err());
        });
        Ok(())
    }

    // This simulation shows how PSK's might be used when there is a large
    // number of keys. Each key is ~ 1 Kb, appending each key to the connection
    // would result 10_000 * 1_024 = 10Mb of additional material on each 
    // connection 🤯. To avoid this, we implement the `PskSelectionCallback` for
    // our keystore.
    #[tokio::test]
    async fn multi_client_example_with_callback() -> Result<(), Box<dyn std::error::Error>> {
        setup_logging();

        let psk_store = PskStore::new(MANY_KEY_SCENARIO);

        // this is us doing out "out of band" sharing. We are ensuring that the
        // clients & servers will have shared keys.
        let client_1_psk = psk_store.get(0).unwrap().into();
        let client_2_psk = psk_store.get(1).unwrap().into();

        let server = tokio::spawn(async {
            big_server(psk_store).await
        });

        let client_1 = tokio::spawn(async {
            assert!(client(client_1_psk).await.is_ok());
        });
        let client_2 = tokio::spawn(async {
            assert!(client(client_2_psk).await.is_ok());
        });
        // both of the clients should have successully joined
        assert!(tokio::try_join!(client_1, client_2).is_ok());
        Ok(())
    }
}
