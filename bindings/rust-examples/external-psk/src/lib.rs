use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::Arc,
};

use aws_lc_rs::rand::SecureRandom;
use s2n_tls::{
    callbacks::{ConnectionFuture, MonotonicClock, WallClock},
    config::{Config, ConnectionInitializer},
    connection,
    enums::PskMode,
    error::Error,
    psk::ExternalPsk,
    security,
};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use turmoil::{net::TcpStream, Sim};

const PORT: u16 = 1738;

const KEY_SIZE: usize = 1024;

// this is a turmoil specific thing, which is needed for s2n-tls to still make "time"
// progress since the simulation is "fast-forwarded". Customers running in the real
// world won't need to set this callback unless they have some reason to override
// the default clock.
struct TurmoilClock;
impl MonotonicClock for TurmoilClock {
    fn get_time(&self) -> std::time::Duration {
        turmoil::sim_elapsed().unwrap()
    }
}

#[derive(Clone)]
pub struct PskStore {
    // mapping from identity -> key material
    keys: HashMap<u64, Vec<u8>>,
}

impl PskStore {
    pub fn new(size: u64) -> Self {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mut keys = HashMap::new();
        for i in 0..size {
            let identity = i;
            let mut material = vec![0; KEY_SIZE];
            rng.fill(&mut material).unwrap();
            keys.insert(identity, material);
        }
        PskStore { keys }
    }

    pub fn get(&self, identity: u64) -> Box<ExternalPsk> {
        let secret = self.keys.get(&identity).unwrap();
        ExternalPsk::new(&identity.to_ne_bytes(), secret).unwrap()
    }
}

/// used by the server to load all of the PSKs onto a connection
impl ConnectionInitializer for PskStore {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
        for (identity, value) in self.keys.iter() {
            let psk = ExternalPsk::new(&identity.to_ne_bytes(), value)?;
            connection.append_psk(&psk)?;
        }
        Ok(None)
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
pub async fn small_server(psk_store: PskStore) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = s2n_tls::config::Config::builder();
    config
        .set_monotonic_clock(TurmoilClock)?
        .set_security_policy(&security::DEFAULT_TLS13)?
        .set_psk_mode(PskMode::External)?
        .set_connection_initializer(psk_store)?;

    let server = TlsAcceptor::new(config.build()?);
    let listener =
        turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

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
    config.set_monotonic_clock(TurmoilClock)?;
    config.set_security_policy(&security::DEFAULT_TLS13)?;
    config.set_connection_initializer(client_psk)?;

    // Create the TlsConnector based on the configuration.
    let client = TlsConnector::new(config.build()?);

    // Connect to the server.
    let stream = TcpStream::connect(("server", PORT)).await?;
    let mut tls = client.connect("localhost", stream).await?;

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
    use std::{sync::Arc, time::Duration};

    use tracing::Level;

    use super::*;

    #[test]
    fn multi_client_example() -> turmoil::Result {
        tracing_subscriber::fmt::fmt()
            .with_max_level(Level::INFO)
            .init();

        // s2n-tls-tokio blinding forces ~ 20 seconds of blinding delay, which 
        // is too long for the default sim. We extend the lifetime to get the real
        // error instead of a "Sim didn't complete within 10 seconds" error.
        let mut sim = turmoil::Builder::new()
            .simulation_duration(Duration::from_secs(60))
            .build();

        let psk_store = PskStore::new(2);

        // this is us doing out "out of band" sharing. We are ensuring that the
        // clients & servers will have shared keys.
        let client_1_psk = psk_store.get(0).into();
        let client_2_psk = psk_store.get(1).into();

        // this client will fail to connect, because the PSK that it is offering
        // is not known to the server
        let client_3_psk =
            ExternalPsk::new(b"not a known psk", b"123456928374928734123123")
                .unwrap()
                .into();

        sim.host("server", move || {
            // this clone isn't generally necessary for servers, but Turmoil might
            // restart the server, and so we need to be able to call this closure
            // multiple times
            let psk_clone = psk_store.clone();
            small_server(psk_clone)
        });
        sim.client("client_1", client(client_1_psk));
        sim.client("client_2", client(client_2_psk));
        sim.client("client_3", async {
            let res = client(client_3_psk).await;
            assert!(res.is_err());
            Ok(())
        });
        sim.run()
    }
}
