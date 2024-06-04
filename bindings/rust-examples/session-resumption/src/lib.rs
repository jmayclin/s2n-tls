use std::{
    alloc::System,
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

use aws_lc_rs::rand::SecureRandom;
use s2n_tls::{
    callbacks::{ConnectionFuture, MonotonicClock, SessionTicketCallback, WallClock},
    config::{Config, ConnectionInitializer},
    connection::Connection,
    error::Error,
    security,
};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use turmoil::net::TcpStream;

const PORT: u16 = 1738;

const KEY_SIZE: usize = 1024;

const STEK_LIFETIMES: Duration = Duration::from_secs(3 * 60);
// we are aiming for system time ranges somewhere in the 1970 + 55 -> 2025 range
const EPOCH_OFFSET: Duration = Duration::from_secs(3_600 * 24 * 365 * 55);

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

// wall clock is used for STEK operations (selection, expiration) so we need to implement
// this
impl WallClock for TurmoilClock {
    fn get_time_since_epoch(&self) -> Duration {
        // aim date at 2025
        turmoil::sim_elapsed().unwrap() + EPOCH_OFFSET
    }
}

#[derive(Default)]
pub struct Stek {
    name: u64,
    secret: [u8; 32],
}

impl Stek {
    fn new(name: u64) -> Self {
        let mut stek = Stek::default();
        stek.name = name;

        // generate key
        let rng = aws_lc_rs::rand::SystemRandom::new();
        rng.fill(&mut stek.secret).unwrap();

        stek
    }
}

#[derive(Clone, Debug)]
struct SessionTicket {
    received: tokio::time::Instant,
    lifetime: std::time::Duration,
    stek_name: u64,
    data: Vec<u8>,
}

#[derive(Default, Clone)]
pub struct SessionTicketStore {
    tickets: Arc<Mutex<VecDeque<SessionTicket>>>,
}

impl SessionTicketCallback for SessionTicketStore {
    fn on_session_ticket(
        &self,
        _connection: &mut Connection,
        session_ticket: &s2n_tls::callbacks::SessionTicket,
    ) {
        let size = session_ticket.len().unwrap();
        let mut data = vec![0; size];
        session_ticket.data(&mut data).unwrap();

        /* ATTEMPT PARSING */
        // let state = data[0];
        // tracing::debug!("state is {:?}", state);

        // let len = u16::from_be_bytes(data[1..3].try_into().unwrap());
        // tracing::debug!("len is {:?}", len);

        let stek_name_start = 3;
        let stek_name_length = 16;
        let stek_name = &data[stek_name_start..stek_name_length];
        let stek_name =
            u64::from_be_bytes(stek_name[0..std::mem::size_of::<u64>()].try_into().unwrap());
        tracing::debug!("stek name is {:?}", stek_name);
        /* FINISH ATTEMPT PARSING */
        let session_ticket = SessionTicket {
            received: tokio::time::Instant::now(),
            lifetime: session_ticket.lifetime().unwrap(),
            stek_name: stek_name,
            data: data,
        };

        // Associate the received session ticket with the connection's IP address.
        self.tickets.lock().unwrap().push_back(session_ticket);
    }
}

/// used by the server to load all of the PSKs onto a connection
impl ConnectionInitializer for SessionTicketStore {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
        let mut tickets = self.tickets.lock().unwrap();

        let front = match tickets.front() {
            Some(front) => front,
            None => {
                return Ok(None);
            }
        };

        let remaining_lifetime = front.lifetime - front.received.elapsed();

        // if there is less than one minute remaining in the lifetime, try to do resumption
        if remaining_lifetime < Duration::from_secs(60) {
            let front = tickets.pop_front().unwrap();
            connection.set_application_context::<SessionTicket>(front.clone());
            connection.set_session_ticket(&front.data)?;
            tracing::trace!("trying to do resumption");
        }

        Ok(None)
    }
}

// a server using simpler PSK setup, only supporting 2 different PSKs. Since there
// is a small number of PSKs, we directly load each of them onto the connection
// using the `ConnectionInitializer` trait implemented on `PskStore`.
pub async fn small_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = s2n_tls::config::Config::builder();

    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/certs/test-key.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();
    let key = std::fs::read(key_path).unwrap();

    config
        .load_pem(&cert, &key)?
        .set_monotonic_clock(TurmoilClock)?
        .set_wall_clock(TurmoilClock)?
        .set_security_policy(&security::DEFAULT_TLS13)?
        .enable_session_tickets(true)?
        .set_ticket_key_encrypt_decrypt_lifetime(STEK_LIFETIMES)?
        .set_ticket_key_decrypt_lifetime(STEK_LIFETIMES)?;

    // add 10 keys that rotate in minutely increments
    for i in 0..10 {
        let stek = Stek::new(i);
        let intro_time = TurmoilClock.get_time_since_epoch() + Duration::from_secs(60 * i);
        let intro_time = SystemTime::UNIX_EPOCH + intro_time;
        config.add_session_ticket_key(&stek.name.to_be_bytes(), &stek.secret, intro_time)?;
    }

    let server = TlsAcceptor::new(config.build()?);
    let listener =
        turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

    loop {
        let server_clone = server.clone();
        let (stream, _peer_addr) = listener.accept().await?;
        tokio::spawn(async move {
            tracing::trace!("spawning new task to handle client");
            let mut tls = server_clone.accept(stream).await.unwrap();
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

pub async fn client() -> Result<(), Box<dyn std::error::Error>> {
    let resumption_attempts = Arc::new(AtomicU32::new(0));
    let resumption_success = Arc::new(AtomicU32::new(0));

    let store = SessionTicketStore::default();

    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();

    let mut config = Config::builder();
    config
        .set_monotonic_clock(TurmoilClock)?
        .set_security_policy(&security::DEFAULT_TLS13)?
        .set_connection_initializer(store.clone())?
        .enable_session_tickets(true)?
        .set_session_ticket_callback(store.clone())?
        .trust_pem(&cert)?;

    let start = Instant::now();
    let mut timer = tokio::time::interval(Duration::from_secs(10));
    // Create the TlsConnector based on the configuration.
    let client = TlsConnector::new(config.build()?);

    // for 10 minutes
    while start.elapsed() < Duration::from_secs(60 * 10) {
        timer.tick().await;

        let client_clone = client.clone();

        let resumption_attempts_handle = Arc::clone(&resumption_attempts);
        let resumption_success_handle = Arc::clone(&resumption_success);

        tokio::spawn(async move {
            // Create the TlsConnector based on the configuration.

            tracing::trace!("client is connecting");
            // Connect to the server.
            let stream = TcpStream::connect(("server", PORT)).await.unwrap();
            let mut tls = client_clone.connect("localhost", stream).await.unwrap();
            if tls
                .as_ref()
                .application_context::<SessionTicket>()
                .is_some()
            {
                resumption_attempts_handle.fetch_add(1, Ordering::SeqCst);
                if tls.as_ref().resumed() {
                    resumption_success_handle.fetch_add(1, Ordering::SeqCst);
                } else {
                    let session_ticket = tls
                        .as_ref()
                        .application_context::<SessionTicket>()
                        .unwrap();

                    tracing::error!("Ticket supposed to be valid for {:?}, only {:?} elapsed", session_ticket.lifetime, session_ticket.received.elapsed());
                }

            }

            let mut data_from_server = vec![0; b"hello client".len()];
            tls.read_exact(&mut data_from_server).await.unwrap();
            assert_eq!(data_from_server, b"hello client");

            tls.shutdown().await.unwrap();

            // generally we will see a 0 length read complete successfully, however there
            // is a possibility that the server's RST reaches the socket before we try the
            // 0 length read, in which case an error is returned. Therefore we can not
            // always expect a successful read here.
            let _ = tls.read(&mut [0]).await;
        });
    }

    tracing::info!(
        "session resumption attempts: {:?}, successes: {:?}",
        resumption_attempts, resumption_success
    );
    assert_eq!(
        resumption_attempts.load(Ordering::SeqCst),
        resumption_success.load(Ordering::SeqCst)
    );

    Ok(())
}

#[cfg(test)]
mod simulation {
    use std::{sync::Once, time::Duration};

    use tracing::Level;

    use super::*;

    // This is not useful the majority of the time (in ci), but it's valuable
    // enough and tedious enough to write that we leave the functionality here,
    // but turned off.
    const LOGGING_ENABLED: bool = true;

    static LOGGER_INIT: Once = Once::new();

    fn setup_logging() {
        LOGGER_INIT.call_once(|| {
            if !LOGGING_ENABLED {
                println!("logging is not enabled");
                return;
            }
            tracing_subscriber::fmt::fmt()
                .with_max_level(Level::DEBUG)
                .with_line_number(true)
                .init();
        });
    }

    // This simulation shows how PSK's might be used when there is only a small
    // number of keys. Keys can be directly added to the connection with
    // `conn.append_psk(...)`.
    #[test]
    fn few_keys_example() -> turmoil::Result {
        setup_logging();

        // s2n-tls-tokio blinding forces ~ 20 seconds of blinding delay, which
        // is too long for the default sim. We extend the lifetime to get the real
        // error instead of a "Sim didn't complete within 10 seconds" error.
        let mut sim = turmoil::Builder::new()
            .simulation_duration(Duration::from_secs(60 * 11))
            .build();
        sim.host("server", move || {
            // this clone isn't generally necessary for servers, but Turmoil might
            // restart the server, and so we need to be able to call this closure
            // multiple times
            small_server()
        });
        sim.client("client", client());
        sim.run()
    }
}
