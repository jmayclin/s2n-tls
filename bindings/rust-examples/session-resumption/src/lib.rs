use std::{
    alloc::System,
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::{
        atomic::{self, AtomicI64, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

use aws_lc_rs::rand::SecureRandom;
use futures_task::noop_waker_ref;
use pair::TestPair;
use s2n_tls::{
    callbacks::{ConnectionFuture, MonotonicClock, SessionTicketCallback, WallClock},
    config::{self, Config, ConnectionInitializer},
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

mod pair;

const PORT: u16 = 1738;

const KEY_SIZE: usize = 1024;
const NUM_TEST_STEKS: usize = 3;
const NUM_HARNESS_THREADS: usize = 64;

/// encrypt_lifetime and decrypt_lifetime are set to this value
const STEK_LIFETIMES: Duration = Duration::from_secs(60);
// we are aiming for system time ranges somewhere in the 1970 + 55 -> 2025 range
const EPOCH_OFFSET: Duration = Duration::from_secs(3_600 * 24 * 365 * 55);

// wall clock is used for STEK operations (selection, expiration) so we need to implement
// this
#[derive(Debug, Default, Clone)]
struct SimulClock(Arc<AtomicU64>);
impl WallClock for SimulClock {
    fn get_time_since_epoch(&self) -> Duration {
        // aim date at 2025
        // necessary for cert expiration stuff, I think
        Duration::from_secs(self.0.load(Ordering::SeqCst)) + EPOCH_OFFSET
    }
}

impl MonotonicClock for SimulClock {
    fn get_time(&self) -> std::time::Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst)) + EPOCH_OFFSET
    }
}

#[derive(Default)]
pub struct Stek {
    name: [u8; 16],
    secret: [u8; 32],
}

impl Stek {
    /// generate a test stek where all bytes in both the name and material are
    /// set to `value`
    fn new(value: u8) -> Self {
        Stek {
            name: [value; 16],
            secret: [value; 32],
        }
    }
}

#[derive(Clone, Debug)]
struct SessionTicket {
    received: tokio::time::Instant,
    lifetime: std::time::Duration,
    pub stek_name: [u8; 16],
    data: Vec<u8>,
}

#[derive(Default, Clone)]
pub struct SessionTicketStore {
    tickets: Arc<Mutex<VecDeque<SessionTicket>>>,
}

impl SessionTicketStore {
    fn get_name(&self) -> [u8; 16] {
        self.tickets
            .lock()
            .unwrap()
            .front()
            .unwrap()
            .stek_name
            .clone()
    }
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
        let stek_name_length = 16 + stek_name_start;
        let stek_name = &data[stek_name_start..stek_name_length];
        println!("stek name is {:?}", stek_name);
        /* FINISH ATTEMPT PARSING */
        let session_ticket = SessionTicket {
            received: tokio::time::Instant::now(),
            lifetime: session_ticket.lifetime().unwrap(),
            stek_name: stek_name.try_into().unwrap(),
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

/// we assume that the diff in clock is 60 at this point (effectively 0 for this simulation)
fn server_config(clock: &SimulClock) -> Result<config::Config, Box<dyn std::error::Error>> {
    let mut config = s2n_tls::config::Config::builder();

    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/certs/test-key.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();
    let key = std::fs::read(key_path).unwrap();

    config
        .load_pem(&cert, &key)?
        //.set_wall_clock(clock.clone())?
        //.set_monotonic_clock(clock.clone())?
        .set_security_policy(&security::DEFAULT_TLS13)?
        .enable_session_tickets(true)?
        .set_ticket_key_encrypt_decrypt_lifetime(STEK_LIFETIMES)?
        .set_ticket_key_decrypt_lifetime(STEK_LIFETIMES)?;

    // add 3 keys that rotate in minutely increments
    for i in 0..NUM_TEST_STEKS {
        let stek = Stek::new(i as u8);
        let intro_time = clock.get_time_since_epoch() + Duration::from_secs(60 * i as u64);
        let intro_time = SystemTime::UNIX_EPOCH + intro_time;
        config.add_session_ticket_key(
            &stek.name,
            &stek.secret,
            SystemTime::now() - Duration::from_secs(1),
        )?;
    }

    Ok(config.build()?)
}

fn client_config(
    clock: &SimulClock,
) -> Result<(config::Config, SessionTicketStore), Box<dyn std::error::Error>> {
    let store = SessionTicketStore::default();

    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();

    let mut config = Config::builder();
    config
        .set_security_policy(&security::DEFAULT)?
        .set_wall_clock(clock.clone())?
        .set_monotonic_clock(clock.clone())?
        .set_connection_initializer(store.clone())?
        .enable_session_tickets(true)?
        .set_session_ticket_callback(store.clone())?
        .trust_pem(&cert)?;
    unsafe {
        // I can't be bothered to figure out my clock marking
        config.disable_x509_verification()?;
    }
    Ok((config.build()?, store))
}

fn repro_trial(seed: u8) -> Result<(), String> {
    let clock = SimulClock::default();
    clock.0.swap(60, Ordering::SeqCst);
    // key intro times are then 60, 120, 180
    let server_config = server_config(&clock).unwrap();
    let (devious_client, devious_ticket) = client_config(&clock).unwrap();

    // 40 seconds after the key 1 intro, but before any other keys are valid.
    clock.0.swap(60 + 40, Ordering::SeqCst);
    // must be session ticket with key 1
    let mut load_initial_session_ticket = TestPair::from_configs(&devious_client, &server_config);
    load_initial_session_ticket
        .client
        .set_waker(Some(noop_waker_ref()))
        .unwrap();
    load_initial_session_ticket.handshake().unwrap();

    assert_eq!(devious_ticket.tickets.lock().unwrap().len(), 1);

    // 120 - 20 seconds after the session ticket was sent
    // key 1 is now expired, but the session ticket still reports a valid lifetime
    clock.0.swap(60 + 40 + 100, Ordering::SeqCst);

    let mut backstabbing_handshake = TestPair::from_configs(&devious_client, &server_config);

    let (innocent_client, innocent_ticket) = client_config(&clock).unwrap();
    let mut innocent_handshake = TestPair::from_configs(&innocent_client, &server_config);
    let backstabbing_handle = std::thread::spawn(move || {
        backstabbing_handshake
            .client
            .set_waker(Some(noop_waker_ref()))
            .unwrap();
        backstabbing_handshake.handshake().unwrap();
        // resumption should not have been successful
        assert!(!backstabbing_handshake.client.resumed());
    });

    let innocent_handle = std::thread::spawn(move || {
        innocent_handshake
            .client
            .set_waker(Some(noop_waker_ref()))
            .unwrap();
        innocent_handshake.handshake().unwrap();
    });

    backstabbing_handle.join().unwrap();
    innocent_handle.join().unwrap();
    let name = innocent_ticket.get_name();
    println!("{:?}", name);
    if name.iter().any(|byte| *byte == 0) {
        return Err("the zero stek name was seen".into());
    }

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

    #[test]
    fn simple() {
        repro_trial(1).unwrap();
    }

    #[test]
    fn repro() {
        let trials = Arc::new(AtomicU64::new(0));
        // 16 cores, each spawns two threads, so 16 threads -> 64 trials
        for _ in 0..NUM_HARNESS_THREADS {
            let trials_handle = Arc::clone(&trials);
            std::thread::spawn(move || {
                let mut seed = 0;
                loop {
                    if trials_handle.load(Ordering::Relaxed) % 100 == 0 {
                        println!("trials: {:?}", trials_handle.load(Ordering::Relaxed));
                    }
                    trials_handle.fetch_add(1, Ordering::Relaxed);
                    seed += 1;
                    seed %= 100;
                    if let Err(e) = repro_trial(seed + 1) {
                        println!("hit the zero name");
                        std::fs::write(
                            format!("trial{}", trials_handle.load(Ordering::Relaxed)),
                            "zero stek name",
                        )
                        .unwrap();
                    }
                };
            });
        }

    }
}
