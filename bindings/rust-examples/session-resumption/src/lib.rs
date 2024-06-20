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
pub const NUM_HARNESS_THREADS: usize = 64;

const SPECIAL_BYTES: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

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
    /// set to `value`. Does note return an all 0 thing if you pass in zero, but 
    /// rather a sentinel key
    fn new(value: u8) -> Self {
        if value == 0 {
            Stek {
                name: SPECIAL_BYTES,
                secret: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            }
        } else {
            Stek {
                name: [value; 16],
                secret: [value; 32],
            }
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
        /* FINISH ATTEMPT PARSING */
        let session_ticket = SessionTicket {
            received: tokio::time::Instant::now(),
            lifetime: session_ticket.lifetime().unwrap(),
            stek_name: stek_name.try_into().unwrap(),
            data: data,
        };

        self.tickets.lock().unwrap().push_back(session_ticket);
    }
}

/// used by the server to load all of the PSKs onto a connection
impl ConnectionInitializer for SessionTicketStore {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
        let tickets = self.tickets.lock().unwrap();

        let front = match tickets.front() {
            Some(front) => front,
            None => {
                return Ok(None);
            }
        };

        connection.set_session_ticket(&front.data)?;

        Ok(None)
    }
}

/// we assume that the diff in clock is 60 at this point (effectively 0 for this simulation)
fn server_config(seed: u8, clock: &SimulClock) -> Result<config::Config, Box<dyn std::error::Error>> {
    let mut config = s2n_tls::config::Config::builder();

    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/certs/test-key.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();
    let key = std::fs::read(key_path).unwrap();

    config
        .load_pem(&cert, &key)?
        .set_wall_clock(clock.clone())?
        //.set_monotonic_clock(clock.clone())?
        .set_security_policy(&security::DEFAULT_TLS13)?
        .enable_session_tickets(true)?
        .set_ticket_key_encrypt_decrypt_lifetime(STEK_LIFETIMES)?
        .set_ticket_key_decrypt_lifetime(STEK_LIFETIMES)?;

    // add 3 keys that rotate in minutely increments
    for i in 0..NUM_TEST_STEKS {
        let stek = Stek::new(seed + i as u8);
        let intro_time = clock.get_time_since_epoch() + Duration::from_secs(60 * i as u64);
        let intro_time = SystemTime::UNIX_EPOCH + intro_time;
        config.add_session_ticket_key(
            &stek.name,
            &stek.secret,
            intro_time,
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
        //.set_monotonic_clock(clock.clone())?
        .set_connection_initializer(store.clone())?
        .enable_session_tickets(true)?
        .set_session_ticket_callback(store.clone())?
        .trust_pem(&cert)?;
    unsafe {
        // I can't be bothered to figure out my clock mocking to get the certificate
        // dates lined up
        config.disable_x509_verification()?;
    }
    Ok((config.build()?, store))
}

pub fn repro_trial(seed: u8) -> Result<(), String> {
    let clock = SimulClock::default();
    clock.0.swap(0, Ordering::SeqCst);
    // key intro times are then 0, 60, 120, 180
    let server_config = server_config(seed,&clock).unwrap();
    let (devious_client, devious_ticket) = client_config(&clock).unwrap();

    // 40 seconds after the key 1 intro, but before any other keys are valid.
    clock.0.swap(40, Ordering::SeqCst);
    // must be session ticket with key 1
    
    // first ticket is encrypted
    let mut load_initial_session_ticket = TestPair::from_configs(&devious_client, &server_config);
    load_initial_session_ticket
        .client
        .set_waker(Some(noop_waker_ref()))
        .unwrap();
    load_initial_session_ticket.handshake().unwrap();

    assert_eq!(devious_ticket.tickets.lock().unwrap().len(), 1);
    //assert_eq!(devious_ticket.get_name(), SPECIAL_BYTES);


    // 120 - 20 seconds after the session ticket was sent
    // key 1 is now expired, but the session ticket still reports a valid lifetime
    clock.0.swap(40 + 100, Ordering::SeqCst);

    // second ticket is encrypted
    let mut backstabbing_handshake = TestPair::from_configs(&devious_client, &server_config);

    let (innocent_client, innocent_ticket) = client_config(&clock).unwrap();
    let mut innocent_handshake = TestPair::from_configs(&innocent_client, &server_config);
    let backstabbing_handle = std::thread::spawn(move || {
        backstabbing_handshake
            .client
            .set_waker(Some(noop_waker_ref()))
            .unwrap();

        // Ballast: This is used to try and line up the 

        backstabbing_handshake.handshake().unwrap();
        // resumption should not have been successful
        assert!(!backstabbing_handshake.client.resumed());
    });

    // third ticket is encrypted
    let innocent_ticket_handle = innocent_ticket.clone();
    let innocent_handle = std::thread::spawn(move || {
        innocent_handshake
            .client
            .set_waker(Some(noop_waker_ref()))
            .unwrap();
        innocent_handshake.handshake().unwrap();

        //assert!(innocent_handshake.client.session_ticket_length().unwrap() > 0);

        if ! innocent_ticket_handle.tickets.lock().unwrap().is_empty() {
            let name = innocent_ticket_handle.get_name();
            if name.iter().any(|byte| *byte == 0) {
                println!("stek name {:?}", name);
                let secret = innocent_handshake.client.give_me_master_secret();
                println!("hex master secret:{}", hex::encode(secret));
                println!("hex ticket data:{}", hex::encode(&innocent_ticket_handle.tickets.lock().unwrap().front().unwrap().data));
                //hex::encode();
            };
        }

        //if innocent_ticket
    });

    backstabbing_handle.join().unwrap();
    innocent_handle.join().unwrap();

    if ! innocent_ticket.tickets.lock().unwrap().is_empty() {
        let name = innocent_ticket.get_name();
        if name.iter().any(|byte| *byte == 0) {
            println!("stek name {:?}", name);
            return Err("the zero stek name was seen".into());
        }
    } else {
        println!("why didn't we get a session ticket?");
    }


    Ok(())
}

#[cfg(test)]
mod simulation {
    use std::{sync::Once, time::Duration};

    use aws_lc_rs::aead::{nonce_sequence, Aad, BoundKey, LessSafeKey, Nonce, OpeningKey, UnboundKey, AES_256_GCM};
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
        repro_trial(0).unwrap();
    }

    struct ZerodCase {
        ticket: &'static str,
        secret: &'static str,
    }

    impl ZerodCase {
        fn new(secret: &'static str, ticket: &'static str) -> Self {
            Self {
                ticket,
                secret,
            }
        }
    }

    // int s2n_server_nst_send(struct s2n_connection *conn)

    // int s2n_server_nst_recv(struct s2n_connection *conn)
    // once again, this is presumably called by the server?

    // s2n_client_serialize_resumption_state

    #[test]
    fn ticket_master_secret_pull() {
        let cases = vec![
            ZerodCase::new("84d51d536b1ea65faaa58abc6d1a2fa8b7b139612a006b02e4ee6b9efb4e8686fb920f4314a3d269a6741bb84eefd012", "010069000000000000000000000000000000008c8f6e47e31e6df3618bf11e1bb02b5f08fc7bcb29a867064de28c18da0cce5c6b62daf2fe4db17b924f3cb2fdc54561a51bde0ab9556eb5b58218bef37e66108f4f20d798352079ace7ff2ea7f906883575d1302d07a72d0a0421c02b18121c7f66ab780084d51d536b1ea65faaa58abc6d1a2fa8b7b139612a006b02e4ee6b9efb4e8686fb920f4314a3d269a6741bb84eefd01201"),
            ZerodCase::new("c6285562802e41c5aceead4c177c14eb7b825d0147f81d7bbf814ebb30bd095e45ceef03aac51363cb8089d294b5341a", "01006900000000000000000000000000000000b5661a33a0e4ed94948f3a36fac891f4eef00df675e2ba97b7d889ed4cedc408481e2b004d907eb8b42d824593e83007c53aa2e31aa0685ef2c630959094225a701e769a397cb547bc6818d3ea39a29cda40e6ea6f21b2aaa80421c02b18121c7f66ab7800c6285562802e41c5aceead4c177c14eb7b825d0147f81d7bbf814ebb30bd095e45ceef03aac51363cb8089d294b5341a01"), 
        ];

        for case in cases {
            let ticket = hex::decode(case.ticket).unwrap();
            //let ticket = VecDeque::from_iter(ticket.into_iter());
            let mut current = 0;

            // this information is added as client specific information in the s2n_client_serialize_resumption_state method
            let tag = ticket[current];
            current += 1;
            let client_ticket_size = u16::from_be_bytes(ticket[current..(current + 2)].try_into().unwrap());
            current += 2;

            // this data comes from the wire
            // however, the lifetime and session_ticket_len have already been read out of the handshake io stuffer in 
            // s2n_server_nst_recv (this naming confuses me). I am small brained, plz halp.
            // so we skip past this to the fields by reverse engineering s2n_encrypt_session_ticket
            let stek_name = &ticket[current..(current + 16)];
            current += 16;
            let iv = &ticket[current..(current + 12)];
            current += 12;
            // all of the data below this point is encrypted under 
            let mut encrypted_blob = ticket[current..(current + 77)].to_owned();
            assert_eq!(encrypted_blob.len(), 77);

            // AAD data is 28 bytes, implicit aad (12) + key name (16)
            let trial_key = [0; 32];
            let unbound_key = UnboundKey::new(&AES_256_GCM, &trial_key).unwrap();
            let aes_key = LessSafeKey::new(unbound_key);
            let nonce = Nonce::try_assume_unique_for_key(&iv).unwrap();

            let aad: [u8; 28] = [0; 12 + 16];
            aes_key.open_in_place(nonce, Aad::from(aad), &mut encrypted_blob).unwrap();
            // AES GCM Tag Len
            let decrypted_data = encrypted_blob[0..(encrypted_blob.len() - 16)].to_owned();

            // should be 61 bytes
            // encrypted blob, from s2n_tls12_serialize_resumption_state
            current = 0;
            let ticket_format = decrypted_data[current];
            assert_eq!(ticket_format, 4);
            current += 1;

            let resume_protocol_version = decrypted_data[current];
            current += 1;

            let cipher = u16::from_be_bytes(decrypted_data[current..(current + 2)].try_into().unwrap());
            current += 2;

            let time = u64::from_be_bytes(decrypted_data[current..(current + 8)].try_into().unwrap());
            current += 8;
            // time: u64

            let master_secret = &decrypted_data[current..(current + 48)];
            let master_secret_from_ticket = hex::encode(master_secret);
            println!("from ticket: {}", master_secret_from_ticket);
            println!("from connection: {}", case.secret);
            assert_eq!(&master_secret_from_ticket, case.secret);
            // master_secret: [u8; 48]
            // ems_negotiated: u8




            // let lifetime: u32 = u32::from_ne_bytes(ticket[current..(current + 4)].try_into().unwrap());
            // current += 2;
            // let session_ticket_len: u16 = u16::from_ne_bytes(ticket[current..(current + 2)].try_into().unwrap());
            // current += 1;
            println!("tag: {:?}", tag);
            println!("client_ticket_size: {:?}", client_ticket_size);
            println!("stek_name: {:?}", stek_name);
            println!("iv: {:?}", iv);

        }

        assert!(false);

        // ticket blob is u16 length
        // u32: lifetime hint
        // u16: session ticket len
        // stuffer blob

    }

    // #[test]
    // fn repro() {
    //     let trials = Arc::new(AtomicU64::new(0));
    //     // 16 cores, each spawns two threads, so 16 threads -> 64 trials
    //     let mut handles = Vec::new();
    //     for _ in 0..NUM_HARNESS_THREADS {
    //         let trials_handle = Arc::clone(&trials);
    //         let handle = std::thread::spawn(move || {
    //             let mut seed = 0;
    //             loop {
    //                 if trials_handle.load(Ordering::Relaxed) % 100000 == 0 {
    //                     println!("trials: {:?}", trials_handle.load(Ordering::Relaxed));
    //                 }
    //                 trials_handle.fetch_add(1, Ordering::Relaxed);
    //                 seed += 1;
    //                 seed %= 100;
    //                 if let Err(e) = repro_trial(seed + 1) {
    //                     println!("hit the zero name");
    //                     std::fs::write(
    //                         format!("trial{}", trials_handle.load(Ordering::Relaxed)),
    //                         "zero stek name",
    //                     )
    //                     .unwrap();
    //                 }
    //             };
    //         });
    //         handles.push(handle);
    //     }
    //     for h in handles {
    //         h.join().unwrap();
    //     }

    // }
}
