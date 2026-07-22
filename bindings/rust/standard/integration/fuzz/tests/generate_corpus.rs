// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generate corpus files from real TLS 1.3 QUIC handshakes and verify that
//! replaying the client bytes produces identical server output.

use s2n_tls::{
    callbacks::{SessionTicket, SessionTicketCallback},
    config,
    connection,
    enums::ClientAuthType,
    security::Policy,
    testing::{self, TestPair},
};
use std::{
    io::Write,
    sync::{mpsc, Arc, Mutex},
    task::Poll,
    time::SystemTime,
};

extern "C" {
    #[link_name = "aws_lc_0_43_0_CRYPTO_get_thread_local"]
    fn CRYPTO_get_thread_local(index: u32) -> *mut core::ffi::c_void;

    #[link_name = "aws_lc_0_43_0_CTR_DRBG_init"]
    fn CTR_DRBG_init(
        drbg: *mut core::ffi::c_void,
        entropy: *const u8,
        personalization: *const u8,
        personalization_len: usize,
    ) -> i32;

    #[link_name = "aws_lc_0_43_0_RAND_bytes"]
    fn RAND_bytes(out: *mut u8, len: usize) -> i32;

    #[link_name = "aws_lc_0_43_0_RAND_public_bytes"]
    fn RAND_public_bytes(out: *mut u8, len: usize) -> i32;
}

const OPENSSL_THREAD_LOCAL_PRIVATE_RAND: u32 = 5;
const OPENSSL_THREAD_LOCAL_PUBLIC_RAND: u32 = 6;
const CTR_DRBG_ENTROPY_LEN: usize = 48;

unsafe fn fuzz_reset_rand() {
    // Force both private and public DRBGs to initialize
    let mut dummy = [0u8; 1];
    RAND_bytes(dummy.as_mut_ptr(), dummy.len());
    RAND_public_bytes(dummy.as_mut_ptr(), dummy.len());

    let zero_entropy = [0u8; CTR_DRBG_ENTROPY_LEN];
    for key in [OPENSSL_THREAD_LOCAL_PRIVATE_RAND, OPENSSL_THREAD_LOCAL_PUBLIC_RAND] {
        let state = CRYPTO_get_thread_local(key);
        if !state.is_null() {
            CTR_DRBG_init(state, zero_entropy.as_ptr(), core::ptr::null(), 0);
        }
    }
}

fn server_config() -> config::Config {
    testing::build_config(&Policy::from_version("default_tls13").unwrap()).unwrap()
}

fn mtls_config() -> config::Config {
    let mut builder =
        testing::config_builder(&Policy::from_version("default_tls13").unwrap()).unwrap();
    builder.set_client_auth_type(ClientAuthType::Required).unwrap();
    builder.build().unwrap()
}

fn resumption_server_config() -> config::Config {
    let mut builder =
        testing::config_builder(&Policy::from_version("default_tls13").unwrap()).unwrap();
    builder
        .add_session_ticket_key(b"fuzz_key", &[0u8; 16], SystemTime::UNIX_EPOCH)
        .unwrap();
    builder.build().unwrap()
}

fn corpus_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join("server_handshake")
        .join(name)
}

fn drain_stream(stream: &std::cell::RefCell<std::collections::VecDeque<u8>>) -> Vec<u8> {
    stream.borrow_mut().drain(..).collect()
}

#[derive(Clone)]
struct Transcript {
    /// (client_bytes, server_bytes) per round
    rounds: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Run a handshake with client and server on separate threads, each with
/// their own deterministic DRBG. Returns the full transcript.
fn generate_transcript(make_config: fn() -> config::Config) -> Transcript {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();
    let (round_tx, round_rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>();

    let client = std::thread::spawn(move || {
        let config = make_config();
        let mut pair = TestPair::from_config(&config);
        pair.client.enable_quic().unwrap();
        unsafe { fuzz_reset_rand() };

        loop {
            let result = pair.client.poll_negotiate();
            let bytes = drain_stream(&pair.io.client_tx_stream);
            if !bytes.is_empty() {
                c2s_tx.send(bytes).unwrap();
            }
            if let Poll::Ready(r) = result {
                r.unwrap();
                break;
            }
            let server_bytes = s2c_rx.recv().unwrap();
            pair.io.server_tx_stream.borrow_mut().write_all(&server_bytes).unwrap();
        }
    });

    let server = std::thread::spawn(move || {
        let config = make_config();
        let mut pair = TestPair::from_config(&config);
        pair.server.enable_quic().unwrap();
        unsafe { fuzz_reset_rand() };

        loop {
            let client_bytes = c2s_rx.recv().unwrap();
            pair.io.client_tx_stream.borrow_mut().write_all(&client_bytes).unwrap();

            let result = pair.server.poll_negotiate();
            let server_bytes = drain_stream(&pair.io.server_tx_stream);
            round_tx.send((client_bytes, server_bytes.clone())).unwrap();
            if !server_bytes.is_empty() {
                s2c_tx.send(server_bytes).unwrap();
            }
            if let Poll::Ready(r) = result {
                r.unwrap();
                break;
            }
        }
    });

    client.join().unwrap();
    server.join().unwrap();

    let mut rounds = Vec::new();
    while let Ok(round) = round_rx.try_recv() {
        rounds.push(round);
    }
    Transcript { rounds }
}

/// Replay the client side of a transcript against a server on its own thread.
/// Assert the server produces byte-identical output.
fn replay_and_verify(make_config: fn() -> config::Config, transcript: Transcript) {
    std::thread::spawn(move || {
        let config = make_config();
        let mut pair = TestPair::from_config(&config);
        pair.server.enable_quic().unwrap();
        unsafe { fuzz_reset_rand() };

        for (i, (client_bytes, expected_server_bytes)) in transcript.rounds.iter().enumerate() {
            pair.io.client_tx_stream.borrow_mut().write_all(client_bytes).unwrap();

            match pair.server.poll_negotiate() {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => panic!("replay failed at round {i}: {e:?}"),
                Poll::Pending => {}
            }

            let actual = drain_stream(&pair.io.server_tx_stream);
            assert_eq!(
                actual, *expected_server_bytes,
                "server output differs at round {i}"
            );
        }
    })
    .join()
    .unwrap();
}

#[test]
fn generate_and_replay_handshake() {
    s2n_tls::init::init();
    let transcript = generate_transcript(server_config);

    let client_bytes: Vec<u8> = transcript.rounds.iter().flat_map(|(c, _)| c).copied().collect();
    std::fs::create_dir_all(corpus_path("")).unwrap();
    let path = corpus_path("tls13_quic_handshake");
    std::fs::write(&path, &client_bytes).unwrap();
    println!("wrote {} bytes to {}", client_bytes.len(), path.display());

    replay_and_verify(server_config, transcript);
}

#[test]
fn generate_and_replay_mtls_handshake() {
    s2n_tls::init::init();
    let transcript = generate_transcript(mtls_config);

    let client_bytes: Vec<u8> = transcript.rounds.iter().flat_map(|(c, _)| c).copied().collect();
    std::fs::create_dir_all(corpus_path("")).unwrap();
    let path = corpus_path("tls13_quic_mtls_handshake");
    std::fs::write(&path, &client_bytes).unwrap();
    println!("wrote {} bytes to {}", client_bytes.len(), path.display());

    replay_and_verify(mtls_config, transcript);
}

#[derive(Default, Clone)]
struct TicketStash(Arc<Mutex<Option<Vec<u8>>>>);

impl SessionTicketCallback for TicketStash {
    fn on_session_ticket(&self, _: &mut connection::Connection, ticket: &SessionTicket) {
        let mut data = vec![0; ticket.len().unwrap()];
        ticket.data(&mut data).unwrap();
        *self.0.lock().unwrap() = Some(data);
    }
}

/// Run an initial handshake to obtain a session ticket, then run a resumption
/// handshake and return the transcript of the resumption handshake.
fn generate_resumption_transcript(make_server_config: fn() -> config::Config) -> Transcript {
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();

    let stash = TicketStash::default();

    // --- Initial handshake to obtain a session ticket ---
    let client_stash = stash.clone();
    let initial_client = std::thread::spawn(move || {
        let mut client_builder =
            testing::config_builder(&Policy::from_version("default_tls13").unwrap()).unwrap();
        client_builder.enable_session_tickets(true).unwrap();
        client_builder
            .set_session_ticket_callback(client_stash.clone())
            .unwrap();
        let client_config = client_builder.build().unwrap();

        let mut pair = TestPair::from_config(&client_config);
        pair.client.enable_quic().unwrap();
        unsafe { fuzz_reset_rand() };

        loop {
            let result = pair.client.poll_negotiate();
            let bytes = drain_stream(&pair.io.client_tx_stream);
            if !bytes.is_empty() {
                c2s_tx.send(bytes).unwrap();
            }
            if let Poll::Ready(r) = result {
                r.unwrap();
                break;
            }
            let server_bytes = s2c_rx.recv().unwrap();
            pair.io
                .server_tx_stream
                .borrow_mut()
                .write_all(&server_bytes)
                .unwrap();
        }

        // Receive the post-handshake NewSessionTicket message from the server.
        let nst_bytes = s2c_rx.recv().unwrap();
        pair.io
            .server_tx_stream
            .borrow_mut()
            .write_all(&nst_bytes)
            .unwrap();
        pair.client.quic_process_post_handshake_message().unwrap();

        // Extract the ticket.
        client_stash.0.lock().unwrap().take().expect("no ticket received")
    });

    let initial_server = std::thread::spawn(move || {
        let config = make_server_config();
        let mut pair = TestPair::from_config(&config);
        pair.server.enable_quic().unwrap();
        unsafe { fuzz_reset_rand() };

        loop {
            let client_bytes = c2s_rx.recv().unwrap();
            pair.io
                .client_tx_stream
                .borrow_mut()
                .write_all(&client_bytes)
                .unwrap();

            let result = pair.server.poll_negotiate();
            let server_bytes = drain_stream(&pair.io.server_tx_stream);
            if !server_bytes.is_empty() {
                s2c_tx.send(server_bytes).unwrap();
            }
            if let Poll::Ready(r) = result {
                r.unwrap();
                break;
            }
        }

        // The server emits a NewSessionTicket post-handshake.
        let nst_bytes = drain_stream(&pair.io.server_tx_stream);
        if !nst_bytes.is_empty() {
            s2c_tx.send(nst_bytes).unwrap();
        }
    });

    let ticket = initial_client.join().unwrap();
    initial_server.join().unwrap();

    // --- Resumption handshake using the ticket ---
    let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
    let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();
    let (round_tx, round_rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>();

    let resumption_client = std::thread::spawn(move || {
        let mut client_builder =
            testing::config_builder(&Policy::from_version("default_tls13").unwrap()).unwrap();
        client_builder.enable_session_tickets(true).unwrap();
        let client_config = client_builder.build().unwrap();

        let mut pair = TestPair::from_config(&client_config);
        pair.client.enable_quic().unwrap();
        pair.client.set_session_ticket(&ticket).unwrap();
        unsafe { fuzz_reset_rand() };

        loop {
            let result = pair.client.poll_negotiate();
            let bytes = drain_stream(&pair.io.client_tx_stream);
            if !bytes.is_empty() {
                c2s_tx.send(bytes).unwrap();
            }
            if let Poll::Ready(r) = result {
                r.unwrap();
                assert!(pair.client.resumed(), "resumption handshake did not resume");
                break;
            }
            let server_bytes = s2c_rx.recv().unwrap();
            pair.io
                .server_tx_stream
                .borrow_mut()
                .write_all(&server_bytes)
                .unwrap();
        }
    });

    let resumption_server = std::thread::spawn(move || {
        let config = make_server_config();
        let mut pair = TestPair::from_config(&config);
        pair.server.enable_quic().unwrap();
        unsafe { fuzz_reset_rand() };

        loop {
            let client_bytes = c2s_rx.recv().unwrap();
            pair.io
                .client_tx_stream
                .borrow_mut()
                .write_all(&client_bytes)
                .unwrap();

            let result = pair.server.poll_negotiate();
            let server_bytes = drain_stream(&pair.io.server_tx_stream);
            round_tx
                .send((client_bytes, server_bytes.clone()))
                .unwrap();
            if !server_bytes.is_empty() {
                s2c_tx.send(server_bytes).unwrap();
            }
            if let Poll::Ready(r) = result {
                r.unwrap();
                break;
            }
        }
    });

    resumption_client.join().unwrap();
    resumption_server.join().unwrap();

    let mut rounds = Vec::new();
    while let Ok(round) = round_rx.try_recv() {
        rounds.push(round);
    }
    Transcript { rounds }
}

#[test]
fn generate_and_replay_resumption_handshake() {
    s2n_tls::init::init();
    let transcript = generate_resumption_transcript(resumption_server_config);

    let client_bytes: Vec<u8> = transcript
        .rounds
        .iter()
        .flat_map(|(c, _)| c)
        .copied()
        .collect();
    std::fs::create_dir_all(corpus_path("")).unwrap();
    let path = corpus_path("tls13_quic_resumption_handshake");
    std::fs::write(&path, &client_bytes).unwrap();
    println!("wrote {} bytes to {}", client_bytes.len(), path.display());

    replay_and_verify(resumption_server_config, transcript);
}
