// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that any single-bit mutation in a TLS session ticket prevents
//! session resumption.

use s2n_tls::{
    callbacks::{SessionTicket, SessionTicketCallback},
    config::Builder,
    connection::Connection,
    security,
    testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler, TestPair},
};
use std::{
    sync::{Arc, Mutex},
    time::SystemTime,
};

const KEY: [u8; 16] = [0; 16];
const KEY_NAME: [u8; 3] = [1, 3, 4];

#[derive(Default, Clone)]
struct TicketStash(Arc<Mutex<Option<Vec<u8>>>>);

impl SessionTicketCallback for TicketStash {
    fn on_session_ticket(&self, _: &mut Connection, ticket: &SessionTicket) {
        let mut data = vec![0; ticket.len().unwrap()];
        ticket.data(&mut data).unwrap();
        *self.0.lock().unwrap() = Some(data);
    }
}

fn build_configs(
    policy: &security::Policy,
    stash: &TicketStash,
) -> (s2n_tls::config::Config, s2n_tls::config::Config) {
    let keypair = CertKeyPair::default();

    let server_config = {
        let mut b = Builder::new();
        b.set_security_policy(policy).unwrap();
        b.load_pem(keypair.cert(), keypair.key()).unwrap();
        b.add_session_ticket_key(&KEY_NAME, &KEY, SystemTime::now())
            .unwrap();
        b.build().unwrap()
    };

    let client_config = {
        let mut b = Builder::new();
        b.set_security_policy(policy).unwrap();
        b.trust_pem(keypair.cert()).unwrap();
        b.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        b.enable_session_tickets(true).unwrap();
        b.set_session_ticket_callback(stash.clone()).unwrap();
        b.build().unwrap()
    };

    (client_config, server_config)
}

/// Do an initial handshake and return the session ticket.
fn obtain_ticket(
    client_config: &s2n_tls::config::Config,
    server_config: &s2n_tls::config::Config,
    stash: &TicketStash,
) -> Vec<u8> {
    let mut pair = TestPair::from_configs(client_config, server_config);
    pair.handshake().unwrap();
    // TLS 1.3 sends the ticket after the handshake; a recv drives the state
    // machine far enough to collect it.
    let _ = pair.client.poll_recv(&mut [0]);
    stash.0.lock().unwrap().take().expect("no ticket received")
}

/// Try to resume with the given ticket bytes. Returns true if the handshake
/// succeeded and the connection was resumed.
fn try_resume(
    ticket: &[u8],
    client_config: &s2n_tls::config::Config,
    server_config: &s2n_tls::config::Config,
) -> bool {
    let mut pair = TestPair::from_configs(client_config, server_config);
    pair.client.set_session_ticket(ticket).unwrap();
    match pair.handshake() {
        Ok(()) => pair.client.resumed(),
        Err(_) => false,
    }
}

fn assert_all_mutations_prevent_resumption(policy: &security::Policy) {
    let stash = TicketStash::default();
    let (client_config, server_config) = build_configs(policy, &stash);

    let ticket = obtain_ticket(&client_config, &server_config, &stash);

    // Sanity: unmodified ticket resumes.
    assert!(
        try_resume(&ticket, &client_config, &server_config),
        "original ticket should resume"
    );

    for bit in 0..ticket.len() * 8 {
        let mut tampered = ticket.clone();
        tampered[bit / 8] ^= 1 << (bit % 8);

        assert!(
            !try_resume(&tampered, &client_config, &server_config),
            "tampered ticket was accepted: flipped bit {bit} (byte {}, bit {})",
            bit / 8,
            bit % 8,
        );
    }
}

/// Property: any mutation of the session ticket prevents resumption
#[test]
fn tls13() {
    assert_all_mutations_prevent_resumption(&security::DEFAULT_TLS13);
}

/// Property: any mutation of the session ticket prevents resumption
/// 
/// TLS 1.2 session tickets differ from TLS 1.3 session tickets, so we test them
/// separately.
#[test]
fn tls12() {
    assert_all_mutations_prevent_resumption(&security::TESTING_TLS12);
}
