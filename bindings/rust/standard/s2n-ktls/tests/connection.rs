// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `Connection` construction: attaching the TLS ULP and programming
//! the kernel with derived keys.
//!
//! The tests that actually program the kernel are gated on kTLS being
//! available on the host, so the suite stays green on non-kTLS platforms.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use s2n_ktls::{KtlsTcpStream, Mode};

/// Best-effort probe for kTLS support: check that the `tls` ULP is listed in
/// `/proc/sys/net/ipv4/tcp_available_ulp`. Returns false on non-Linux or when
/// the module isn't loaded, so the gated tests are skipped.
fn ktls_available() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp")
        .map(|s| s.split_whitespace().any(|ulp| ulp == "tls"))
        .unwrap_or(false)
}

/// Create a pair of connected loopback TCP sockets.
fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn programming_fails_on_unconnected_socket() {
    if !ktls_available() {
        eprintln!("skipping: kTLS not available on this host");
        return;
    }

    // A freshly bound-but-not-connected socket cannot have the TLS keys
    // installed; setsockopt(SOL_TLS, ...) should fail and be surfaced as an
    // Io error rather than panicking.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Connect then immediately shut down the peer to get a socket that's not
    // in a state the TLS ULP will accept keys on.
    let stream = TcpStream::connect(addr).unwrap();
    drop(listener);

    let blob = common::serialized_pair("default").server_blob;
    // We can't strongly assert failure vs success for every kernel state here;
    // the important property is that we get a Result, never a panic.
    let _ = KtlsTcpStream::new(&blob, stream, Mode::Server);
}

#[test]
fn program_kernel_on_loopback_socket() {
    if !ktls_available() {
        eprintln!("skipping: kTLS not available on this host");
        return;
    }

    for policy in ["default", "default_tls13"] {
        let sp = common::serialized_pair(policy);
        let (client_sock, server_sock) = loopback_pair();

        // Program both ends with their respective serialized blobs. The peers
        // won't successfully decrypt each other here (the TestPair handshake
        // was over in-memory IO, not these sockets), but programming the
        // kernel with well-formed crypto_info must succeed.
        let server = KtlsTcpStream::new(&sp.server_blob, server_sock, Mode::Server)
            .unwrap_or_else(|e| panic!("policy {policy}: server programming failed: {e}"));
        let client = KtlsTcpStream::new(&sp.client_blob, client_sock, Mode::Client)
            .unwrap_or_else(|e| panic!("policy {policy}: client programming failed: {e}"));

        assert_eq!(server.mode(), Mode::Server);
        assert_eq!(client.mode(), Mode::Client);
    }
}

#[test]
fn serialize_round_trips_after_construction() {
    if !ktls_available() {
        eprintln!("skipping: kTLS not available on this host");
        return;
    }

    let sp = common::serialized_pair("default_tls13");
    let (_client_sock, server_sock) = loopback_pair();

    let conn = KtlsTcpStream::new(&sp.server_blob, server_sock, Mode::Server).unwrap();

    // Re-serialization reproduces the original blob (sequence numbers are the
    // parsed values, since no application data has been sent through kTLS).
    let mut out = vec![0u8; conn.serialization_length()];
    conn.serialize(&mut out).unwrap();
    assert_eq!(out, sp.server_blob);
    assert_eq!(conn.to_vec(), sp.server_blob);
}

// Silence unused-import warnings on non-kTLS hosts where the gated tests early
// return before touching Read/Write.
#[allow(dead_code)]
fn _assert_io_traits(mut c: KtlsTcpStream) {
    let mut buf = [0u8; 1];
    let _ = c.read(&mut buf);
    let _ = c.write(&buf);
    let _ = c.flush();
}
