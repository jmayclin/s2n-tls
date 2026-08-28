// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test: a normal s2n-tls peer exchanges application data with an
//! `s2n_ktls::Connection` whose record layer is handled by the kernel.
//!
//! Flow:
//! 1. Complete a real TLS handshake over a loopback TCP socket, with s2n-tls on
//!    both ends (the server side has V1 serialization enabled).
//! 2. Serialize the server connection and enable kTLS on the server socket via
//!    `s2n_ktls::Connection`.
//! 3. Exchange application data in both directions: the plain s2n-tls client
//!    talks to the kTLS server through the kernel.
//! 4. Verify the kTLS connection re-serializes to a parseable blob.
//!
//! Gated on kTLS being available so the suite stays green on other hosts.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::mpsc;
use std::task::Poll;
use std::thread;

use s2n_ktls::{Connection, Mode};
use s2n_tls::connection::Connection as S2nConnection;
use s2n_tls::enums::Mode as S2nMode;

fn ktls_available() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp")
        .map(|s| s.split_whitespace().any(|ulp| ulp == "tls"))
        .unwrap_or(false)
}

/// Drive an s2n-tls handshake to completion over a blocking fd.
fn negotiate_blocking(conn: &mut S2nConnection) {
    loop {
        match conn.poll_negotiate() {
            Poll::Ready(Ok(_)) => return,
            Poll::Ready(Err(e)) => panic!("handshake failed: {e}"),
            Poll::Pending => {
                // With blocking sockets the callbacks block, so Pending should
                // be rare; yield and retry.
                std::thread::yield_now();
            }
        }
    }
}

fn poll_send_all(conn: &mut S2nConnection, mut buf: &[u8]) {
    while !buf.is_empty() {
        match conn.poll_send(buf) {
            Poll::Ready(Ok(n)) => buf = &buf[n..],
            Poll::Ready(Err(e)) => panic!("poll_send failed: {e}"),
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn poll_recv_exact(conn: &mut S2nConnection, buf: &mut [u8]) {
    let mut filled = 0;
    while filled < buf.len() {
        match conn.poll_recv(&mut buf[filled..]) {
            Poll::Ready(Ok(n)) => {
                assert_ne!(n, 0, "unexpected EOF from s2n-tls peer");
                filled += n;
            }
            Poll::Ready(Err(e)) => panic!("poll_recv failed: {e}"),
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn run_e2e(policy: &str) {
    // Two connected blocking loopback sockets.
    let (client_sock, server_sock) = loopback_pair();
    let client_fd = client_sock.as_raw_fd();
    let server_fd = server_sock.as_raw_fd();

    // The client runs a normal s2n-tls connection on its own thread. It must
    // outlive the handshake and the data exchange.
    let (client_ready_tx, client_ready_rx) = mpsc::channel::<()>();
    let (client_done_tx, client_done_rx) = mpsc::channel::<()>();
    let policy_owned = policy.to_string();

    let client_thread = thread::spawn(move || {
        // Keep the socket alive for the duration of this thread.
        let _client_sock = client_sock;
        let mut fd: RawFd = client_fd;

        let config = common::plain_config(&policy_owned);
        let mut client = S2nConnection::new(S2nMode::Client);
        client.set_config(config).unwrap();
        unsafe {
            client.set_send_callback(Some(common::send_cb)).unwrap();
            client.set_receive_callback(Some(common::recv_cb)).unwrap();
            client
                .set_send_context(&mut fd as *mut RawFd as *mut _)
                .unwrap();
            client
                .set_receive_context(&mut fd as *mut RawFd as *mut _)
                .unwrap();
        }

        negotiate_blocking(&mut client);

        // Receive the server's greeting (sent via kTLS) and echo a reply.
        let mut greeting = [0u8; 12];
        poll_recv_exact(&mut client, &mut greeting);
        assert_eq!(&greeting, b"hello ktls!\n");

        poll_send_all(&mut client, b"hi from client\n");

        // Signal the greeting was received, then wait for the main thread to
        // finish reading our reply before tearing down the socket.
        client_ready_tx.send(()).unwrap();
        client_done_rx.recv().unwrap();
    });

    // The server side: complete the handshake with plain s2n-tls, serialize,
    // then hand the socket to kTLS.
    let mut server_fd_holder: RawFd = server_fd;
    let config = common::serializable_config(policy);
    let mut server = S2nConnection::new(S2nMode::Server);
    server.set_config(config).unwrap();
    unsafe {
        server.set_send_callback(Some(common::send_cb)).unwrap();
        server.set_receive_callback(Some(common::recv_cb)).unwrap();
        server
            .set_send_context(&mut server_fd_holder as *mut RawFd as *mut _)
            .unwrap();
        server
            .set_receive_context(&mut server_fd_holder as *mut RawFd as *mut _)
            .unwrap();
    }

    negotiate_blocking(&mut server);

    // Serialize the negotiated server connection.
    let len = server.serialization_length().unwrap();
    let mut blob = vec![0u8; len];
    server.serialize(&mut blob).unwrap();

    // Enabling kTLS requires that s2n-tls no longer touch the socket. Drop the
    // s2n-tls server connection so only the kernel drives the socket now.
    drop(server);

    // Hand the socket to kTLS.
    let mut ktls_server = Connection::new(&blob, server_sock, Mode::Server)
        .unwrap_or_else(|e| panic!("policy {policy}: enabling kTLS failed: {e}"));

    // Send a greeting to the client through the kernel, then read the reply.
    ktls_server.write_all(b"hello ktls!\n").unwrap();
    ktls_server.flush().unwrap();

    // Wait until the client has received our greeting and sent its reply.
    client_ready_rx.recv().unwrap();

    let mut reply = [0u8; 15];
    ktls_server.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"hi from client\n");

    // The kTLS connection re-serializes to a parseable blob.
    let reserialized = ktls_server.to_vec();
    assert_eq!(reserialized, blob);
    s2n_ktls::protocol::serialization::SerializedConnection::parse(&reserialized).unwrap();

    // Allow the client thread to finish.
    client_done_tx.send(()).unwrap();
    client_thread.join().unwrap();
}

#[test]
fn e2e_tls12_ktls_server() {
    if !ktls_available() {
        eprintln!("skipping: kTLS not available on this host");
        return;
    }
    run_e2e("default");
}

#[test]
fn e2e_tls13_ktls_server() {
    if !ktls_available() {
        eprintln!("skipping: kTLS not available on this host");
        return;
    }
    run_e2e("default_tls13");
}
