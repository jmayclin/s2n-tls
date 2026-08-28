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

use s2n_ktls::{KtlsTcpStream, Mode};
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
    let mut ktls_server = KtlsTcpStream::new(&blob, server_sock, Mode::Server)
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

/// End-to-end test with TLS 1.3 key updates in both directions.
///
/// Flow:
/// 1. Complete a real TLS 1.3 handshake over a loopback TCP socket, with
///    plain s2n-tls on both ends (server has V1 serialization enabled).
/// 2. Serialize the server connection, drop it, and enable kTLS on the server
///    socket via [`KtlsTcpStream`].
/// 3. Client sends data, then performs a key update, then sends more data.
///    The kTLS server reads all of it: the `KeyUpdate` is detected and the RX
///    key re-programmed transparently inside `read`, with **no** call into
///    s2n-tls.
/// 4. The kTLS server performs its own (TX) key update via
///    [`KtlsTcpStream::update_send_key`] and sends data under the new key; the
///    plain s2n-tls client processes the `KeyUpdate` and reads the data.
#[test]
fn e2e_tls13_ktls_key_update() {
    assert!(ktls_available());

    let (client_sock, server_sock) = loopback_pair();
    let client_fd = client_sock.as_raw_fd();
    let server_fd = server_sock.as_raw_fd();

    let (server_ready_tx, server_ready_rx) = mpsc::channel::<()>();
    let (client_done_tx, client_done_rx) = mpsc::channel::<()>();

    let client_thread = thread::spawn(move || {
        let _client_sock = client_sock;
        let mut fd: RawFd = client_fd;

        let config = common::plain_config("default_tls13");
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

        // Wait until the server has kTLS enabled before sending anything.
        server_ready_rx.recv().unwrap();

        // Send data under the initial key.
        poll_send_all(&mut client, b"hello before update\n");

        // Perform a client -> server key update. request_key_update only sets a
        // flag; the KeyUpdate message is emitted on the next send, ahead of the
        // application data, which is then encrypted under the new key.
        use s2n_tls::enums::PeerKeyUpdate;
        client
            .request_key_update(PeerKeyUpdate::KeyUpdateNotRequested)
            .unwrap();
        poll_send_all(&mut client, b"hello after update\n");

        // Now receive data from the server. The server performs its own key
        // update before sending; s2n-tls processes the incoming KeyUpdate
        // during poll_recv and reads the application data under the new key.
        let mut reply = [0u8; 19];
        poll_recv_exact(&mut client, &mut reply);
        assert_eq!(&reply, b"server after update");

        client_done_tx.send(()).unwrap();
    });

    // Server side: handshake with plain s2n-tls, serialize, hand to kTLS.
    let mut server_fd_holder: RawFd = server_fd;
    let config = common::serializable_config("default_tls13");
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
    assert_eq!(
        server.actual_protocol_version().unwrap(),
        s2n_tls::enums::Version::TLS13
    );

    let len = server.serialization_length().unwrap();
    let mut blob = vec![0u8; len];
    server.serialize(&mut blob).unwrap();
    drop(server);

    let mut ktls_server = KtlsTcpStream::new(&blob, server_sock, Mode::Server).unwrap();

    // Let the client start sending.
    server_ready_tx.send(()).unwrap();

    // Read data sent under the initial key.
    let mut msg1 = [0u8; 20];
    ktls_server.read_exact(&mut msg1).unwrap();
    assert_eq!(&msg1, b"hello before update\n");

    // Read data sent after the client's key update. The KeyUpdate record is
    // detected and the RX key re-programmed transparently inside read().
    let mut msg2 = [0u8; 19];
    ktls_server.read_exact(&mut msg2).unwrap();
    assert_eq!(&msg2, b"hello after update\n");
    assert_eq!(
        ktls_server.recv_key_updates(),
        1,
        "server should have applied exactly one RX key update"
    );

    // Now the kTLS server performs its own (TX) key update and sends data under
    // the new key.
    ktls_server.update_send_key(false).unwrap();
    assert_eq!(ktls_server.send_key_updates(), 1);
    ktls_server.write_all(b"server after update").unwrap();
    ktls_server.flush().unwrap();

    client_done_rx.recv().unwrap();
    client_thread.join().unwrap();
}

#[test]
fn e2e_tls12_ktls_server() {
    assert!(ktls_available());
    run_e2e("default");
}

#[test]
fn e2e_tls13_ktls_server() {
    assert!(ktls_available());
    run_e2e("default_tls13");
}
