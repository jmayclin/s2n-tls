// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    callbacks::VerifyHostNameCallback, connection::{self, Connection}, enums::Blinding, security
};
use bytes::{Bytes, BytesMut};
use core::task::Poll;
use std::{collections::VecDeque, sync::{atomic::{AtomicUsize, Ordering}, Arc}};
use libc::c_void;
use s2n_tls_sys::s2n_status_code::Type as s2n_status_code;


pub type TestError = Box<dyn std::error::Error>;
pub type TestResult<T, E = TestError> = core::result::Result<T, E>;

pub fn test_error(msg: &str) -> crate::error::Error {
    crate::error::Error::application(msg.into())
}

pub fn assert_test_error(input: TestError, msg: &str) {
    let error = input
        .downcast::<crate::error::Error>()
        .expect("Unexpected generic error type");
    if let Some(inner) = error.application_error() {
        assert_eq!(msg, inner.to_string())
    } else {
        panic!("Unexpected known error type");
    }
}

#[derive(Clone)]
pub struct Counter(Arc<AtomicUsize>);
impl Counter {
    fn new() -> Self {
        Counter(Arc::new(AtomicUsize::new(0)))
    }
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

pub trait GeneralConnection: core::fmt::Debug {
    fn poll_negotiate<Ctx: Context>(&mut self, context: &mut Ctx) -> Poll<TestResult<()>>;
    fn poll_action<Ctx: Context, F>(&mut self, context: &mut Ctx, action: F) -> Poll<TestResult<()>>
    where
        F: FnOnce(&mut crate::connection::Connection) -> Poll<Result<usize, crate::error::Error>>;
}

pub trait Context {
    fn receive(&mut self, max_len: Option<usize>) -> Option<Bytes>;
    fn send(&mut self, data: Bytes);
}

pub enum Mode {
    Client,
    Server,
}

#[derive(Debug)]
pub struct Pair<Server: GeneralConnection, Client: GeneralConnection> {
    pub server: (Server, MemoryContext),
    pub client: (Client, MemoryContext),
    pub max_iterations: usize,
}

impl<Server: GeneralConnection, Client: GeneralConnection> Pair<Server, Client> {
    /// The number of iterations that will be executed until the handshake exits with an error
    ///
    /// This is to prevent endless looping without making progress on the connection.
    const DEFAULT_ITERATIONS: usize = 100;

    pub fn new(server: Server, client: Client) -> Self {
        Self {
            server: (server, Default::default()),
            client: (client, Default::default()),
            max_iterations: Self::DEFAULT_ITERATIONS,
        }
    }
    pub fn poll(&mut self) -> Poll<TestResult<()>> {
        assert!(
            self.max_iterations > 0,
            "handshake has iterated too many times: {:#?}",
            self,
        );
        let client_res = self.client.0.poll_negotiate(&mut self.client.1);
        let server_res = self.server.0.poll_negotiate(&mut self.server.1);
        self.client.1.transfer(&mut self.server.1);
        self.max_iterations -= 1;
        match (client_res, server_res) {
            (Poll::Ready(client_res), Poll::Ready(server_res)) => {
                client_res?;
                server_res?;
                Ok(()).into()
            }
            (Poll::Ready(client_res), _) => {
                client_res?;
                Poll::Pending
            }
            (_, Poll::Ready(server_res)) => {
                server_res?;
                Poll::Pending
            }
            _ => Poll::Pending,
        }
    }

    pub fn poll_send(&mut self, sender: Mode, buf: &[u8]) -> Poll<TestResult<()>> {
        let result = match sender {
            Mode::Client => self.client.0.poll_action(&mut self.client.1, |conn| {
                crate::connection::Connection::poll_send(conn, buf)
            }),
            Mode::Server => self.server.0.poll_action(&mut self.server.1, |conn| {
                crate::connection::Connection::poll_send(conn, buf)
            }),
        };
        self.server.1.transfer(&mut self.client.1);
        match result {
            Poll::Ready(result) => {
                result?;
                Ok(()).into()
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn poll_recv(&mut self, receiver: Mode, buf: &mut [u8]) -> Poll<TestResult<()>> {
        let result = match receiver {
            Mode::Client => self.client.0.poll_action(&mut self.client.1, |conn| {
                crate::connection::Connection::poll_recv(conn, buf)
            }),
            Mode::Server => self.server.0.poll_action(&mut self.server.1, |conn| {
                crate::connection::Connection::poll_recv(conn, buf)
            }),
        };
        match result {
            Poll::Ready(result) => {
                result?;
                Ok(()).into()
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Default)]
pub struct MemoryContext {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Bytes>,
}

impl MemoryContext {
    pub fn transfer(&mut self, other: &mut Self) {
        self.rx.extend(other.tx.drain(..));
        other.rx.extend(self.tx.drain(..));
    }
}

impl Context for MemoryContext {
    fn receive(&mut self, max_len: Option<usize>) -> Option<Bytes> {
        loop {
            let mut chunk = self.rx.pop_front()?;

            if chunk.is_empty() {
                continue;
            }

            let max_len = max_len.unwrap_or(usize::MAX);

            if chunk.len() > max_len {
                self.rx.push_front(chunk.split_off(max_len));
            }

            return Some(chunk);
        }
    }

    fn send(&mut self, data: Bytes) {
        self.tx.push_back(data);
    }
}

pub struct CertKeyPair {
    pub cert_path: &'static str,
    pub cert: &'static [u8],
    pub key: &'static [u8],
}

impl Default for CertKeyPair {
    fn default() -> Self {
        CertKeyPair {
            cert_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../tests/pems/rsa_4096_sha512_client_cert.pem",
            ),
            cert: &include_bytes!("../../../../../tests/pems/rsa_4096_sha512_client_cert.pem")[..],
            key: &include_bytes!("../../../../../tests/pems/rsa_4096_sha512_client_key.pem")[..],
        }
    }
}

impl CertKeyPair {
    pub fn cert_path(&self) -> &'static str {
        self.cert_path
    }

    pub fn cert(&self) -> &'static [u8] {
        self.cert
    }

    pub fn key(&self) -> &'static [u8] {
        self.key
    }
}

pub struct InsecureAcceptAllCertificatesHandler {}
impl VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

pub struct RejectAllCertificatesHandler {}
impl VerifyHostNameCallback for RejectAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        false
    }
}

pub fn build_config(cipher_prefs: &security::Policy) -> Result<crate::config::Config, TestError> {
    let builder = config_builder(cipher_prefs)?;
    Ok(builder.build().expect("Unable to build server config"))
}

pub fn config_builder(cipher_prefs: &security::Policy) -> Result<crate::config::Builder, TestError> {
    let mut builder = crate::config::Builder::new();
    let keypair = CertKeyPair::default();
    // Build a config
    builder
        .set_security_policy(cipher_prefs)
        .expect("Unable to set config cipher preferences");
    builder
        .load_pem(keypair.cert(), keypair.key())
        .expect("Unable to load cert/pem");
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .expect("Unable to set a host verify callback.");
    builder.trust_pem(keypair.cert()).expect("load cert pem");
    Ok(builder)
}

pub fn tls_pair(config: crate::config::Config) -> Pair<Harness, Harness> {
    // create and configure a server connection
    let mut server = crate::connection::Connection::new_server();
    // some tests check for connection failure so disable blinding to avoid delay
    server.as_mut().set_blinding(Blinding::SelfService).unwrap();
    server
        .set_config(config.clone())
        .expect("Failed to bind config to server connection");
    let server = Harness::new(server);

    // create a client connection
    let mut client = crate::connection::Connection::new_client();
    // some tests check for connection failure so disable blinding to avoid delay
    client.as_mut().set_blinding(Blinding::SelfService).unwrap();
    client
        .set_config(config)
        .expect("Unable to set client config");
    let client = Harness::new(client);

    Pair::new(server, client)
}

pub fn establish_connection(config: crate::config::Config) {
    // create and configure a server connection
    let mut server = crate::connection::Connection::new_server();
    server
        .set_config(config.clone())
        .expect("Failed to bind config to server connection");
    let server = Harness::new(server);

    // create a client connection
    let mut client = crate::connection::Connection::new_client();
    client
        .set_config(config)
        .expect("Unable to set client config");
    let client = Harness::new(client);

    let pair = Pair::new(server, client);
    poll_tls_pair(pair);
}

pub fn poll_tls_pair(mut pair: Pair<Harness, Harness>) -> Pair<Harness, Harness> {
    loop {
        match pair.poll() {
            Poll::Ready(result) => {
                result.unwrap();
                break;
            }
            Poll::Pending => continue,
        }
    }

    pair
}

pub fn poll_tls_pair_result(pair: &mut Pair<Harness, Harness>) -> TestResult<()> {
    loop {
        match pair.poll() {
            Poll::Ready(result) => return result,
            Poll::Pending => continue,
        }
    }
}


const SEND_BUFFER_CAPACITY: usize = 4096;

#[derive(Debug)]
pub struct Harness {
    pub connection: connection::Connection,
    pub send_buffer: BytesMut,
    pub handshake_done: bool,
    // TODO add a size
}

impl Harness {
    pub fn new(connection: connection::Connection) -> Self {
        Self {
            connection,
            send_buffer: BytesMut::new(),
            handshake_done: false,
        }
    }

    pub fn connection(&self) -> &connection::Connection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut connection::Connection {
        &mut self.connection
    }
}

impl GeneralConnection for Harness {
    fn poll_negotiate<Ctx: Context>(&mut self, context: &mut Ctx) -> Poll<TestResult<()>> {
        let mut callback: Callback<Ctx> = Callback {
            context,
            err: None,
            send_buffer: &mut self.send_buffer,
        };

        unsafe {
            // Safety: the callback struct must live as long as the callbacks are
            // set on on the connection
            callback.set(&mut self.connection);
        }

        let result = self.connection.poll_negotiate().map_ok(|_| ());

        callback.unset(&mut self.connection)?;

        match result {
            Poll::Ready(Ok(_)) => {
                if !self.handshake_done {
                    self.handshake_done = true;
                }
                Ok(()).into()
            }
            Poll::Ready(Err(err)) => Err(err.into()).into(),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_action<Ctx: Context, F>(&mut self, context: &mut Ctx, action: F) -> Poll<TestResult<()>>
    where
        F: FnOnce(&mut connection::Connection) -> Poll<Result<usize, crate::error::Error>>,
    {
        let mut callback: Callback<Ctx> = Callback {
            context,
            err: None,
            send_buffer: &mut self.send_buffer,
        };

        unsafe {
            // Safety: the callback struct must live as long as the callbacks are
            // set on on the connection
            callback.set(&mut self.connection);
        }

        let result = action(&mut self.connection);

        callback.unset(&mut self.connection)?;

        match result {
            Poll::Ready(Ok(_)) => Ok(()).into(),
            Poll::Ready(Err(err)) => Err(err.into()).into(),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct Callback<'a, T> {
    pub context: &'a mut T,
    pub err: Option<TestError>,
    pub send_buffer: &'a mut BytesMut,
}

impl<'a, T: 'a + Context> Callback<'a, T> {
    unsafe fn set(&mut self, connection: &mut connection::Connection) {
        let context = self as *mut Self as *mut c_void;

        // We use unwrap here since s2n-tls will just check if connection is not null
        connection.set_send_callback(Some(Self::send_cb)).unwrap();
        connection.set_send_context(context).unwrap();
        connection
            .set_receive_callback(Some(Self::recv_cb))
            .unwrap();
        connection.set_receive_context(context).unwrap();
    }

    /// Removes all of the callback and context pointers from the connection
    pub fn unset(mut self, connection: &mut connection::Connection) -> TestResult<()> {
        unsafe {
            unsafe extern "C" fn send_cb(
                _context: *mut c_void,
                _data: *const u8,
                _len: u32,
            ) -> s2n_status_code {
                -1
            }

            unsafe extern "C" fn recv_cb(
                _context: *mut c_void,
                _data: *mut u8,
                _len: u32,
            ) -> s2n_status_code {
                -1
            }

            // We use unwrap here since s2n-tls will just check if connection is not null
            connection.set_send_callback(Some(send_cb)).unwrap();
            connection.set_send_context(core::ptr::null_mut()).unwrap();
            connection.set_receive_callback(Some(recv_cb)).unwrap();
            connection
                .set_receive_context(core::ptr::null_mut())
                .unwrap();

            // Flush the send buffer before returning to the connection
            self.flush();

            if let Some(err) = self.err {
                return Err(err);
            }

            Ok(())
        }
    }

    unsafe extern "C" fn send_cb(
        context: *mut c_void,
        data: *const u8,
        len: u32,
    ) -> s2n_status_code {
        let context = &mut *(context as *mut Self);
        let data = core::slice::from_raw_parts(data, len as _);
        context.on_write(data) as _
    }

    /// Called when sending data
    fn on_write(&mut self, data: &[u8]) -> usize {
        // If this write would cause the current send buffer to reallocate,
        // we should flush and create a new send buffer.
        let remaining_capacity = self.send_buffer.capacity() - self.send_buffer.len();

        if remaining_capacity < data.len() {
            // Flush the send buffer before reallocating it
            self.flush();

            // ensure we only do one allocation for this write
            let len = SEND_BUFFER_CAPACITY.max(data.len());

            debug_assert!(
                self.send_buffer.is_empty(),
                "dropping a send buffer with data will result in data loss"
            );
            *self.send_buffer = BytesMut::with_capacity(len);
        }

        // Write the current data to the send buffer
        //
        // NOTE: we don't immediately flush to the context since s2n-tls may do
        //       several small writes in a row.
        self.send_buffer.extend_from_slice(data);

        data.len()
    }

    /// Flushes the send buffer into the context
    fn flush(&mut self) {
        if !self.send_buffer.is_empty() {
            let chunk = self.send_buffer.split().freeze();
            self.context.send(chunk);
        }
    }

    /// The function s2n-tls calls when it wants to receive data
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> s2n_status_code {
        let context = &mut *(context as *mut Self);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        match context.on_read(data) {
            0 => {
                // https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#a699fd9e05a8e8163811db6cab01af973
                // s2n-tls wants us to set the global errno to signal blocked
                errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                -1
            }
            len => len as _,
        }
    }

    /// Called when receiving data
    fn on_read(&mut self, data: &mut [u8]) -> usize {
        let max_len = Some(data.len());

        // TODO: loop until data buffer is full.
        if let Some(chunk) = self.context.receive(max_len) {
            let len = chunk.len();
            data[..len].copy_from_slice(&chunk);
            len
        } else {
            0
        }
    }
}


