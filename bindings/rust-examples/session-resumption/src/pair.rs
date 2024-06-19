use std::{cell::RefCell, collections::VecDeque, ffi::{c_int, c_void}, io::{Read, Write}, pin::Pin, task::Poll};

use s2n_tls::{config, connection, enums, error};

type LocalDataBuffer = RefCell<VecDeque<u8>>;

/// TestPair is a testing utility used to easily test handshakes and send data.
///
/// SAFETY: if the server or client connection is moved outside of the struct, IO
/// is not safe to perform. The connections use pointers to data buffers owned by
/// the Harness. If the Harness goes out of scope, the data buffers will be dropped
/// and the pointers will be invalid.
///
/// The most common usecase is handshaking a simple config.
/// ```ignore
/// // given some config
/// let config = build_config(&crate::security::DEFAULT_TLS13).unwrap();
/// // create a pair (client + server) with uses that config
/// let mut pair = TestPair::from_config(&config);
/// // assert a successful handshake
/// assert!(pair.handshake().is_ok());
/// // we can also do IO using the poll_* functions
/// // this data is sent using the shared data buffers owned by the harness
/// assert!(pair.server.poll_send(&[3, 1, 4]).is_ready());
/// let mut buffer = [0; 3];
/// assert!(pair.client.poll_recv(&mut buffer).is_ready());
/// assert_eq!([3, 1, 4], buffer);
/// ```
//
// The doctest is `ignore`d because testing utilities are not publicly exported
// and therefore can't be referenced in a doc comment.
//
// We allow dead_code, because otherwise the compiler complains about the tx_streams
// never being read. This is because it can't reason through the pointers that were
// passed into the s2n-tls connection io contexts.
#[allow(dead_code)]
pub struct TestPair {
    pub server: connection::Connection,
    pub client: connection::Connection,

    // Pin: since we are dereferencing this pointer (because it is passed as the send/recv ctx)
    // we need to ensure that the pointer remains in the same place
    // Box: A Vec (or VecDeque) may be moved or reallocated, so we need another layer of
    // indirection to have a stable (pinned) reference
    /// a data buffer that the server writes to and the client reads from
    server_tx_stream: Pin<Box<LocalDataBuffer>>,
    /// a data buffer that the client writes to and the server reads from
    client_tx_stream: Pin<Box<LocalDataBuffer>>,
}

impl TestPair {
    /// utility method to test simple handshakes
    ///
    /// Create a client and server from the associated `config`, and try to complete
    /// a TLS handshake. The result of the handshake is returned.
    pub fn handshake_with_config(config: &config::Config) -> Result<(), error::Error> {
        Self::from_configs(config, config).handshake()
    }

    /// create a pair from a config
    ///
    /// A server and client connection will be created, and both will be associated
    /// with `config`. The connections will be setup for IO over shared memory,
    /// but no IO is performed. To handshake the connections, call `handshake()`.
    pub fn from_config(config: &config::Config) -> Self {
        Self::from_configs(config, config)
    }

    pub fn from_configs(client_config: &config::Config, server_config: &config::Config) -> Self {
        let client_tx_stream = Box::pin(Default::default());
        let server_tx_stream = Box::pin(Default::default());

        let client = Self::register_connection(
            enums::Mode::Client,
            client_config,
            &client_tx_stream,
            &server_tx_stream,
        )
        .unwrap();

        let server = Self::register_connection(
            enums::Mode::Server,
            server_config,
            &server_tx_stream,
            &client_tx_stream,
        )
        .unwrap();

        Self {
            server,
            client,
            server_tx_stream,
            client_tx_stream,
        }
    }

    /// create a connection ready for harness IO
    ///
    /// This mostly consists of setting the IO callbacks and the IO contexts.
    ///
    /// We also set blinding to "SelfService" to avoid long delays after failures
    /// in unit tests. However, this will cause calls to `poll_shutdown` to return
    /// Poll::Pending until the blinding delay elapses.
    fn register_connection(
        mode: enums::Mode,
        config: &config::Config,
        send_ctx: &Pin<Box<LocalDataBuffer>>,
        recv_ctx: &Pin<Box<LocalDataBuffer>>,
    ) -> Result<connection::Connection, error::Error> {
        let mut conn = connection::Connection::new(mode);
        conn.set_config(config.clone())?
            .set_blinding(enums::Blinding::SelfService)?
            .set_send_callback(Some(Self::send_cb))?
            .set_receive_callback(Some(Self::recv_cb))?;
        unsafe {
            // cast 1 : send_ctx as &LocalDataBuffer -> get a plain reference to underlying LocalDataBuffer
            //
            // cast 2: &LocalDataBuffer as *const LocalDataBuffer -> cast the reference to a pointer
            //     SAFETY: the LocalDataBuffer must live as long as the connection does. This can be violated if the
            //             connections are moved out from the struct.
            //
            // cast 3: *const LocalDataBuffer as *mut c_void -> cast into the final *mut c_void required
            //     SAFETY: serialized access is enforced by the interior RefCell, so it is safe to vend out
            //             multiple mutable pointers to this item. We ensure this by casting back to an immutable
            //             reference in the send and recv callbacks
            conn.set_send_context(
                send_ctx as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
            )?
            .set_receive_context(
                recv_ctx as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
            )?;
        }
        Ok(conn)
    }

    /// perform a TLS handshake between the connections
    ///
    /// This method will call `poll_negotiate` on each connection until both return
    /// Ready(Ok) which indicates a successful handshake, or until one of the connections
    /// returns Ready(Err) which indicates some fatal error.
    pub fn handshake(&mut self) -> Result<(), error::Error> {
        loop {
            match (self.client.poll_negotiate(), self.server.poll_negotiate()) {
                // if everything is finished and Ok, return Ok
                (Poll::Ready(Ok(_)), Poll::Ready(Ok(_))) => return Ok(()),
                // if there has been an error on the server
                (_, Poll::Ready(Err(e))) => return Err(e),
                // or an error on the client, then return the error
                (Poll::Ready(Err(e)), _) => return Err(e),
                _ => { /* not ready, poll again */ }
            }
        }
    }

    unsafe extern "C" fn send_cb(context: *mut c_void, data: *const u8, len: u32) -> c_int {
        let context = &*(context as *const LocalDataBuffer);
        let data = core::slice::from_raw_parts(data, len as _);
        let bytes_written = context.borrow_mut().write(data).unwrap();
        bytes_written as c_int
    }

    // Note: this callback will be invoked multiple times in the event that
    // the byte-slices of the VecDeque are not contiguous (wrap around).
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &*(context as *const LocalDataBuffer);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        match context.borrow_mut().read(data) {
            Ok(len) => {
                if len == 0 {
                    // returning a length of 0 indicates a channel close (e.g. a
                    // TCP Close) which would not be correct here. To just communicate
                    // that there is no more data, we instead set the errno to
                    // WouldBlock and return -1.
                    errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                    -1
                } else {
                    len as c_int
                }
            }
            Err(err) => {
                // VecDeque IO Operations should never fail
                panic!("{err:?}");
            }
        }
    }
}
