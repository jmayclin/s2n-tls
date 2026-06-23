mod io_callbacks;
mod witchcraft;
use std::{
    collections::{HashMap, VecDeque},
    io::{ErrorKind, Read, Write},
    net::SocketAddr,
    os::{raw::c_void, unix::net::UnixStream},
    pin::Pin,
    task::Poll,
};

use bytes::{BufMut, BytesMut};
use s2n_tls::{
    callbacks::VerifyHostNameCallback, config::Config, connection::Connection,
    enums::ClientAuthType, error::Error as S2NError, security::DEFAULT_TLS13,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DEFAULT_CA: &str = include_str!(
    "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/ec_ecdsa_p521_sha512/ca-cert.pem"
);
pub const SERVER_CHAIN: &str = include_str!(
    "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/ec_ecdsa_p521_sha512/server-chain.pem"
);
pub const SERVER_KEY: &str = include_str!(
    "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/ec_ecdsa_p521_sha512/server-key.pem"
);
pub const CLIENT_CERT: &str = include_str!(
    "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/ec_ecdsa_p521_sha512/client-cert.pem"
);
pub const CLIENT_KEY: &str = include_str!(
    "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/ec_ecdsa_p521_sha512/client-key.pem"
);

// pub const PING_PONG_VOLLEYS: usize = 1000;
pub const PING_PONG_VOLLEYS: usize = 100;

pub fn client_config() -> Result<s2n_tls::config::Config, S2NError> {
    let mut builder = Config::builder();
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder
        .load_pem(CLIENT_CERT.as_bytes(), CLIENT_KEY.as_bytes())
        .unwrap();
    builder.trust_pem(DEFAULT_CA.as_bytes()).unwrap();
    builder.set_client_auth_type(ClientAuthType::Required)?;
    unsafe { builder.disable_x509_verification().unwrap() };
    builder.build()
}

struct HostNameVerifier;

impl VerifyHostNameCallback for HostNameVerifier {
    fn verify_host_name(&self, host_name: &str) -> bool {
        true
    }
}

pub fn server_config() -> Result<s2n_tls::config::Config, S2NError> {
    let mut builder = Config::builder();
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder
        .load_pem(SERVER_CHAIN.as_bytes(), SERVER_KEY.as_bytes())
        .unwrap();
    builder.trust_pem(DEFAULT_CA.as_bytes()).unwrap();
    builder.set_client_auth_type(ClientAuthType::Required)?;
    builder.set_verify_host_callback(HostNameVerifier)?;
    builder.build()
}

/// We need a memory type that we can read and write to.
///
/// Normally we would use a VecDeque but it's not possible to read into a VecDeque
/// in a zero copy way. This is necessary because we need to read from the Tokio
/// TcpStream into this buffer.
///
/// So instead we use a Vec. While Vec does implement write, it does not implement
/// read, so we have to do that manually.
struct ByteBuffer(Vec<u8>);

impl ByteBuffer {
    fn with_capacity(capacity: usize) -> Self {
        ByteBuffer(Vec::with_capacity(capacity))
    }
}

impl Read for ByteBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // TODO: I suspect that it is more efficient to shift/memcpy the elements
        // rather than actually splitting the vector.
        let data_to_read = usize::min(buf.len(), self.0.len());
        println!("data to read is {data_to_read}");
        if data_to_read == 0 {
            return Ok(0);
        }
        let remaining = self.0.split_off(data_to_read);
        buf[0..data_to_read].copy_from_slice(&self.0);
        *self = ByteBuffer(remaining);
        Ok(data_to_read)
    }
}

pub struct HandshakeOffloadingConnection {
    transport: tokio::net::TcpStream,
    config: s2n_tls::config::Config,
}

/// This is a wrapper for an s2n-tls connection, designed to poll a handshake to
/// completion on a blocking thread.
///
/// This can be particularly useful in the context of an async runtime, where where
/// compute-heavy operations (e.g. signature generation) should be avoided on the
/// main thread
///
/// Applications should directly call [s2n_tls::connection::Connection::poll_negotiate]
/// on the connection member.
struct HandshakeOffloadHarness {
    /// This holds records that have been sent from the peer
    recv_buffer: Pin<Box<ByteBuffer>>,
    /// this holds records that need to be sent to the peer
    send_buffer: Pin<Box<Vec<u8>>>,
    pub connection: Connection,
}

impl HandshakeOffloadHarness {
    fn new(config: Config) -> Self {
        let recv_buffer = Box::pin(ByteBuffer::with_capacity(1_024));
        let send_buffer = Box::pin(Vec::with_capacity(1_024));

        let mut connection = s2n_tls::connection::Connection::new_server();
        connection.set_config(config).unwrap();
        connection.set_receive_callback(Some(io_callbacks::generic_recv_cb::<ByteBuffer>));
        connection.set_send_callback(Some(io_callbacks::generic_send_cb::<Vec<u8>>));

        unsafe {
            connection.set_receive_context(&*recv_buffer as *const ByteBuffer as *mut c_void);
            connection.set_send_context(&*send_buffer as *const Vec<u8> as *mut c_void);
        }

        Self {
            send_buffer,
            recv_buffer,
            connection,
        }
    }
}

impl HandshakeOffloadingConnection {
    pub fn new(transport: tokio::net::TcpStream, config: s2n_tls::config::Config) -> Self {
        Self { transport, config }
    }

    pub async fn handshake(
        mut self,
    ) -> Result<s2n_tls_tokio::TlsStream<tokio::net::TcpStream>, s2n_tls::error::Error> {
        let mut offload_harness = HandshakeOffloadHarness::new(self.config);

        loop {
            // read data from the tcp stream into the handshake offload harness
            let read = self.transport
                .read_buf(&mut offload_harness.recv_buffer.0)
                .await
                .map_err(|io_error| S2NError::application(io_error.into()))?;
            println!("reading {read} from the wire");

            // use it to poll progress in the handshake
            let (finished, offload_harness_handle) = tokio::task::spawn_blocking(move || {
                match offload_harness.connection.poll_negotiate() {
                    Poll::Ready(Ok(_)) => (true, offload_harness),
                    Poll::Ready(Err(e)) => {
                        panic!("ignoring error handling for the sake of simplicity: {e}");
                    }
                    Poll::Pending => (false, offload_harness),
                }
            })
            .await
            .unwrap();
            offload_harness = offload_harness_handle;

            // write any message that s2n-tls generated
            self.transport
                .write_all(&offload_harness.send_buffer)
                .await
                .unwrap();
            offload_harness.send_buffer.clear();

            if finished {
                break;
            }
        }

        Ok(witchcraft::to_tokio_connection(
            offload_harness.connection,
            self.transport,
        ))
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use s2n_tls_tokio::TlsConnector;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[tokio::test]
    async fn it_works() {
        let server_config = server_config().unwrap();
        let client_config = client_config().unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
        
        let server = tokio::spawn(async move {
            let (stream, addr) = tcp_listener.accept().await.unwrap();
            let offloaded_connection = HandshakeOffloadingConnection::new(stream, server_config);
            let mut tls_stream = offloaded_connection.handshake().await.unwrap();
            println!("tls_stream: {tls_stream:?}");

            tls_stream.write_all(b"ready").await.unwrap();

            tls_stream.shutdown().await;
            tls_stream.read(&mut [0]).await;
        });

        let client = tokio::spawn(async {
            let client = TlsConnector::new(client_config);

            // Connect to the server.
            let stream = TcpStream::connect("127.0.0.1:9001").await.unwrap();
            let mut tls = client.connect("leaf", stream).await.unwrap();

            let mut buffer = [0; 5];
            tls.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"ready");

            tls.shutdown().await;
            // println!("{elapsed:?}");
        });

        let server = server.await.unwrap();
        let client = client.await.unwrap();
    }
}
