// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    fmt::Debug,
    fs::read_to_string,
    io::{self, ErrorKind, Read, Write},
    pin::Pin,
    rc::Rc,
    sync::Arc,
};
use strum::EnumIter;

#[derive(Clone, Copy, EnumIter)]
pub enum PemType {
    ServerKey,
    ServerCertChain,
    ClientKey,
    ClientCertChain,
    CACert,
}

impl PemType {
    fn get_filename(&self) -> &str {
        match self {
            PemType::ServerKey => "server-key.pem",
            PemType::ServerCertChain => "server-chain.pem",
            PemType::ClientKey => "client-key.pem",
            PemType::ClientCertChain => "client-cert.pem",
            PemType::CACert => "ca-cert.pem",
        }
    }
}

#[derive(Clone, Copy, Default, EnumIter)]
pub enum SigType {
    #[default]
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ecdsa384,
    Ecdsa256,
}

impl SigType {
    pub fn get_dir_name(&self) -> &str {
        match self {
            SigType::Rsa2048 => "rsa2048",
            SigType::Rsa3072 => "rsa3072",
            SigType::Rsa4096 => "rsa4096",
            SigType::Ecdsa384 => "ecdsa384",
            SigType::Ecdsa256 => "ecdsa256",
        }
    }
}

impl Debug for SigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_dir_name())
    }
}

pub fn get_cert_path(pem_type: PemType, sig_type: SigType) -> String {
    format!(
        "certs/{}/{}",
        sig_type.get_dir_name(),
        pem_type.get_filename()
    )
}

pub fn read_to_bytes(pem_type: PemType, sig_type: SigType) -> Vec<u8> {
    read_to_string(get_cert_path(pem_type, sig_type))
        .unwrap()
        .into_bytes()
}

#[derive(Clone, Copy)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Clone, Copy, Default, EnumIter, Eq, PartialEq)]
pub enum HandshakeType {
    #[default]
    ServerAuth,
    MutualAuth,
    Resumption,
}

impl Debug for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeType::ServerAuth => write!(f, "server-auth"),
            HandshakeType::MutualAuth => write!(f, "mTLS"),
            HandshakeType::Resumption => write!(f, "resumption"),
        }
    }
}

// these parameters were the only ones readily usable for all three libaries:
// s2n-tls, rustls, and openssl
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, EnumIter, Eq, PartialEq)]
pub enum CipherSuite {
    #[default]
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
}

#[derive(Clone, Copy, Default, EnumIter)]
pub enum KXGroup {
    Secp256R1,
    #[default]
    X25519,
}

impl Debug for KXGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256R1 => write!(f, "secp256r1"),
            Self::X25519 => write!(f, "x25519"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoConfig {
    pub cipher_suite: CipherSuite,
    pub kx_group: KXGroup,
    pub sig_type: SigType,
}

impl CryptoConfig {
    pub fn new(cipher_suite: CipherSuite, kx_group: KXGroup, sig_type: SigType) -> Self {
        Self {
            cipher_suite,
            kx_group,
            sig_type,
        }
    }
}

/// The TlsBenchConfig trait allows us to map benchmarking parameters to
/// a configuration object
pub trait TlsBenchConfig: Sized {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>>;
}

/// The TlsConnection object can be created from a corresponding config type.
pub trait TlsConnection: Sized {
    /// Library-specific config struct
    type Config;

    /// Name of the connection type
    fn name() -> String;

    /// Make connection from existing config and buffer
    fn new_from_config(config: &Self::Config, io: ViewIO) -> Result<Self, Box<dyn Error>>;

    /// Run one handshake step: receive msgs from other connection, process, and send new msgs
    fn handshake(&mut self) -> Result<(), Box<dyn Error>>;

    fn handshake_completed(&self) -> bool;

    fn get_negotiated_cipher_suite(&self) -> CipherSuite;

    fn negotiated_tls13(&self) -> bool;

    /// Describes whether a connection was resumed. This method is only valid on
    /// server connections because of rustls API limitations.
    fn resumed_connection(&self) -> bool;

    /// Send `data` to the peer
    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>>;

    /// Receive `data` from the peer
    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>>;
}

pub type LocalDataBuffer = RefCell<VecDeque<u8>>;
#[derive(Debug)]
// We allow dead_code, because otherwise the compiler complains about the tx_streams
// never being read. This is because it can't reason through the pointers that were
// passed into the s2n-tls connection io contexts.
#[allow(dead_code)]
pub struct TestPairIO {
    // Pin: since we are dereferencing this pointer (because it is passed as the send/recv ctx)
    // we need to ensure that the pointer remains in the same place
    // Box: A Vec (or VecDeque) may be moved or reallocated, so we need another layer of
    // indirection to have a stable (pinned) reference
    /// a data buffer that the server writes to and the client reads from
    pub server_tx_stream: Arc<Pin<Box<LocalDataBuffer>>>,
    /// a data buffer that the client writes to and the server reads from
    pub client_tx_stream: Arc<Pin<Box<LocalDataBuffer>>>,
}

impl TestPairIO {
    fn client_view(&self) -> ViewIO {
        ViewIO {
            send_ctx: Arc::clone(&self.client_tx_stream),
            recv_ctx: Arc::clone(&self.server_tx_stream),
        }
    }

    fn server_view(&self) -> ViewIO {
        ViewIO {
            send_ctx: Arc::clone(&self.server_tx_stream),
            recv_ctx: Arc::clone(&self.client_tx_stream),
        }
    }
}

/// A "view" of the IO.
///
/// This view is client/server specific, and notably implements the read and write
/// traits.
///
/// This has to be a struct (instead of a tuple of references) because a tuple is
/// always treated as a foreign struct, which prevents us from implement io::Read
/// and io::Write on it.
pub struct ViewIO {
    pub send_ctx: Arc<Pin<Box<LocalDataBuffer>>>,
    pub recv_ctx: Arc<Pin<Box<LocalDataBuffer>>>,
}

impl io::Read for ViewIO {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res = self.recv_ctx.borrow_mut().read(buf);
        if let Ok(0) = res {
            // we are faking a stream, so return WouldBlock on read of length 0
            Err(std::io::Error::new(ErrorKind::WouldBlock, "blocking"))
        } else {
            res
        }
    }
}

impl<'a> io::Write for ViewIO {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send_ctx.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct TlsConnPair<C: TlsConnection, S: TlsConnection> {
    pub client: C,
    pub server: S,
    pub io: TestPairIO,
}

impl<C, S> Default for TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
    C::Config: TlsBenchConfig,
    S::Config: TlsBenchConfig,
{
    fn default() -> Self {
        Self::new_bench_pair(CryptoConfig::default(), HandshakeType::default()).unwrap()
    }
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
    C::Config: TlsBenchConfig,
    S::Config: TlsBenchConfig,
{
    /// Initialize buffers, configs, and connections (pre-handshake)
    pub fn new_bench_pair(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        // do an initial handshake to generate the session ticket
        if handshake_type == HandshakeType::Resumption {
            let server_config =
                S::Config::make_config(Mode::Server, crypto_config, handshake_type)?;
            let client_config =
                C::Config::make_config(Mode::Client, crypto_config, handshake_type)?;

            // handshake the client and server connections. This will result in
            // session ticket getting stored in client_config
            let mut pair = TlsConnPair::<C, S>::from_configs(&client_config, &server_config);
            pair.handshake()?;
            // NewSessionTicket messages are part of the application data and sent
            // after the handshake is complete, so we must trigger an additional
            // "read" on the client connection to ensure that the session ticket
            // gets received and stored in the config
            pair.round_trip_transfer(&mut [0]).unwrap();

            // new_from_config is called interally by the TlsConnPair::new
            // method and will check if a session ticket is available and set it
            // on the connection. This results in the session ticket in
            // client_config (from the previous handshake) getting set on the
            // client connection.
            return Ok(TlsConnPair::<C, S>::from_configs(
                &client_config,
                &server_config,
            ));
        }

        Ok(TlsConnPair::<C, S>::from_configs(
            &C::Config::make_config(Mode::Client, crypto_config, handshake_type).unwrap(),
            &S::Config::make_config(Mode::Server, crypto_config, handshake_type).unwrap(),
        ))
    }
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
{
    pub fn from_configs(client_config: &C::Config, server_config: &S::Config) -> Self {
        let io = TestPairIO {
            server_tx_stream: Arc::new(Box::pin(Default::default())),
            client_tx_stream: Arc::new(Box::pin(Default::default())),
        };
        let client = C::new_from_config(&client_config, io.client_view()).unwrap();
        let server = S::new_from_config(&server_config, io.server_view()).unwrap();

        Self { client, server, io }
        //Self::from_connections(client, server)
    }

    /// Take back ownership of individual connections in the TlsConnPair
    pub fn split(self) -> (C, S) {
        (self.client, self.server)
    }

    /// Run handshake on connections
    /// Two round trips are needed for the server to receive the Finished message
    /// from the client and be ready to send data
    pub fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        for _ in 0..2 {
            self.client.handshake()?;
            self.server.handshake()?;
        }
        assert!(self.handshake_completed());
        Ok(())
    }

    /// Checks if handshake is finished for both client and server
    pub fn handshake_completed(&self) -> bool {
        self.client.handshake_completed() && self.server.handshake_completed()
    }

    pub fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        assert!(self.handshake_completed());
        assert!(
            self.client.get_negotiated_cipher_suite() == self.server.get_negotiated_cipher_suite()
        );
        self.client.get_negotiated_cipher_suite()
    }

    pub fn negotiated_tls13(&self) -> bool {
        self.client.negotiated_tls13() && self.server.negotiated_tls13()
    }

    /// Send data from client to server, and then from server to client
    pub fn round_trip_transfer(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        // send data from client to server
        self.client.send(data)?;
        self.server.recv(data)?;

        // send data from server to client
        self.server.send(data)?;
        self.client.recv(data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "openssl")]
    use crate::OpenSslConnection;
    #[cfg(feature = "rustls")]
    use crate::RustlsConnection;
    use crate::{S2NConnection, TlsConnPair};
    use std::path::Path;
    use strum::IntoEnumIterator;

    #[test]
    fn test_cert_paths_valid() {
        for pem_type in PemType::iter() {
            for sig_type in SigType::iter() {
                assert!(
                    Path::new(&get_cert_path(pem_type, sig_type)).exists(),
                    "cert not found"
                );
            }
        }
    }

    #[test]
    fn test_all() {
        test_type::<S2NConnection, S2NConnection>();
        #[cfg(feature = "rustls")]
        test_type::<RustlsConnection, RustlsConnection>();
        #[cfg(feature = "openssl")]
        test_type::<OpenSslConnection, OpenSslConnection>();
    }

    fn test_type<C, S>()
    where
        S: TlsConnection,
        C: TlsConnection,
        C::Config: TlsBenchConfig,
        S::Config: TlsBenchConfig,
    {
        println!("{} client --- {} server", C::name(), S::name());
        handshake_configs::<C, S>();
        transfer::<C, S>();
    }

    fn handshake_configs<C, S>()
    where
        S: TlsConnection,
        C: TlsConnection,
        C::Config: TlsBenchConfig,
        S::Config: TlsBenchConfig,
    {
        for handshake_type in HandshakeType::iter() {
            for cipher_suite in CipherSuite::iter() {
                for kx_group in KXGroup::iter() {
                    for sig_type in SigType::iter() {
                        let crypto_config = CryptoConfig::new(cipher_suite, kx_group, sig_type);
                        let mut conn_pair =
                            TlsConnPair::<C, S>::new_bench_pair(crypto_config, handshake_type)
                                .unwrap();

                        assert!(!conn_pair.handshake_completed());
                        conn_pair.handshake().unwrap();
                        assert!(conn_pair.handshake_completed());

                        assert!(conn_pair.negotiated_tls13());
                        assert_eq!(cipher_suite, conn_pair.get_negotiated_cipher_suite());
                    }
                }
            }
        }
    }

    fn session_resumption<C, S>()
    where
        S: TlsConnection,
        C: TlsConnection,
        C::Config: TlsBenchConfig,
        S::Config: TlsBenchConfig,
    {
        println!("testing with client:{} server:{}", C::name(), S::name());
        let mut conn_pair =
            TlsConnPair::<C, S>::new_bench_pair(CryptoConfig::default(), HandshakeType::Resumption)
                .unwrap();
        conn_pair.handshake().unwrap();
        let (_, server) = conn_pair.split();
        assert!(server.resumed_connection());
    }

    #[test]
    fn session_resumption_interop() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init()
            .unwrap();
        session_resumption::<S2NConnection, S2NConnection>();
        session_resumption::<S2NConnection, RustlsConnection>();
        session_resumption::<S2NConnection, OpenSslConnection>();

        session_resumption::<RustlsConnection, RustlsConnection>();
        session_resumption::<RustlsConnection, S2NConnection>();
        session_resumption::<RustlsConnection, OpenSslConnection>();

        session_resumption::<OpenSslConnection, OpenSslConnection>();
        session_resumption::<OpenSslConnection, S2NConnection>();
        session_resumption::<OpenSslConnection, RustlsConnection>();
    }

    fn transfer<C, S>()
    where
        S: TlsConnection,
        C: TlsConnection,
        C::Config: TlsBenchConfig,
        S::Config: TlsBenchConfig,
    {
        // use a large buffer to test across TLS record boundaries
        let mut buf = [0x56u8; 1000000];
        for cipher_suite in CipherSuite::iter() {
            let crypto_config =
                CryptoConfig::new(cipher_suite, KXGroup::default(), SigType::default());
            let mut conn_pair =
                TlsConnPair::<C, S>::new_bench_pair(crypto_config, HandshakeType::default())
                    .unwrap();
            conn_pair.handshake().unwrap();
            conn_pair.round_trip_transfer(&mut buf).unwrap();
        }
    }
}
