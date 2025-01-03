// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod bench_config;
mod io;

pub use bench_config::*;
pub use io::{LocalDataBuffer, TestPairIO, ViewIO};

use std::{any::Any, error::Error, rc::Rc};

#[derive(Clone, Copy)]
pub enum Mode {
    Client,
    Server,
}

/// The TlsConnection object can be created from a corresponding config type.
pub trait TlsConnection: Sized {
    /// Library-specific config struct
    type Config;

    /// Name of the connection type
    fn name() -> String;

    /// Make connection from existing config and buffer
    fn new_from_config(
        mode: Mode,
        config: &Self::Config,
        io: &TestPairIO,
    ) -> Result<Self, Box<dyn Error>>;

    /// Run one handshake step: receive msgs from other connection, process, and send new msgs
    fn handshake(&mut self) -> Result<(), Box<dyn Error>>;

    // fn shutdown(&mut self)

    /// Send application data to ConnectedBuffer
    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>>;

    /// Read application data from ConnectedBuffer
    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>>;

    fn handshake_completed(&self) -> bool;

    fn get_negotiated_cipher_suite(&self) -> CipherSuite;

    fn negotiated_tls13(&self) -> bool;

    /// Describes whether a connection was resumed. This method is only valid on
    /// server connections because of rustls API limitations.
    fn resumed_connection(&self) -> bool;
}

/// A TlsConnPair owns the client and server tls connections along with the IO buffers.
pub struct TlsConnPair<C: TlsConnection, S: TlsConnection> {
    pub client: C,
    pub server: S,
    pub io: TestPairIO,
    /// In some cases (notably session resumption) connections needs to store some
    /// information and use it in a different connection. Currently, client_context
    /// is only used for session resumption scenarios when
    pub client_context: Option<Box<dyn Any>>,
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
{
    pub fn from_configs(client_config: &C::Config, server_config: &S::Config) -> Self {
        let io = TestPairIO {
            server_tx_stream: Rc::pin(Default::default()),
            client_tx_stream: Rc::pin(Default::default()),
        };
        let client = C::new_from_config(Mode::Client, client_config, &io).unwrap();
        let server = S::new_from_config(Mode::Server, server_config, &io).unwrap();
        Self {
            client,
            server,
            io,
            client_context: None,
        }
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
    use crate::{OpenSslConnection, RustlsConnection, S2NConnection, TlsConnPair};
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
        test_type::<RustlsConnection, RustlsConnection>();
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
