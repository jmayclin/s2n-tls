use super::{TlsConnPair, TlsConnection};

use crate::harness;
use std::{error::Error, fmt::Debug, fs::read_to_string};
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
        mode: super::Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>>;
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
                S::Config::make_config(harness::Mode::Server, crypto_config, handshake_type)?;
            let client_config =
                C::Config::make_config(harness::Mode::Client, crypto_config, handshake_type)?;

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
            &C::Config::make_config(harness::Mode::Client, crypto_config, handshake_type).unwrap(),
            &S::Config::make_config(harness::Mode::Server, crypto_config, handshake_type).unwrap(),
        ))
    }
}
