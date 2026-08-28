// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parsing and writing of the s2n-tls "V1" serialized connection format.
//!
//! See `tls/s2n_connection_serialize.c` in s2n-tls for the reference
//! implementation. The layout (all integers big-endian) is:
//!
//! ```text
//! u64  version tag (== 1, S2N_SERIALIZED_CONN_V1)
//! u8   protocol version major
//! u8   protocol version minor
//! [u8; 2]  cipher suite IANA value
//! [u8; 8]  client sequence number
//! [u8; 8]  server sequence number
//! u16  max fragment length
//! ---- version-specific secrets ----
//! TLS1.2: master_secret[48] client_random[32] server_random[32]
//! TLS1.3: client_app_secret[N] server_app_secret[N] resumption_master_secret[N]
//!         where N is the PRF hash digest size (32 for SHA-256, 48 for SHA-384)
//! ```
//!
//! The format is **unauthenticated** and carries secret key material.
//!
//! This crate only supports the subset of configurations that Linux kTLS can
//! use: TLS1.2 and TLS1.3 with AES-128-GCM or AES-256-GCM. Any other protocol
//! version or cipher is rejected during [`SerializedConnection::parse`].

use s2n_codec::{
    DecoderBuffer, DecoderBufferResult, DecoderError, DecoderParameterizedValue, DecoderValue,
    Encoder, EncoderBuffer, EncoderValue,
};

use crate::Error;

/// The value of the leading `u64` version tag (`S2N_SERIALIZED_CONN_V1`).
pub(crate) const SERIALIZED_CONN_V1: u64 = 1;

/// TLS master secret length (TLS1.2), in bytes.
pub(crate) const TLS_SECRET_LEN: usize = 48;
/// TLS `client_random`/`server_random` length, in bytes.
pub(crate) const TLS_RANDOM_DATA_LEN: usize = 32;
/// Sequence number length, in bytes.
pub(crate) const TLS_SEQUENCE_NUM_LEN: usize = 8;

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

impl ProtocolVersion {
    /// The `(major, minor)` byte pair used in the wire format.
    pub(crate) fn major_minor(self) -> (u8, u8) {
        match self {
            ProtocolVersion::Tls12 => (3, 3),
            ProtocolVersion::Tls13 => (3, 4),
        }
    }
}

impl<'a> DecoderValue<'a> for ProtocolVersion {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (major, buffer) = buffer.decode::<u8>().map_err(decoder_err)?;
        let (minor, buffer) = buffer.decode::<u8>().map_err(decoder_err)?;
        match (major, minor) {
            (3, 3) => Ok((ProtocolVersion::Tls12, buffer)),
            (3, 4) => Ok((ProtocolVersion::Tls13, buffer)),
            _ => Err(decoder_err(DecoderError::InvariantViolation(
                "only TLS1.2 and TLS1.3 are supported",
            ))),
        }
    }
}

/// The AEAD algorithm negotiated by the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM (16-byte key).
    Aes128Gcm,
    /// AES-256-GCM (32-byte key).
    Aes256Gcm,
}

impl AeadAlgorithm {
    /// The symmetric key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
        }
    }
}

/// The hash used by the connection's PRF / HKDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (32-byte digest).
    Sha256,
    /// SHA-384 (48-byte digest).
    Sha384,
}

impl HashAlgorithm {
    /// The digest size in bytes. For TLS1.3 this is also the traffic secret
    /// size stored in the serialized blob.
    pub fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
        }
    }
}

/// A supported cipher suite, identified by its 2-byte IANA value.
///
/// Only AES-128-GCM and AES-256-GCM suites are represented; all other suites
/// are rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    iana: [u8; 2],
    aead: AeadAlgorithm,
    hash: HashAlgorithm,
}

impl CipherSuite {
    /// The 2-byte IANA identifier.
    pub fn iana_value(&self) -> [u8; 2] {
        self.iana
    }

    /// The AEAD algorithm for this suite.
    pub fn aead(&self) -> AeadAlgorithm {
        self.aead
    }

    /// The PRF/HKDF hash for this suite.
    pub fn hash(&self) -> HashAlgorithm {
        self.hash
    }
}

impl<'a> DecoderValue<'a> for CipherSuite {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (iana, buffer) = buffer.decode::<[u8; 2]>().map_err(decoder_err)?;
        match CipherSuite::from_iana(iana) {
            Ok(v) => Ok((v, buffer)),
            Err(e) => Err(decoder_err(DecoderError::InvariantViolation(match e {
                Error::UnsupportedConfiguration(msg) => msg,
                Error::InvalidSerialization(msg) => msg,
                Error::Crypto(msg) => msg,
                Error::Io(_) => "I/O error during decoding",
            }))),
        }
    }
}

impl EncoderValue for CipherSuite {
    fn encode<E: Encoder>(&self, encoder: &mut E) {
        encoder.write_slice(&self.iana);
    }

    fn encoding_size_for_encoder<E: Encoder>(&self, _encoder: &E) -> usize {
        2
    }
}

impl CipherSuite {
    /// Look up a supported cipher suite by its IANA value, rejecting anything
    /// that kTLS cannot use.
    fn from_iana(iana: [u8; 2]) -> Result<Self, Error> {
        use AeadAlgorithm::*;
        use HashAlgorithm::*;

        // (iana, aead, hash) for every AES-GCM suite s2n-tls can negotiate,
        // across TLS1.2 and TLS1.3. AES-128-GCM suites use SHA-256; AES-256-GCM
        // suites use SHA-384.
        let (aead, hash) = match iana {
            // TLS1.2 AES-128-GCM (SHA-256)
            [0x00, 0x9C] // TLS_RSA_WITH_AES_128_GCM_SHA256
            | [0x00, 0x9E] // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            | [0xC0, 0x2B] // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | [0xC0, 0x2F] // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            => (Aes128Gcm, Sha256),

            // TLS1.2 AES-256-GCM (SHA-384)
            [0x00, 0x9D] // TLS_RSA_WITH_AES_256_GCM_SHA384
            | [0x00, 0x9F] // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            | [0xC0, 0x2C] // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | [0xC0, 0x30] // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            => (Aes256Gcm, Sha384),

            // TLS1.3
            [0x13, 0x01] => (Aes128Gcm, Sha256), // TLS_AES_128_GCM_SHA256
            [0x13, 0x02] => (Aes256Gcm, Sha384), // TLS_AES_256_GCM_SHA384

            _ => {
                return Err(Error::UnsupportedConfiguration(
                    "only AES-128-GCM and AES-256-GCM cipher suites are supported",
                ))
            }
        };

        Ok(CipherSuite { iana, aead, hash })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tls12Secret {
    /// The 48-byte master secret.
    master_secret: [u8; TLS_SECRET_LEN],
    /// The 32-byte client random.
    client_random: [u8; TLS_RANDOM_DATA_LEN],
    /// The 32-byte server random.
    server_random: [u8; TLS_RANDOM_DATA_LEN],
}

impl DecoderValue<'_> for Tls12Secret {
    fn decode(bytes: DecoderBuffer<'_>) -> DecoderBufferResult<'_, Self> {
        let (master_secret, bytes) = bytes.decode()?;
        let (client_random, bytes) = bytes.decode()?;
        let (server_random, bytes) = bytes.decode()?;
        let value = Self {
            master_secret,
            client_random,
            server_random,
        };
        Ok((value, bytes))
    }
}

impl EncoderValue for Tls12Secret {
    fn encode<E: Encoder>(&self, encoder: &mut E) {
        encoder.encode(&self.master_secret.as_slice());
        encoder.encode(&self.client_random.as_slice());
        encoder.encode(&self.server_random.as_slice());
    }
}

/// TLS1.3 application traffic secrets. Each secret is `secret_size` bytes,
/// which equals the cipher suite's PRF hash digest size.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tls13Secret {
    /// Client application traffic secret.
    client_application_secret: Vec<u8>,
    /// Server application traffic secret.
    server_application_secret: Vec<u8>,
    /// Resumption master secret.
    resumption_master_secret: Vec<u8>,
}

impl DecoderParameterizedValue<'_> for Tls13Secret {
    /// the secret_size, determined by the cipher suites PRF hash digest
    type Parameter = usize;

    fn decode_parameterized(
        parameter: Self::Parameter,
        bytes: DecoderBuffer<'_>,
    ) -> DecoderBufferResult<'_, Self> {
        let secret_size = parameter;
        let buffer = bytes;
        let (client_application_secret, buffer) = buffer.decode_slice(secret_size)?;
        let (server_application_secret, buffer) = buffer.decode_slice(secret_size)?;
        let (resumption_master_secret, buffer) = buffer.decode_slice(secret_size)?;
        let value = Self {
            client_application_secret: client_application_secret.as_less_safe_slice().to_vec(),
            server_application_secret: server_application_secret.as_less_safe_slice().to_vec(),
            resumption_master_secret: resumption_master_secret.as_less_safe_slice().to_vec(),
        };
        Ok((value, buffer))
    }
}

impl EncoderValue for Tls13Secret {
    fn encode<E: Encoder>(&self, encoder: &mut E) {
        encoder.encode(&self.client_application_secret.as_slice());
        encoder.encode(&self.server_application_secret.as_slice());
        encoder.encode(&self.resumption_master_secret.as_slice());
    }
}

/// The version-specific secret material carried in the serialized blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secrets {
    /// TLS1.2 secrets: the master secret and the client/server randoms. The
    /// record keys are re-derived from these via the TLS1.2 PRF.
    Tls12(Tls12Secret),
    /// TLS1.3 application traffic secrets. Each secret is `secret_size` bytes,
    /// which equals the cipher suite's PRF hash digest size.
    Tls13 {
        /// Client application traffic secret.
        client_application_secret: Vec<u8>,
        /// Server application traffic secret.
        server_application_secret: Vec<u8>,
        /// Resumption master secret.
        resumption_master_secret: Vec<u8>,
    },
}

impl EncoderValue for Secrets {
    fn encode<E: Encoder>(&self, encoder: &mut E) {
        match self {
            Secrets::Tls12(secret) => {
                encoder.encode(secret);
            }
            Secrets::Tls13 {
                client_application_secret,
                server_application_secret,
                resumption_master_secret,
            } => {
                encoder.write_slice(client_application_secret);
                encoder.write_slice(server_application_secret);
                encoder.write_slice(resumption_master_secret);
            }
        }
    }

    fn encoding_size_for_encoder<E: Encoder>(&self, _encoder: &E) -> usize {
        match self {
            Secrets::Tls12 { .. } => TLS_SECRET_LEN + TLS_RANDOM_DATA_LEN + TLS_RANDOM_DATA_LEN,
            Secrets::Tls13 {
                client_application_secret,
                ..
            } => client_application_secret.len() * 3,
        }
    }
}

/// A parsed s2n-tls "V1" serialized connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedConnection {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    /// Client record sequence number at the time of serialization.
    pub client_sequence_number: [u8; TLS_SEQUENCE_NUM_LEN],
    /// Server record sequence number at the time of serialization.
    pub server_sequence_number: [u8; TLS_SEQUENCE_NUM_LEN],
    /// Maximum outgoing fragment length.
    pub max_fragment_length: u16,
    /// Version-specific secret material.
    pub secrets: Secrets,
}

impl<'a> DecoderValue<'a> for SerializedConnection {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (version, buffer) = buffer.decode::<u64>().map_err(decoder_err)?;
        if version != SERIALIZED_CONN_V1 {
            return Err(decoder_err(DecoderError::InvariantViolation(
                "unrecognized serialization version tag",
            )));
        }

        let (protocol_version, buffer) = buffer.decode()?;
        let (cipher_suite, buffer) = buffer.decode::<CipherSuite>()?;
        let (client_sequence_number, buffer) = buffer.decode()?;
        let (server_sequence_number, buffer) = buffer.decode()?;
        let (max_fragment_length, buffer) = buffer.decode()?;

        // Decode version-specific secrets inline since Secrets::decode is not meant
        // to be called directly.
        let (secrets, buffer) = match protocol_version {
            ProtocolVersion::Tls12 => {
                let (secret, buffer) = buffer.decode()?;
                (Secrets::Tls12(secret), buffer)
            }
            ProtocolVersion::Tls13 => {
                let secret_size = cipher_suite.hash().digest_len();
                let (client_application_secret, buffer) =
                    buffer.decode_slice(secret_size).map_err(decoder_err)?;
                let (server_application_secret, buffer) =
                    buffer.decode_slice(secret_size).map_err(decoder_err)?;
                let (resumption_master_secret, buffer) =
                    buffer.decode_slice(secret_size).map_err(decoder_err)?;
                (
                    Secrets::Tls13 {
                        client_application_secret: client_application_secret
                            .into_less_safe_slice()
                            .to_vec(),
                        server_application_secret: server_application_secret
                            .into_less_safe_slice()
                            .to_vec(),
                        resumption_master_secret: resumption_master_secret
                            .into_less_safe_slice()
                            .to_vec(),
                    },
                    buffer,
                )
            }
        };

        let conn = SerializedConnection {
            protocol_version,
            cipher_suite,
            client_sequence_number,
            server_sequence_number,
            max_fragment_length,
            secrets,
        };

        // The decoder leaves any remaining bytes in the buffer. We must ensure
        // the entire buffer was consumed to reject malformed blobs with trailing data.
        if !buffer.is_empty() {
            return Err(decoder_err(DecoderError::UnexpectedBytes(buffer.len())));
        }

        Ok((conn, buffer))
    }
}

impl EncoderValue for SerializedConnection {
    fn encode<E: Encoder>(&self, encoder: &mut E) {
        encoder.encode(&SERIALIZED_CONN_V1);

        let (major, minor) = self.protocol_version.major_minor();
        encoder.encode(&major);
        encoder.encode(&minor);

        self.cipher_suite.encode(encoder);

        encoder.write_slice(&self.client_sequence_number);
        encoder.write_slice(&self.server_sequence_number);

        encoder.encode(&self.max_fragment_length);

        self.secrets.encode(encoder);
    }

    fn encoding_size_for_encoder<E: Encoder>(&self, _encoder: &E) -> usize {
        // Fixed header: u64 version + 2 protocol + 2 cipher + 8 + 8 seq + u16 frag.
        const FIXED: usize = 8 + 2 + 2 + TLS_SEQUENCE_NUM_LEN + TLS_SEQUENCE_NUM_LEN + 2;
        let secrets = match &self.secrets {
            Secrets::Tls12 { .. } => TLS_SECRET_LEN + TLS_RANDOM_DATA_LEN + TLS_RANDOM_DATA_LEN,
            Secrets::Tls13 {
                client_application_secret,
                ..
            } => client_application_secret.len() * 3,
        };
        FIXED + secrets
    }
}

impl SerializedConnection {
    /// Parse a serialized connection blob.
    ///
    /// Returns [`Error::InvalidSerialization`] if the buffer is malformed or
    /// truncated, and [`Error::UnsupportedConfiguration`] if the connection
    /// used a protocol version or cipher that this crate does not support.
    pub fn parse(bytes: &[u8]) -> Result<SerializedConnection, Error> {
        let buffer = DecoderBuffer::new(bytes);
        let (conn, _buffer) = SerializedConnection::decode(buffer).map_err(|e| {
            // Convert DecoderError to our Error
            match e {
                DecoderError::UnexpectedEof(_) => {
                    Error::InvalidSerialization("unexpected end of buffer")
                }
                DecoderError::UnexpectedBytes(_) => Error::InvalidSerialization(
                    "unexpected trailing bytes in serialized connection",
                ),
                DecoderError::LengthCapacityExceeded => {
                    Error::InvalidSerialization("length could not be represented")
                }
                DecoderError::InvariantViolation(msg) => Error::InvalidSerialization(msg),
            }
        })?;
        Ok(conn)
    }

    /// The number of bytes this connection serializes to.
    ///
    /// Corresponds to `s2n_connection_serialization_length`.
    pub fn serialization_length(&self) -> usize {
        // Fixed header: u64 version + 2 protocol + 2 cipher + 8 + 8 seq + u16 frag.
        const FIXED: usize = 8 + 2 + 2 + TLS_SEQUENCE_NUM_LEN + TLS_SEQUENCE_NUM_LEN + 2;
        let secrets = match &self.secrets {
            Secrets::Tls12 { .. } => TLS_SECRET_LEN + TLS_RANDOM_DATA_LEN + TLS_RANDOM_DATA_LEN,
            Secrets::Tls13 {
                client_application_secret,
                ..
            } => client_application_secret.len() * 3,
        };
        FIXED + secrets
    }

    /// Serialize this connection into `out`, appending the exact V1 byte layout.
    ///
    /// The output is byte-for-byte compatible with s2n-tls's
    /// `s2n_connection_deserialize`.
    pub fn write(&self, out: &mut Vec<u8>) {
        let len = self.serialization_length();
        let mut scratch = vec![0u8; len];
        let mut encoder = EncoderBuffer::new(&mut scratch);
        self.encode(&mut encoder);
        let written = encoder.len();
        debug_assert_eq!(written, len);
        out.extend_from_slice(&scratch);
    }

    /// Serialize this connection into a freshly allocated buffer.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialization_length());
        self.write(&mut out);
        out
    }
}

/// Map an s2n-codec [`DecoderError`] to our [`Error::InvalidSerialization`].
fn decoder_err(err: DecoderError) -> DecoderError {
    match err {
        DecoderError::UnexpectedEof(_) => {
            DecoderError::InvariantViolation("unexpected end of buffer")
        }
        DecoderError::UnexpectedBytes(len) => DecoderError::UnexpectedBytes(len),
        DecoderError::LengthCapacityExceeded => {
            DecoderError::InvariantViolation("length could not be represented")
        }
        DecoderError::InvariantViolation(msg) => DecoderError::InvariantViolation(msg),
    }
}
