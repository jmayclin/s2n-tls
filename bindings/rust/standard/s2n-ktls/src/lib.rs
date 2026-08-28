// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]

//! `s2n-ktls` enables Linux kernel TLS (kTLS) for connections that were
//! negotiated by s2n-tls.
//!
//! The typical flow is:
//! 1. Complete a TLS handshake with s2n-tls.
//! 2. Serialize the connection into the s2n-tls "V1" serialization format.
//! 3. Hand the serialized blob and the underlying socket to
//!    [`Connection::new`], which re-derives the record keys, programs the
//!    kernel (`setsockopt(TCP_ULP, "tls")` + `TLS_TX`/`TLS_RX`), and takes
//!    over synchronous I/O.
//!
//! The crate is split into two layers:
//! - [`protocol`]: pure, I/O-free logic. Parsing/writing the serialized blob,
//!   re-deriving keys, and building the kernel `crypto_info` structures.
//! - [`connection`]: the [`Connection`] type, which owns the socket and
//!   performs the `setsockopt` calls and I/O.
//!
//! # Supported configurations
//!
//! Only configurations that Linux kTLS can actually use are supported:
//! - TLS 1.2 and TLS 1.3
//! - AES-128-GCM and AES-256-GCM
//!
//! Any other protocol version or cipher is rejected when the serialized blob
//! is parsed.
//!
//! # Security
//!
//! The s2n-tls serialized connection format is **unauthenticated** and contains
//! secret key material (master secret or application traffic secrets). Callers
//! are responsible for verifying the integrity of the blob before handing it to
//! this crate, and for protecting it in transit and at rest. This crate never
//! logs secret material.

pub mod connection;
pub mod protocol;

pub use connection::{Connection, Mode};
pub use error::Error;

mod error {
    /// Errors returned by `s2n-ktls`.
    #[non_exhaustive]
    #[derive(Debug, thiserror::Error)]
    pub enum Error {
        /// The serialized connection blob was malformed or truncated.
        #[error("invalid serialized connection: {0}")]
        InvalidSerialization(&'static str),
        /// The serialized connection used a protocol version or cipher suite
        /// that this crate does not support (only TLS1.2/TLS1.3 with
        /// AES-128-GCM or AES-256-GCM are supported).
        #[error("unsupported configuration: {0}")]
        UnsupportedConfiguration(&'static str),
        /// A cryptographic operation (key derivation) failed.
        #[error("key derivation failed: {0}")]
        Crypto(&'static str),
        /// A system call (e.g. `setsockopt`) failed.
        #[error("system call failed: {0}")]
        Io(#[from] std::io::Error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_populated() {
        let err = Error::UnsupportedConfiguration("test");
        assert!(err.to_string().contains("unsupported configuration"));
    }
}
