// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`Connection`] type: owns a socket, programs the kernel for kTLS, and
//! performs synchronous I/O.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, RawFd};

use crate::protocol::crypto_info::CryptoInfo;
use crate::protocol::key_schedule::DerivedKeys;
use crate::protocol::serialization::SerializedConnection;
use crate::Error;

// Socket-level constants from `tls/s2n_ktls_parameters.h`. Linux does not
// reliably expose these via its uapi headers, so we define them inline.
const S2N_SOL_TCP: libc::c_int = 6;
const S2N_TCP_ULP: libc::c_int = 31;
const S2N_SOL_TLS: libc::c_int = 282;
const S2N_TLS_TX: libc::c_int = 1;
const S2N_TLS_RX: libc::c_int = 2;
/// The ULP name, including its trailing NUL (`"tls\0"`).
const TLS_ULP_NAME: &[u8] = b"tls\0";

/// Which endpoint of the connection this socket represents.
///
/// This is required because the serialized blob does not record it, but it
/// determines which derived key is used for sending (TX) vs receiving (RX):
/// a client sends with the client key and receives with the server key, and
/// vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// This socket is the TLS client.
    Client,
    /// This socket is the TLS server.
    Server,
}

/// A kTLS-enabled connection.
///
/// Constructed from an s2n-tls serialized connection blob and an owned socket.
/// The kernel performs record-layer encryption/decryption; this type exposes
/// synchronous I/O over the socket via the [`Read`] and [`Write`] traits.
#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    /// The parsed connection state, retained so the connection can be
    /// re-serialized. Note that once kTLS is enabled the kernel owns the live
    /// sequence numbers; see [`Connection::serialize`].
    parsed: SerializedConnection,
    mode: Mode,
}

impl Connection {
    /// Build a kTLS connection from a serialized blob and an owned socket.
    ///
    /// This parses the blob, re-derives the record keys, and programs the
    /// kernel: it attaches the TLS ULP (`setsockopt(TCP_ULP, "tls")`) and then
    /// installs the TX and RX keys (`setsockopt(SOL_TLS, TLS_TX/TLS_RX, ...)`).
    ///
    /// `mode` indicates whether this socket is the client or the server, which
    /// determines the TX/RX key assignment.
    ///
    /// # Errors
    /// - [`Error::InvalidSerialization`] / [`Error::UnsupportedConfiguration`]
    ///   if the blob cannot be parsed or uses an unsupported configuration.
    /// - [`Error::Crypto`] if key derivation fails.
    /// - [`Error::Io`] if a `setsockopt` call fails (for example, if the `tls`
    ///   kernel module is not loaded, or the kernel does not support kTLS).
    pub fn new(blob: &[u8], stream: TcpStream, mode: Mode) -> Result<Self, Error> {
        let parsed = SerializedConnection::parse(blob)?;
        let keys = DerivedKeys::derive(&parsed)?;

        let conn = Connection {
            stream,
            parsed,
            mode,
        };
        conn.program_kernel(&keys)?;
        Ok(conn)
    }

    /// Attach the TLS ULP and install the TX and RX keys.
    fn program_kernel(&self, keys: &DerivedKeys) -> Result<(), Error> {
        let fd = self.stream.as_raw_fd();

        // Attach the "tls" ULP. This is a prerequisite for the SOL_TLS calls.
        // Following s2n-tls, we intentionally ignore the result here: it may
        // fail if the ULP is already attached, and if it genuinely isn't
        // available the subsequent SOL_TLS setsockopt will fail and we check
        // that.
        unsafe {
            libc::setsockopt(
                fd,
                S2N_SOL_TCP,
                S2N_TCP_ULP,
                TLS_ULP_NAME.as_ptr() as *const libc::c_void,
                TLS_ULP_NAME.len() as libc::socklen_t,
            );
        }

        // Determine which derived role is TX (our write key) and which is RX
        // (the peer's write key).
        let (tx_key, tx_iv, tx_seq, rx_key, rx_iv, rx_seq) = match self.mode {
            Mode::Client => (
                &keys.client_key,
                &keys.client_iv,
                &self.parsed.client_sequence_number,
                &keys.server_key,
                &keys.server_iv,
                &self.parsed.server_sequence_number,
            ),
            Mode::Server => (
                &keys.server_key,
                &keys.server_iv,
                &self.parsed.server_sequence_number,
                &keys.client_key,
                &keys.client_iv,
                &self.parsed.client_sequence_number,
            ),
        };

        let version = self.parsed.protocol_version;
        let aead = self.parsed.cipher_suite.aead();

        let tx_info = CryptoInfo::build(version, aead, tx_key, tx_iv, tx_seq)?;
        self.set_tls_sockopt(fd, S2N_TLS_TX, tx_info.as_bytes())?;

        let rx_info = CryptoInfo::build(version, aead, rx_key, rx_iv, rx_seq)?;
        self.set_tls_sockopt(fd, S2N_TLS_RX, rx_info.as_bytes())?;

        Ok(())
    }

    fn set_tls_sockopt(&self, fd: RawFd, optname: libc::c_int, value: &[u8]) -> Result<(), Error> {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                S2N_SOL_TLS,
                optname,
                value.as_ptr() as *const libc::c_void,
                value.len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// The [`Mode`] this connection was created with.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Borrow the underlying socket.
    pub fn get_ref(&self) -> &TcpStream {
        &self.stream
    }

    /// The number of bytes [`Connection::serialize`] will produce.
    pub fn serialization_length(&self) -> usize {
        self.parsed.serialization_length()
    }

    /// Serialize the connection back into the s2n-tls "V1" blob format.
    ///
    /// The output is byte-for-byte compatible with s2n-tls's
    /// `s2n_connection_deserialize`.
    ///
    /// # Caveat: sequence numbers
    ///
    /// This re-emits the state parsed at construction time, including the
    /// original sequence numbers. Once kTLS is enabled, the **kernel** owns the
    /// live sequence numbers as records are sent and received; this method does
    /// not read them back (via `getsockopt`). Serializing a connection that has
    /// already transferred application data will therefore produce stale
    /// sequence numbers. Reading the live sequence numbers back from the kernel
    /// is left for a future iteration.
    pub fn serialize(&self, output: &mut [u8]) -> Result<(), Error> {
        let needed = self.parsed.serialization_length();
        if output.len() < needed {
            return Err(Error::InvalidSerialization("output buffer too small"));
        }
        let mut buf = Vec::with_capacity(needed);
        self.parsed.write(&mut buf);
        output[..needed].copy_from_slice(&buf);
        Ok(())
    }

    /// Serialize the connection into a freshly allocated buffer.
    pub fn to_vec(&self) -> Vec<u8> {
        self.parsed.to_vec()
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
