// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`Connection`] type: owns a socket, programs the kernel for kTLS, and
//! performs synchronous I/O.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use s2n_codec::{DecoderBuffer, DecoderError, DecoderValue};

use crate::protocol::crypto_info::CryptoInfo;
use crate::protocol::key_schedule::{DerivedKeys, SecretRole, TrafficSecrets};
use crate::protocol::serialization::{ProtocolVersion, Secrets, SerializedConnection};
use crate::Error;

// Socket-level constants from `tls/s2n_ktls_parameters.h`. Linux does not
// reliably expose these via its uapi headers, so we define them inline.
const S2N_SOL_TCP: libc::c_int = 6;
const S2N_TCP_ULP: libc::c_int = 31;
const S2N_SOL_TLS: libc::c_int = 282;
const S2N_TLS_TX: libc::c_int = 1;
const S2N_TLS_RX: libc::c_int = 2;
/// `TLS_SET_RECORD_TYPE` / `TLS_GET_RECORD_TYPE` cmsg types (`<linux/tls.h>`).
const S2N_TLS_SET_RECORD_TYPE: libc::c_int = 1;
const S2N_TLS_GET_RECORD_TYPE: libc::c_int = 2;
/// The ULP name, including its trailing NUL (`"tls\0"`).
const TLS_ULP_NAME: &[u8] = b"tls\0";

// TLS record content types (RFC 8446 section 5.1).
const TLS_CONTENT_TYPE_ALERT: u8 = 21;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

enum ContentType {
    Alert,
    Handshake,
    ApplicationData,
}

impl DecoderValue<'_> for ContentType {
    fn decode(bytes: DecoderBuffer<'_>) -> s2n_codec::DecoderBufferResult<'_, Self> {
        let (value, bytes) = bytes.decode::<u8>()?;
        let content_type = match value {
            TLS_CONTENT_TYPE_ALERT => ContentType::Alert,
            TLS_CONTENT_TYPE_HANDSHAKE => ContentType::Handshake,
            TLS_CONTENT_TYPE_APPLICATION_DATA => ContentType::ApplicationData,
            _ => {
                return Err(DecoderError::InvariantViolation(
                    "unrecognized content type",
                ))
            }
        };
        Ok((content_type, bytes))
    }
}

// Post-handshake message / alert constants.
const TLS_HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;
/// A serialized `KeyUpdate` handshake message: `type(1) || length(3) || request(1)`.
const KEY_UPDATE_MESSAGE_LEN: usize = 5;
const KEY_UPDATE_NOT_REQUESTED: u8 = 0;
const KEY_UPDATE_REQUESTED: u8 = 1;
const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_DESCRIPTION_CLOSE_NOTIFY: u8 = 0;

/// A sequence number that has been reset to zero.
///
/// Per RFC 8446 section 5.3, the record sequence number is reset to zero
/// whenever the traffic key changes, so a re-programmed direction always starts
/// at sequence number 0.
const ZERO_SEQUENCE_NUMBER: [u8; 8] = [0u8; 8];

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

impl Mode {
    /// The [`SecretRole`] used for records we send (TX).
    fn tx_role(self) -> SecretRole {
        match self {
            Mode::Client => SecretRole::Client,
            Mode::Server => SecretRole::Server,
        }
    }

    /// The [`SecretRole`] used for records we receive (RX): the peer's write
    /// secret.
    fn rx_role(self) -> SecretRole {
        match self {
            Mode::Client => SecretRole::Server,
            Mode::Server => SecretRole::Client,
        }
    }
}

/// A kTLS-enabled connection.
///
/// Constructed from an s2n-tls serialized connection blob and an owned socket.
/// The kernel performs record-layer encryption/decryption; this type exposes
/// synchronous I/O over the socket via the [`Read`] and [`Write`] traits.
///
/// # TLS 1.3 key updates
///
/// For TLS 1.3 connections this type tracks the current application traffic
/// secrets internally (see [`TrafficSecrets`]) so it can handle `KeyUpdate`
/// messages without any help from s2n-tls:
///
/// - **Receiving:** [`read`](Read::read) is implemented with `recvmsg` so it can
///   observe the record content type. When the kernel surfaces a `KeyUpdate`
///   handshake record, the RX secret is advanced, the RX key re-derived, and
///   the kernel re-programmed via `setsockopt(TLS_RX)` — transparently, before
///   `read` returns any subsequent application data. This is required because
///   the kernel pauses decryption after a `KeyUpdate` (failing reads with
///   `EKEYEXPIRED`) until the new key is installed.
/// - **Sending:** [`update_send_key`](KtlsTcpStream::update_send_key) writes a
///   `KeyUpdate` message to the peer, advances the TX secret, and re-programs
///   `setsockopt(TLS_TX)`.
#[derive(Debug)]
pub struct KtlsTcpStream {
    stream: std::net::TcpStream,
    /// The parsed connection state, retained so the connection can be
    /// re-serialized. Note that once kTLS is enabled the kernel owns the live
    /// sequence numbers; see [`KtlsTcpStream::serialize`].
    parsed: SerializedConnection,
    mode: Mode,
    /// Current TLS 1.3 traffic secrets, tracked across key updates. `None` for
    /// TLS 1.2 connections, which have no `KeyUpdate`.
    secrets: Option<TrafficSecrets>,
    /// Number of RX key updates applied (peer -> us). Exposed for observability
    /// and testing.
    recv_key_updates: u64,
    /// Number of TX key updates applied (us -> peer).
    send_key_updates: u64,
    /// Whether the peer has sent a `close_notify` alert (clean EOF).
    peer_closed: bool,
}

impl KtlsTcpStream {
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
    pub fn new(blob: &[u8], stream: std::net::TcpStream, mode: Mode) -> Result<Self, Error> {
        let serialized_connection = {
            let buffer = DecoderBuffer::new(blob);
            buffer
                .decode_exact()
                .map_err(|_| Error::InvalidSerialization("unexpected end of buffer"))?
        };
        let keys = DerivedKeys::derive(&serialized_connection)?;
        let secrets = TrafficSecrets::from_serialized(&serialized_connection);

        let conn = KtlsTcpStream {
            stream,
            parsed: serialized_connection,
            mode,
            secrets,
            recv_key_updates: 0,
            send_key_updates: 0,
            peer_closed: false,
        };
        conn.program_kernel(&keys)?;
        Ok(conn)
    }

    /// Re-program one direction of the kernel with a freshly derived TLS 1.3
    /// key/IV at sequence number zero.
    ///
    /// Only valid for TLS 1.3: `role` selects which tracked traffic secret to
    /// derive from, and `optname` is [`S2N_TLS_TX`] or [`S2N_TLS_RX`].
    fn reprogram_tls13_direction(
        &self,
        optname: libc::c_int,
        role: SecretRole,
    ) -> Result<(), Error> {
        let secrets = self
            .secrets
            .as_ref()
            .ok_or(Error::UnsupportedConfiguration(
                "key update is only supported for TLS 1.3",
            ))?;
        let (key, iv) = secrets.derive_key_and_iv(role)?;
        let aead = self.parsed.cipher_suite.aead();
        // A key change resets the record sequence number to zero.
        let crypto_info = CryptoInfo::build(
            ProtocolVersion::Tls13,
            aead,
            &key,
            &iv,
            &ZERO_SEQUENCE_NUMBER,
        )?;
        self.set_tls_sockopt(self.stream.as_raw_fd(), optname, crypto_info.as_bytes())
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
                &self.parsed.client_sequence_number.to_be_bytes(),
                &keys.server_key,
                &keys.server_iv,
                &self.parsed.server_sequence_number.to_be_bytes(),
            ),
            Mode::Server => (
                &keys.server_key,
                &keys.server_iv,
                &self.parsed.server_sequence_number.to_be_bytes(),
                &keys.client_key,
                &keys.client_iv,
                &self.parsed.client_sequence_number.to_be_bytes(),
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
    /// The number of bytes [`KtlsTcpStream::serialize`] will produce.
    pub fn serialization_length(&self) -> usize {
        self.parsed.serialization_length()
    }

    /// The number of RX key updates (peer -> us) that have been applied.
    pub fn recv_key_updates(&self) -> u64 {
        self.recv_key_updates
    }

    /// The number of TX key updates (us -> peer) that have been applied.
    pub fn send_key_updates(&self) -> u64 {
        self.send_key_updates
    }

    /// Whether the peer has sent a `close_notify` alert. Once set, [`read`]
    /// returns EOF (`Ok(0)`).
    ///
    /// [`read`]: Read::read
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Perform a TLS 1.3 key update on the **send** (TX) direction.
    ///
    /// This sends a `KeyUpdate` handshake message to the peer, advances our
    /// write traffic secret, re-derives the write key, and re-programs the
    /// kernel via `setsockopt(SOL_TLS, TLS_TX)`. All application data written
    /// after this call is encrypted under the new key.
    ///
    /// If `request_peer_update` is true, the peer is asked to update its own
    /// sending key in response (`update_requested`); the peer's eventual
    /// `KeyUpdate` is then handled transparently by [`read`](Read::read).
    ///
    /// # Errors
    /// - [`Error::UnsupportedConfiguration`] if this is not a TLS 1.3
    ///   connection.
    /// - [`Error::Io`] if writing the `KeyUpdate` record or the
    ///   `setsockopt(TLS_TX)` call fails.
    pub fn update_send_key(&mut self, request_peer_update: bool) -> Result<(), Error> {
        if self.parsed.protocol_version != ProtocolVersion::Tls13 {
            return Err(Error::UnsupportedConfiguration(
                "key update is only supported for TLS 1.3",
            ));
        }

        // Send the KeyUpdate handshake message *before* switching keys, so it
        // is encrypted under the current (old) TX key, as the peer expects.
        let request = if request_peer_update {
            KEY_UPDATE_REQUESTED
        } else {
            KEY_UPDATE_NOT_REQUESTED
        };
        let msg = [
            TLS_HANDSHAKE_TYPE_KEY_UPDATE,
            0,
            0,
            (KEY_UPDATE_MESSAGE_LEN - 4) as u8, // 24-bit length == 1
            request,
        ];
        self.send_record(TLS_CONTENT_TYPE_HANDSHAKE, &msg)?;

        // Advance our write secret and re-program the kernel's TX key.
        let role = self.mode.tx_role();
        self.secrets
            .as_mut()
            .expect("TLS 1.3 connection has traffic secrets")
            .advance(role)?;
        self.reprogram_tls13_direction(S2N_TLS_TX, role)?;
        self.send_key_updates = self.send_key_updates.saturating_add(1);
        Ok(())
    }

    /// Handle a `KeyUpdate` received from the peer: advance the RX secret,
    /// re-derive the RX key, and re-program `setsockopt(SOL_TLS, TLS_RX)`.
    ///
    /// The kernel pauses decryption after delivering a `KeyUpdate` record until
    /// the new key is installed, so this must run before the next application
    /// record can be read.
    fn process_recv_key_update(&mut self) -> Result<(), Error> {
        let role = self.mode.rx_role();
        self.secrets
            .as_mut()
            .ok_or(Error::UnsupportedConfiguration(
                "received a KeyUpdate on a non-TLS-1.3 connection",
            ))?
            .advance(role)?;
        self.reprogram_tls13_direction(S2N_TLS_RX, role)?;
        self.recv_key_updates = self.recv_key_updates.saturating_add(1);
        Ok(())
    }

    /// Send a single TLS record of the given content type over kTLS.
    ///
    /// The content type is passed to the kernel as a `TLS_SET_RECORD_TYPE`
    /// control message; the kernel encrypts the payload as a record of that
    /// type.
    fn send_record(&self, record_type: u8, payload: &[u8]) -> Result<(), Error> {
        let fd = self.stream.as_raw_fd();
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };

        // Control message carrying the record content type.
        let mut cmsg_buf = [0u8; unsafe { cmsg_space(1) }];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(Error::Crypto("failed to build control message"));
            }
            (*cmsg).cmsg_level = S2N_SOL_TLS;
            (*cmsg).cmsg_type = S2N_TLS_SET_RECORD_TYPE;
            (*cmsg).cmsg_len = libc::CMSG_LEN(1) as _;
            *libc::CMSG_DATA(cmsg) = record_type;
            msg.msg_controllen = libc::CMSG_SPACE(1) as _;

            let ret = libc::sendmsg(fd, &msg, 0);
            if ret < 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    /// Receive a single record via `recvmsg`, reporting its content type.
    ///
    /// Returns `(bytes_read, record_type)`. A `record_type` of
    /// [`TLS_CONTENT_TYPE_APPLICATION_DATA`] means `buf[..bytes_read]` is
    /// application data for the caller; other record types are protocol
    /// messages handled internally.
    fn recv_record(&self, buf: &mut [u8]) -> std::io::Result<(usize, ContentType)> {
        // setup the recvmsg arguments
        let fd = self.stream.as_raw_fd();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; unsafe { cmsg_space(1) }];
        let mut msg: libc::msghdr = {
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov as *mut libc::iovec;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_buf.len() as _;
            msg
        };

        let ret = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let n = ret as usize;

        let record_type = {
            // Extract the record content type from the control message. If the
            // kernel did not attach one (e.g. plain application data on some
            // kernels), default to application data.
            let mut record_type = TLS_CONTENT_TYPE_APPLICATION_DATA;
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if !cmsg.is_null()
                    && (*cmsg).cmsg_level == S2N_SOL_TLS
                    && (*cmsg).cmsg_type == S2N_TLS_GET_RECORD_TYPE
                {
                    record_type = *libc::CMSG_DATA(cmsg);
                }
            }
            DecoderBuffer::new(&[record_type])
                .decode_exact()
                .map_err(|_| {
                    std::io::Error::new(ErrorKind::InvalidData, "unexpected content type")
                })?
        };

        Ok((n, record_type))
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

    /// Read the live record sequence number for a direction back from the
    /// kernel via `getsockopt(SOL_TLS, TLS_TX | TLS_RX)`.
    ///
    /// Once kTLS is enabled the kernel, not this crate, owns the record
    /// sequence numbers: they advance as records are sent and received.
    /// `getsockopt` returns the current `crypto_info` for the direction, whose
    /// trailing `rec_seq` field holds the next sequence number to be used.
    ///
    /// The kernel is strict about the buffer length: it must be *exactly*
    /// `sizeof(crypto_info)` for the negotiated cipher (40 bytes for
    /// AES-128-GCM, 56 for AES-256-GCM). Any other size fails with `EINVAL`.
    fn read_kernel_sequence_number(&self, optname: libc::c_int) -> Result<u64, Error> {
        let aead = self.parsed.cipher_suite.aead();
        // struct tls12_crypto_info_aes_gcm_*: header(4) + iv(8) + key + salt(4) + rec_seq(8)
        let info_len = 4 + 8 + aead.key_len() + 4 + 8;
        let mut buf = vec![0u8; info_len];
        let mut len = info_len as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                self.stream.as_raw_fd(),
                S2N_SOL_TLS,
                optname,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        if (len as usize) != info_len {
            return Err(Error::Crypto(
                "kernel returned unexpected crypto_info length",
            ));
        }

        // rec_seq is the final 8 bytes of the structure, stored in big-endian.
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[info_len - 8..]);
        Ok(u64::from_be_bytes(seq_bytes))
    }

    /// The [`Mode`] this connection was created with.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Borrow the underlying socket.
    pub fn get_ref(&self) -> &std::net::TcpStream {
        &self.stream
    }

    /// Build a [`SerializedConnection`] reflecting the connection's current
    /// live state: the record sequence numbers read back from the kernel and,
    /// for TLS 1.3, the traffic secrets advanced across any key updates.
    ///
    /// This is the state that must be serialized so that a peer (for example, a
    /// vanilla s2n-tls connection created via `s2n_connection_deserialize`) can
    /// resume the record protocol exactly where kTLS left off.
    fn current_state(&self) -> Result<SerializedConnection, Error> {
        let mut state = self.parsed.clone();

        // 1) Read the live sequence numbers back from the kernel. TX is the
        //    direction we write; RX is the direction we read. Map those to the
        //    client/server slots in the serialized layout.
        let tx_seq = self.read_kernel_sequence_number(S2N_TLS_TX)?;
        let rx_seq = self.read_kernel_sequence_number(S2N_TLS_RX)?;
        let (client_seq, server_seq) = match self.mode {
            Mode::Client => (tx_seq, rx_seq),
            Mode::Server => (rx_seq, tx_seq),
        };
        state.client_sequence_number = client_seq;
        state.server_sequence_number = server_seq;

        // 2) For TLS 1.3, emit the *current* traffic secrets (advanced by any
        //    key updates), not the initial ones parsed at construction.
        if let Some(secrets) = &self.secrets {
            if let Secrets::Tls13(tls13) = &mut state.secrets {
                tls13.client_application_secret = secrets.client_secret().to_vec();
                tls13.server_application_secret = secrets.server_secret().to_vec();
            }
        }

        Ok(state)
    }

    /// Serialize the connection back into the s2n-tls "V1" blob format.
    ///
    /// The output is byte-for-byte compatible with s2n-tls's
    /// `s2n_connection_deserialize`, so a serialized kTLS connection can be
    /// handed back to a vanilla s2n-tls connection (or another `KtlsTcpStream`)
    /// to resume the session.
    ///
    /// Unlike a naive re-emit of the construction-time blob, this captures the
    /// connection's *current* state:
    /// - **Sequence numbers** are read back from the kernel via
    ///   `getsockopt(SOL_TLS, TLS_TX/TLS_RX)`, since the kernel owns them once
    ///   kTLS is enabled and they advance as records flow.
    /// - **TLS 1.3 traffic secrets** reflect any key updates that have occurred
    ///   (see [`KtlsTcpStream::update_send_key`] and the automatic RX handling
    ///   in [`read`](Read::read)).
    ///
    /// # Errors
    /// - [`Error::Io`] if the `getsockopt` calls fail.
    /// - [`Error::InvalidSerialization`] if `output` is too small.
    pub fn serialize(&self, output: &mut [u8]) -> Result<(), Error> {
        let state = self.current_state()?;
        let needed = state.serialization_length();
        if output.len() < needed {
            return Err(Error::InvalidSerialization("output buffer too small"));
        }
        let mut buf = Vec::with_capacity(needed);
        state.write(&mut buf);
        output[..needed].copy_from_slice(&buf);
        Ok(())
    }

    /// Serialize the connection into a freshly allocated buffer.
    ///
    /// See [`serialize`](KtlsTcpStream::serialize) for what state is captured.
    ///
    /// # Errors
    /// - [`Error::Io`] if reading the live sequence numbers from the kernel
    ///   fails.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(self.current_state()?.to_vec())
    }
}

impl Read for KtlsTcpStream {
    /// Read application data, transparently handling TLS 1.3 `KeyUpdate`
    /// messages and `close_notify` alerts.
    ///
    /// This uses `recvmsg` so it can inspect each record's content type:
    /// - **Application data** is copied to `buf` and its length returned.
    /// - A **`KeyUpdate`** handshake record advances the RX secret and
    ///   re-programs the kernel's RX key, then the read loops to fetch the next
    ///   record. This is necessary because the kernel pauses decryption after a
    ///   `KeyUpdate` until the new key is installed.
    /// - A **`close_notify`** alert is reported as EOF (`Ok(0)`).
    /// - Other post-handshake handshake messages are ignored (the loop
    ///   continues).
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.peer_closed {
            return Ok(0);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            let (n, record_type) = self.recv_record(buf)?;

            // recvmsg returns 0 on a clean TCP EOF.
            if n == 0 {
                return Ok(0);
            }

            match record_type {
                ContentType::ApplicationData => return Ok(n),
                ContentType::Handshake => {
                    // The only post-handshake handshake message kTLS surfaces
                    // that we must act on is KeyUpdate.
                    if n >= 1 && buf[0] == TLS_HANDSHAKE_TYPE_KEY_UPDATE {
                        self.process_recv_key_update()
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                    }
                    // Loop to read the next record (application data will now
                    // decrypt under the new key).
                    continue;
                }
                ContentType::Alert => {
                    // close_notify (level warning, description 0) is a clean
                    // shutdown; report EOF.
                    if n >= 2
                        && buf[0] == ALERT_LEVEL_WARNING
                        && buf[1] == ALERT_DESCRIPTION_CLOSE_NOTIFY
                    {
                        self.peer_closed = true;
                        return Ok(0);
                    }
                    // Any other alert is a fatal error.
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "received TLS alert",
                    ));
                }
            }
        }
    }
}

impl Write for KtlsTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// `CMSG_SPACE(len)` evaluated at compile time for stack buffer sizing.
///
/// `libc::CMSG_SPACE` is not `const` on all platforms, so we replicate its
/// arithmetic: `CMSG_ALIGN(sizeof(cmsghdr)) + CMSG_ALIGN(len)`.
const unsafe fn cmsg_space(len: usize) -> usize {
    let align = std::mem::size_of::<usize>();
    let hdr = std::mem::size_of::<libc::cmsghdr>();
    let aligned_hdr = (hdr + align - 1) & !(align - 1);
    let aligned_len = (len + align - 1) & !(align - 1);
    aligned_hdr + aligned_len
}
