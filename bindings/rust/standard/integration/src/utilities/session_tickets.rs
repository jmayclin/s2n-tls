// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parsing and tampering helpers for the session blob that an s2n-tls client gets
//! from `s2n_connection_get_session`, mirroring `tls/s2n_resume.c`.
//!
//! Client blob: `format (1 = ticket) | ticket length (u16) | ticket | resumption state`.
//! Session id based resumption (format 0) is not supported.
//!
//! The ticket is encrypted by the server under its session ticket key (STEK);
//! [`TicketKey`] and [`ServerTicket`] decrypt and re-encrypt it.

use openssl::{
    md::Md,
    pkey::Id,
    pkey_ctx::PkeyCtx,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use s2n_codec::{DecoderBuffer, DecoderBufferResult, DecoderError, DecoderValue};
use std::error::Error;

/// `s2n_client_tls_session_state_format` in tls/s2n_resume.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientFormat {
    SessionId = 0,
    SessionTicket = 1,
}

impl TryFrom<u8> for ClientFormat {
    type Error = DecoderError;

    fn try_from(value: u8) -> Result<Self, DecoderError> {
        match value {
            0 => Ok(Self::SessionId),
            1 => Ok(Self::SessionTicket),
            _ => Err(DecoderError::InvariantViolation("unknown client format")),
        }
    }
}

/// `s2n_serial_format_version` in tls/s2n_resume.h: the first byte of a resumption
/// state. Only `Tls12V3` and `Tls13V2` are current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SerializedFormat {
    Tls12V1 = 1,
    Tls13V1 = 2,
    Tls12V2 = 3,
    Tls12V3 = 4,
    Tls13V2 = 5,
}

impl TryFrom<u8> for SerializedFormat {
    type Error = DecoderError;

    fn try_from(value: u8) -> Result<Self, DecoderError> {
        match value {
            1 => Ok(Self::Tls12V1),
            2 => Ok(Self::Tls13V1),
            3 => Ok(Self::Tls12V2),
            4 => Ok(Self::Tls12V3),
            5 => Ok(Self::Tls13V2),
            _ => Err(DecoderError::InvariantViolation(
                "unknown serialized format",
            )),
        }
    }
}

impl<'a> DecoderValue<'a> for SerializedFormat {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (value, buffer) = buffer.decode::<u8>()?;
        Ok((Self::try_from(value)?, buffer))
    }
}

/// `struct s2n_resumption_state_tls12`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls12State {
    pub version: SerializedFormat,
    pub condensed_protocol_version: u8,
    pub cipher_id: [u8; 2],
    pub ticket_issue_unix_ns: u64,
    pub master_secret: [u8; 48],
    pub ems_negotiated: bool,
}

impl<'a> DecoderValue<'a> for Tls12State {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (version, buffer) = buffer.decode()?;
        let (condensed_protocol_version, buffer) = buffer.decode()?;
        let (cipher_id, buffer) = buffer.decode()?;
        let (ticket_issue_unix_ns, buffer) = buffer.decode()?;
        let (master_secret, buffer) = buffer.decode()?;
        let (ems_negotiated, buffer) = buffer.decode::<u8>()?;
        let state = Self {
            version,
            condensed_protocol_version,
            cipher_id,
            ticket_issue_unix_ns,
            master_secret,
            ems_negotiated: ems_negotiated != 0,
        };
        Ok((state, buffer))
    }
}

/// `struct s2n_resumption_state_tls13`. The early data fields are empty unless
/// `max_early_data_size > 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13State {
    pub version: SerializedFormat,
    pub condensed_protocol_version: u8,
    pub cipher_id: [u8; 2],
    pub ticket_issue_unix_ns: u64,
    pub ticket_age_add: u32,
    pub resumption_secret: Vec<u8>,
    pub keying_material_expiration: u64,
    pub max_early_data_size: u32,
    pub app_protocol: Vec<u8>,
    pub early_data_context: Vec<u8>,
}

impl<'a> DecoderValue<'a> for Tls13State {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (version, buffer) = buffer.decode()?;
        let (condensed_protocol_version, buffer) = buffer.decode()?;
        let (cipher_id, buffer) = buffer.decode()?;
        let (ticket_issue_unix_ns, buffer) = buffer.decode()?;
        let (ticket_age_add, buffer) = buffer.decode()?;
        let (resumption_secret, buffer) = buffer.decode_slice_with_len_prefix::<u8>()?;
        let (keying_material_expiration, buffer) = buffer.decode()?;
        let (max_early_data_size, mut buffer) = buffer.decode::<u32>()?;

        let (mut app_protocol, mut early_data_context) = (vec![], vec![]);
        if max_early_data_size > 0 {
            let (protocol, rest) = buffer.decode_slice_with_len_prefix::<u8>()?;
            let (context, rest) = rest.decode_slice_with_len_prefix::<u16>()?;
            app_protocol = protocol.into_less_safe_slice().to_vec();
            early_data_context = context.into_less_safe_slice().to_vec();
            buffer = rest;
        }

        let state = Self {
            version,
            condensed_protocol_version,
            cipher_id,
            ticket_issue_unix_ns,
            ticket_age_add,
            resumption_secret: resumption_secret.into_less_safe_slice().to_vec(),
            keying_material_expiration,
            max_early_data_size,
            app_protocol,
            early_data_context,
        };
        Ok((state, buffer))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumptionState {
    Tls12(Tls12State),
    Tls13(Tls13State),
}

impl ResumptionState {
    pub fn version(&self) -> SerializedFormat {
        match self {
            Self::Tls12(state) => state.version,
            Self::Tls13(state) => state.version,
        }
    }
}

impl<'a> DecoderValue<'a> for ResumptionState {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        match SerializedFormat::try_from(buffer.peek_byte(0)?)? {
            SerializedFormat::Tls12V3 => {
                let (state, buffer) = buffer.decode::<Tls12State>()?;
                Ok((Self::Tls12(state), buffer))
            }
            SerializedFormat::Tls13V2 => {
                let (state, buffer) = buffer.decode::<Tls13State>()?;
                Ok((Self::Tls13(state), buffer))
            }
            _ => Err(DecoderError::InvariantViolation(
                "unsupported serialized format",
            )),
        }
    }
}

/// A parsed client session blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSession {
    /// The opaque ticket issued by the server.
    pub ticket: Vec<u8>,
    pub state: ResumptionState,
}

impl ClientSession {
    /// Parses the whole blob. Trailing bytes are an error.
    pub fn deserialize(blob: &[u8]) -> Result<Self, DecoderError> {
        DecoderBuffer::new(blob).decode_exact()
    }

    /// Offset of the resumption state, which is also the offset of its version byte.
    pub fn state_offset(&self) -> usize {
        1 + 2 + self.ticket.len()
    }
}

impl<'a> DecoderValue<'a> for ClientSession {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (format, buffer) = buffer.decode::<u8>()?;
        if ClientFormat::try_from(format)? != ClientFormat::SessionTicket {
            return Err(DecoderError::InvariantViolation(
                "session id based resumption is not supported",
            ));
        }
        let (ticket, buffer) = buffer.decode_slice_with_len_prefix::<u16>()?;
        let (state, buffer) = buffer.decode()?;
        let ticket = ticket.into_less_safe_slice().to_vec();
        Ok((Self { ticket, state }, buffer))
    }
}

/// Overwrites the version byte of a serialized resumption state with any value.
/// `raw` must start at the state, e.g. `&mut blob[session.state_offset()..]`.
/// Panics if it doesn't start with a current version, which catches a wrong offset.
pub fn raw_version_assign(raw: &mut [u8], new_version: u8) {
    let version = raw.first_mut().expect("empty state");
    assert!(
        [
            SerializedFormat::Tls12V3 as u8,
            SerializedFormat::Tls13V2 as u8
        ]
        .contains(version),
        "state does not start with a current version"
    );
    *version = new_version;
}

/// Returns `blob` with its ticket replaced by `new_ticket`.
pub fn replace_ticket(blob: &[u8], new_ticket: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let offset = ClientSession::deserialize(blob)?.state_offset();
    let len = u16::try_from(new_ticket.len())?.to_be_bytes();
    let format = [ClientFormat::SessionTicket as u8];
    Ok([&format[..], &len, new_ticket, &blob[offset..]].concat())
}

fn hkdf_sha256(key: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Box<dyn Error>> {
    // Empty salt, as in s2n-tls.
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_key(key)?;
    ctx.add_hkdf_info(info)?;
    ctx.derive(Some(out))?;
    Ok(())
}

/// A session ticket key (STEK), derived like `s2n_config_add_ticket_crypto_key`.
pub struct TicketKey {
    key_name: [u8; 16],
    aes_key: [u8; 32],
    /// 12 byte implicit AAD followed by the key name.
    aad: Vec<u8>,
}

impl TicketKey {
    pub fn derive(name: &[u8], key: &[u8]) -> Result<Self, Box<dyn Error>> {
        let mut key_name = [0; 16];
        key_name[..name.len()].copy_from_slice(name);

        let mut derived = [0; 32 + 12];
        hkdf_sha256(key, &[], &mut derived)?;
        Ok(Self {
            key_name,
            aes_key: derived[..32].try_into().unwrap(),
            aad: [&derived[32..], &key_name[..]].concat(),
        })
    }

    /// The per-ticket AES key, as in `s2n_resume_generate_unique_ticket_key`.
    fn ticket_key(&self, nonce: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
        let mut key = [0; 32];
        hkdf_sha256(&self.aes_key, nonce, &mut key)?;
        Ok(key)
    }
}

/// A ticket as encrypted by an s2n-tls server:
/// `version (1) | key name (16) | nonce (32) | iv (12) | AES-256-GCM ciphertext | tag (16)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTicket {
    key_name: [u8; 16],
    nonce: [u8; 32],
    iv: [u8; 12],
    /// The ciphertext followed by the tag.
    body: Vec<u8>,
}

const TICKET_VERSION: u8 = 1;
const TAG_LEN: usize = 16;

impl<'a> DecoderValue<'a> for ServerTicket {
    fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
        let (version, buffer) = buffer.decode::<u8>()?;
        if version != TICKET_VERSION {
            return Err(DecoderError::InvariantViolation("unknown ticket version"));
        }
        let (key_name, buffer) = buffer.decode()?;
        let (nonce, buffer) = buffer.decode()?;
        let (iv, buffer) = buffer.decode()?;
        let remaining = buffer.len();
        let (body, buffer) = buffer.decode_slice(remaining)?;
        let body = body.into_less_safe_slice().to_vec();
        Ok((
            Self {
                key_name,
                nonce,
                iv,
                body,
            },
            buffer,
        ))
    }
}

impl ServerTicket {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DecoderError> {
        DecoderBuffer::new(bytes).decode_exact()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let version = [TICKET_VERSION];
        [
            &version[..],
            &self.key_name,
            &self.nonce,
            &self.iv,
            &self.body,
        ]
        .concat()
    }

    /// Decrypts the resumption state.
    pub fn decrypt(&self, key: &TicketKey) -> Result<Vec<u8>, Box<dyn Error>> {
        let ciphertext_len = self
            .body
            .len()
            .checked_sub(TAG_LEN)
            .ok_or("ticket too short")?;
        let (ciphertext, tag) = self.body.split_at(ciphertext_len);
        let aes_key = key.ticket_key(&self.nonce)?;
        let cipher = Cipher::aes_256_gcm();
        Ok(decrypt_aead(
            cipher,
            &aes_key,
            Some(&self.iv),
            &key.aad,
            ciphertext,
            tag,
        )?)
    }

    /// Encrypts `state` into a new ticket with this ticket's nonce and IV.
    /// Reusing the IV is only acceptable in tests.
    pub fn reencrypt(&self, key: &TicketKey, state: &[u8]) -> Result<Self, Box<dyn Error>> {
        let aes_key = key.ticket_key(&self.nonce)?;
        let mut tag = [0; TAG_LEN];
        let cipher = Cipher::aes_256_gcm();
        let mut body = encrypt_aead(cipher, &aes_key, Some(&self.iv), &key.aad, state, &mut tag)?;
        body.extend_from_slice(&tag);
        Ok(Self {
            key_name: key.key_name,
            nonce: self.nonce,
            iv: self.iv,
            body,
        })
    }
}
