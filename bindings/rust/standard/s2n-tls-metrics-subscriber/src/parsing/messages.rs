// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_codec::{
    DecoderBuffer, DecoderValue,
    decoder::{PrefixedBlob, PrefixedList},
};

use crate::parsing::PrefixedListComplex;
use s2n_tls_metrics_schema::static_lists::{Cipher, Group, Signature, Version};

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
#[allow(dead_code)]
pub(crate) struct ClientHello<'a> {
    pub protocol_version: Version,
    pub random: [u8; 32],
    pub legacy_session_id: PrefixedBlob<'a, u8>,
    pub cipher_suites: PrefixedList<'a, u16, Cipher>,
    pub compression_methods: PrefixedBlob<'a, u8>,
    pub extensions: Option<PrefixedBlob<'a, u16>>,
}

impl<'a> DecoderValue<'a> for ClientHello<'a> {
    fn decode(bytes: s2n_codec::DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (protocol_version, bytes) = bytes.decode()?;
        let (random, bytes) = bytes.decode()?;
        let (legacy_session_id, bytes) = bytes.decode()?;
        let (cipher_suites, bytes) = bytes.decode()?;
        let (compression_methods, bytes) = bytes.decode()?;
        let (extensions, bytes) = bytes.decode()?;

        let value = Self {
            protocol_version,
            random,
            legacy_session_id,
            cipher_suites,
            compression_methods,
            extensions,
        };

        Ok((value, bytes))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7
pub(crate) struct SupportedGroups<'a> {
    pub named_group_list: PrefixedList<'a, u16, Group>,
}

impl<'a> DecoderValue<'a> for SupportedGroups<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (named_group_list, bytes) = bytes.decode()?;
        let value = Self { named_group_list };
        Ok((value, bytes))
    }
}

pub(crate) struct KeyShareEntry<'a> {
    pub group: Group,
    // Decoded only to advance past this entry to the next one.
    #[allow(dead_code)]
    pub key_exchange: PrefixedBlob<'a, u16>,
}

impl<'a> DecoderValue<'a> for KeyShareEntry<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (group, bytes) = bytes.decode()?;
        let (key_exchange, bytes) = bytes.decode()?;
        let value = Self {
            group,
            key_exchange,
        };
        Ok((value, bytes))
    }
}

/// The `key_share` extension in a ClientHello, defined in
/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8
pub(crate) struct KeyShareClientHello<'a> {
    pub client_shares: PrefixedListComplex<'a, u16, KeyShareEntry<'a>>,
}

impl<'a> DecoderValue<'a> for KeyShareClientHello<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (client_shares, bytes) = bytes.decode()?;
        let value = Self { client_shares };
        Ok((value, bytes))
    }
}

impl<'a> KeyShareClientHello<'a> {
    /// The offered key share groups, in the order the client sent them.
    pub fn groups(&self) -> Vec<Group> {
        self.client_shares.iter().map(|entry| entry.group).collect()
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
pub(crate) struct SupportedVersionsClientHello<'a> {
    pub versions: PrefixedList<'a, u8, Version>,
}

impl<'a> DecoderValue<'a> for SupportedVersionsClientHello<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (versions, bytes) = bytes.decode()?;
        let value = Self { versions };
        Ok((value, bytes))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
pub(crate) struct SignatureSchemeList<'a> {
    pub supported_signature_algorithms: PrefixedList<'a, u16, Signature>,
}

impl<'a> DecoderValue<'a> for SignatureSchemeList<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (supported_signature_algorithms, bytes) = bytes.decode()?;
        let value = Self {
            supported_signature_algorithms,
        };
        Ok((value, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_tls_metrics_schema::static_lists::Group;

    /// Build a `key_share` extension body: a u16-prefixed list of entries, each
    /// a u16 group followed by a u16-prefixed key_exchange blob.
    fn key_share_body(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut shares = Vec::new();
        for (group, key_exchange) in entries {
            shares.extend_from_slice(&group.to_be_bytes());
            shares.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
            shares.extend_from_slice(key_exchange);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        body.extend_from_slice(&shares);
        body
    }

    #[test]
    fn decodes_entries_in_order_skipping_key_exchange() {
        // x25519 = 29, secp384r1 = 24; differently-sized key_exchange blobs
        // exercise the variable-length skip between entries.
        let body = key_share_body(&[(29, &[0x01; 32]), (24, &[0x02; 97])]);
        let parsed = DecoderBuffer::new(&body)
            .decode_exact::<KeyShareClientHello>()
            .unwrap();
        assert_eq!(parsed.groups(), vec![Group::x25519, Group::secp384r1]);
    }

    #[test]
    fn empty_list_yields_no_groups() {
        let body = key_share_body(&[]);
        let parsed = DecoderBuffer::new(&body)
            .decode_exact::<KeyShareClientHello>()
            .unwrap();
        assert!(parsed.groups().is_empty());
    }

    #[test]
    fn truncated_entry_fails_whole_decode() {
        let mut shares = Vec::new();
        // entry 1: secp256r1 (23), 2-byte key_exchange
        shares.extend_from_slice(&23u16.to_be_bytes());
        shares.extend_from_slice(&2u16.to_be_bytes());
        shares.extend_from_slice(&[0xAA, 0xBB]);
        // entry 2: claims a 100-byte key_exchange but provides none
        shares.extend_from_slice(&24u16.to_be_bytes());
        shares.extend_from_slice(&100u16.to_be_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        body.extend_from_slice(&shares);

        assert!(
            DecoderBuffer::new(&body)
                .decode_exact::<KeyShareClientHello>()
                .is_err()
        );
    }
}
