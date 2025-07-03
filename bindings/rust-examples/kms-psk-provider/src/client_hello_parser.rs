use crate::{
    codec::{DecodeByteSource, DecodeValue, U24},
    prefixed_list::{PrefixedBlob, PrefixedList},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeType {
    ClientHello,
    Unknown(u8),
}

impl DecodeValue for HandshakeType {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, remaining) = u8::decode_from(buffer)?;
        let protocol = match value {
            1 => Self::ClientHello,
            x => Self::Unknown(x),
        };
        Ok((protocol, remaining))
    }
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtensionType {
    PreSharedKey = 41,
    SupportedVersions = 43,
    Unknown(u16),
}

impl DecodeValue for ExtensionType {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, remaining) = u16::decode_from(buffer)?;
        let protocol = match value {
            41 => Self::PreSharedKey,
            43 => Self::SupportedVersions,
            x => Self::Unknown(x),
        };
        Ok((protocol, remaining))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    SSLv3,
    TLSv1_0,
    TLSv1_1,
    TLSv1_2,
    TLSv1_3,
    Unknown(u16),
}

impl DecodeValue for Protocol {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, remaining) = u16::decode_from(buffer)?;
        let protocol = match value {
            0x0300 => Self::SSLv3,
            0x0301 => Self::TLSv1_0,
            0x0302 => Self::TLSv1_1,
            0x0303 => Self::TLSv1_2,
            0x0304 => Self::TLSv1_3,
            x => Self::Unknown(x),
        };
        Ok((protocol, remaining))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: PrefixedBlob<u16>,
    pub obfuscated_ticket_age: u32,
}

impl DecodeValue for PskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (identity, buffer) = buffer.decode_value()?;
        let (obfuscated_ticket_age, buffer) = buffer.decode_value()?;

        let value = Self {
            identity,
            obfuscated_ticket_age,
        };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskBinderEntry {
    entry: PrefixedBlob<u8>,
}

impl DecodeValue for PskBinderEntry {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (entry, buffer) = buffer.decode_value()?;

        let value = Self { entry };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresharedKeyClientHello {
    pub identities: PrefixedList<PskIdentity, u16>,
    pub binders: PrefixedList<PskBinderEntry, u16>,
}

impl DecodeValue for PresharedKeyClientHello {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (identities, buffer) = buffer.decode_value()?;
        let (binders, buffer) = buffer.decode_value()?;

        let value = Self {
            identities,
            binders,
        };

        Ok((value, buffer))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedVersionClientHello {
    pub versions: PrefixedList<Protocol, u8>,
}

impl DecodeValue for SupportedVersionClientHello {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (versions, buffer) = buffer.decode_value()?;

        let value = Self {
            versions,
        };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeMessageHeader {
    pub handshake_type: HandshakeType,
    pub handshake_message_length: U24,
}

impl DecodeValue for HandshakeMessageHeader {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (handshake_type, buffer) = buffer.decode_value()?;
        let (handshake_message_length, buffer) = buffer.decode_value()?;

        let value = Self {
            handshake_type,
            handshake_message_length,
        };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub protocol_version: Protocol,
    pub random: [u8; 32],
    pub session_id: PrefixedBlob<u8>,
    pub offered_ciphers: PrefixedBlob<u16>,
    pub compression_methods: PrefixedBlob<u8>,
    pub extensions: PrefixedList<Extension, u16>,
}

impl DecodeValue for ClientHello {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (protocol_version, buffer) = buffer.decode_value()?;
        let (random, buffer) = buffer.decode_value()?;
        let (session_id, buffer) = buffer.decode_value()?;
        let (offered_ciphers, buffer) = buffer.decode_value()?;
        let (compression_methods, buffer) = buffer.decode_value()?;
        let (extensions, buffer) = buffer.decode_value()?;

        let value = Self {
            protocol_version,
            random,
            session_id,
            offered_ciphers,
            compression_methods,
            extensions,
        };

        Ok((value, buffer))
    }
}

/// This is the "basic" extension struct. Any extension will be able to be parsed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    // TODO: emit metrics whenever we see an extension type that isn't recognized
    pub extension_type: ExtensionType,
    pub extension_data: PrefixedBlob<u16>,
}

impl DecodeValue for Extension {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (extension_type, buffer) = buffer.decode_value()?;
        let (extension_data, buffer) = buffer.decode_value()?;

        let value = Self {
            extension_type,
            extension_data,
        };

        Ok((value, buffer))
    }
}
