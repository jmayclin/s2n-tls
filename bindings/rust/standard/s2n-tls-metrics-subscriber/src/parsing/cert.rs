// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A minimal X509 parser to efficiently extract the limited information that we
//! care about.
//!
//! ### Why not get this from s2n-tls?
//!
//! C/Rust FFI gets you the worst of both worlds. It would require defining all
//! of the enums on the C side, and threading that access through into the rust
//! bindings. Additionally, most of these fields are not currently public. With
//! the current state of the C library, it seems better to have a strongly encapsulated
//! chunk of complexity in the non-security critical component, rather than pushing
//! that down into the TLS layer.
//!
//! Additionally, this keeps open a future where the metrics subscriber is also
//! used by AWS-LC's libssl.
//!
//! ### Why not use an existing library?
//!
//! Performance.
//!
//! These are numbers from a very rough benchmark that I did 2026-04-17.
//!
//! |    Parser   | Per-cert |
//! |-------------|----------|
//! | webpki      |  0.333µs (no key/sig) |
//! | s2n-codec   |  0.769µs |
//! | manual-der  |  0.794µs |
//! | x509-parser |  5.7µs |
//! | x509-cert   | 13.8µs |
//! | aws-lc      | 21.7µs |
//!
//! Existing cert parsing libraries are roughly 6x slower than this custom implementation.
//! webpki is super speedy, but doesn't pull out the key/signature information that
//! we need.
//!
//! While 5.7 us may seem pretty fast, in an mTLS case we might end up parsing 6
//! cert chains per handshake, and adding 34.2 us would be a nearly 10% performance
//! hit.

use s2n_codec::decoder::DecoderError;

/// Parsed cert fields from the TBSCertificate.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedCert {
    pub serial: Vec<u8>,
    pub issuer: String,
    pub subject: String,
    pub key_type: KeyType,
    pub signature: SignatureAlgorithm,
}

/// KeyType can be decoded from an AlgorithmIdentifier element of an X509 certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyType {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    RsaPss2048,
    RsaPss3072,
    RsaPss4096,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    /// NOTE: RSA-PSS encodes the hash algorithm in the AlgorithmIdentifier
    /// parameters (RSASSA-PSS-params), not in the OID itself. We currently
    /// only parse the OID, so the hash (e.g. SHA256) is not reported.
    RsaPss,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Unknown,
}

impl SignatureAlgorithm {
    const OID_RSA_PKCS_SHA1: &str = "1.2.840.113549.1.1.5";
    const OID_RSA_PKCS_SHA256: &str = "1.2.840.113549.1.1.11";
    const OID_RSA_PKCS_SHA384: &str = "1.2.840.113549.1.1.12";
    const OID_RSA_PKCS_SHA512: &str = "1.2.840.113549.1.1.13";
    const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
    const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
    const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
    const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

    fn from_oid(oid: &str) -> Self {
        match oid {
            Self::OID_RSA_PKCS_SHA1 => Self::RsaPkcsSha1,
            Self::OID_RSA_PKCS_SHA256 => Self::RsaPkcsSha256,
            Self::OID_RSA_PKCS_SHA384 => Self::RsaPkcsSha384,
            Self::OID_RSA_PKCS_SHA512 => Self::RsaPkcsSha512,
            Self::OID_RSA_PSS => Self::RsaPss,
            Self::OID_ECDSA_SHA256 => Self::EcdsaSha256,
            Self::OID_ECDSA_SHA384 => Self::EcdsaSha384,
            Self::OID_ECDSA_SHA512 => Self::EcdsaSha512,
            _ => Self::Unknown,
        }
    }
}

mod der_codec {
    use core::mem::size_of;
    use s2n_codec::{DecoderBuffer, DecoderBufferResult, DecoderError, DecoderValue};

    // DER tag constants
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_OID: u8 = 0x06;
    const TAG_BIT_STRING: u8 = 0x03;
    const TAG_CONTEXT_0: u8 = 0xa0; // [0] EXPLICIT (certificate version)

    // OID varint encoding
    const HIGH_BIT_MASK: u8 = 0b10000000;
    const LOWER_BIT_MASK: u8 = 0b01111111;

    /// A DER-encoded length field.
    ///
    /// DER length encoding:
    /// - `< 0x80`: short form — the byte IS the length (0–127)
    /// - `>= 0x80`: long form — low 7 bits = number of subsequent bytes
    ///   encoding the length as a big-endian unsigned integer
    /// - `0x80` (indefinite length) is invalid in DER
    struct DerLength(usize);

    enum DerLengthEncoding {
        Short,
        Long,
        Indefinite,
    }

    impl DerLengthEncoding {
        const SENTINEL_VALUE: u8 = 0b10000000;
        const LONG_FORM_MASK: u8 = 0b01111111;
        fn from_first_byte(first_length_byte: u8) -> Self {
            if first_length_byte < Self::SENTINEL_VALUE {
                Self::Short
            } else if first_length_byte > Self::SENTINEL_VALUE {
                Self::Long
            } else {
                Self::Indefinite
            }
        }
    }

    impl<'a> DecoderValue<'a> for DerLength {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let first = buffer.peek_byte(0)?;
            let encoding = DerLengthEncoding::from_first_byte(first);
            match encoding {
                DerLengthEncoding::Short => {
                    let (length, buffer) = buffer.decode::<u8>()?;
                    Ok((DerLength(length as usize), buffer))
                }
                DerLengthEncoding::Long => {
                    // the number of bytes in the length encoding
                    let (length_encoding_size, buffer) = {
                        let (size, buffer) = buffer.decode::<u8>()?;
                        let size = (size & DerLengthEncoding::LONG_FORM_MASK) as usize;
                        if size > size_of::<usize>() {
                            return Err(s2n_codec::decoder::DecoderError::LengthCapacityExceeded);
                        }
                        (size, buffer)
                    };
                    let (length, buffer) = {
                        let (len_bytes, buffer) = buffer.decode_slice(length_encoding_size)?;
                        let raw = len_bytes.into_less_safe_slice();
                        let mut buf = [0u8; size_of::<usize>()];
                        buf[size_of::<usize>() - raw.len()..].copy_from_slice(raw);
                        (usize::from_be_bytes(buf), buffer)
                    };
                    Ok((DerLength(length), buffer))
                }
                DerLengthEncoding::Indefinite => {
                    // "indefinite" form of length encoding, not allowed for DER
                    // > The definite form of length encoding shall be used, encoded in the minimum number of octets.
                    // > 10.1 - Distinguished Encoding Rules: Length Forms
                    // > ITU-T X.690
                    Err(DecoderError::InvariantViolation(
                        "indefinite length encoding not allowed",
                    ))
                }
            }
        }
    }

    /// A DER tag-length-value: (tag, content bytes).
    pub struct Tlv<'a> {
        pub tag: u8,
        pub content: &'a [u8],
    }

    impl<'a> DecoderValue<'a> for Tlv<'a> {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let (tag, buffer) = buffer.decode::<u8>()?;
            let (DerLength(len), buffer) = buffer.decode::<DerLength>()?;
            let (content, buffer) = buffer.decode_slice(len)?;
            Ok((
                Tlv {
                    tag,
                    content: content.into_less_safe_slice(),
                },
                buffer,
            ))
        }
    }

    /// A base-128 varint component of a DER OID. High bit is a continuation flag,
    /// low 7 bits are payload.
    struct OidComponent(u32);

    impl<'a> DecoderValue<'a> for OidComponent {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let mut acc = 0u32;
            let mut buffer = buffer;
            loop {
                let (byte, rest) = buffer.decode::<u8>()?;
                acc = acc
                    .checked_shl(7)
                    .and_then(|a| a.checked_add((byte & LOWER_BIT_MASK) as u32))
                    .ok_or(s2n_codec::decoder::DecoderError::LengthCapacityExceeded)?;
                buffer = rest;
                let continuation = byte & HIGH_BIT_MASK != 0;
                if !continuation {
                    return Ok((OidComponent(acc), buffer));
                }
            }
        }
    }

    /// OidComponents are variable length, so this might consume multiple bytes.
    /// The first OidComponent has a special interpretation, because it
    /// actually packs together two Oids. Hence we refer to this as the OidRoot
    /// to distinguish that it actually contains _two_ components.
    ///
    /// The packing scheme is as follows
    /// - combined < 40:  arc 0, second = combined
    /// - combined < 80:  arc 1, second = combined - 40
    /// - combined >= 80: arc 2, second = combined - 80
    struct OidRoot {
        first: u32,
        second: u32,
    }

    impl<'a> DecoderValue<'a> for OidRoot {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let (OidComponent(combined), buffer) = buffer.decode::<OidComponent>()?;
            let (first, second) = if combined < 40 {
                (0, combined)
            } else if combined < 80 {
                (1, combined - 40)
            } else {
                (2, combined - 80)
            };
            Ok((OidRoot { first, second }, buffer))
        }
    }

    /// A DER-encoded OID element (tag 0x06 + length + content), decoded into
    /// dotted-decimal notation. Validates the tag during decode, eliminating
    /// the need for manual TAG_OID assertions at each call site.
    pub struct Oid(pub String);

    impl<'a> DecoderValue<'a> for Oid {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let (tlv, buffer) = buffer.decode::<Tlv<'a>>()?;
            if tlv.tag != TAG_OID {
                return Err(DecoderError::InvariantViolation("expected OID tag"));
            }

            let mut content = DecoderBuffer::new(tlv.content);
            let mut parts = Vec::new();

            let (root, rest) = content.decode::<OidRoot>()?;
            parts.push(root.first);
            parts.push(root.second);
            content = rest;

            while !content.is_empty() {
                let (OidComponent(val), rest) = content.decode::<OidComponent>()?;
                parts.push(val);
                content = rest;
            }

            let oid = parts
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(".");

            Ok((Oid(oid), buffer))
        }
    }

    /// The RSA public key decoded from a BIT STRING containing
    /// SEQUENCE { INTEGER(modulus), INTEGER(exponent) }.
    struct RsaPublicKey<'a> {
        modulus: &'a [u8],
    }

    impl<'a> DecoderValue<'a> for RsaPublicKey<'a> {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            // BIT STRING wrapper
            let (bits_tlv, buffer) = buffer.decode::<Tlv<'a>>()?;
            if bits_tlv.tag != TAG_BIT_STRING {
                return Err(DecoderError::InvariantViolation("expected BIT STRING tag"));
            }
            let key_content = &bits_tlv.content[1..]; // skip unused-bits byte
            // outer SEQUENCE
            let (seq_tlv, _) = DecoderBuffer::new(key_content).decode::<Tlv<'_>>()?;
            if seq_tlv.tag != TAG_SEQUENCE {
                return Err(DecoderError::InvariantViolation(
                    "expected SEQUENCE in RSA key",
                ));
            }
            // first INTEGER is the modulus
            let (modulus_tlv, _) = DecoderBuffer::new(seq_tlv.content).decode::<Tlv<'_>>()?;
            let modulus = modulus_tlv.content;
            // strip leading 0x00 sign padding
            let modulus = if modulus.first() == Some(&0x00) {
                &modulus[1..]
            } else {
                modulus
            };
            Ok((RsaPublicKey { modulus }, buffer))
        }
    }

    /// Decode a KeyType from the content of a subjectPublicKeyInfo SEQUENCE.
    impl<'a> DecoderValue<'a> for super::KeyType {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            use super::KeyType;

            // Key algorithm OIDs
            const OID_RSA: &str = "1.2.840.113549.1.1.1";
            const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
            const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

            // EC named curve OIDs
            const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";
            const OID_SECP384R1: &str = "1.3.132.0.34";
            const OID_SECP521R1: &str = "1.3.132.0.35";

            // AlgorithmIdentifier SEQUENCE
            let (key_alg_tlv, rest) = buffer.decode::<Tlv<'a>>()?;
            let (Oid(key_oid), key_alg_rest) =
                DecoderBuffer::new(key_alg_tlv.content).decode::<Oid>()?;

            match key_oid.as_str() {
                // EC — curve OID in parameters fully determines the key type
                OID_EC_PUBLIC_KEY => {
                    let (Oid(curve_oid), _) = key_alg_rest.decode::<Oid>()?;
                    let key_type = match curve_oid.as_str() {
                        OID_SECP256R1 => KeyType::Secp256r1,
                        OID_SECP384R1 => KeyType::Secp384r1,
                        OID_SECP521R1 => KeyType::Secp521r1,
                        _ => KeyType::Unknown,
                    };
                    Ok((key_type, rest))
                }

                // RSA/RSA-PSS — parse BIT STRING to extract modulus size
                OID_RSA | OID_RSA_PSS => {
                    let (rsa_key, buffer) = rest.decode::<RsaPublicKey<'_>>()?;

                    let key_type = match (key_oid.as_str(), rsa_key.modulus.len() * 8) {
                        (OID_RSA, 1024) => KeyType::Rsa1024,
                        (OID_RSA, 2048) => KeyType::Rsa2048,
                        (OID_RSA, 3072) => KeyType::Rsa3072,
                        (OID_RSA, 4096) => KeyType::Rsa4096,
                        (OID_RSA_PSS, 2048) => KeyType::RsaPss2048,
                        (OID_RSA_PSS, 3072) => KeyType::RsaPss3072,
                        (OID_RSA_PSS, 4096) => KeyType::RsaPss4096,
                        _ => KeyType::Unknown,
                    };
                    Ok((key_type, buffer))
                }

                // Ed25519/Ed448 and other unknown key types
                _ => Ok((KeyType::Unknown, buffer)),
            }
        }
    }

    /// Extract the Common Name (CN) from a Relative Distinguished Name (RDN) Sequence.
    ///
    /// For our purposes, we discard all other fields (e.g. organization, country)
    ///
    /// Returns an empty string if no CN is found.
    fn decode_common_name(content: &[u8]) -> Result<String, DecoderError> {
        /// Raw DER bytes of the CN OID (2.5.4.3)
        /// 
        /// We compare against these hard coded bytes because OID decoding into 
        /// a dotted string is relatively expensive. Actually decoding OIDs here
        /// resulted in ~3.07 us to parse a cert. With the hard coded bytes it's
        /// only ~1.15 us to parse a cert.
        const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03];

        let mut buffer = DecoderBuffer::new(content);
        while !buffer.is_empty() {
            let (set_tlv, rest) = buffer.decode::<Tlv<'_>>()?;
            let mut set_buf = DecoderBuffer::new(set_tlv.content);
            while !set_buf.is_empty() {
                let (attr_tlv, set_rest) = set_buf.decode::<Tlv<'_>>()?;
                let (oid_tlv, val_buf) =
                    DecoderBuffer::new(attr_tlv.content).decode::<Tlv<'_>>()?;
                let (val_tlv, _) = val_buf.decode::<Tlv<'_>>()?;
                if oid_tlv.tag == TAG_OID && oid_tlv.content == CN_OID_BYTES {
                    let cn = core::str::from_utf8(val_tlv.content).unwrap_or("invalid utf8");
                    return Ok(cn.to_string());
                }
                set_buf = set_rest;
            }
            buffer = rest;
        }
        Ok(String::new())
    }

    impl<'a> DecoderValue<'a> for super::ParsedCert {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            // Certificate ::= SEQUENCE { tbs, sigAlg, sig }
            let (cert_seq, _buffer) = buffer.decode::<Tlv<'a>>()?;

            // TBSCertificate ::= SEQUENCE { ... }
            let (tbs_tlv, _) = DecoderBuffer::new(cert_seq.content).decode::<Tlv<'a>>()?;
            let mut buffer = DecoderBuffer::new(tbs_tlv.content);

            // [0] EXPLICIT version (optional, tag 0xa0)
            if buffer.peek_byte(0)? == TAG_CONTEXT_0 {
                let (_, b) = buffer.decode::<Tlv<'a>>()?;
                buffer = b;
            }

            // serial
            let (serial_tlv, buffer) = buffer.decode::<Tlv<'a>>()?;

            // signature AlgorithmIdentifier
            let (sig_alg_tlv, buffer) = buffer.decode::<Tlv<'a>>()?;
            let (Oid(sig_oid), _) = DecoderBuffer::new(sig_alg_tlv.content).decode::<Oid>()?;

            // issuer
            let (issuer_tlv, buffer) = buffer.decode::<Tlv<'a>>()?;

            // validity (skip)
            let (_, buffer) = buffer.decode::<Tlv<'a>>()?;

            // subject
            let (subject_tlv, buffer) = buffer.decode::<Tlv<'a>>()?;

            // subjectPublicKeyInfo
            let (spki_tlv, _) = buffer.decode::<Tlv<'a>>()?;
            let (key_type, _) = DecoderBuffer::new(spki_tlv.content).decode::<super::KeyType>()?;

            Ok((
                super::ParsedCert {
                    serial: serial_tlv.content.to_vec(),
                    issuer: decode_common_name(issuer_tlv.content)?,
                    subject: decode_common_name(subject_tlv.content)?,
                    key_type,
                    signature: super::SignatureAlgorithm::from_oid(&sig_oid),
                },
                DecoderBuffer::new(&[]),
            ))
        }
    }
}

/// Parse a DER-encoded certificate into its component fields.
pub fn parse(der: &[u8]) -> Result<ParsedCert, DecoderError> {
    let buf = s2n_codec::DecoderBuffer::new(der);
    let (parsed, _) = buf.decode::<ParsedCert>()?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_tls::testing::{CertKeyPair, TestPair};

    /// Helper: do a handshake with the given cert and return the leaf DER.
    fn handshake_leaf_der(prefix: &str) -> Vec<u8> {
        let cert = CertKeyPair::from_path(prefix, "cert", "key", "cert");
        let policy = s2n_tls::security::DEFAULT_TLS13;
        let mut builder = s2n_tls::config::Builder::new();
        builder.set_security_policy(&policy).unwrap();
        builder.load_pem(cert.cert(), cert.key()).unwrap();
        builder.trust_pem(cert.cert()).unwrap();
        builder
            .set_verify_host_callback(s2n_tls::testing::InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        builder.with_system_certs(false).unwrap();
        let config = builder.build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let chain = pair.server.selected_cert().unwrap();
        chain
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .der()
            .unwrap()
            .to_vec()
    }

    const S2N_LOCALHOST: &str = "localhost";

    /// All s2n-tls test certs are self-signed CN=localhost certs that differ
    /// only in key type, signature algorithm, and serial number.
    #[test]
    fn s2n_test_certs() {
        let cases: &[(&str, &[u8], KeyType, SignatureAlgorithm)] = &[
            (
                "rsa_2048_sha256_client_",
                &[0x00, 0xa9, 0xea, 0x92, 0x92, 0x5c, 0x65, 0x56, 0x34],
                KeyType::Rsa2048,
                SignatureAlgorithm::RsaPkcsSha256,
            ),
            (
                "rsa_2048_sha384_client_",
                &[0x00, 0xf5, 0x20, 0xe0, 0xfd, 0x51, 0xdd, 0xcb, 0x40],
                KeyType::Rsa2048,
                SignatureAlgorithm::RsaPkcsSha384,
            ),
            (
                "rsa_4096_sha512_client_",
                &[0x00, 0xda, 0x54, 0x50, 0xbd, 0xeb, 0x60, 0xcb, 0x7d],
                KeyType::Rsa4096,
                SignatureAlgorithm::RsaPkcsSha512,
            ),
            (
                "ecdsa_p256_pkcs1_",
                &[
                    0x3d, 0x86, 0x04, 0x9c, 0xad, 0xb8, 0xa8, 0x3c, 0xf3, 0xe7, 0xd2, 0x08, 0x0d,
                    0xc3, 0x4b, 0x73, 0x83, 0xf6, 0x1f, 0x9b,
                ],
                KeyType::Secp256r1,
                SignatureAlgorithm::EcdsaSha256,
            ),
            (
                "ecdsa_p384_pkcs1_",
                &[
                    0x33, 0x15, 0x1a, 0x7b, 0xe6, 0xb3, 0x75, 0xad, 0x4c, 0x49, 0x9d, 0xde, 0xb1,
                    0xc2, 0x5f, 0x25, 0x36, 0x70, 0x45, 0xa9,
                ],
                KeyType::Secp384r1,
                SignatureAlgorithm::EcdsaSha256,
            ),
            (
                "localhost_rsa_pss_2048_sha256_",
                &[
                    0x31, 0x94, 0xe2, 0x4a, 0xc2, 0x96, 0xdc, 0xe9, 0x94, 0x3d, 0xfd, 0x67, 0xc4,
                    0xa8, 0x94, 0x52, 0x05, 0xc2, 0x77, 0x44,
                ],
                KeyType::RsaPss2048,
                SignatureAlgorithm::RsaPss,
            ),
        ];

        for (prefix, serial, key_type, signature) in cases {
            let der = handshake_leaf_der(prefix);
            let expected = ParsedCert {
                serial: serial.to_vec(),
                issuer: S2N_LOCALHOST.into(),
                subject: S2N_LOCALHOST.into(),
                key_type: key_type.clone(),
                signature: signature.clone(),
            };
            assert_eq!(parse(&der).unwrap(), expected, "failed for {prefix}");
        }
    }

    /// This tests are cert parsing against the public certificate chain returned by
    /// `sqs.us-east-2.amazonaws.com`
    #[test]
    fn sqs_cert_chain() {
        const SQS_LEAF: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/test_certs/sqs_leaf.der"
        ));
        const SQS_INTERMEDIATE: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/test_certs/sqs_intermediate.der"
        ));
        const SQS_ROOT: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/test_certs/sqs_root.der"
        ));

        assert_eq!(
            parse(SQS_LEAF).unwrap(),
            ParsedCert {
                serial: vec![
                    0x06, 0xb1, 0xde, 0xc6, 0x59, 0x3a, 0x5f, 0x5d, 0x52, 0xcc, 0xce, 0x05, 0x13,
                    0x23, 0x8d, 0x1c,
                ],
                issuer: "Amazon RSA 2048 M04".into(),
                subject: "sqs.us-east-2.amazonaws.com".into(),
                key_type: KeyType::Rsa2048,
                signature: SignatureAlgorithm::RsaPkcsSha256,
            }
        );

        assert_eq!(
            parse(SQS_INTERMEDIATE).unwrap(),
            ParsedCert {
                serial: vec![
                    0x07, 0x73, 0x12, 0x4f, 0x2a, 0x95, 0x2e, 0x3e, 0xd1, 0x8a, 0x58, 0xbd, 0xb8,
                    0x5d, 0x1b, 0xc0, 0xce, 0x5f, 0x27,
                ],
                issuer: "Amazon Root CA 1".into(),
                subject: "Amazon RSA 2048 M04".into(),
                key_type: KeyType::Rsa2048,
                signature: SignatureAlgorithm::RsaPkcsSha256,
            }
        );

        assert_eq!(
            parse(SQS_ROOT).unwrap(),
            ParsedCert {
                serial: vec![
                    0x06, 0x7f, 0x94, 0x4a, 0x2a, 0x27, 0xcd, 0xf3, 0xfa, 0xc2, 0xae, 0x2b, 0x01,
                    0xf9, 0x08, 0xee, 0xb9, 0xc4, 0xc6,
                ],
                issuer: "Starfield Services Root Certificate Authority - G2".into(),
                subject: "Amazon Root CA 1".into(),
                key_type: KeyType::Rsa2048,
                signature: SignatureAlgorithm::RsaPkcsSha256,
            }
        );
    }

    /// We should gracefully parse certs with unknown cert types, returning the
    /// well-defined "unknown" enums.
    ///
    /// Internally, this is an Ed25519 cert produced with OpenSSL. s2n-tls doesn't
    /// support Ed25519, which is why we don't actually support this value.
    #[test]
    fn ed25519_unknown_key_type() {
        assert_eq!(
            parse(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/resources/test_certs/ed25519_cert.der"
            )))
            .unwrap(),
            ParsedCert {
                serial: vec![
                    0x5b, 0x9d, 0xf7, 0x74, 0x5d, 0x46, 0x4e, 0xaf, 0x5f, 0x71, 0x9a, 0xb9, 0xa1,
                    0xb9, 0x55, 0xf9, 0xfe, 0x8b, 0x71, 0x59,
                ],
                issuer: "localhost".into(),
                subject: "localhost".into(),
                key_type: KeyType::Unknown,
                signature: SignatureAlgorithm::Unknown,
            }
        );
    }

    #[test]
    fn error_cases() {
        // garbage data
        assert!(parse(&[0xff, 0x00]).is_err());

        // empty data
        assert!(parse(&[]).is_err());

        // truncated data
        let der = handshake_leaf_der("rsa_2048_sha256_client_");
        assert!(parse(&der[..der.len() / 2]).is_err());
    }

    #[test]
    fn benchmark() {
        use std::time::Instant;

        let der = handshake_leaf_der("rsa_4096_sha512_client_");

        const N: u32 = 1000;
        let start = Instant::now();
        for _ in 0..N {
            let _ = parse(&der).unwrap();
        }
        let dur = start.elapsed();

        eprintln!(
            "\n--- s2n-codec cert parse ({N} iterations) ---\n\
             parse: {:?} ({:?}/cert)",
            dur,
            dur / N,
        );
    }
}
