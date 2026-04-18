// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_codec::decoder::DecoderError;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyType {
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
    Unknown(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignatureAlgorithm {
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
    Unknown(String),
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
            Self::OID_RSA_PKCS_SHA1 => SignatureAlgorithm::RsaPkcsSha1,
            Self::OID_RSA_PKCS_SHA256 => SignatureAlgorithm::RsaPkcsSha256,
            Self::OID_RSA_PKCS_SHA384 => SignatureAlgorithm::RsaPkcsSha384,
            Self::OID_RSA_PKCS_SHA512 => SignatureAlgorithm::RsaPkcsSha512,
            Self::OID_RSA_PSS => SignatureAlgorithm::RsaPss,
            Self::OID_ECDSA_SHA256 => SignatureAlgorithm::EcdsaSha256,
            Self::OID_ECDSA_SHA384 => SignatureAlgorithm::EcdsaSha384,
            Self::OID_ECDSA_SHA512 => SignatureAlgorithm::EcdsaSha512,
            _ => SignatureAlgorithm::Unknown(oid.to_string()),
        }
    }
}

/// Key type and signature algorithm for any certificate.
pub(crate) struct CertInfo {
    pub key: KeyType,
    pub signature: SignatureAlgorithm,
}

/// Full information for a leaf certificate, including identity fields.
pub(crate) struct LeafCertInfo {
    pub serial: Vec<u8>,
    pub issuer: Vec<u8>,
    pub common_name: Vec<u8>,
    pub cert: CertInfo,
}

mod der_codec {
    use core::mem::size_of;
    use s2n_codec::{DecoderBuffer, DecoderBufferResult, DecoderValue};

    // DER tag constants
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_OID: u8 = 0x06;
    const TAG_CONTEXT_0: u8 = 0xa0; // [0] EXPLICIT (certificate version)

    // DER length encoding thresholds
    const DER_LENGTH_SHORT_FORM_MAX: u8 = 0x80;
    const DER_LENGTH_LONG_FORM_MASK: u8 = 0x7f;

    // OID varint encoding
    const OID_VARINT_CONTINUATION: u8 = 0x80;
    const OID_VARINT_DATA_MASK: u8 = 0x7f;

    /// A DER-encoded length field.
    ///
    /// DER length encoding:
    /// - `< 0x80`: short form — the byte IS the length (0–127)
    /// - `>= 0x80`: long form — low 7 bits = number of subsequent bytes
    ///   encoding the length as a big-endian unsigned integer
    /// - `0x80` (indefinite length) is invalid in DER
    struct DerLength(usize);

    impl<'a> DecoderValue<'a> for DerLength {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            let (first, buffer) = buffer.decode::<u8>()?;
            let short_form_encoding = first < DER_LENGTH_SHORT_FORM_MAX;
            if short_form_encoding {
                Ok((DerLength(first as usize), buffer))
            } else {
                let num_length_bytes = (first & DER_LENGTH_LONG_FORM_MASK) as usize;
                if num_length_bytes > size_of::<usize>() {
                    return Err(s2n_codec::decoder::DecoderError::LengthCapacityExceeded);
                }
                let (len_bytes, buffer) = buffer.decode_slice(num_length_bytes)?;
                let raw = len_bytes.into_less_safe_slice();
                let mut buf = [0u8; size_of::<usize>()];
                buf[size_of::<usize>() - raw.len()..].copy_from_slice(raw);
                Ok((DerLength(usize::from_be_bytes(buf)), buffer))
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
                    .and_then(|a| a.checked_add((byte & OID_VARINT_DATA_MASK) as u32))
                    .ok_or(s2n_codec::decoder::DecoderError::LengthCapacityExceeded)?;
                buffer = rest;
                let continuation = byte & OID_VARINT_CONTINUATION != 0;
                if !continuation {
                    return Ok((OidComponent(acc), buffer));
                }
            }
        }
    }

    /// The first component(s) of a DER OID. The first two arcs are packed together:
    /// - combined < 40:  arc 0, second = combined
    /// - combined < 80:  arc 1, second = combined - 40
    /// - combined >= 80: arc 2, second = combined - 80
    ///
    /// For arcs 0 and 1 this is always a single byte, but arc 2 with a large
    /// second component can be a multi-byte varint.
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

    /// Decode a DER OID body (content bytes, without the tag+length) into dotted-decimal.
    pub fn decode_oid(bytes: &[u8]) -> Result<String, s2n_codec::decoder::DecoderError> {
        let mut buffer = DecoderBuffer::new(bytes);
        let mut parts = Vec::new();

        let (root, rest) = buffer.decode::<OidRoot>()?;
        parts.push(root.first);
        parts.push(root.second);
        buffer = rest;

        while !buffer.is_empty() {
            let (OidComponent(val), rest) = buffer.decode::<OidComponent>()?;
            parts.push(val);
            buffer = rest;
        }

        Ok(parts
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("."))
    }

    // Key algorithm OIDs
    const OID_RSA: &str = "1.2.840.113549.1.1.1";
    const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
    const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

    // EC named curve OIDs
    const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";
    const OID_SECP384R1: &str = "1.3.132.0.34";
    const OID_SECP521R1: &str = "1.3.132.0.35";

    /// Decode a KeyType from the content of a subjectPublicKeyInfo SEQUENCE.
    impl<'a> DecoderValue<'a> for super::KeyType {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            use super::KeyType;

            // AlgorithmIdentifier SEQUENCE
            let (key_alg_tlv, rest) = buffer.decode::<Tlv<'a>>()?;
            let (key_oid_tlv, key_alg_rest) =
                DecoderBuffer::new(key_alg_tlv.content).decode::<Tlv<'a>>()?;
            let key_oid = decode_oid(key_oid_tlv.content)?;

            match key_oid.as_str() {
                // EC — curve OID in parameters fully determines the key type
                OID_EC_PUBLIC_KEY => {
                    let key_type = {
                        let (param_tlv, _) = key_alg_rest.decode::<Tlv<'a>>()?;
                        if param_tlv.tag == TAG_OID {
                            match decode_oid(param_tlv.content)?.as_str() {
                                OID_SECP256R1 => KeyType::Secp256r1,
                                OID_SECP384R1 => KeyType::Secp384r1,
                                OID_SECP521R1 => KeyType::Secp521r1,
                                curve => KeyType::Unknown(curve.to_string()),
                            }
                        } else {
                            KeyType::Unknown(key_oid)
                        }
                    };
                    Ok((key_type, rest))
                }

                // RSA/RSA-PSS — parse BIT STRING to extract modulus size
                OID_RSA | OID_RSA_PSS => {
                    let (key_bits_tlv, buffer) = rest.decode::<Tlv<'a>>()?;
                    let key_content = &key_bits_tlv.content[1..]; // skip unused-bits byte
                    // Public key is SEQUENCE { INTEGER(modulus), INTEGER(exponent) }
                    let (key_sequence, remaining) =
                        DecoderBuffer::new(key_content).decode::<Tlv<'_>>()?;

                    let key_bits = {
                        if key_sequence.tag == TAG_SEQUENCE {
                            let (modulus_tlv, remaining) =
                                DecoderBuffer::new(key_sequence.content).decode::<Tlv<'_>>()?;

                            let modulus = modulus_tlv.content;
                            // modulus may have a leading 0x00 padding byte for sign
                            let modulus = if modulus.first() == Some(&0x00) {
                                &modulus[1..]
                            } else {
                                modulus
                            };
                            modulus.len() * 8
                        } else {
                            key_content.len() * 8
                        }
                    };

                    let key_type = match (key_oid.as_str(), key_bits) {
                        (OID_RSA, 1024) => KeyType::Rsa1024,
                        (OID_RSA, 2048) => KeyType::Rsa2048,
                        (OID_RSA, 3072) => KeyType::Rsa3072,
                        (OID_RSA, 4096) => KeyType::Rsa4096,
                        (OID_RSA_PSS, 2048) => KeyType::RsaPss2048,
                        (OID_RSA_PSS, 3072) => KeyType::RsaPss3072,
                        (OID_RSA_PSS, 4096) => KeyType::RsaPss4096,
                        _ => KeyType::Unknown(format!("UNKNOWN")),
                    };
                    Ok((key_type, buffer))
                }

                // Ed25519/Ed448 and other unknown key types
                _ => Ok((KeyType::Unknown(key_oid), rest)),
            }
        }
    }

    /// Parsed cert fields needed for CertInfo/LeafCertInfo.
    pub struct ParsedCert<'a> {
        pub serial: &'a [u8],
        pub issuer: &'a [u8],
        pub subject: &'a [u8],
        pub key_type: super::KeyType,
        pub sig_oid: String,
    }

    impl<'a> DecoderValue<'a> for ParsedCert<'a> {
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
            let (sig_oid_tlv, _) = DecoderBuffer::new(sig_alg_tlv.content).decode::<Tlv<'a>>()?;
            let sig_oid = decode_oid(sig_oid_tlv.content)?;

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
                ParsedCert {
                    serial: serial_tlv.content,
                    issuer: issuer_tlv.content,
                    subject: subject_tlv.content,
                    key_type,
                    sig_oid,
                },
                DecoderBuffer::new(&[]),
            ))
        }
    }
}

/// Parse only key type and signature algorithm from a single DER cert.
pub(crate) fn parse_cert(der: &[u8]) -> Result<CertInfo, DecoderError> {
    let buf = s2n_codec::DecoderBuffer::new(der);
    let (parsed, _) = buf.decode::<der_codec::ParsedCert<'_>>()?;
    Ok(CertInfo {
        key: parsed.key_type,
        signature: SignatureAlgorithm::from_oid(&parsed.sig_oid),
    })
}

/// Parse full leaf information (serial, issuer, CN, key, sig) from a single DER cert.
pub(crate) fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, DecoderError> {
    let buf = s2n_codec::DecoderBuffer::new(der);
    let (parsed, _) = buf.decode::<der_codec::ParsedCert<'_>>()?;
    Ok(LeafCertInfo {
        serial: parsed.serial.to_vec(),
        issuer: parsed.issuer.to_vec(),
        common_name: parsed.subject.to_vec(),
        cert: CertInfo {
            key: parsed.key_type,
            signature: SignatureAlgorithm::from_oid(&parsed.sig_oid),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_tls::testing::{CertKeyPair, TestPair};

    /// Helper: do a handshake with the given cert and return the leaf DER.
    fn handshake_leaf_der(cert: &CertKeyPair) -> Vec<u8> {
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

    /// All test certs have subject CN=localhost, so "localhost" appears in the
    /// raw DER-encoded subject bytes.
    fn assert_leaf(
        info: &LeafCertInfo,
        expected_serial: &[u8],
        expected_key: &KeyType,
        expected_sig: &SignatureAlgorithm,
    ) {
        assert_eq!(
            info.serial, expected_serial,
            "serial mismatch: {:02x?}",
            info.serial
        );
        assert!(!info.issuer.is_empty());
        assert!(
            info.common_name.windows(9).any(|w| w == b"localhost"),
            "subject should contain 'localhost': {:02x?}",
            info.common_name,
        );
        assert_eq!(&info.cert.key, expected_key);
        assert_eq!(&info.cert.signature, expected_sig);
    }

    // -- RSA certs --

    #[test]
    fn rsa_2048_sha256() {
        let cert = CertKeyPair::from_path("rsa_2048_sha256_client_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);
        let info = parse_leaf(&der).unwrap();
        assert_leaf(
            &info,
            &[0x00, 0xa9, 0xea, 0x92, 0x92, 0x5c, 0x65, 0x56, 0x34],
            &KeyType::Rsa2048,
            &SignatureAlgorithm::RsaPkcsSha256,
        );
    }

    #[test]
    fn rsa_2048_sha384() {
        let cert = CertKeyPair::from_path("rsa_2048_sha384_client_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);
        let info = parse_leaf(&der).unwrap();
        assert_leaf(
            &info,
            &[0x00, 0xf5, 0x20, 0xe0, 0xfd, 0x51, 0xdd, 0xcb, 0x40],
            &KeyType::Rsa2048,
            &SignatureAlgorithm::RsaPkcsSha384,
        );
    }

    #[test]
    fn rsa_4096_sha512() {
        let cert = CertKeyPair::from_path("rsa_4096_sha512_client_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);
        let info = parse_leaf(&der).unwrap();
        assert_leaf(
            &info,
            &[0x00, 0xda, 0x54, 0x50, 0xbd, 0xeb, 0x60, 0xcb, 0x7d],
            &KeyType::Rsa4096,
            &SignatureAlgorithm::RsaPkcsSha512,
        );
    }

    // -- ECDSA certs --

    #[test]
    fn ecdsa_p256_sha256() {
        let cert = CertKeyPair::from_path("ecdsa_p256_pkcs1_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);
        let info = parse_leaf(&der).unwrap();
        assert_leaf(
            &info,
            &[
                0x3d, 0x86, 0x04, 0x9c, 0xad, 0xb8, 0xa8, 0x3c, 0xf3, 0xe7, 0xd2, 0x08, 0x0d, 0xc3,
                0x4b, 0x73, 0x83, 0xf6, 0x1f, 0x9b,
            ],
            &KeyType::Secp256r1,
            &SignatureAlgorithm::EcdsaSha256,
        );
    }

    #[test]
    fn ecdsa_p384_sha256() {
        let cert = CertKeyPair::from_path("ecdsa_p384_pkcs1_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);
        let info = parse_leaf(&der).unwrap();
        assert_leaf(
            &info,
            &[
                0x33, 0x15, 0x1a, 0x7b, 0xe6, 0xb3, 0x75, 0xad, 0x4c, 0x49, 0x9d, 0xde, 0xb1, 0xc2,
                0x5f, 0x25, 0x36, 0x70, 0x45, 0xa9,
            ],
            &KeyType::Secp384r1,
            &SignatureAlgorithm::EcdsaSha256,
        );
    }

    // -- RSA-PSS cert --

    #[test]
    fn rsa_pss_2048_sha256() {
        let cert = CertKeyPair::from_path("localhost_rsa_pss_2048_sha256_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);
        let info = parse_leaf(&der).unwrap();
        assert_leaf(
            &info,
            &[
                0x31, 0x94, 0xe2, 0x4a, 0xc2, 0x96, 0xdc, 0xe9, 0x94, 0x3d, 0xfd, 0x67, 0xc4, 0xa8,
                0x94, 0x52, 0x05, 0xc2, 0x77, 0x44,
            ],
            &KeyType::RsaPss2048,
            &SignatureAlgorithm::RsaPss,
        );
    }

    // -- error handling --

    #[test]
    fn parse_cert_rejects_garbage() {
        assert!(parse_cert(&[0xff, 0x00]).is_err());
    }

    #[test]
    fn parse_cert_rejects_empty() {
        assert!(parse_cert(&[]).is_err());
    }

    #[test]
    fn parse_cert_rejects_truncated() {
        let cert = CertKeyPair::from_path("rsa_2048_sha256_client_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);
        assert!(parse_cert(&der[..der.len() / 2]).is_err());
    }

    #[test]
    fn benchmark() {
        use std::time::Instant;

        let cert = CertKeyPair::from_path("rsa_4096_sha512_client_", "cert", "key", "cert");
        let der = handshake_leaf_der(&cert);

        const N: u32 = 1000;

        let start = Instant::now();
        for _ in 0..N {
            let _ = parse_cert(&der).unwrap();
        }
        let cert_dur = start.elapsed();

        let start = Instant::now();
        for _ in 0..N {
            let _ = parse_leaf(&der).unwrap();
        }
        let leaf_dur = start.elapsed();

        eprintln!(
            "\n--- s2n-codec cert parse ({N} iterations) ---\n\
             parse_cert: {:?} ({:?}/cert)\n\
             parse_leaf: {:?} ({:?}/cert)",
            cert_dur,
            cert_dur / N,
            leaf_dur,
            leaf_dur / N,
        );
    }
}
