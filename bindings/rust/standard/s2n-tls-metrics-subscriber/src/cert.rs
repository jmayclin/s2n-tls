use s2n_tls::cert_chain::CertificateChain;
use std::fmt;

/// Key type and signature algorithm for any certificate.
struct CertInfo {
    // e.g. RSA2048, secp384r1
    key: String,
    // e.g. RSA_PKCS+SHA256, ECDSA+SHA384
    signature: String,
}

/// Full information for a leaf certificate, including identity fields.
struct LeafCertInfo {
    serial: Vec<u8>,
    issuer: Vec<u8>,
    common_name: Vec<u8>,
    cert: CertInfo,
}

/// Errors that can occur during certificate parsing.
#[derive(Debug)]
enum CertParseError {
    S2n(s2n_tls::error::Error),
    X509Parser(String),
    X509Cert(String),
    OpenSsl(openssl::error::ErrorStack),
    WebPki(webpki::Error),
}

impl fmt::Display for CertParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertParseError::S2n(e) => write!(f, "s2n-tls: {e}"),
            CertParseError::X509Parser(e) => write!(f, "x509-parser: {e}"),
            CertParseError::X509Cert(e) => write!(f, "x509-cert: {e}"),
            CertParseError::OpenSsl(e) => write!(f, "openssl: {e}"),
            CertParseError::WebPki(e) => write!(f, "webpki: {e}"),
        }
    }
}

impl From<s2n_tls::error::Error> for CertParseError {
    fn from(e: s2n_tls::error::Error) -> Self {
        CertParseError::S2n(e)
    }
}

impl From<openssl::error::ErrorStack> for CertParseError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        CertParseError::OpenSsl(e)
    }
}

impl From<webpki::Error> for CertParseError {
    fn from(e: webpki::Error) -> Self {
        CertParseError::WebPki(e)
    }
}

trait CertParser {
    /// Parse only key type and signature algorithm from a single DER cert.
    fn parse_cert(der: &[u8]) -> Result<CertInfo, CertParseError>;

    /// Parse full leaf information (serial, issuer, CN, key, sig) from a single DER cert.
    fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, CertParseError>;
}

fn oid_to_key_description(oid: &str, key_bits: usize) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => format!("RSA{key_bits}"),
        "1.2.840.10045.2.1" => format!("EC{key_bits}"),
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        _ => format!("{oid}/{key_bits}"),
    }
}

fn oid_to_sig_description(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "RSA_PKCS+SHA1".to_string(),
        "1.2.840.113549.1.1.11" => "RSA_PKCS+SHA256".to_string(),
        "1.2.840.113549.1.1.12" => "RSA_PKCS+SHA384".to_string(),
        "1.2.840.113549.1.1.13" => "RSA_PKCS+SHA512".to_string(),
        "1.2.840.113549.1.1.10" => "RSA_PSS".to_string(),
        "1.2.840.10045.4.3.2" => "ECDSA+SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ECDSA+SHA384".to_string(),
        "1.2.840.10045.4.3.4" => "ECDSA+SHA512".to_string(),
        _ => oid.to_string(),
    }
}

// ---------------------------------------------------------------------------
// x509-parser
// ---------------------------------------------------------------------------
struct X509ParserImpl;

impl X509ParserImpl {
    fn parse(der: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>, CertParseError> {
        use x509_parser::prelude::*;
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| CertParseError::X509Parser(e.to_string()))?;
        Ok(cert)
    }
}

impl CertParser for X509ParserImpl {
    fn parse_cert(der: &[u8]) -> Result<CertInfo, CertParseError> {
        let cert = Self::parse(der)?;
        let pk = cert.public_key();
        Ok(CertInfo {
            key: oid_to_key_description(&pk.algorithm.algorithm.to_string(), pk.subject_public_key.data.len() * 8),
            signature: oid_to_sig_description(&cert.signature_algorithm.algorithm.to_string()),
        })
    }

    fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, CertParseError> {
        let cert = Self::parse(der)?;
        let pk = cert.public_key();
        Ok(LeafCertInfo {
            serial: cert.raw_serial().to_vec(),
            issuer: cert.issuer().to_string().into_bytes(),
            common_name: cert.subject().iter_common_name().next()
                .and_then(|attr| attr.as_str().ok())
                .unwrap_or("").as_bytes().to_vec(),
            cert: CertInfo {
                key: oid_to_key_description(&pk.algorithm.algorithm.to_string(), pk.subject_public_key.data.len() * 8),
                signature: oid_to_sig_description(&cert.signature_algorithm.algorithm.to_string()),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// x509-cert
// ---------------------------------------------------------------------------
struct X509CertImpl;

impl CertParser for X509CertImpl {
    fn parse_cert(der: &[u8]) -> Result<CertInfo, CertParseError> {
        use der::Decode;
        use x509_cert::Certificate;
        let cert = Certificate::from_der(der).map_err(|e| CertParseError::X509Cert(e.to_string()))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        Ok(CertInfo {
            key: oid_to_key_description(&spki.algorithm.oid.to_string(), spki.subject_public_key.raw_bytes().len() * 8),
            signature: oid_to_sig_description(&cert.signature_algorithm.oid.to_string()),
        })
    }

    fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, CertParseError> {
        use der::Decode;
        use x509_cert::Certificate;
        let cert = Certificate::from_der(der).map_err(|e| CertParseError::X509Cert(e.to_string()))?;
        let tbs = &cert.tbs_certificate;
        let spki = &tbs.subject_public_key_info;
        Ok(LeafCertInfo {
            serial: tbs.serial_number.as_bytes().to_vec(),
            issuer: tbs.issuer.to_string().into_bytes(),
            common_name: tbs.subject.to_string()
                .split(',').find(|s| s.starts_with("CN="))
                .and_then(|s| s.strip_prefix("CN="))
                .unwrap_or("").to_string().into_bytes(),
            cert: CertInfo {
                key: oid_to_key_description(&spki.algorithm.oid.to_string(), spki.subject_public_key.raw_bytes().len() * 8),
                signature: oid_to_sig_description(&cert.signature_algorithm.oid.to_string()),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// openssl
// ---------------------------------------------------------------------------
struct OpenSslImpl;

impl OpenSslImpl {
    fn cert_info(cert: &openssl::x509::X509) -> Result<CertInfo, CertParseError> {
        let pkey = cert.public_key()?;
        let key_oid = match pkey.id() {
            openssl::pkey::Id::RSA => "1.2.840.113549.1.1.1",
            openssl::pkey::Id::EC => "1.2.840.10045.2.1",
            openssl::pkey::Id::ED25519 => "1.3.101.112",
            _ => "unknown",
        };
        let sig_desc = match cert.signature_algorithm().object().nid().long_name().unwrap_or("unknown") {
            "sha1WithRSAEncryption" => "RSA_PKCS+SHA1",
            "sha256WithRSAEncryption" => "RSA_PKCS+SHA256",
            "sha384WithRSAEncryption" => "RSA_PKCS+SHA384",
            "sha512WithRSAEncryption" => "RSA_PKCS+SHA512",
            "rsassaPss" => "RSA_PSS",
            "ecdsa-with-SHA256" => "ECDSA+SHA256",
            "ecdsa-with-SHA384" => "ECDSA+SHA384",
            "ecdsa-with-SHA512" => "ECDSA+SHA512",
            other => other,
        }.to_string();
        Ok(CertInfo {
            key: oid_to_key_description(key_oid, pkey.bits() as usize),
            signature: sig_desc,
        })
    }
}

impl CertParser for OpenSslImpl {
    fn parse_cert(der: &[u8]) -> Result<CertInfo, CertParseError> {
        let cert = openssl::x509::X509::from_der(der)?;
        Self::cert_info(&cert)
    }

    fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, CertParseError> {
        use openssl::nid::Nid;
        let cert = openssl::x509::X509::from_der(der)?;
        Ok(LeafCertInfo {
            serial: cert.serial_number().to_bn()?.to_vec(),
            issuer: cert.issuer_name().entries()
                .map(|e| format!("{}={}", e.object().nid().short_name().unwrap_or("?"),
                    e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default()))
                .collect::<Vec<_>>().join(",").into_bytes(),
            common_name: cert.subject_name().entries_by_nid(Nid::COMMONNAME).next()
                .map(|e| e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default())
                .unwrap_or_default().into_bytes(),
            cert: Self::cert_info(&cert)?,
        })
    }
}

// ---------------------------------------------------------------------------
// manual DER (zero-dependency, zero-alloc parsing)
// ---------------------------------------------------------------------------
struct ManualDerImpl;

fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let &tag = input.first()?;
    let (len, offset) = match *input.get(1)? {
        n if n < 0x80 => (n as usize, 2),
        n => {
            let num = (n & 0x7f) as usize;
            let mut len = 0usize;
            for &b in input.get(2..2 + num)? {
                len = (len << 8) | b as usize;
            }
            (len, 2 + num)
        }
    };
    Some((tag, input.get(offset..offset + len)?, input.get(offset + len..)?))
}

fn skip_tlv(input: &[u8]) -> Option<&[u8]> {
    read_tlv(input).map(|(_, _, rest)| rest)
}

fn decode_oid(bytes: &[u8]) -> String {
    let mut parts = Vec::new();
    let first = *bytes.first().unwrap_or(&0);
    parts.push((first / 40) as u32);
    parts.push((first % 40) as u32);
    let mut acc = 0u32;
    for &b in &bytes[1..] {
        acc = (acc << 7) | (b & 0x7f) as u32;
        if b & 0x80 == 0 {
            parts.push(acc);
            acc = 0;
        }
    }
    parts.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")
}

/// Walk a DER cert to the key fields. Returns (serial, issuer, subject, key_desc, sig_desc).
fn parse_der_cert(der: &[u8]) -> Option<(&[u8], &[u8], &[u8], String, String)> {
    let (_, cert_content, _) = read_tlv(der)?;
    let (_, tbs, _) = read_tlv(cert_content)?;
    let mut pos = tbs;

    // [0] EXPLICIT version (optional)
    if pos.first() == Some(&0xa0) { pos = skip_tlv(pos)?; }

    let (_, serial, rest) = read_tlv(pos)?; pos = rest;

    let (_, sig_alg_seq, rest) = read_tlv(pos)?;
    let (_, sig_oid_bytes, _) = read_tlv(sig_alg_seq)?;
    let sig_desc = oid_to_sig_description(&decode_oid(sig_oid_bytes));
    pos = rest;

    let (_, issuer, rest) = read_tlv(pos)?; pos = rest;
    pos = skip_tlv(pos)?; // validity
    let (_, subject, rest) = read_tlv(pos)?; pos = rest;

    let (_, spki, _) = read_tlv(pos)?;
    let (_, key_alg_seq, spki_rest) = read_tlv(spki)?;
    let (_, key_oid_bytes, _) = read_tlv(key_alg_seq)?;
    let (_, key_bits_raw, _) = read_tlv(spki_rest)?;
    let key_bits = (key_bits_raw.len().saturating_sub(1)) * 8;
    let key_desc = oid_to_key_description(&decode_oid(key_oid_bytes), key_bits);

    Some((serial, issuer, subject, key_desc, sig_desc))
}

impl CertParser for ManualDerImpl {
    fn parse_cert(der: &[u8]) -> Result<CertInfo, CertParseError> {
        let (_, _, _, key, signature) =
            parse_der_cert(der).ok_or_else(|| CertParseError::X509Parser("bad DER".into()))?;
        Ok(CertInfo { key, signature })
    }

    fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, CertParseError> {
        let (serial, issuer, subject, key, signature) =
            parse_der_cert(der).ok_or_else(|| CertParseError::X509Parser("bad DER".into()))?;
        Ok(LeafCertInfo {
            serial: serial.to_vec(),
            issuer: issuer.to_vec(),
            common_name: subject.to_vec(),
            cert: CertInfo { key, signature },
        })
    }
}

// ---------------------------------------------------------------------------
// s2n-codec DER parser
// ---------------------------------------------------------------------------
struct S2nCodecImpl;

mod der_codec {
    use core::mem::size_of;
    use s2n_codec::{DecoderBuffer, DecoderBufferResult, DecoderValue};

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
            let short_form_encoding = first < 0x80;
            if short_form_encoding {
                Ok((DerLength(first as usize), buffer))
            } else {
                let num_length_bytes = (first & 0x7f) as usize;
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
            Ok((Tlv { tag, content: content.into_less_safe_slice() }, buffer))
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
                acc = acc.checked_shl(7)
                    .and_then(|a| a.checked_add((byte & 0x7f) as u32))
                    .ok_or(s2n_codec::decoder::DecoderError::LengthCapacityExceeded)?;
                buffer = rest;
                let continuation = byte & 0x80 != 0;
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

        Ok(parts.iter().map(|n| n.to_string()).collect::<Vec<_>>().join("."))
    }

    /// Parsed cert fields needed for CertInfo/LeafCertInfo.
    pub struct ParsedCert<'a> {
        pub serial: &'a [u8],
        pub issuer: &'a [u8],
        pub subject: &'a [u8],
        pub key_oid: String,
        pub key_bits: usize,
        pub sig_oid: String,
    }

    impl<'a> DecoderValue<'a> for ParsedCert<'a> {
        fn decode(buffer: DecoderBuffer<'a>) -> DecoderBufferResult<'a, Self> {
            // Certificate ::= SEQUENCE { tbs, sigAlg, sig }
            let (cert_seq, buffer) = buffer.decode::<Tlv<'a>>()?;

            // TBSCertificate ::= SEQUENCE { ... }
            let (tbs_tlv, _) = DecoderBuffer::new(cert_seq.content).decode::<Tlv<'a>>()?;
            let mut buffer = DecoderBuffer::new(tbs_tlv.content);

            // [0] EXPLICIT version (optional, tag 0xa0)
            if buffer.peek_byte(0)? == 0xa0 {
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
            let (key_alg_tlv, buffer) = DecoderBuffer::new(spki_tlv.content).decode::<Tlv<'a>>()?;
            let (key_oid_tlv, _) = DecoderBuffer::new(key_alg_tlv.content).decode::<Tlv<'a>>()?;
            let (key_bits_tlv, _) = buffer.decode::<Tlv<'a>>()?;
            // BIT STRING has a leading "unused bits" byte
            let key_bits = (key_bits_tlv.content.len().saturating_sub(1)) * 8;

            Ok((ParsedCert {
                serial: serial_tlv.content,
                issuer: issuer_tlv.content,
                subject: subject_tlv.content,
                key_oid: decode_oid(key_oid_tlv.content)?,
                key_bits,
                sig_oid,
            }, DecoderBuffer::new(&[])))
        }
    }
}

impl CertParser for S2nCodecImpl {
    fn parse_cert(der: &[u8]) -> Result<CertInfo, CertParseError> {
        use s2n_codec::DecoderBuffer;
        let buf = DecoderBuffer::new(der);
        let (parsed, _) = buf.decode::<der_codec::ParsedCert<'_>>()
            .map_err(|e| CertParseError::X509Parser(format!("s2n-codec: {e}")))?;
        Ok(CertInfo {
            key: oid_to_key_description(&parsed.key_oid, parsed.key_bits),
            signature: oid_to_sig_description(&parsed.sig_oid),
        })
    }

    fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, CertParseError> {
        use s2n_codec::DecoderBuffer;
        let buf = DecoderBuffer::new(der);
        let (parsed, _) = buf.decode::<der_codec::ParsedCert<'_>>()
            .map_err(|e| CertParseError::X509Parser(format!("s2n-codec: {e}")))?;
        Ok(LeafCertInfo {
            serial: parsed.serial.to_vec(),
            issuer: parsed.issuer.to_vec(),
            common_name: parsed.subject.to_vec(),
            cert: CertInfo {
                key: oid_to_key_description(&parsed.key_oid, parsed.key_bits),
                signature: oid_to_sig_description(&parsed.sig_oid),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// rustls-webpki
// ---------------------------------------------------------------------------
struct WebPkiImpl;

impl CertParser for WebPkiImpl {
    fn parse_cert(der: &[u8]) -> Result<CertInfo, CertParseError> {
        use rustls_pki_types::CertificateDer;
        let cert_der = CertificateDer::from(der);
        let _cert = webpki::EndEntityCert::try_from(&cert_der)?;
        // webpki doesn't decode key/sig algorithm
        Ok(CertInfo { key: "unknown".to_string(), signature: "unknown".to_string() })
    }

    fn parse_leaf(der: &[u8]) -> Result<LeafCertInfo, CertParseError> {
        use rustls_pki_types::CertificateDer;
        let cert_der = CertificateDer::from(der);
        let cert = webpki::EndEntityCert::try_from(&cert_der)?;
        Ok(LeafCertInfo {
            serial: cert.serial().to_vec(),
            issuer: cert.issuer().to_vec(),
            common_name: cert.subject().to_vec(),
            cert: CertInfo { key: "unknown".to_string(), signature: "unknown".to_string() },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_tls::{
        security::DEFAULT_TLS13,
        testing::{config_builder, TestPair},
    };

    fn leaf_der(pair: &TestPair) -> Vec<u8> {
        let chain = pair.server.selected_cert().unwrap();
        chain.iter().next().unwrap().unwrap().der().unwrap().to_vec()
    }

    fn assert_leaf(info: &LeafCertInfo, expected_cn: &[u8], expected_key: &str, expected_sig: &str) {
        assert!(
            info.serial.ends_with(&[0xda, 0x54, 0x50, 0xbd, 0xeb, 0x60, 0xcb, 0x7d]),
            "unexpected serial: {:02x?}", info.serial,
        );
        assert!(!info.issuer.is_empty());
        assert_eq!(info.common_name, expected_cn);
        assert_eq!(info.cert.key, expected_key);
        assert_eq!(info.cert.signature, expected_sig);
    }

    fn assert_cert(info: &CertInfo, expected_key: &str, expected_sig: &str) {
        assert_eq!(info.key, expected_key);
        assert_eq!(info.signature, expected_sig);
    }

    #[test]
    fn x509_parser_parse_leaf() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);
        assert_leaf(&X509ParserImpl::parse_leaf(&der).unwrap(), b"localhost", "RSA4208", "RSA_PKCS+SHA512");
    }

    #[test]
    fn x509_parser_parse_cert() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);
        assert_cert(&X509ParserImpl::parse_cert(&der).unwrap(), "RSA4208", "RSA_PKCS+SHA512");
    }

    #[test]
    fn x509_cert_parse_leaf() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);
        assert_leaf(&X509CertImpl::parse_leaf(&der).unwrap(), b"localhost", "RSA4208", "RSA_PKCS+SHA512");
    }

    #[test]
    fn openssl_parse_leaf() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);
        assert_leaf(&OpenSslImpl::parse_leaf(&der).unwrap(), b"localhost", "RSA4096", "RSA_PKCS+SHA512");
    }

    #[test]
    fn manual_der_parse_leaf() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);
        let info = ManualDerImpl::parse_leaf(&der).unwrap();
        assert!(info.serial.ends_with(&[0xda, 0x54, 0x50, 0xbd, 0xeb, 0x60, 0xcb, 0x7d]));
        assert_eq!(info.cert.key, "RSA4208");
        assert_eq!(info.cert.signature, "RSA_PKCS+SHA512");
    }

    #[test]
    fn s2n_codec_parse_leaf() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);
        let info = S2nCodecImpl::parse_leaf(&der).unwrap();
        assert!(info.serial.ends_with(&[0xda, 0x54, 0x50, 0xbd, 0xeb, 0x60, 0xcb, 0x7d]));
        assert_eq!(info.cert.key, "RSA4208");
        assert_eq!(info.cert.signature, "RSA_PKCS+SHA512");
    }

    #[test]
    fn webpki_parse_leaf() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);
        let info = WebPkiImpl::parse_leaf(&der).unwrap();
        assert!(!info.serial.is_empty());
        assert!(!info.issuer.is_empty());
    }

    #[test]
    fn all_parsers_agree_on_sig() {
        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);

        let a = X509ParserImpl::parse_cert(&der).unwrap();
        let b = X509CertImpl::parse_cert(&der).unwrap();
        let c = OpenSslImpl::parse_cert(&der).unwrap();
        let d = ManualDerImpl::parse_cert(&der).unwrap();

        assert_eq!(a.signature, b.signature);
        assert_eq!(b.signature, c.signature);
        assert_eq!(c.signature, d.signature);
    }

    #[test]
    fn benchmark_parse_cert() {
        use std::time::Instant;

        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);

        const N: u32 = 1000;

        let start = Instant::now();
        for _ in 0..N { let _ = ManualDerImpl::parse_cert(&der).unwrap(); }
        let manual = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = S2nCodecImpl::parse_cert(&der).unwrap(); }
        let s2n_codec = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = WebPkiImpl::parse_cert(&der).unwrap(); }
        let webpki = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = X509ParserImpl::parse_cert(&der).unwrap(); }
        let x509_parser = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = OpenSslImpl::parse_cert(&der).unwrap(); }
        let openssl = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = X509CertImpl::parse_cert(&der).unwrap(); }
        let x509_cert = start.elapsed();

        eprintln!(
            "\n--- parse_cert benchmark ({N} iterations) ---\n\
             manual-der:  {:?} ({:?}/cert)\n\
             s2n-codec:   {:?} ({:?}/cert)\n\
             webpki:      {:?} ({:?}/cert)\n\
             x509-parser: {:?} ({:?}/cert)\n\
             openssl:     {:?} ({:?}/cert)\n\
             x509-cert:   {:?} ({:?}/cert)",
            manual, manual / N, s2n_codec, s2n_codec / N,
            webpki, webpki / N, x509_parser, x509_parser / N,
            openssl, openssl / N, x509_cert, x509_cert / N,
        );
    }

    #[test]
    fn benchmark_parse_leaf() {
        use std::time::Instant;

        let config = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();
        let der = leaf_der(&pair);

        const N: u32 = 1000;

        let start = Instant::now();
        for _ in 0..N { let _ = ManualDerImpl::parse_leaf(&der).unwrap(); }
        let manual = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = S2nCodecImpl::parse_leaf(&der).unwrap(); }
        let s2n_codec = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = WebPkiImpl::parse_leaf(&der).unwrap(); }
        let webpki = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = X509ParserImpl::parse_leaf(&der).unwrap(); }
        let x509_parser = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = OpenSslImpl::parse_leaf(&der).unwrap(); }
        let openssl = start.elapsed();

        let start = Instant::now();
        for _ in 0..N { let _ = X509CertImpl::parse_leaf(&der).unwrap(); }
        let x509_cert = start.elapsed();

        eprintln!(
            "\n--- parse_leaf benchmark ({N} iterations) ---\n\
             manual-der:  {:?} ({:?}/cert)\n\
             s2n-codec:   {:?} ({:?}/cert)\n\
             webpki:      {:?} ({:?}/cert)\n\
             x509-parser: {:?} ({:?}/cert)\n\
             openssl:     {:?} ({:?}/cert)\n\
             x509-cert:   {:?} ({:?}/cert)",
            manual, manual / N, s2n_codec, s2n_codec / N,
            webpki, webpki / N, x509_parser, x509_parser / N,
            openssl, openssl / N, x509_cert, x509_cert / N,
        );
    }
}
