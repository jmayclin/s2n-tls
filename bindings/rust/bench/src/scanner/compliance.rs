use crate::scanner::params::{Hash, Sig, SignatureScheme};

use super::{
    params::{Cipher, KxGroup, LegacyCipher, Protocol, Signature, Tls13Cipher},
    Report,
};

pub trait ComplianceRegime {
    fn regime() -> &'static str;

    fn protocols() -> Vec<Protocol>;
    fn ciphers() -> Vec<Cipher>;
    fn groups() -> Vec<KxGroup>;
    fn signatures() -> Vec<Signature>;

    fn compliance(report: &Report) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for p in &report.protocols {
            if !Self::protocols().contains(p) {
                errors.push(format!(
                    "ERROR: {} violation - supports unallowed protocol: {:?}",
                    Self::regime(),
                    p,
                ))
            }
        }

        for g in &report.groups {
            if !Self::groups().contains(g) {
                errors.push(format!(
                    "ERROR: {} violation - supports unallowed group: {:?}",
                    Self::regime(),
                    g,
                ))
            }
        }

        for c in &report.ciphers {
            if !Self::ciphers().contains(c) {
                errors.push(format!(
                    "ERROR: {} violation - supports unallowed cipher: {:?}",
                    Self::regime(),
                    c
                ));
            }
        }

        for s in &report.signatures {
            if !Self::signatures().contains(s) {
                errors.push(format!(
                    "ERROR: {} violation - supports unallowed signature: {:?}",
                    Self::regime(),
                    s
                ))
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub struct CryptoRecommendation20231130;

impl CryptoRecommendation20231130 {}

impl ComplianceRegime for CryptoRecommendation20231130 {
    fn regime() -> &'static str {
        "CryptoRecommendation 2023-11-30"
    }

    fn protocols() -> Vec<Protocol> {
        vec![Protocol::TLS_1_2, Protocol::TLS_1_3]
    }

    fn ciphers() -> Vec<Cipher> {
        vec![
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_256_CBC_SHA),
            Cipher::Tls13(Tls13Cipher::TLS_AES_128_GCM_SHA256),
            Cipher::Tls13(Tls13Cipher::TLS_AES_256_GCM_SHA384),
        ]
    }

    fn groups() -> Vec<KxGroup> {
        vec![
            KxGroup::P_256,
            KxGroup::P_384,
            KxGroup::P_521,
            KxGroup::X25519,
            KxGroup::X448,
        ]
    }

    fn signatures() -> Vec<Signature> {
        vec![
            Signature::SignatureScheme(SignatureScheme::ecdsa_secp256r1_sha256),
            Signature::SignatureScheme(SignatureScheme::ecdsa_secp384r1_sha384),
            Signature::SignatureScheme(SignatureScheme::ecdsa_secp521r1_sha512),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha256),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha384),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha512),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha256),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha384),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha512),
            Signature::SigHash(Sig::RSA, Hash::SHA1),
            Signature::SigHash(Sig::RSA, Hash::SHA256),
            Signature::SigHash(Sig::RSA, Hash::SHA384),
            Signature::SigHash(Sig::RSA, Hash::SHA512),
            Signature::SigHash(Sig::RSA_PSS, Hash::SHA256),
            Signature::SigHash(Sig::RSA_PSS, Hash::SHA384),
            Signature::SigHash(Sig::RSA_PSS, Hash::SHA512),
            Signature::SigHash(Sig::ECDSA, Hash::SHA256),
            Signature::SigHash(Sig::ECDSA, Hash::SHA384),
            Signature::SigHash(Sig::ECDSA, Hash::SHA512),
        ]
    }
}
