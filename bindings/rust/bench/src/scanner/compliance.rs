use crate::scanner::params::{Hash, Sig, SignatureScheme};

use super::{
    params::{Cipher, KxGroup, LegacyCipher, Protocol, Signature, Tls13Cipher},
    Certificate, Report,
};

pub trait ComplianceRegime {
    /// The name of the compliance regime
    fn regime() -> &'static str;

    /// A list of the TLS protocol versions allowed by the compliance regime
    fn protocols() -> Vec<Protocol>;

    /// A list of the allowed Ciphers for the compliance regime
    fn ciphers() -> Vec<Cipher>;

    /// A list of the allowed key exchange groups for the compliance regime
    fn groups() -> Vec<KxGroup>;

    /// a list of the allowed transcript signatures for the compliance regime
    fn signatures() -> Vec<Signature>;

    /// a function used to validate that a certificate complies with the expected
    /// compliance regime. For example, this might ensure that ensure that the RSA
    /// modulus is greater than 3072 bits, or check that the certificate signature
    /// is SHA384 or SHA512. This method should return a descriptive error message,
    /// something like "The certificate is invalid because RFC9151 doesn't allow for
    /// RSA key sizes smaller than 3072 bits".
    fn validate_certificate(_cert: &Certificate) -> Result<(), String> {
        Ok(())
    }

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

        for chain in &report.cert_chain {
            for cert in chain {
                if let Err(error_message) = Self::validate_certificate(cert) {
                    errors.push(format!(
                        "ERROR: {} violation - {}",
                        Self::regime(),
                        error_message
                    ))
                }
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

pub struct RFC9151;

impl ComplianceRegime for RFC9151 {
    fn regime() -> &'static str {
        "rfc9151"
    }

    fn protocols() -> Vec<Protocol> {
        vec![Protocol::TLS_1_3, Protocol::TLS_1_2]
    }

    fn ciphers() -> Vec<Cipher> {
        vec![
            Cipher::Tls13(Tls13Cipher::TLS_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
        ]
    }

    fn groups() -> Vec<KxGroup> {
        vec![KxGroup::ffdhe3072, KxGroup::ffdhe4096, KxGroup::P_384]
    }

    fn signatures() -> Vec<Signature> {
        vec![
            Signature::SignatureScheme(SignatureScheme::ecdsa_secp384r1_sha384),
            Signature::SignatureScheme(SignatureScheme::rsa_pkcs1_sha384),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha384),
            Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha384),
            Signature::SigHash(Sig::ECDSA, Hash::SHA384),
            Signature::SigHash(Sig::RSA, Hash::SHA384),
            Signature::SigHash(Sig::RSA_PSS, Hash::SHA384),
        ]
    }
}
