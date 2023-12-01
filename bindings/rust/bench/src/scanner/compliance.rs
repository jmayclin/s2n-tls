use super::{
    params::{Cipher, KxGroup, LegacyCipher, Protocol, Tls13Cipher},
    Report,
};

pub trait ComplianceRegime {
    fn regime() -> &'static str;
    fn compliance(report: &Report) -> Result<(), Vec<String>>;
}

pub struct CryptoRecommendation20231130;

impl CryptoRecommendation20231130 {
    pub const ALLOWED_PROTOCOLS: [Protocol; 2] = [Protocol::TLS_1_2, Protocol::TLS_1_3];

    pub const ALLOWED_GROUPS: [KxGroup; 5] = [
        KxGroup::P_256,
        KxGroup::P_384,
        KxGroup::P_521,
        KxGroup::X25519,
        KxGroup::X448,
    ];

    pub const ALLOWED_CIPHERS: [Cipher; 19] = [
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
    ];
}

impl ComplianceRegime for CryptoRecommendation20231130 {
    fn regime() -> &'static str {
        "CryptoRecommendation 2023-11-30"
    }

    fn compliance(report: &Report) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for p in &report.protocols {
            if !Self::ALLOWED_PROTOCOLS.contains(p) {
                errors.push(format!(
                    "ERROR: {} violation - supports unallowed protocol: {:?}",
                    Self::regime(),
                    p,
                ))
            }
        }

        for g in &report.groups {
            if !Self::ALLOWED_GROUPS.contains(g) {
                errors.push(format!(
                    "ERROR: {} violation - supports unallowed groups: {:?}",
                    Self::regime(),
                    g,
                ))
            }
        }

        for c in &report.ciphers {
            if !Self::ALLOWED_CIPHERS.contains(c) {
                errors.push(format!(
                    "ERROR: {} violation - supports unallowed cipher: {:?}",
                    Self::regime(),
                    c
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
