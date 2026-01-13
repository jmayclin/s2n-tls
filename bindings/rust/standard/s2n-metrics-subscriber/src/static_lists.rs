//! This module contains the static lists of all possible values emitted by the
//! s2n-tls "getter" APIs. These static lists are important because they allow us
//! to maintain an array of atomic counters instead of having to resort to a hashmap

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{LazyLock, Mutex},
};

#[cfg(test)]
use s2n_tls_sys_internal::s2n_cipher_suite;

pub trait ToStaticString {
    fn to_static_string(&self) -> &'static str;
}

impl ToStaticString for s2n_tls::enums::Version {
    fn to_static_string(&self) -> &'static str {
        match self {
            s2n_tls::enums::Version::SSLV3 => "SSLv3",
            s2n_tls::enums::Version::TLS10 => "TLSv1_0",
            s2n_tls::enums::Version::TLS11 => "TLSv1_1",
            s2n_tls::enums::Version::TLS12 => "TLSv1_2",
            s2n_tls::enums::Version::TLS13 => "TLSv1_3",
            _ => "unknown",
        }
    }
}

pub const VERSIONS_AVAILABLE_IN_S2N: &[&'static str] =
    &["SSLv3", "TLSv1_0", "TLSv1_1", "TLSv1_2", "TLSv1_3"];

/// Convert a pointer to null terminated bytes into a static string
///
/// Safety: the memory pointed to by value is static
/// Safety: the bytes are null terminated
#[cfg(test)]
unsafe fn static_memory_to_str(value: *const u8) -> &'static str {
    use std::ffi::CStr;
    CStr::from_ptr(value).to_str().unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Cipher {
    openssl_name: &'static str,
    iana_description: &'static str,
    iana_value: [u8; 2],
}

impl Cipher {
    const fn new(
        iana_value: [u8; 2],
        iana_description: &'static str,
        openssl_name: &'static str,
    ) -> Self {
        Self {
            openssl_name,
            iana_description,
            iana_value,
        }
    }

    #[cfg(test)]
    fn from_s2n_cipher_suite(s2n_cipher: &s2n_cipher_suite) -> Self {
        unsafe {
            // SAFETY: the name and iana_name fields are both static, null-terminated
            // strings
            let openssl_name = static_memory_to_str(s2n_cipher.name);
            let iana_description = static_memory_to_str(s2n_cipher.iana_name);
            let iana_value = s2n_cipher.iana_value;
            Self::new(iana_value, iana_description, openssl_name)
        }
    }
}

struct Group {
    iana_description: &'static str,
    iana_value: u16,
}

/// We are required to track OpenSSL naming because that is what 
#[rustfmt::skip]
pub const CIPHERS_AVAILABLE_IN_S2N: &[Cipher] = &[
    Cipher::new([0, 156], "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256", ),
    Cipher::new([0, 47], "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA", ),
    Cipher::new([0, 60], "TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256", ),
    Cipher::new([0, 157], "TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384", ),
    Cipher::new([0, 53], "TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA", ),
    Cipher::new([0, 61], "TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256", ),
    Cipher::new([0, 10], "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA", ),
    Cipher::new([0, 158], "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256", ),
    Cipher::new([0, 51], "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA", ),
    Cipher::new([0, 103], "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256", ),
    Cipher::new([0, 159], "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384", ),
    Cipher::new([0, 57], "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA", ),
    Cipher::new([0, 107], "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256", ),
    Cipher::new([204, 170], "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE-RSA-CHACHA20-POLY1305", ),
    Cipher::new([0, 22], "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE-RSA-DES-CBC3-SHA", ),
    Cipher::new([192, 43], "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", ),
    Cipher::new([192, 9], "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE-ECDSA-AES128-SHA", ),
    Cipher::new([192, 35], "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256", ),
    Cipher::new([192, 44], "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384", ),
    Cipher::new([192, 10], "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE-ECDSA-AES256-SHA", ),
    Cipher::new([192, 36], "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384", ),
    Cipher::new([204, 169], "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", ),
    Cipher::new([192, 47], "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", ),
    Cipher::new([192, 19], "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA", ),
    Cipher::new([192, 39], "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256", ),
    Cipher::new([192, 48], "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384", ),
    Cipher::new([192, 20], "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE-RSA-AES256-SHA", ),
    Cipher::new([192, 40], "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384", ),
    Cipher::new([204, 168], "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-CHACHA20-POLY1305", ),
    Cipher::new([192, 18], "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA", ),
    Cipher::new([192, 17], "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE-RSA-RC4-SHA", ),
    Cipher::new([0, 4], "TLS_RSA_WITH_RC4_128_MD5", "RC4-MD5", ),
    Cipher::new([0, 5], "TLS_RSA_WITH_RC4_128_SHA", "RC4-SHA", ),
    Cipher::new([19, 1], "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", ),
    Cipher::new([19, 2], "TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384", ),
    Cipher::new([19, 3], "TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256", ),
];

pub const GROUPS_AVAILABLE_IN_S2N: &[&'static str] = &[
    "MLKEM1024",
    "SecP256r1Kyber768Draft00",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "X25519Kyber768Draft00",
    "X25519MLKEM768",
    "secp256r1",
    "secp256r1_kyber-512-r3",
    "secp384r1",
    "secp384r1_kyber-768-r3",
    "secp521r1",
    "secp521r1_kyber-1024-r3",
    "x25519",
    "x25519_kyber-512-r3",
];



#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        ffi::{c_char, c_int, c_void, CStr},
        sync::LazyLock,
    };

    /// return all of the ciphers defined in any s2n-tls security policy
    fn all_available_ciphers() -> Vec<Cipher> {
        let ciphers: HashSet<Cipher> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let names: Vec<Cipher> = sp
                    .ciphers()
                    .iter()
                    .cloned()
                    .map(Cipher::from_s2n_cipher_suite)
                    .collect();
                names
            })
            .flatten()
            .collect();
        let mut ciphers: Vec<Cipher> = ciphers.into_iter().collect();
        ciphers.sort_by_key(|cipher| cipher.iana_description);
        ciphers
    }

    /// return all of the groups defined in any s2n-tls security policy
    fn all_available_groups() -> Vec<&'static str> {
        let groups: HashSet<&'static str> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let kem_names = sp.kems().iter().map(|kem| unsafe {
                    // SAFETY: kem names are stored as C string literals, which
                    // are both static and null terminated.
                    static_memory_to_str(kem.name)
                });
                let curve_names = sp.curves().iter().map(|curve| unsafe {
                    // SAFETY: curve names are stored as C string literals, which
                    // are both static and null terminated.
                    static_memory_to_str(curve.name)
                });
                kem_names.chain(curve_names).collect::<Vec<&'static str>>()
            })
            .flatten()
            .collect();
        let mut groups: Vec<&'static str> = groups.into_iter().collect();
        groups.sort();
        groups
    }

    #[test]
    fn all_ciphers_in_static_list() {
        let ciphers = all_available_ciphers();
        assert_eq!(&ciphers, CIPHERS_AVAILABLE_IN_S2N);
    }

    #[test]
    fn all_groups_in_static_list() {
        let groups = all_available_groups();
        assert_eq!(&groups, GROUPS_AVAILABLE_IN_S2N);
    }
}
