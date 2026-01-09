//! This module contains the static lists of all possible values emitted by the
//! s2n-tls "getter" APIs. These static lists are important because they allow us
//! to maintain an array of atomic counters instead of having to resort to a hashmap

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{LazyLock, Mutex},
};

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

/// we use the nasty openssl naming, bc that's what s2n-tls currently returns from it's
/// APIs
#[rustfmt::skip]
pub const CIPHERS_AVAILABLE_IN_S2N: &[(&'static str, [u8; 2], &'static str)] = &[
    ("AES128-GCM-SHA256", [0, 156], "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    ("AES128-SHA", [0, 47], "TLS_RSA_WITH_AES_128_CBC_SHA"),
    ("AES128-SHA256", [0, 60], "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    ("AES256-GCM-SHA384", [0, 157], "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    ("AES256-SHA", [0, 53], "TLS_RSA_WITH_AES_256_CBC_SHA"),
    ("AES256-SHA256", [0, 61], "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    ("DES-CBC3-SHA", [0, 10], "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    ("DHE-RSA-AES128-GCM-SHA256", [0, 158], "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    ("DHE-RSA-AES128-SHA", [0, 51], "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    ("DHE-RSA-AES128-SHA256", [0, 103], "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    ("DHE-RSA-AES256-GCM-SHA384", [0, 159], "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    ("DHE-RSA-AES256-SHA", [0, 57], "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    ("DHE-RSA-AES256-SHA256", [0, 107], "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
    ("DHE-RSA-CHACHA20-POLY1305", [204, 170], "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    ("DHE-RSA-DES-CBC3-SHA", [0, 22], "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", [192, 43], "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    ("ECDHE-ECDSA-AES128-SHA", [192, 9], "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    ("ECDHE-ECDSA-AES128-SHA256", [192, 35], "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", [192, 44], "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    ("ECDHE-ECDSA-AES256-SHA", [192, 10], "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    ("ECDHE-ECDSA-AES256-SHA384", [192, 36], "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", [204, 169], "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    ("ECDHE-RSA-AES128-GCM-SHA256", [192, 47], "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    ("ECDHE-RSA-AES128-SHA", [192, 19], "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    ("ECDHE-RSA-AES128-SHA256", [192, 39], "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    ("ECDHE-RSA-AES256-GCM-SHA384", [192, 48], "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    ("ECDHE-RSA-AES256-SHA", [192, 20], "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    ("ECDHE-RSA-AES256-SHA384", [192, 40], "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    ("ECDHE-RSA-CHACHA20-POLY1305", [204, 168], "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    ("ECDHE-RSA-DES-CBC3-SHA", [192, 18], "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    ("ECDHE-RSA-RC4-SHA", [192, 17], "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
    ("RC4-MD5", [0, 4], "TLS_RSA_WITH_RC4_128_MD5"),
    ("RC4-SHA", [0, 5], "TLS_RSA_WITH_RC4_128_SHA"),
    ("TLS_AES_128_GCM_SHA256", [19, 1], "TLS_AES_128_GCM_SHA256"),
    ("TLS_AES_256_GCM_SHA384", [19, 2], "TLS_AES_256_GCM_SHA384"),
    ("TLS_CHACHA20_POLY1305_SHA256", [19, 3], "TLS_CHACHA20_POLY1305_SHA256"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    Negotiated,
    Supported,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PrefixKey {
    item: &'static str,
    parameter: TlsParam,
    state: State,
}

impl PrefixKey {
    fn new(item: &'static str, parameter: TlsParam, state: State) -> Self {
        Self {
            item,
            parameter,
            state,
        }
    }

    fn value(&self) -> String {
        format!("{:?}.{}.{}", self.state, self.parameter, self.item)
    }
}

/// We want all of our counters to be prefixed, e.g. `group.secp256r1`
///
/// metrique needs the string to be static, so we deliberately "leak" the data.
///
/// This is acceptable because it's just a finite set of values.
pub struct Prefixer {
    /// lookup from raw item to prefixed item
    prefixes: Mutex<HashMap<PrefixKey, &'static str>>,
}

// we use a single global prefixer
static PREFIXER: LazyLock<Prefixer> = LazyLock::new(|| Prefixer {
    prefixes: Mutex::new(HashMap::new()),
});

impl Prefixer {
    pub fn get_with_prefix(item: &'static str, parameter: TlsParam, state: State) -> &'static str {
        let key = PrefixKey::new(item, parameter, state);
        PREFIXER
            .prefixes
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_insert_with(|| key.value().leak())
    }
}

// pub static NEGOTIATED_CIPHER_PREFIXER: LazyLock<Prefixer<&'static str>> =
//     LazyLock::new(|| Prefixer::new("n.cipher."));
// pub static SUPPORTED_CIPHER_PREFIXER: LazyLock<Prefixer<&'static str>> =
//     LazyLock::new(|| Prefixer::new("s.cipher."));
// pub static NEGOTIATED_GROUP_PREFIXER: LazyLock<Prefixer<&'static str>> =
//     LazyLock::new(|| Prefixer::new("n.group."));
// pub static SUPPORTED_GROUP_PREFIXER: LazyLock<Prefixer<&'static str>> =
//     LazyLock::new(|| Prefixer::new("s.group."));
// pub static PROTOCOL_VERSION_PREFIXER: LazyLock<Prefixer<s2n_tls::enums::Version>> =
//     LazyLock::new(|| Prefixer::new("protocol_version."));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsParam {
    /// E.g. TLS 1.2
    Version,
    /// E.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    Cipher,
    /// E.g. SecP256r1MLKEM768
    Group,
    /// E.g. ecdsa_secp384r1_sha384
    SignatureScheme,
}

impl TlsParam {
    pub fn index_to_iana_name(&self, index: usize) -> Option<&'static str> {
        match self {
            TlsParam::Version => VERSIONS_AVAILABLE_IN_S2N.get(index).map(|name| *name),
            TlsParam::Cipher => CIPHERS_AVAILABLE_IN_S2N.get(index).map(|name| (*name).2),
            TlsParam::Group => GROUPS_AVAILABLE_IN_S2N.get(index).map(|name| *name),
            TlsParam::SignatureScheme => todo!(),
        }
    }

    pub fn iana_name_to_metric_index(&self, name: &'static str) -> Option<usize> {
        match self {
            TlsParam::Version => VERSIONS_AVAILABLE_IN_S2N
                .iter()
                .position(|version| *version == name),
            TlsParam::Cipher => CIPHERS_AVAILABLE_IN_S2N
                .iter()
                .position(|cipher| cipher.2 == name),
            TlsParam::Group => GROUPS_AVAILABLE_IN_S2N
                .iter()
                .position(|group| *group == name),
            TlsParam::SignatureScheme => todo!(),
        }
    }
}

impl Display for TlsParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsParam::Version => write!(f, "version"),
            TlsParam::Cipher => write!(f, "cipher"),
            TlsParam::Group => write!(f, "group"),
            TlsParam::SignatureScheme => write!(f, "signature_scheme"),
        }
    }
}

/// Maps from the the s2n cipher string representation to the array of the
pub fn cipher_ossl_name_to_index(name: &'static str) -> Option<usize> {
    CIPHERS_AVAILABLE_IN_S2N
        .iter()
        .position(|current_cipher| *current_cipher.0 == *name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        ffi::{c_char, c_int, c_void, CStr},
        sync::LazyLock,
    };

    // struct s2n_kem_preferences {
    //     /* kems used for hybrid TLS 1.2 */
    //     uint8_t kem_count;
    //     const struct s2n_kem **kems;

    //     /* tls13_kem_groups used for hybrid TLS 1.3 */
    //     const uint8_t tls13_kem_group_count;
    //     const struct s2n_kem_group **tls13_kem_groups;

    //     /* Which draft revision data format should the client use in its ClientHello. Currently the server will auto-detect
    //      * the format the client used from the TotalLength, and will match the client's behavior for backwards compatibility.
    //      *
    //      * Link: https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design
    //      *  - Draft 0:   PQ Hybrid KEM format: (Total Length, PQ Length, PQ Share, ECC Length, ECC Share)
    //      *  - Draft 1-5: PQ Hybrid KEM format: (Total Length, PQ Share, ECC Share)
    //      */
    //     uint8_t tls13_pq_hybrid_draft_revision;
    // };

    // struct s2n_ecc_preferences {
    //     uint8_t count;
    //     const struct s2n_ecc_named_curve *const *ecc_curves;
    // };

    // struct s2n_ecc_named_curve {
    //     /* See https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8 */
    //     uint16_t iana_id;
    //     /* See nid_list in openssl/ssl/t1_lib.c */
    //     int libcrypto_nid;
    //     const char *name;
    //     const uint8_t share_size;
    //     int (*generate_key)(const struct s2n_ecc_named_curve *named_curve, EVP_PKEY **evp_pkey);
    // };

    #[derive(Debug)]
    #[repr(C)]
    struct s2n_ecc_named_curve {
        iana_id: u16,
        libcrypto_nid: c_int,
        name: *const c_char,
        // ignored
    }

    impl s2n_ecc_named_curve {
        /// iana name
        fn name(&self) -> &'static str {
            unsafe { CStr::from_ptr(self.name).to_str().unwrap() }
        }
    }

    #[derive(Debug)]
    #[repr(C)]
    struct s2n_ecc_preferences {
        count: u8,
        ecc_curves: *mut *const s2n_ecc_named_curve,
    }

    // struct s2n_kem {
    //     const char *name;
    //     int kem_nid;
    //     const kem_extension_size kem_extension_id;
    //     const kem_public_key_size public_key_length;
    //     const kem_private_key_size private_key_length;
    //     const kem_shared_secret_size shared_secret_key_length;
    //     const kem_ciphertext_key_size ciphertext_length;
    //     /* NIST Post Quantum KEM submissions require the following API for compatibility */
    //     int (*generate_keypair)(IN const struct s2n_kem *kem, OUT uint8_t *public_key, OUT uint8_t *private_key);
    //     int (*encapsulate)(IN const struct s2n_kem *kem, OUT uint8_t *ciphertext, OUT uint8_t *shared_secret, IN const uint8_t *public_key);
    //     int (*decapsulate)(IN const struct s2n_kem *kem, OUT uint8_t *shared_secret, IN const uint8_t *ciphertext, IN const uint8_t *private_key);
    // };

    // struct s2n_kem_group {
    //     const char *name;
    //     uint16_t iana_id;
    //     const struct s2n_ecc_named_curve *curve;
    //     const struct s2n_kem *kem;

    //     /* Whether the PQ KeyShare should be sent before the ECC KeyShare. Only enabled for X25519MLKEM768.
    //      * See: https://datatracker.ietf.org/doc/html/draft-kwiatkowski-tls-ecdhe-mlkem-02#name-negotiated-groups */
    //     bool send_kem_first;
    // };

    #[derive(Debug)]
    #[repr(C)]
    struct s2n_kem_group {
        name: *const c_char,
        iana_id: u16,
        // ignored
    }

    impl s2n_kem_group {
        /// iana name
        fn name(&self) -> &'static str {
            unsafe { CStr::from_ptr(self.name).to_str().unwrap() }
        }
    }

    #[derive(Debug)]
    #[repr(C)]
    struct s2n_kem_preferences {
        kem_count: u8,
        kem: *mut *mut c_void, // s2n_kem
        tls13_kem_group_count: u8,
        tls13_kem_group: *mut *mut s2n_kem_group,
        // ignored
    }

    #[derive(Debug)]
    #[repr(C)]
    pub struct s2n_cipher_suite {
        available_bitfield: u8,
        /// nasty openssl name
        name: *const c_char,
        /// based iana name
        iana_name: *const c_char,
        iana_value: [u8; 2],
        // everything else is ignored
    }

    impl s2n_cipher_suite {
        fn nasty_name(&self) -> &'static str {
            unsafe { CStr::from_ptr(self.name).to_str().unwrap() }
        }

        fn iana_name(&self) -> &'static str {
            unsafe { CStr::from_ptr(self.iana_name).to_str().unwrap() }
        }

        fn iana_value(&self) -> [u8; 2] {
            self.iana_value
        }
    }

    #[derive(Debug)]
    #[repr(C)]
    pub struct s2n_cipher_preferences {
        count: u16,
        suites: *mut *mut s2n_cipher_suite,
        allow_chacha20_boosting: bool,
    }

    #[derive(Debug)]
    #[repr(C)]
    pub struct s2n_security_policy {
        minimum_protocol_version: u8,
        cipher_preferences: *const s2n_cipher_preferences, // s2n_cipher_preference
        kem_preferences: *const s2n_kem_preferences,
        signature_preference: *const c_void, // s2n_signature_preferences
        certificate_signature_preferences: *const c_void, //s2n_signature_preferences
        ecc_preferences: *const s2n_ecc_preferences, // s2n_ecc_preferences
        certificate_key_preferences: *const c_void, // s2n_certificate_key_preferences
        certificate_preferences_apply_locally: bool,
        rules: [bool; 2],
    }

    impl s2n_security_policy {
        fn ciphers(&self) -> &'static [&'static s2n_cipher_suite] {
            let cipher_preferences = unsafe { &*self.cipher_preferences };
            let count = cipher_preferences.count;
            unsafe {
                std::slice::from_raw_parts(
                    std::mem::transmute(cipher_preferences.suites),
                    count as _,
                )
            }
        }

        fn curves(&self) -> &'static [&'static s2n_ecc_named_curve] {
            let curve_preferences = unsafe { &*self.ecc_preferences };
            let count = curve_preferences.count;
            if count == 0 {
                return &[];
            }
            unsafe {
                std::slice::from_raw_parts(
                    std::mem::transmute(curve_preferences.ecc_curves),
                    count as _,
                )
            }
        }

        fn kems(&self) -> &'static [&'static s2n_kem_group] {
            let preferences = unsafe { &*self.kem_preferences };
            let count = preferences.tls13_kem_group_count;
            println!("count is {count}");
            if count == 0 {
                return &[];
            }
            unsafe {
                std::slice::from_raw_parts(
                    std::mem::transmute(preferences.tls13_kem_group),
                    count as _,
                )
            }
        }
    }

    // struct s2n_security_policy_selection {
    //     const char *version;
    //     const struct s2n_security_policy *security_policy;
    //     unsigned ecc_extension_required : 1;
    //     unsigned pq_kem_extension_required : 1;
    //     unsigned supports_tls13 : 1;
    // };
    /// This is our handwritten binding for the s2n_security_policy_selection struct.
    /// Otherwise our rust application would have no idea how to interpret the data
    /// in the "security_policy_selection" symbol.
    #[derive(Debug)]
    #[repr(C)]
    pub struct s2n_security_policy_selection {
        version: *const u8,
        security_policy: *const s2n_security_policy,
        bitfield: u8,
    }

    // We tell the rust compiler that it's safe to send this struct across threads.
    // Bascially, it doesn't have any thread-local state.
    unsafe impl Send for s2n_security_policy_selection {}
    unsafe impl Sync for s2n_security_policy_selection {}

    impl s2n_security_policy_selection {
        /// Retrieve the ascii name, e.g. "default_fips" or "20250115".
        fn name(&self) -> &'static str {
            unsafe { CStr::from_ptr(self.version as *const _).to_str().unwrap() }
        }
    }

    unsafe extern "C" {
        // This tells the rust compiler to link to the "security_policy_selection"
        // symbol in _some_ artifact. Note that the compiler can not validate the type
        // of data that is actually being linked to, that's on us.
        //
        // We have to tell a bit of a lie and pretend that this is an individual item,
        // because the size of the array isn't know from the rust side.
        //
        // extern struct s2n_security_policy_selection security_policy_selection[];
        pub static security_policy_selection: s2n_security_policy_selection;
    }

    pub static SECURITY_POLICY_TABLE: LazyLock<&'static [s2n_security_policy_selection]> =
        LazyLock::new(|| unsafe {
            let table_pointer = &security_policy_selection as *const s2n_security_policy_selection;
            let count = {
                let mut current = table_pointer;
                let mut count = 0;
                while !(*current).version.is_null() {
                    count += 1;
                    current = current.add(1);
                }
                count -= 1;
                count
            };

            std::slice::from_raw_parts(table_pointer, count)
        });

    /// get all the available security policy names
    pub fn available_security_policies() -> Vec<&'static str> {
        SECURITY_POLICY_TABLE.iter().map(|sp| sp.name()).collect()
    }

    #[test]
    fn security_policy_count() {
        assert_eq!(available_security_policies().len(), 143);
    }

    #[test]
    fn available_ciphers() {
        for sp in *SECURITY_POLICY_TABLE {
            println!("sp: {}", sp.name());
            let sp = unsafe { &*sp.security_policy };
            let cipher_preferences = sp.ciphers();
            for cipher in cipher_preferences {
                println!("\t{}", cipher.iana_name());
            }
        }
    }

    /// return all of the available s2n-tls ciphers in nasty (openssl) format
    fn all_available_ciphers() -> Vec<(&'static str, [u8; 2], &'static str)> {
        let ciphers: HashSet<(&'static str, [u8; 2], &'static str)> = SECURITY_POLICY_TABLE
            .iter()
            .map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let names: Vec<(&'static str, [u8; 2], &'static str)> = sp
                    .ciphers()
                    .iter()
                    .map(|c| (c.nasty_name(), c.iana_value(), c.iana_name()))
                    .collect();
                names
            })
            .flatten()
            .collect();
        let mut ciphers: Vec<(&'static str, [u8; 2], &'static str)> = ciphers.into_iter().collect();
        ciphers.sort();
        ciphers
    }

    /// return all of the available s2n-tls ciphers in nasty (openssl) format
    fn all_available_groups() -> Vec<&'static str> {
        let groups: HashSet<&'static str> = SECURITY_POLICY_TABLE
            .iter()
            .map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let kem_names = sp.kems().iter().map(|c| c.name());
                let curve_names = sp.curves().iter().map(|c| c.name());
                kem_names.chain(curve_names).collect::<Vec<&'static str>>()
                //curve_names.collect::<Vec<&'static str>>()
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
        for c in ciphers.iter() {
            println!("{c:?}");
        }
        assert_eq!(&ciphers, CIPHERS_AVAILABLE_IN_S2N);
    }

    #[test]
    fn all_groups_in_static_list() {
        let groups = all_available_groups();
        assert_eq!(&groups, GROUPS_AVAILABLE_IN_S2N);
    }
}
