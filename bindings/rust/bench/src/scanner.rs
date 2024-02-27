#![allow(non_camel_case_types)]

use std::{
    collections::{hash_map::DefaultHasher, BTreeSet, HashMap, VecDeque},
    error::Error,
    net::ToSocketAddrs,
    sync::{Once, RwLock},
    time::{Duration, Instant},
};

use log::error;
use openssl::{
    asn1::Asn1Time,
    pkey::Id,
    ssl::{SslRef, SslStream},
    x509::X509Ref,
};

use serde::{Deserialize, Serialize};

use crate::{
    openssl::OpenSslConfig, s2n_tls::S2NConfig, OpenSslConnection, S2NConnection, TlsConnPair,
    TlsConnection,
};
use params::{Cipher, LegacyCipher, Tls13Cipher};

use self::params::{
    all_parameters, Hash, KeyExchange, KxGroup, ParameterType, Protocol, Sig, Signature,
};
pub mod compliance;
pub mod security_policies;

pub const MAX_ENDPOINT_TPS: usize = 10;

/// This struct represents a query for some particular capability in a peer (server).
/// The query of interest is the `interest` field. TLS Parameters interact in a lot
/// of odd ways, so the `interest()` method will filter the parameters down as necessary.
///
/// This is often constructed from the `QueryEngine::omni_query` method which allows
/// you to specify as broad a range of supported capabilities as possible.
#[derive(Debug, Clone)]
pub struct TlsQuery {
    pub interest: ParameterType,

    pub protocols: Vec<Protocol>,
    pub ciphers: Vec<Cipher>,
    pub curves: Vec<KxGroup>,
    pub signatures: Vec<Signature>,
}

impl TlsQuery {
    pub fn new(interest: ParameterType) -> Self {
        let mut query = Self::default();
        query.interest(interest);
        query
    }

    fn interest(&mut self, interest: ParameterType) {
        self.interest = interest;

        match interest {
            // if interest is a tls 13 cipher, only tls13 should be allowed
            // if querying a signature scheme, only tls13 should be allowed
            ParameterType::Cipher(Cipher::Tls13(_))
            | ParameterType::Signature(Signature::SignatureScheme(_)) => {
                self.protocols = vec![Protocol::TLS_1_3]
            }
            // if querying a ffdhe group, only 1.3 should be allowed because dhe groups
            // only recognized in the groups selection for TLS 1.3
            ParameterType::Group(g) if g.key_exchange() == KeyExchange::DHE => {
                self.protocols = vec![Protocol::TLS_1_3]
            }
            // if interest is a legacy cipher, only tls10 - tls12 should be allowed
            // if querying a sig/hash tuple, only tls10 - tls12 should be allowed
            ParameterType::Cipher(Cipher::Legacy(_))
            | ParameterType::Signature(Signature::SigHash(_, _)) => {
                self.protocols = vec![Protocol::TLS_1_0, Protocol::TLS_1_1, Protocol::TLS_1_2]
            }
            _ => {}
        }

        // when setting the supported groups, it is necessary to restrict the ciphers
        // to a reasonable groups, otherwise (for example) RSA key transport might be
        // used with an RSA certificate, and none of the key exchange is _actually_
        // taking place
        if let ParameterType::Group(g) = interest {
            let ciphers = self
                .ciphers
                .iter()
                .cloned()
                .filter(|c| match c {
                    Cipher::Tls13(_) => true,
                    Cipher::Legacy(c) => c.key_exchange() == Some(g.key_exchange()),
                })
                .collect();
            self.ciphers = ciphers;
        }

        // if we are interested in a SigHash Signature, then we need to make
        // sure we aren't negotiating a cipher with RSA kx, otherwise no
        // transcript signature is actually used
        if let ParameterType::Signature(Signature::SigHash(_, _)) = interest {
            let ciphers = self
                .ciphers
                .iter()
                .cloned()
                .filter(|c| match c {
                    Cipher::Tls13(_) => true,
                    Cipher::Legacy(c) => c.key_exchange() != Some(KeyExchange::RSA),
                })
                .collect();
            self.ciphers = ciphers;
        }

        // remove all other parameters except the one that is of interest. This way
        // we know that a successful negotiation means that the parameter is
        // supported.
        match interest {
            ParameterType::Protocol(p) => self.protocols = vec![p],
            ParameterType::Cipher(c) => self.ciphers = vec![c],
            ParameterType::Group(g) => self.curves = vec![g],
            ParameterType::Signature(s) => self.signatures = vec![s],
        }
    }
}

impl Default for TlsQuery {
    fn default() -> Self {
        Self {
            interest: ParameterType::Protocol(Protocol::TLS_1_3),
            protocols: vec![
                Protocol::TLS_1_0,
                Protocol::TLS_1_1,
                Protocol::TLS_1_2,
                Protocol::TLS_1_3,
            ],
            ciphers: vec![
                Cipher::Tls13(Tls13Cipher::TLS_AES_128_GCM_SHA256),
                Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
                Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
            ],
            curves: vec![KxGroup::X25519, KxGroup::P_256, KxGroup::P_384],
            signatures: vec![
                Signature::SigHash(Sig::RSA_PSS, Hash::SHA256),
                Signature::SigHash(Sig::ECDSA, Hash::SHA256),
                Signature::SigHash(Sig::ECDSA, Hash::SHA384),
            ],
        }
    }
}

// use BTreeSet because we want to be able to hash these
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Hash, Clone)]
pub struct Report {
    pub endpoint: String,
    pub protocols: BTreeSet<Protocol>,
    pub ciphers: BTreeSet<Cipher>,
    pub groups: BTreeSet<KxGroup>,
    pub signatures: BTreeSet<Signature>,
    // PEM encoded
    // This is a Vec of certificates because a single endpoint might return
    // multiple certificate chains. For example a an endpoint might serve both
    // an ECDSA cert chain and an RSA cert chain.
    pub cert_chain: BTreeSet<Vec<Certificate>>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone, PartialOrd, Ord)]
pub enum CertificatePublicKey {
    // size, exponent
    RSA(u32, u32),
    // group
    ECDSA(u32),
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone, PartialOrd, Ord)]
pub struct Certificate {
    subject: String,
    issuer: String,
    expiration_days: i32,
    signature: String, // ossl nid long name
    pub_key: CertificatePublicKey,
}

impl Certificate {
    fn from_ossl(cert: &X509Ref) -> Self {
        let subject = format!("{:?}", cert.subject_name());
        let issuer = format!("{:?}", cert.issuer_name());
        let expiration_days = -cert
            .not_after()
            .diff(&Asn1Time::from_unix(0).unwrap())
            .unwrap()
            .days;
        let pub_key = cert.public_key().unwrap();
        let pub_key = if pub_key.id() == Id::RSA {
            let size = pub_key.bits();
            let exponent = pub_key
                .rsa()
                .unwrap()
                .e()
                .to_dec_str()
                .unwrap()
                .parse::<u32>()
                .unwrap();
            CertificatePublicKey::RSA(size, exponent)
        } else {
            assert_eq!(pub_key.id(), Id::EC);
            CertificatePublicKey::ECDSA(pub_key.bits())
        };
        let signature = cert
            .signature_algorithm()
            .object()
            .nid()
            .long_name()
            .unwrap()
            .to_owned();
        Certificate {
            subject,
            issuer,
            expiration_days,
            signature,
            pub_key,
        }
    }
}

impl Report {
    pub fn new(endpoint: &str) -> Self {
        let mut report = Self::default();
        report.endpoint = endpoint.to_string();
        report
    }

    pub fn insert_capability(&mut self, param: ParameterType) {
        match param {
            ParameterType::Protocol(p) => self.protocols.insert(p),
            ParameterType::Cipher(c) => self.ciphers.insert(c),
            ParameterType::Group(g) => self.groups.insert(g),
            ParameterType::Signature(s) => self.signatures.insert(s),
        };
    }

    pub fn security_policy_fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut h = DefaultHasher::new();
        self.protocols.hash(&mut h);
        self.ciphers.hash(&mut h);
        self.groups.hash(&mut h);
        self.signatures.hash(&mut h);
        h.finish()
    }

    /// add the certificate chain to the report and the peer key to the report
    pub fn enrich(&mut self, connection: &SslRef) -> Result<(), &str> {
        // we always expect there to be a peer cert chain, no anonymous cipher
        // suites, psk, or resumption is expected
        let chain = match connection.peer_cert_chain() {
            Some(chain) => chain,
            None => return Err("no certificate chain found"),
        };

        let pem_vec: Vec<Certificate> = chain.iter().map(Certificate::from_ossl).collect();
        self.cert_chain.insert(pem_vec);
        // there won't be a peer temp key when RSA transport is used
        if let Ok(key) = connection.peer_tmp_key() {
            let group = KxGroup::from_ossl(&key);
            self.insert_capability(ParameterType::Group(group));
        }

        Ok(())
    }

    pub fn cert_information(&self) {
        log::info!("there were {} cert chains", self.cert_chain.len());
        for chain in self.cert_chain.iter() {
            for c in chain.iter() {
                log::info!("{:?}", c);
            }
        }
    }

    pub fn cert_check(&self) -> Result<(), Vec<String>> {
        let mut success = true;
        let mut errors = Vec::new();

        for chain in self.cert_chain.iter() {
            let leaf_expiration = chain.first().unwrap().expiration_days;
            if leaf_expiration < 30 {
                success = false;
                errors.push(format!(
                    "WARNING: Certificate expires in {} days",
                    leaf_expiration
                ));
            }

            for cert in chain.iter() {
                let subject = &cert.subject;
                match cert.pub_key {
                    CertificatePublicKey::RSA(size, exponent) => {
                        if size != 2048 {
                            errors.push(format!("WARNING: Certificate {subject} using nonstandard RSA size of {size}"));
                        }
                        if exponent != 65537 {
                            errors.push(format!("ERROR: Certificate {subject} using nonstandard RSA exponent of {exponent}"));
                        }
                    }
                    CertificatePublicKey::ECDSA(size) => {
                        if size != 256 {
                            errors.push(format!("WARNING: Certificate {subject} using nonstandard ECDSA curve {size}"));
                        }
                    }
                }
            }
        }
        if success {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn supports_sha1(&self) -> bool {
        self.signatures.iter().any(|s| match s {
            Signature::SignatureScheme(scheme) => format!("{:?}", scheme).contains("sha1"),
            Signature::SigHash(_, Hash::SHA1) => true,
            _ => false,
        })
    }

    pub fn rsa_cert(&self) -> bool {
        for chain in self.cert_chain.iter() {
            if let CertificatePublicKey::RSA(_, _) = chain.first().unwrap().pub_key {
                return true;
            }
        }
        false
    }

    pub fn ecdsa_cert(&self) -> bool {
        for chain in self.cert_chain.iter() {
            if let CertificatePublicKey::ECDSA(_) = chain.first().unwrap().pub_key {
                return true;
            }
        }
        false
    }

    pub fn supports_13(&self) -> bool {
        self.protocols.contains(&Protocol::TLS_1_3)
    }

    pub fn supports_cipher(&self, cipher: &str) -> bool {
        self.ciphers
            .iter()
            .map(|c| format!("{:?}", c))
            .any(|c| c.contains(cipher))
    }
}

static LOAD_LEGACY_PROVIDER: Once = Once::new();
pub struct QueryEngine {
    unsupported_params: Vec<ParameterType>,
    // creating an s2n_config is very expensive, especially when using DH params
    // we cache configs here to reuse
    s2n_configs: RwLock<HashMap<String, Vec<S2NConfig>>>,
}

pub struct TokenBucket {
    queries: VecDeque<Instant>,
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenBucket {
    pub fn new() -> Self {
        TokenBucket {
            queries: VecDeque::new(),
        }
    }

    pub fn query_finished(&mut self) {
        self.queries.push_front(Instant::now());
    }

    pub fn wait(&mut self) -> Duration {
        if self.queries.is_empty() {
            return Duration::ZERO;
        }
        // exclude any queries that happened more than a second ago
        while self.queries.back().unwrap().elapsed().as_secs_f32() > 1.0 {
            self.queries.pop_back();
        }

        // there have been less than 10 queries in the last second, so go ahead and query
        if self.queries.len() < 10 {
            Duration::ZERO
        } else {
            assert_eq!(self.queries.len(), 10);
            Duration::from_secs(1).saturating_sub(self.queries.back().unwrap().elapsed())
        }
    }
}

impl std::fmt::Debug for QueryEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryEngine")
            .field("unsupported_params", &self.unsupported_params)
            .field("s2n_configs count", &self.s2n_configs.read().unwrap().len())
            .finish()
    }
}

impl QueryEngine {
    /// return a `TlsQuery` that indicates supports for all parameters that the underlying
    /// libcrypto supports.
    pub fn construct_omni_query(&self) -> TlsQuery {
        // assume all protocols are supported
        let mut query = TlsQuery::default();
        let supported: Vec<ParameterType> = all_parameters()
            .into_iter()
            .filter(|param| !self.unsupported_params.contains(param))
            .collect();
        let ciphers = supported
            .iter()
            .filter_map(|param| {
                if let ParameterType::Cipher(c) = param {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect();

        let groups = supported
            .iter()
            .filter_map(|param| {
                if let ParameterType::Group(g) = param {
                    Some(*g)
                } else {
                    None
                }
            })
            .collect();

        // openssl throws an error if there are overlapping signature schemes and sig/hash tuples
        let signatures = supported
            .iter()
            .filter_map(|param| {
                if let ParameterType::Signature(s) = param {
                    Some(*s)
                } else {
                    None
                }
            })
            .filter(|s| {
                if let Signature::SigHash(_, _) = s {
                    true
                } else {
                    false
                }
            })
            .collect();

        query.ciphers = ciphers;
        query.curves = groups;
        query.signatures = signatures;
        query
    }

    /// Return the `S2NConfig`s that use some particular security policy. Each
    /// `S2NConfig` is using a different type of certificate. This is necessary
    /// because the full capabilities of a security policy can not be expressed
    /// with just a single config.
    pub fn get_s2n_configs(&self, security_policy: &str) -> Vec<S2NConfig> {
        if let Some(configs) = self.s2n_configs.read().unwrap().get(security_policy) {
            return configs.clone();
        }

        let configs = S2NConfig::new_security_policy_server(security_policy);

        // get exclusive reference
        let mut config_map = self.s2n_configs.write().unwrap();
        if !config_map.contains_key(security_policy) {
            config_map.insert(security_policy.to_owned(), configs.clone());
        }
        drop(config_map);

        // in the event that some other thread wrote to the map first, then use
        // configs that they generates so everyone is using the same config
        self.s2n_configs
            .read()
            .unwrap()
            .get(security_policy)
            .unwrap()
            .clone()
    }

    /// query for the capabilities of the underlying openssl implementation. Generally
    /// not all configurations will be supported.
    pub fn construct_engine() -> Self {
        LOAD_LEGACY_PROVIDER.call_once(|| {
            let fetch = openssl::md::Md::fetch(None, "WHIRLPOOL", None);
            // can't load MD5 because legacy isn't there yet
            assert!(fetch.is_err());

            // if the legacy provider is dropped then it is unloaded and will
            // have no impact. Therefore we "forget" the legacy provider to keep
            // it around for the entire lifetime of the program.
            let load = openssl::provider::Provider::try_load(None, "legacy", false).unwrap();
            std::mem::forget(load);

            // as a sanity check, we should now be able to load MD5 since the
            // legacy provider is available
            let fetch = openssl::md::Md::fetch(None, "WHIRLPOOL", None);
            assert!(fetch.is_ok());
        });

        let query = TlsQuery::default();

        // panic if the default parameters aren't supported
        OpenSslConfig::tls_security_query(&query).unwrap();

        // get a list of all of the parameters
        let unsupported_params: Vec<ParameterType> = params::all_parameters()
            .into_iter()
            .map(|param| {
                let mut query = TlsQuery::default();
                query.interest(param);
                query
            })
            .filter(|query| {
                let result = OpenSslConfig::tls_security_query(query);
                log::trace!("{:?}", result.as_ref().err());
                result.is_err()
            })
            .map(|query| query.interest)
            .collect();

        log::info!("Libcrypto Capability Query");
        log::info!("total params: {}", params::all_parameters().len());
        log::info!("unsupported params: {}", unsupported_params.len());

        Self {
            unsupported_params,
            s2n_configs: Default::default(),
        }
    }

    /// get a list of TlsQueries for the available libcrypto capabilities
    pub fn get_tls_queries(&self) -> Vec<TlsQuery> {
        params::all_parameters()
            .into_iter()
            .filter(|param| !self.unsupported_params.contains(param))
            .map(|param| {
                let mut query = self.construct_omni_query();
                query.interest(param);
                query
            })
            .collect()
    }

    pub fn inspect_endpoint(&self, endpoint: &str) -> Result<Report, Box<dyn Error + Sync + Send>> {
        //let address: Vec<std::net::SocketAddr> = (endpoint, 443).to_socket_addrs()?.collect();
        //log::debug!("DNS lookup for {endpoint} returned {} addresses, {:?}", address.len(), address);

        let _query_token = MAX_ENDPOINT_TPS;
        let mut queries = Vec::new();
        let mut report = Report::new(endpoint);
        let query_iter = self.get_tls_queries().into_iter().map(|query| {
            let config = OpenSslConfig::tls_security_query(&query).unwrap();
            (query, config)
        });
        // do a single DNS query, because otherwise DNS will throttle us :(
        let lookup = format!("{endpoint}:443");
        log::trace!("trying to check {lookup}");
        let ips = lookup.to_socket_addrs()?;
        // to be polite, spread scans out among all of the available IP addresses
        let mut ips = ips.cycle();
        log::trace!("beginning the querying");
        for (query, config) in query_iter {
            // This is a very naive way of ensuring that we stay beneath MAX_ENDPOINT_TPS.
            // it causes us to undershoot it, but that's generally fine.
            std::thread::sleep(Duration::from_millis(1_000 / MAX_ENDPOINT_TPS as u64));

            // we should always be able to connect to the endpoint and create the SslStream
            // if this fails then we have not successfully queried the endpoint
            let stream = std::net::TcpStream::connect_timeout(
                &ips.next().unwrap(),
                Duration::from_secs(10),
            )?;

            let mut ssl = config.create();
            // this must be set otherwise certain wicker endpoints fail to connect
            ssl.set_hostname(endpoint).unwrap();
            let mut stream = SslStream::new(ssl, stream)?;
            let res = stream.connect();
            if res.is_err() {
                log::debug!("{} does not support {:?}", endpoint, query.interest);
                continue;
            }

            let handshake = stream.do_handshake();

            // finished the handshake
            queries.push(Instant::now());
            if handshake.is_ok() {
                report.enrich(stream.ssl()).unwrap();

                log::debug!("supports {:?}", query.interest);
                report.insert_capability(query.interest);
            } else {
                log::debug!("does not support {:?}", query.interest);
            }
        }
        Ok(report)
    }

    pub fn inspect_security_policy(&self, security_policy: &str) -> Report {
        let configs = self.get_s2n_configs(security_policy);
        // I think this should be rewritten with for loop :(
        let start = Instant::now();
        let mut report = Report::new(security_policy);

        for query in self.get_tls_queries() {
            let ossl_config = OpenSslConfig::tls_security_query(&query).unwrap();
            for s2n_config in configs.iter() {
                let mut pair =
                    TlsConnPair::<OpenSslConnection, S2NConnection>::new(&ossl_config, s2n_config);
                // if the handshake fails, try with a different certificate
                if pair.handshake().is_err() {
                    continue;
                } else {
                    let (client, server) = pair.split();
                    // let hash = client.connection().signature_nid().unwrap();
                    // println!("the hash is {:?}", hash);
                    // check that the query of interest was actually negotiated. It is expected
                    // that this might fail for signature algorithms, but it is unexpected that
                    // it would fail for anything else.
                    // assert_state(client, server, query)
                    if let ParameterType::Signature(Signature::SigHash(_s, _h)) = query.interest {
                        // this means we were interested in a sig hash thing, which might have fallen prey to silly
                        // parameter defaults (which I despise, btw, in case that wasn't clear). STOP PUTTING DEFAULT VALUES
                        // IN YOUR PROTOCOLS DAMN IT.
                        let s2n_sig = Signature::SigHash(
                            server
                                .connection()
                                .selected_signature_algorithm()
                                .unwrap()
                                .into(),
                            server
                                .connection()
                                .selected_hash_algorithm()
                                .unwrap()
                                .into(),
                        );
                        println!("{:?}", s2n_sig);
                        if client.connection().peer_signature_type_nid().is_err()
                            || client.connection().peer_signature_nid().is_err()
                        {
                            error!(
                                "sig:{:?} - hash:{:?}",
                                client.connection().peer_signature_type_nid(),
                                client.connection().peer_signature_nid()
                            );
                            error!("no peer signature type with sp :{:?}, for interest {:?}, s2n was {:?}", security_policy, query.interest, s2n_sig);
                            error!(
                                "negoatiated cipher: {:?}",
                                server.connection().cipher_suite().unwrap()
                            );
                            continue;
                        }
                        let actual = Signature::SigHash(
                            client
                                .connection()
                                .peer_signature_type_nid()
                                .unwrap()
                                .into(),
                            client.connection().peer_signature_nid().unwrap().into(),
                        );
                        report.insert_capability(ParameterType::Signature(actual));
                    } else {
                        report.insert_capability(query.interest);
                    }
                    if let Ok(key) = client.connection().peer_tmp_key() {
                        let group = ParameterType::Group(KxGroup::from_ossl(&key));
                        report.insert_capability(group);
                    }
                }
            }
        }
        log::info!(
            "{security_policy} query took {} ms",
            start.elapsed().as_millis()
        );
        report
    }
}

pub mod params {
    use openssl::{
        pkey::{Id, PKey, Public},
        ssl::SslVersion,
    };
    use serde::{Deserialize, Serialize};
    use std::fmt::Display;
    use strum::IntoEnumIterator;

    use strum::EnumIter;

    pub fn all_parameters() -> Vec<ParameterType> {
        Protocol::iter()
            .map(ParameterType::Protocol)
            .chain(Tls13Cipher::iter().map(|c| ParameterType::Cipher(Cipher::Tls13(c))))
            .chain(LegacyCipher::iter().map(|c| ParameterType::Cipher(Cipher::Legacy(c))))
            .chain(KxGroup::iter().map(ParameterType::Group))
            .chain(Sig::iter().flat_map(|s| {
                Hash::iter().map(move |h| ParameterType::Signature(Signature::SigHash(s, h)))
            }))
            .chain(
                SignatureScheme::iter()
                    .map(|s| ParameterType::Signature(Signature::SignatureScheme(s))),
            )
            .collect()
    }

    #[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
    pub enum ParameterType {
        Protocol(Protocol),
        Cipher(Cipher),
        Group(KxGroup),
        Signature(Signature),
    }

    // the PartialOrd derive creates an implementation based on enum ordering,
    // so don't change the order of the protocol listing.
    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, PartialOrd, Ord, Serialize, Deserialize,
    )]
    pub enum Protocol {
        TLS_1_0,
        TLS_1_1,
        TLS_1_2,
        TLS_1_3,
    }

    impl Protocol {
        pub fn ossl_version(&self) -> SslVersion {
            match self {
                Self::TLS_1_0 => SslVersion::TLS1,
                Self::TLS_1_1 => SslVersion::TLS1_1,
                Self::TLS_1_2 => SslVersion::TLS1_2,
                Self::TLS_1_3 => SslVersion::TLS1_3,
            }
        }
    }

    // There are separate enums required because openssl legacy ciphers have
    // different names because they are special little flowers
    // It might make sense to move the openssl specific name mapping to a different
    // file
    #[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord)]
    pub enum Cipher {
        Tls13(Tls13Cipher),
        Legacy(LegacyCipher),
    }

    // we only try and negoatie the KxGroup value for TLS 1.3, but we report it
    // for lower versions
    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord,
    )]
    pub enum KxGroup {
        P_521,
        P_384,
        P_256,
        X25519,
        X448,
        // 512 and 1024 are not IANA values, so can't be set in OpenSSL
        // should fail out during configuration
        ffdhe512,
        ffdhe1024,
        ffdhe2048,
        ffdhe3072,
        ffdhe4096,
        ffdhe6144,
        ffdhe8192,
    }

    impl KxGroup {
        pub fn key_exchange(&self) -> KeyExchange {
            match self {
                Self::P_521 | Self::P_384 | Self::P_256 | Self::X25519 | Self::X448 => {
                    KeyExchange::ECDHE
                }
                _ => KeyExchange::DHE,
            }
        }

        pub fn from_ossl(key: &PKey<Public>) -> Self {
            match key.id() {
                Id::DH => match key.bits() {
                    512 => Self::ffdhe512,
                    1024 => Self::ffdhe1024,
                    2048 => Self::ffdhe2048,
                    3072 => Self::ffdhe3072,
                    4096 => Self::ffdhe4096,
                    6144 => Self::ffdhe6144,
                    8192 => Self::ffdhe8192,
                    x => panic!("unexpected dh key size {x}"),
                },
                Id::EC => match key.bits() {
                    256 => Self::P_256,
                    384 => Self::P_384,
                    521 => Self::P_521,
                    x => panic!("unexpected ec key size {x}"),
                },
                Id::X25519 => Self::X25519,
                Id::X448 => Self::X448,
                _ => panic!("unexpected key type"),
            }
        }
    }

    impl Display for KxGroup {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::P_521 => write!(f, "P-521"),
                Self::P_384 => write!(f, "P-384"),
                Self::P_256 => write!(f, "P-256"),
                _ => write!(f, "{:?}", self),
            }
        }
    }
    #[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord)]
    pub enum Signature {
        SignatureScheme(SignatureScheme),
        SigHash(Sig, Hash),
    }

    impl Display for Signature {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::SignatureScheme(scheme) => write!(f, "{:?}", scheme),
                Self::SigHash(sig, hash) => write!(f, "{}+{:?}", sig, hash),
            }
        }
    }

    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord,
    )]
    pub enum Sig {
        RSA,
        RSA_PSS,
        DSA,
        ECDSA,
    }

    impl From<s2n_tls::enums::SignatureAlgorithm> for Sig {
        fn from(value: s2n_tls::enums::SignatureAlgorithm) -> Self {
            match value {
                s2n_tls::enums::SignatureAlgorithm::RSA_PKCS1 => Sig::RSA,
                s2n_tls::enums::SignatureAlgorithm::RSA_PSS_RSAE => Sig::RSA_PSS,
                s2n_tls::enums::SignatureAlgorithm::ECDSA => Sig::ECDSA,
                _ => panic!("unknown s2n sig alg: {:?}", value),
            }
        }
    }

    impl From<openssl::nid::Nid> for Sig {
        fn from(value: openssl::nid::Nid) -> Self {
            match value {
                openssl::nid::Nid::RSAENCRYPTION => Sig::RSA,
                openssl::nid::Nid::RSASSAPSS => Sig::RSA_PSS,
                openssl::nid::Nid::X9_62_ID_ECPUBLICKEY => Sig::ECDSA,
                _ => {
                    panic!(
                        "unknown openssl sig nid: {}, {}",
                        value.long_name().unwrap(),
                        value.as_raw()
                    );
                }
            }
        }
    }

    impl Display for Sig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::RSA_PSS => write!(f, "RSA-PSS"),
                _ => write!(f, "{:?}", self),
            }
        }
    }

    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord,
    )]
    pub enum Hash {
        MD5,
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
    }

    impl From<s2n_tls::enums::HashAlgorithm> for Hash {
        fn from(value: s2n_tls::enums::HashAlgorithm) -> Self {
            match value {
                s2n_tls::enums::HashAlgorithm::MD5 => Hash::MD5,
                s2n_tls::enums::HashAlgorithm::SHA1 => Hash::SHA1,
                s2n_tls::enums::HashAlgorithm::SHA224 => Hash::SHA224,
                s2n_tls::enums::HashAlgorithm::SHA256 => Hash::SHA256,
                s2n_tls::enums::HashAlgorithm::SHA384 => Hash::SHA384,
                s2n_tls::enums::HashAlgorithm::SHA512 => Hash::SHA512,
                _ => {
                    panic!("unknown s2n hash alg: {:?}", value);
                }
            }
        }
    }

    impl From<openssl::nid::Nid> for Hash {
        fn from(value: openssl::nid::Nid) -> Self {
            match value {
                openssl::nid::Nid::SHA1 => Hash::SHA1,
                openssl::nid::Nid::SHA224 => Hash::SHA224,
                openssl::nid::Nid::SHA256 => Hash::SHA256,
                openssl::nid::Nid::SHA384 => Hash::SHA384,
                openssl::nid::Nid::SHA512 => Hash::SHA512,
                _ => {
                    panic!(
                        "unknown openssl hash nid:{} -> {}",
                        value.as_raw(),
                        value.long_name().unwrap()
                    );
                }
            }
        }
    }

    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord,
    )]
    pub enum SignatureScheme {
        /* RSASSA-PKCS1-v1_5 algorithms */
        rsa_pkcs1_sha256,
        rsa_pkcs1_sha384,
        rsa_pkcs1_sha512,
        /* ECDSA algorithms */
        ecdsa_secp256r1_sha256,
        ecdsa_secp384r1_sha384,
        ecdsa_secp521r1_sha512,
        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        rsa_pss_rsae_sha256,
        rsa_pss_rsae_sha384,
        rsa_pss_rsae_sha512,
        /* EdDSA algorithms */
        ed25519,
        ed448,
        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        rsa_pss_pss_sha256,
        rsa_pss_pss_sha384,
        rsa_pss_pss_sha512,
        /* Legacy algorithms */
        rsa_pkcs1_sha1,
        ecdsa_sha1,
    }

    impl SignatureScheme {
        // this method is used to make sure that we aren't accidentally
        // loading identical signature schemes into Openssl, because it will
        // error if that happens
        pub fn get_sig(&self) -> Option<Sig> {
            match self {
                Self::rsa_pkcs1_sha256
                | Self::rsa_pkcs1_sha384
                | Self::rsa_pkcs1_sha512
                | Self::rsa_pkcs1_sha1 => Some(Sig::RSA),
                Self::ecdsa_secp256r1_sha256
                | Self::ecdsa_secp384r1_sha384
                | Self::ecdsa_secp521r1_sha512
                | Self::ecdsa_sha1 => Some(Sig::ECDSA),
                Self::ed25519 | Self::ed448 => None,
                _ => Some(Sig::RSA_PSS),
            }
        }
    }

    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord,
    )]
    pub enum Tls13Cipher {
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_128_CCM_SHA256,
        TLS_AES_128_CCM_8_SHA256,
    }

    // these are the key exchange methods that s2n supports, and are commonly supported in the wild
    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord,
    )]
    pub enum KeyExchange {
        RSA,
        ECDHE,
        DHE,
    }

    #[derive(
        Debug, PartialEq, Eq, Hash, EnumIter, Copy, Clone, Serialize, Deserialize, PartialOrd, Ord,
    )]
    pub enum LegacyCipher {
        // SSL_RSA_WITH_NULL_MD5,
        // SSL_RSA_WITH_NULL_SHA,
        // SSL_RSA_WITH_RC4_128_MD5,
        // SSL_RSA_WITH_RC4_128_SHA,
        // SSL_RSA_WITH_IDEA_CBC_SHA,
        // SSL_RSA_WITH_3DES_EDE_CBC_SHA,
        // SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA,
        // SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA,
        // SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        // SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        // SSL_DH_anon_WITH_RC4_128_MD5,
        // SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,
        TLS_RSA_WITH_NULL_MD5,
        TLS_RSA_WITH_NULL_SHA,
        TLS_RSA_WITH_RC4_128_MD5,
        TLS_RSA_WITH_RC4_128_SHA,
        TLS_RSA_WITH_IDEA_CBC_SHA,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        TLS_DH_anon_WITH_RC4_128_MD5,
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
        TLS_RSA_WITH_AES_128_CBC_SHA,
        TLS_RSA_WITH_AES_256_CBC_SHA,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_DH_anon_WITH_AES_128_CBC_SHA,
        TLS_DH_anon_WITH_AES_256_CBC_SHA,
        TLS_DHE_DSS_WITH_RC4_128_SHA,
        TLS_ECDHE_RSA_WITH_NULL_SHA,
        TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        TLS_ECDH_anon_WITH_NULL_SHA,
        TLS_ECDH_anon_WITH_RC4_128_SHA,
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
        TLS_RSA_WITH_NULL_SHA256,
        TLS_RSA_WITH_AES_128_CBC_SHA256,
        TLS_RSA_WITH_AES_256_CBC_SHA256,
        TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_256_GCM_SHA384,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_DH_anon_WITH_AES_128_CBC_SHA256,
        TLS_DH_anon_WITH_AES_256_CBC_SHA256,
        TLS_DH_anon_WITH_AES_128_GCM_SHA256,
        TLS_DH_anon_WITH_AES_256_GCM_SHA384,
        TLS_RSA_WITH_AES_128_CCM,
        TLS_RSA_WITH_AES_256_CCM,
        TLS_DHE_RSA_WITH_AES_128_CCM,
        TLS_DHE_RSA_WITH_AES_256_CCM,
        TLS_RSA_WITH_AES_128_CCM_8,
        TLS_RSA_WITH_AES_256_CCM_8,
        TLS_DHE_RSA_WITH_AES_128_CCM_8,
        TLS_DHE_RSA_WITH_AES_256_CCM_8,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
    }

    impl LegacyCipher {
        pub fn openssl(&self) -> &'static str {
            match self {
                // Self::SSL_RSA_WITH_NULL_MD5 => "NULL-MD5",
                // Self::SSL_RSA_WITH_NULL_SHA => "NULL-SHA",
                // Self::SSL_RSA_WITH_RC4_128_MD5 => "RC4-MD5",
                // Self::SSL_RSA_WITH_RC4_128_SHA => "RC4-SHA",
                // Self::SSL_RSA_WITH_IDEA_CBC_SHA => "IDEA-CBC-SHA",
                // Self::SSL_RSA_WITH_3DES_EDE_CBC_SHA => "DES-CBC3-SHA",
                // Self::SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA => "DH-DSS-DES-CBC3-SHA",
                // Self::SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA => "DH-RSA-DES-CBC3-SHA",
                // Self::SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA => "DHE-DSS-DES-CBC3-SHA",
                // Self::SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA => "DHE-RSA-DES-CBC3-SHA",
                // Self::SSL_DH_anon_WITH_RC4_128_MD5 => "ADH-RC4-MD5",
                // Self::SSL_DH_anon_WITH_3DES_EDE_CBC_SHA => "ADH-DES-CBC3-SHA",
                Self::TLS_RSA_WITH_NULL_MD5 => "NULL-MD5",
                Self::TLS_RSA_WITH_NULL_SHA => "NULL-SHA",
                Self::TLS_RSA_WITH_RC4_128_MD5 => "RC4-MD5",
                Self::TLS_RSA_WITH_RC4_128_SHA => "RC4-SHA",
                Self::TLS_RSA_WITH_IDEA_CBC_SHA => "IDEA-CBC-SHA",
                Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA => "DES-CBC3-SHA",
                Self::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => "DHE-DSS-DES-CBC3-SHA",
                Self::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => "DHE-RSA-DES-CBC3-SHA",
                Self::TLS_DH_anon_WITH_RC4_128_MD5 => "ADH-RC4-MD5",
                Self::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA => "ADH-DES-CBC3-SHA",
                Self::TLS_RSA_WITH_AES_128_CBC_SHA => "AES128-SHA",
                Self::TLS_RSA_WITH_AES_256_CBC_SHA => "AES256-SHA",
                Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA => "DH-DSS-AES128-SHA",
                Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA => "DH-DSS-AES256-SHA",
                Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA => "DH-RSA-AES128-SHA",
                Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA => "DH-RSA-AES256-SHA",
                Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA => "DHE-DSS-AES128-SHA",
                Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA => "DHE-DSS-AES256-SHA",
                Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => "DHE-RSA-AES128-SHA",
                Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => "DHE-RSA-AES256-SHA",
                Self::TLS_DH_anon_WITH_AES_128_CBC_SHA => "ADH-AES128-SHA",
                Self::TLS_DH_anon_WITH_AES_256_CBC_SHA => "ADH-AES256-SHA",
                Self::TLS_DHE_DSS_WITH_RC4_128_SHA => "DHE-DSS-RC4-SHA",
                Self::TLS_ECDHE_RSA_WITH_NULL_SHA => "ECDHE-RSA-NULL-SHA",
                Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA => "ECDHE-RSA-RC4-SHA",
                Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => "ECDHE-RSA-DES-CBC3-SHA",
                Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => "ECDHE-RSA-AES128-SHA",
                Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => "ECDHE-RSA-AES256-SHA",
                Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA => "ECDHE-ECDSA-NULL-SHA",
                Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => "ECDHE-ECDSA-RC4-SHA",
                Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => "ECDHE-ECDSA-DES-CBC3-SHA",
                Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => "ECDHE-ECDSA-AES128-SHA",
                Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => "ECDHE-ECDSA-AES256-SHA",
                Self::TLS_ECDH_anon_WITH_NULL_SHA => "AECDH-NULL-SHA",
                Self::TLS_ECDH_anon_WITH_RC4_128_SHA => "AECDH-RC4-SHA",
                Self::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => "AECDH-DES-CBC3-SHA",
                Self::TLS_ECDH_anon_WITH_AES_128_CBC_SHA => "AECDH-AES128-SHA",
                Self::TLS_ECDH_anon_WITH_AES_256_CBC_SHA => "AECDH-AES256-SHA",
                Self::TLS_RSA_WITH_NULL_SHA256 => "NULL-SHA256",
                Self::TLS_RSA_WITH_AES_128_CBC_SHA256 => "AES128-SHA256",
                Self::TLS_RSA_WITH_AES_256_CBC_SHA256 => "AES256-SHA256",
                Self::TLS_RSA_WITH_AES_128_GCM_SHA256 => "AES128-GCM-SHA256",
                Self::TLS_RSA_WITH_AES_256_GCM_SHA384 => "AES256-GCM-SHA384",
                Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => "DH-RSA-AES128-SHA256",
                Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => "DH-RSA-AES256-SHA256",
                Self::TLS_DH_RSA_WITH_AES_128_GCM_SHA256 => "DH-RSA-AES128-GCM-SHA256",
                Self::TLS_DH_RSA_WITH_AES_256_GCM_SHA384 => "DH-RSA-AES256-GCM-SHA384",
                Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => "DH-DSS-AES128-SHA256",
                Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => "DH-DSS-AES256-SHA256",
                Self::TLS_DH_DSS_WITH_AES_128_GCM_SHA256 => "DH-DSS-AES128-GCM-SHA256",
                Self::TLS_DH_DSS_WITH_AES_256_GCM_SHA384 => "DH-DSS-AES256-GCM-SHA384",
                Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => "DHE-RSA-AES128-SHA256",
                Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => "DHE-RSA-AES256-SHA256",
                Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => "DHE-RSA-AES128-GCM-SHA256",
                Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => "DHE-RSA-AES256-GCM-SHA384",
                Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => "DHE-DSS-AES128-SHA256",
                Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => "DHE-DSS-AES256-SHA256",
                Self::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 => "DHE-DSS-AES128-GCM-SHA256",
                Self::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 => "DHE-DSS-AES256-GCM-SHA384",
                Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => "ECDHE-RSA-AES128-SHA256",
                Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => "ECDHE-RSA-AES256-SHA384",
                Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "ECDHE-RSA-AES128-GCM-SHA256",
                Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "ECDHE-RSA-AES256-GCM-SHA384",
                Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => "ECDHE-ECDSA-AES128-SHA256",
                Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => "ECDHE-ECDSA-AES256-SHA384",
                Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "ECDHE-ECDSA-AES128-GCM-SHA256",
                Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "ECDHE-ECDSA-AES256-GCM-SHA384",
                Self::TLS_DH_anon_WITH_AES_128_CBC_SHA256 => "ADH-AES128-SHA256",
                Self::TLS_DH_anon_WITH_AES_256_CBC_SHA256 => "ADH-AES256-SHA256",
                Self::TLS_DH_anon_WITH_AES_128_GCM_SHA256 => "ADH-AES128-GCM-SHA256",
                Self::TLS_DH_anon_WITH_AES_256_GCM_SHA384 => "ADH-AES256-GCM-SHA384",
                Self::TLS_RSA_WITH_AES_128_CCM => "AES128-CCM",
                Self::TLS_RSA_WITH_AES_256_CCM => "AES256-CCM",
                Self::TLS_DHE_RSA_WITH_AES_128_CCM => "DHE-RSA-AES128-CCM",
                Self::TLS_DHE_RSA_WITH_AES_256_CCM => "DHE-RSA-AES256-CCM",
                Self::TLS_RSA_WITH_AES_128_CCM_8 => "AES128-CCM8",
                Self::TLS_RSA_WITH_AES_256_CCM_8 => "AES256-CCM8",
                Self::TLS_DHE_RSA_WITH_AES_128_CCM_8 => "DHE-RSA-AES128-CCM8",
                Self::TLS_DHE_RSA_WITH_AES_256_CCM_8 => "DHE-RSA-AES256-CCM8",
                Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM => "ECDHE-ECDSA-AES128-CCM",
                Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM => "ECDHE-ECDSA-AES256-CCM",
                Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => "ECDHE-ECDSA-AES128-CCM8",
                Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => "ECDHE-ECDSA-AES256-CCM8",
                Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-RSA-CHACHA20-POLY1305",
                Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                    "ECDHE-ECDSA-CHACHA20-POLY1305"
                }
                Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "DHE-RSA-CHACHA20-POLY1305",
                Self::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => "PSK-CHACHA20-POLY1305",
                Self::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => "ECDHE-PSK-CHACHA20-POLY1305",
                Self::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => "DHE-PSK-CHACHA20-POLY1305",
                Self::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => "RSA-PSK-CHACHA20-POLY1305",
            }
        }

        pub fn key_exchange(&self) -> Option<KeyExchange> {
            let representation = format!("{:?}", self);
            if representation.contains("TLS_DHE") {
                Some(KeyExchange::DHE)
            } else if representation.contains("TLS_RSA") {
                Some(KeyExchange::RSA)
            } else if representation.contains("TLS_ECDHE") {
                Some(KeyExchange::ECDHE)
            } else {
                None
            }
        }
    }
}
#[cfg(test)]
mod test {
    use openssl::{bn::BigNum, nid::Nid, pkey::Id};

    use strum::IntoEnumIterator;

    use crate::{OpenSslConnection, S2NConnection};

    use super::{params::*, *};

    fn handshake(
        security_policy: &str,
        query: &TlsQuery,
    ) -> Result<(OpenSslConnection, S2NConnection), Box<dyn Error>> {
        // the rust compiler isn't clever enough to figure this out without the option
        let mut e = None;

        for s2n_config in S2NConfig::new_security_policy_server(security_policy).iter() {
            let mut pair = TlsConnPair::<OpenSslConnection, S2NConnection>::new(
                &OpenSslConfig::tls_security_query(query).unwrap(),
                &s2n_config,
            );
            let res = pair.handshake();
            if res.is_ok() {
                return Ok(pair.split());
            } else {
                println!("error encounterd {:?}", res.as_ref().err());
                e = res.err();
            }
        }
        return Err(e.unwrap());
    }

    #[test]
    fn unsupported_configuration_detected() {
        let qe = QueryEngine::construct_engine();
        println!("unsupported parameters: {:?}", qe.unsupported_params);
        assert_ne!(qe.unsupported_params.len(), 0);
        assert_ne!(qe.unsupported_params.len(), all_parameters().len());
    }

    // the test server is automatically configured with a 2048 bit diffie hellman
    // group. Confirm that we successfully detect it.
    #[test]
    fn dh_key_check() {
        let qe = QueryEngine::construct_engine();
        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Cipher(Cipher::Legacy(
            LegacyCipher::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        )));

        let (client, _server) = handshake("20190214", &query).unwrap();
        println!(
            "server cipher: {}",
            _server.connection().cipher_suite().unwrap()
        );
        let peer_key = client.connection().peer_tmp_key().unwrap();
        assert_eq!(peer_key.bits(), 2048);
        assert_eq!(peer_key.id(), Id::DH);

        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Group(KxGroup::ffdhe3072));

        let result = handshake("default_tls13", &query);
        assert!(result.is_err());
    }

    #[test]
    fn rsa_cert_check() {
        let qe = QueryEngine::construct_engine();
        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Cipher(Cipher::Legacy(
            LegacyCipher::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        )));

        let (client, _server) = handshake("20190214", &query).unwrap();
        let cert = client.connection().peer_cert_chain().unwrap();
        for c in cert.iter() {
            println!("issues name: {:?}", c.issuer_name());
            let pub_key = c.public_key().unwrap();
            println!("publc key: {:?}", pub_key);
            println!("p8ublic key bits: {:?}", pub_key.bits());
            //assert_eq!(pub_key.id(), Id::RSA);
            let pub_key = pub_key.rsa().unwrap();
            assert_eq!(pub_key.size() * u8::BITS, 2048);
            println!("rsa size (bits): {:?}", pub_key.size() * 8);
            let exponent = pub_key.e();
            let _modulus = pub_key.n();
            println!("rsa key: {:?}, {:?}", pub_key, exponent);

            assert_eq!(
                exponent.to_owned().unwrap(),
                BigNum::from_u32(65537).unwrap()
            );
            //assert_eq!(modulus.to_owned().unwrap(), BigNum::from_u32(2048).unwrap());
        }
        println!(
            "server cipher: {}",
            _server.connection().cipher_suite().unwrap()
        );

        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Group(KxGroup::ffdhe3072));

        let result = handshake("default_tls13", &query);
        assert!(result.is_err());
    }

    #[test]
    fn ecdh_key_check() {
        // TLS 1.2 ECDHE
        let qe = QueryEngine::construct_engine();
        let mut query = qe.construct_omni_query();

        // negotiate an elliptic curve
        query.interest(ParameterType::Cipher(Cipher::Legacy(
            LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        )));

        let (client, _server) = handshake("default", &query).unwrap();
        let peer_key = client.connection().peer_tmp_key().unwrap();
        // p256 is the default key group
        assert_eq!(peer_key.id(), Id::EC);
        println!("{:?}", peer_key.bits());
        assert_eq!(peer_key.bits(), 256);

        // TLS 1.3 - X25519 Groups
        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Group(KxGroup::X25519));
        let (client, _server) = handshake("default_tls13", &query).unwrap();
        let peer_key = client.connection().peer_tmp_key().unwrap();
        assert_eq!(peer_key.id(), Id::X25519);

        // TLS 1.3 - P256 Groups
        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Group(KxGroup::P_256));
        let (client, _server) = handshake("default_tls13", &query).unwrap();
        let peer_key = client.connection().peer_tmp_key().unwrap();
        assert_eq!(peer_key.id(), Id::EC);
        assert_eq!(peer_key.bits(), 256);

        // TLS 1.3 - P384 Groups
        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Group(KxGroup::P_384));
        let (client, _server) = handshake("default_tls13", &query).unwrap();
        let peer_key = client.connection().peer_tmp_key().unwrap();
        assert_eq!(peer_key.id(), Id::EC);
        assert_eq!(peer_key.bits(), 384);

        // TODO: Openssl does _not_ like our key selection here:
        // thread 'scanner::test::ecdh_key_check' panicked at 'called
        // `Result::unwrap()` on an `Err` value: Error { code: ErrorCode(1),
        // cause: Some(Ssl(ErrorStack([Error { code: 167772538, library: "SSL
        // routines", function: "tls12_check_peer_sigalg", reason: "wrong
        // curve", file: "ssl/t1_lib.c", line: 1549 }]))) }', src/scanner.rs:1030:67

        // TLS 1.2 - X25519 Groups
        // let mut query = qe.construct_omni_query();
        // query.interest(ParameterType::Group(KxGroup::X25519));
        // query.protocols = vec![Protocol::TLS_1_2];
        // let (client, server) = handshake("default_tls13", &query).unwrap();
        // let peer_key = client.connection().peer_tmp_key().unwrap();
        // assert_eq!(peer_key.id(), Id::X25519);

        // // TLS 1.2 - P256 Groups
        // let mut query = qe.construct_omni_query();
        // query.interest(ParameterType::Group(KxGroup::P_256));
        // query.protocols = vec![Protocol::TLS_1_2];

        // let (client, server) = handshake("default_tls13", &query).unwrap();
        // let peer_key = client.connection().peer_tmp_key().unwrap();
        // assert_eq!(peer_key.id(), Id::EC);
        // assert_eq!(peer_key.bits(), 256);

        // // TLS 1.2 - P384 Groups
        // let mut query = qe.construct_omni_query();
        // query.interest(ParameterType::Group(KxGroup::P_384));
        // query.protocols = vec![Protocol::TLS_1_2];
        // println!("{:?}", query);

        //let (client, server) = handshake("default_tls13", &query).unwrap();
        //let peer_key = client.connection().peer_tmp_key().unwrap();
        //assert_eq!(peer_key.id(), Id::EC);
        //assert_eq!(peer_key.bits(), 384);
    }

    // Openssl will allow a fallback to SHA1 algorithms unless a strict mode is
    // set. We allow all of the bad things to probe more algorithms so this results
    // in the unfortunate scenario where we _think_ that we have successfully
    // negoatied an algorithm, but that is not actually the case.
    // If you try and reproduce this with openssl s_client, my explanation will
    // seem wrong, but the only reason that it fails on s_client is because the
    // default security level (on Openssl 3.0.2) doesn't allow RSA+SHA1. If you
    // set the security value to zero, then the negotiation will be successful.
    // https://github.com/openssl/openssl/blob/openssl-3.0.2/ssl/t1_lib.c#L1546
    // > "Allow fallback to SHA1 if not strict mode"
    #[test]
    fn openssl_does_not_respect_sigalg() {
        let qe = QueryEngine::construct_engine();
        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Signature(Signature::SigHash(
            Sig::RSA_PSS,
            Hash::SHA256,
        )));

        // default is bad and doesn't allow tls 1.3
        let s2n_configs = S2NConfig::new_security_policy_server("default");
        let succeeded = s2n_configs
            .into_iter()
            .map(|s2n| {
                let mut pair = TlsConnPair::<OpenSslConnection, S2NConnection>::new(
                    &OpenSslConfig::tls_security_query(&query).unwrap(),
                    &s2n,
                );
                let output = pair.handshake();
                if output.is_ok() {
                    let (client, server) = pair.split();
                    // we wanted RSA-PSS+SHA256, and got this instead because it
                    // is the s2n fallback.
                    let expected = Signature::SigHash(Sig::RSA, Hash::SHA1);
                    let s2n_view = Signature::SigHash(
                        server
                            .connection()
                            .selected_signature_algorithm()
                            .unwrap()
                            .into(),
                        server
                            .connection()
                            .selected_hash_algorithm()
                            .unwrap()
                            .into(),
                    );
                    let ossl_view = Signature::SigHash(
                        client
                            .connection()
                            .peer_signature_type_nid()
                            .unwrap()
                            .into(),
                        client.connection().peer_signature_nid().unwrap().into(),
                    );
                    assert_eq!(s2n_view, expected);
                    assert_eq!(ossl_view, expected);
                }

                output
            })
            .any(|result| result.is_ok());
        assert!(succeeded);
    }

    #[test]
    fn num_queries() {
        let qe = QueryEngine::construct_engine();
        let queries = qe.get_tls_queries();
        // 88, then 116? with OpenSSL 3.0.2 15 Mar 2022
        // 115 -> this is when I didn't have weak-crypto enabled
        // previously 117?
        // now 122? The shuffle is unfortunately infuriating
        // make sure that 3des is supported
        // make sure that the weak-crypto feature is enabled on openssl-src if this is failing
        // I clobbered the openssl-sys definition to make this happen

        println!("unsupported: {:?}", qe.unsupported_params);

        // make sure 3des is being queried for
        assert!(!qe
            .unsupported_params
            .contains(&ParameterType::Cipher(Cipher::Legacy(
                LegacyCipher::TLS_RSA_WITH_3DES_EDE_CBC_SHA
            ))));

        // rc4 is being queried for
        assert!(!qe
            .unsupported_params
            .contains(&ParameterType::Cipher(Cipher::Legacy(
                LegacyCipher::TLS_RSA_WITH_RC4_128_SHA
            ))));

        assert_eq!(queries.len(), 128);
    }

    //#[test]
    fn rsa_md5_sig_alg() {
        let qe = QueryEngine::construct_engine();
        // let mut query = TlsQuery::default();
        // RSA+MD5 can't be manually entered, at least on OSSL v3. It is simply
        // the product of not having sent any sig algs on a pre TLS 1.2 connection
        // let mut query = qe.construct_omni_query();
        // query.interest(ParameterType::Signature(Signature::SigHash(Sig::RSA, Hash::MD5)));
        // let ossl = OpenSslConfig::tls_security_query(&query);
        // println!("result was {:?}", ossl.as_ref().err());
        // assert!(ossl.is_ok());
    }

    #[test]
    fn cipher_validation() {
        let qe = QueryEngine::construct_engine();

        let queries = LegacyCipher::iter()
            .map(|cipher| ParameterType::Cipher(Cipher::Legacy(cipher)))
            .filter(|param| !qe.unsupported_params.contains(param))
            .map(|param| {
                let mut query = qe.construct_omni_query();
                query.interest(param);
                query
            });
        let configured_s2n = S2NConfig::new_security_policy_server("default_tls13");
        for query in queries {
            let configured_openssl = OpenSslConfig::tls_security_query(&query).unwrap();
            let mut pair = TlsConnPair::<
                crate::openssl::OpenSslConnection,
                crate::s2n_tls::S2NConnection,
            >::new(&configured_openssl, configured_s2n.first().unwrap());
            let res = pair.handshake();
            if res.is_ok() {
                let (_client, server) = pair.split();
                if let ParameterType::Cipher(Cipher::Legacy(c)) = query.interest {
                    assert_eq!(c.openssl(), server.connection().cipher_suite().unwrap());
                } else {
                    panic!();
                }
            }
        }
    }

    #[test]
    fn rsa_pss_default() {
        let qe = QueryEngine::construct_engine();
        let mut query = qe.construct_omni_query();
        query.interest(ParameterType::Signature(Signature::SigHash(
            Sig::RSA_PSS,
            Hash::SHA256,
        )));

        let (client, server) = handshake("default", &query).unwrap();
        println!(
            "server connect {:?}",
            server.connection().selected_signature_algorithm()
        );
    }

    #[test]
    fn legacy_loading() {
        // whirlpool is only available from the legacy provider
        // we should fail to fetch it because the provider is not yet loaded, but
        // this test might not be the first to run in which case -> sadness
        // let fetch = openssl::md::Md::fetch(None, "WHIRLPOOL", None);
        // assert!(fetch.is_err());
        let qe = QueryEngine::construct_engine();

        // after constructing an engine for the first time, the legacy provider should
        // be loaded
        let fetch = openssl::md::Md::fetch(None, "WHIRLPOOL", None);
        assert!(fetch.is_ok());
    }
}

extern "C" {
    fn OBJ_sn2nid(name: *const u8) -> i32;
}

#[cfg(test)]
mod known_test {
    use std::ffi::{c_char, CString};

    use known_test::params::SignatureScheme;

    use super::*;

    // this does work but char is platform specific do don't bother dealing with this
    // #[test]
    // fn call_ossl() {
    //     let arg = CString::new("MD5").unwrap();
    //     let ret = unsafe { OBJ_sn2nid(arg.as_ptr()) };
    //     println!("ret :{:?}", ret);
    //     assert_ne!(ret, 0);
    //     //assert!(false);
    // }

    // coverage: groups without TLS 1.3
    #[test]
    fn sp_default() {
        let qe = QueryEngine::construct_engine();
        let report = qe.inspect_security_policy("default");
        println!("{:?}", report);
        let expected_protocols = BTreeSet::from_iter(
            vec![Protocol::TLS_1_0, Protocol::TLS_1_1, Protocol::TLS_1_2].into_iter(),
        );

        let expected_groups = BTreeSet::from_iter(vec![KxGroup::P_256, KxGroup::P_384].into_iter());

        /*
         * const struct s2n_signature_scheme* const s2n_sig_scheme_pref_list_20140601[] = {
         *     /* RSA PKCS1 */
         *     &s2n_rsa_pkcs1_sha256,
         *     &s2n_rsa_pkcs1_sha384,
         *     &s2n_rsa_pkcs1_sha512,
         *     &s2n_rsa_pkcs1_sha224,
         *
         *     /* ECDSA - TLS 1.2 */
         *     &s2n_ecdsa_sha256, /* same iana value as TLS 1.3 s2n_ecdsa_secp256r1_sha256 */
         *     &s2n_ecdsa_secp256r1_sha256,
         *     &s2n_ecdsa_sha384, /* same iana value as TLS 1.3 s2n_ecdsa_secp384r1_sha384 */
         *     &s2n_ecdsa_secp384r1_sha384,
         *     &s2n_ecdsa_sha512,
         *     &s2n_ecdsa_sha224,
         *
         *     /* SHA-1 Legacy */
         *     &s2n_rsa_pkcs1_sha1,
         *     &s2n_ecdsa_sha1,
         * };
         */
        let expected_signatures = BTreeSet::from_iter(
            vec![
                Signature::SigHash(Sig::RSA, Hash::SHA256),
                Signature::SigHash(Sig::RSA, Hash::SHA384),
                Signature::SigHash(Sig::RSA, Hash::SHA512),
                Signature::SigHash(Sig::RSA, Hash::SHA224),
                Signature::SigHash(Sig::RSA, Hash::SHA1),
                // ECDSA removed: none of the cipher suites actually allow for
                // ECDSA signature schemes
            ]
            .into_iter(),
        );

        /*
         * struct s2n_cipher_suite *cipher_suites_20170210[] = {
         *     &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
         *     &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
         *     &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
         *     &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
         *     &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
         *     &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
         *     &s2n_rsa_with_aes_128_gcm_sha256,
         *     &s2n_rsa_with_aes_128_cbc_sha256,
         *     &s2n_rsa_with_aes_128_cbc_sha
         * };
         */
        let expected_ciphers = BTreeSet::from_iter(vec![
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA),
        ]);

        assert_eq!(report.protocols, expected_protocols);
        assert_eq!(report.groups, expected_groups);
        assert_eq!(report.signatures, expected_signatures);
        assert_eq!(report.ciphers, expected_ciphers);
    }

    // coverage TLS 1.3, X25519
    #[test]
    fn sp_default_tls13() {
        let qe = QueryEngine::construct_engine();
        let report = qe.inspect_security_policy("default_tls13");
        println!("{:?}", report);
        let expected_protocols = BTreeSet::from_iter(
            vec![
                Protocol::TLS_1_0,
                Protocol::TLS_1_1,
                Protocol::TLS_1_2,
                Protocol::TLS_1_3,
            ]
            .into_iter(),
        );

        let expected_groups =
            BTreeSet::from_iter(vec![KxGroup::X25519, KxGroup::P_256, KxGroup::P_384].into_iter());

        let expected_signatures = BTreeSet::from_iter(
            vec![
                Signature::SignatureScheme(SignatureScheme::ecdsa_secp256r1_sha256),
                Signature::SignatureScheme(SignatureScheme::ecdsa_secp384r1_sha384),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha256),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha384),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha512),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha256), // TLS adores complexity, different cert
                Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha384),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha512),
                Signature::SigHash(Sig::RSA, Hash::SHA1),
                Signature::SigHash(Sig::RSA, Hash::SHA224),
                Signature::SigHash(Sig::RSA, Hash::SHA256),
                Signature::SigHash(Sig::RSA, Hash::SHA384),
                Signature::SigHash(Sig::RSA, Hash::SHA512),
                Signature::SigHash(Sig::RSA_PSS, Hash::SHA256),
                Signature::SigHash(Sig::RSA_PSS, Hash::SHA384),
                Signature::SigHash(Sig::RSA_PSS, Hash::SHA512),
                Signature::SigHash(Sig::ECDSA, Hash::SHA1),
                Signature::SigHash(Sig::ECDSA, Hash::SHA224),
                Signature::SigHash(Sig::ECDSA, Hash::SHA256),
                Signature::SigHash(Sig::ECDSA, Hash::SHA384),
                Signature::SigHash(Sig::ECDSA, Hash::SHA512),
            ]
            .into_iter(),
        );

        let expected_ciphers = BTreeSet::from_iter(vec![
            Cipher::Tls13(Tls13Cipher::TLS_AES_128_GCM_SHA256),
            Cipher::Tls13(Tls13Cipher::TLS_AES_256_GCM_SHA384),
            Cipher::Tls13(Tls13Cipher::TLS_CHACHA20_POLY1305_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        ]);

        assert_eq!(report.protocols, expected_protocols);
        assert_eq!(report.groups, expected_groups);
        assert_eq!(report.signatures, expected_signatures);
        assert_eq!(report.ciphers, expected_ciphers);
    }

    // coverage P-521
    #[test]
    fn sp_20230317() {
        let qe = QueryEngine::construct_engine();
        let report = qe.inspect_security_policy("20230317");
        println!("report: {:?}", report);
        let expected_protocols =
            BTreeSet::from_iter(vec![Protocol::TLS_1_2, Protocol::TLS_1_3].into_iter());

        let expected_groups =
            BTreeSet::from_iter(vec![KxGroup::P_256, KxGroup::P_384, KxGroup::P_521].into_iter());

        /*
         * const struct s2n_signature_scheme* const s2n_sig_scheme_pref_list_20230317[] = {
         *     /* RSA */
         *     &s2n_rsa_pss_rsae_sha256,
         *     &s2n_rsa_pss_rsae_sha384,
         *     &s2n_rsa_pss_rsae_sha512,
         *     &s2n_rsa_pkcs1_sha256,
         *     &s2n_rsa_pkcs1_sha384,
         *     &s2n_rsa_pkcs1_sha512,
         *
         *     /* TLS1.2 with ECDSA */
         *     &s2n_ecdsa_sha256, /* same iana value as TLS 1.3 s2n_ecdsa_secp256r1_sha256 */
         *     &s2n_ecdsa_sha384, /* same iana value as TLS 1.3 s2n_ecdsa_secp384r1_sha384 */
         *     &s2n_ecdsa_sha512,
         *
         *     /* TLS1.3 with ECDSA */
         *     &s2n_ecdsa_secp256r1_sha256,
         *     &s2n_ecdsa_secp384r1_sha384,
         *     &s2n_ecdsa_secp521r1_sha512,
         *
         *     /* TLS1.3 with RSA-PSS */
         *     &s2n_rsa_pss_pss_sha256,
         *     &s2n_rsa_pss_pss_sha384,
         *     &s2n_rsa_pss_pss_sha512,
         * };
         */
        let expected_signatures = BTreeSet::from_iter(
            vec![
                Signature::SignatureScheme(SignatureScheme::ecdsa_secp256r1_sha256),
                Signature::SignatureScheme(SignatureScheme::ecdsa_secp384r1_sha384),
                Signature::SignatureScheme(SignatureScheme::ecdsa_secp521r1_sha512),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha256),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha384),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_rsae_sha512),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha256), // TLS adores complexity, different cert
                Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha384),
                Signature::SignatureScheme(SignatureScheme::rsa_pss_pss_sha512),
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
            .into_iter(),
        );

        let expected_ciphers = BTreeSet::from_iter(vec![
            Cipher::Tls13(Tls13Cipher::TLS_AES_128_GCM_SHA256),
            Cipher::Tls13(Tls13Cipher::TLS_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        ]);

        assert_eq!(report.protocols, expected_protocols);
        assert_eq!(report.groups, expected_groups);
        assert_eq!(report.signatures, expected_signatures);
        assert_eq!(report.ciphers, expected_ciphers);
    }

    // coverage: diffie hellman groups
    // coverage: 3des
    #[test]
    fn sp_20140601() {
        let qe = QueryEngine::construct_engine();
        let report = qe.inspect_security_policy("20140601");
        let expected_protocols = BTreeSet::from_iter(
            vec![Protocol::TLS_1_0, Protocol::TLS_1_1, Protocol::TLS_1_2].into_iter(),
        );

        let expected_groups = BTreeSet::from_iter(vec![KxGroup::ffdhe2048].into_iter());

        /*
         * const struct s2n_signature_scheme* const s2n_sig_scheme_pref_list_20140601[] = {
         *     /* RSA PKCS1 */
         *     &s2n_rsa_pkcs1_sha256,
         *     &s2n_rsa_pkcs1_sha384,
         *     &s2n_rsa_pkcs1_sha512,
         *     &s2n_rsa_pkcs1_sha224,
         *
         *     /* ECDSA - TLS 1.2 */
         *     &s2n_ecdsa_sha256, /* same iana value as TLS 1.3 s2n_ecdsa_secp256r1_sha256 */
         *     &s2n_ecdsa_secp256r1_sha256,
         *     &s2n_ecdsa_sha384, /* same iana value as TLS 1.3 s2n_ecdsa_secp384r1_sha384 */
         *     &s2n_ecdsa_secp384r1_sha384,
         *     &s2n_ecdsa_sha512,
         *     &s2n_ecdsa_sha224,
         *
         *     /* SHA-1 Legacy */
         *     &s2n_rsa_pkcs1_sha1,
         *     &s2n_ecdsa_sha1,
         * };
         */
        let expected_signatures = BTreeSet::from_iter(
            vec![
                Signature::SigHash(Sig::RSA, Hash::SHA256),
                Signature::SigHash(Sig::RSA, Hash::SHA384),
                Signature::SigHash(Sig::RSA, Hash::SHA512),
                Signature::SigHash(Sig::RSA, Hash::SHA224),
                Signature::SigHash(Sig::RSA, Hash::SHA1),
                // ECDSA removed: none of the cipher suites actually allow for
                // ECDSA signature schemes
            ]
            .into_iter(),
        );

        /*
         * struct s2n_cipher_suite *cipher_suites_20140601[] = {
         *     &s2n_dhe_rsa_with_aes_128_cbc_sha256,
         *     &s2n_dhe_rsa_with_aes_128_cbc_sha,
         *     &s2n_dhe_rsa_with_3des_ede_cbc_sha,
         *     &s2n_rsa_with_aes_128_cbc_sha256,
         *     &s2n_rsa_with_aes_128_cbc_sha,
         *     &s2n_rsa_with_3des_ede_cbc_sha,
         *     &s2n_rsa_with_rc4_128_sha,
         *     &s2n_rsa_with_rc4_128_md5
         * };
         */
        let expected_ciphers = BTreeSet::from_iter(vec![
            Cipher::Legacy(LegacyCipher::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA256),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_AES_128_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_3DES_EDE_CBC_SHA),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_RC4_128_MD5),
            Cipher::Legacy(LegacyCipher::TLS_RSA_WITH_RC4_128_SHA),
            // EC4 removed: openssl has better security posture than us and
            // makes it _super_ difficult to use RC4 -> which might be a good
            // argument to deprecate it
        ]);

        assert_eq!(report.protocols, expected_protocols);
        assert_eq!(report.groups, expected_groups);
        assert_eq!(report.signatures, expected_signatures);
        assert_eq!(report.ciphers, expected_ciphers);
    }
}
