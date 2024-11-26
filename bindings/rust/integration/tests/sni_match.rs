use std::collections::HashMap;

/// The informal name of the cert, like "alligator_ecdsa" or "mixed_wildcards"
type CertName = &'static str;

struct TestCert {
    cert_name: CertName,
    /// PEM encoded certificate
    cert: Vec<u8>,
    /// PEM encoded private key
    key: Vec<u8>,
    domains: Vec<&'static str>,
}

enum SniTestCert {
    AlligatorRsa,
    AlligatorRsa2,
    AlligatorEcdsa,
    BeaverRsa,
    ManyAnimalsRsa,
    NarwhalCn,
    OctopusCnPlatypusSan,
    QuailCnRattlesnakeSan,
    ManyAnimalsMixedCase,
    EmbeddedWildcard,
    NonEmptyLabelWildcard,
    TrailingWildcard,
    WildcardInsect,
    Termite,
    Underwing,
}

enum AuthType {
    Rsa,
    Ecdsa
}

struct TestCase {
    certs: Vec<SniTestCert>,
    default: Option<SniTestCert>,
}

impl TestCase {
    fn new(certs: Vec<SniTestCert>, default: Option<SniTestCert>) -> Self {
        Self { certs, default }
    }

    /// This method handles assertions internally
    fn request(&self, sni: Option<&str>, expected_cert: SniTestCert) {
        // disable hostname validation on the client

        // the only trusted cert is the expected cert. So if something other than
        // the expected cert is returned, then the handshake will fail.
    }

    /// This method handles assertions internally
    fn request_with_client_support(&self, sni: Option<&str>, client_support: Vec<AuthType>, expected_cert: SniTestCert) {
        // disable hostname validation on the client

        // the only trusted cert is the expected cert. So if something other than
        // the expected cert is returned, then the handshake will fail.
    }
}

#[test]
fn harness_sanity_check() {
    // ensure that returning a non-expected cert results in a failure
}

#[test]
fn positive_sni_match() {
    let setup = TestCase::new(
        vec![
            SniTestCert::AlligatorRsa,
            SniTestCert::BeaverRsa,
            SniTestCert::ManyAnimalsRsa,
        ],
        Some(SniTestCert::AlligatorRsa),
    );

    // sni match for default cert
    setup.request(Some("www.alligator.com"), SniTestCert::AlligatorRsa);

    // sni match for non-default cert
    setup.request(Some("www.beaver.com"), SniTestCert::BeaverRsa);
}

#[test]
fn negative_sni_match() {
    let setup = TestCase::new(
        vec![
            SniTestCert::AlligatorRsa,
            SniTestCert::BeaverRsa,
            SniTestCert::AlligatorEcdsa,
        ],
        Some(SniTestCert::AlligatorRsa),
    );

    // default cert is returned if there are no SNI matches
    setup.request(Some("no.matching.domain"), SniTestCert::AlligatorRsa);

    // default cert is returned if no SNI is sent
    setup.request(None, SniTestCert::AlligatorRsa);

}

#[test]
fn auth_priority() {
    // server returns the supported auth type
    // when
    //     - the server supports multiple auth types for the request domain
    //     - the client supports a single auth type
    // then
    //    -> the server chooses the client-supported option

    // server returns server preference auth type
    // when
    //     - the server supports multiple auth types AND
    //     - the client supports multiple auth types
    // then
    //     -> the server chooses the server-preferred option
}

#[test]
fn match_priority() {
    // domain match has greater priotity than auth match
}

#[test]
fn cn_matching() {
    // positive - cert with single CN and no SANs

    // postive - cert with multiple CNs and no SANs

    // negative - cert with CN and SANs will not match on CN
}

#[test]
fn san_matching() {
    // positive - cert with a single SAN will match
    // positive - cert with multiple SANs will match
}

#[test]
fn wildcard_matching() {
    // s2n-tls only supports wildcards with a single * as the left label, e.g. *.b.c
    // positive case(s):

    // negative case: embedded wildcard is not treated as a wildcard e.g. a.*.c

    // negative case: trailing * is not treated as a wildcard, e.g. a.b.*
}

#[test]
fn wildcard_matching_priority() {
    // exact sni match is preferred over wildcard match

    // exact sni match is preferred over wildcard match, even if client
}

#[test]
fn loading_order() {}

#[test]
fn case_sensitivity() {
    // case insensitive SAN match

    // case insensitive wildcard match
}

impl TestCert {
    /// Create a reference to an existing TestCert
    ///
    /// ### Arguments
    /// * `cert_name`: The informal name of the cert, e.g. "termite"
    /// * `cert_key`: The key used in the cert.pem and key.pem paths, e.g. "termite_rsa"
    /// * `domains`: The names included as SANs or CNs on the cert
    fn new(
        cert_name: &'static str,
        cert_key: &'static str,
        domains: &'static [&'static str],
    ) -> Self {
        const CERT_DIRECTORY: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tests/pems/sni");

        let cert = std::fs::read(format!("{CERT_DIRECTORY}/{cert_key}_cert.pem")).unwrap();
        let key = std::fs::read(format!("{CERT_DIRECTORY}/{cert_key}_key.pem")).unwrap();
        TestCert {
            cert_name,
            cert,
            key,
            domains: domains.to_owned(),
        }
    }
}

struct CertStore {
    certs: HashMap<CertName, TestCert>,
}

impl CertStore {
    fn from_sni_test_certs() -> Self {
        let certs = vec![
            TestCert::new("alligator", "alligator", &["www.alligator.com"]),
            TestCert::new(
                "second_alligator_rsa",
                "second_alligator_rsa",
                &["www.alligator.com"],
            ),
            TestCert::new("alligator_ecdsa", "alligator_ecdsa", &["www.alligator.com"]),
            TestCert::new("beaver", "beaver", &["www.beaver.com"]),
            TestCert::new(
                "many_animals",
                "many_animal_sans_rsa",
                &[
                    "www.catfish.com",
                    "www.dolphin.com",
                    "www.elephant.com",
                    "www.falcon.com",
                    "www.gorilla.com",
                    "www.horse.com",
                    "www.impala.com",
                    "Jackal",
                    "k.e.e.l.b.i.l.l.e.d.t.o.u.c.a.n",
                    "LADYBUG.LADYBUG",
                    "com.penguin.macaroni",
                ],
            ),
            TestCert::new("narwhal_cn", "narwhal_cn", &["www.narwhal.com"]),
            TestCert::new(
                "octopus_cn_platypus_san",
                "octopus_cn_platypus_san",
                &["www.platypus.com"],
            ),
            TestCert::new(
                "quail_cn_rattlesnake_cn",
                "quail_cn_rattlesnake_cn",
                &["www.quail.com", "www.rattlesnake.com"],
            ),
            TestCert::new(
                "many_animals_mixed_case",
                "many_animal_sans_mixed_case_rsa",
                &[
                    "alligator.com",
                    "beaver.com",
                    "catFish.com",
                    "WWW.dolphin.COM",
                    "www.ELEPHANT.com",
                    "www.Falcon.Com",
                    "WWW.gorilla.COM",
                    "www.horse.com",
                    "WWW.IMPALA.COM",
                    "WwW.jAcKaL.cOm",
                ],
            ),
            TestCert::new(
                "embedded_wildcard",
                "embedded_wildcard_rsa",
                &["www.labelstart*labelend.com"],
            ),
            TestCert::new(
                "non_empty_label_wildcard",
                "non_empty_label_wildcard_rsa",
                &["WILD*.middle.end"],
            ),
            TestCert::new(
                "trailing_wildcard",
                "trailing_wildcard_rsa",
                &["the.prefix.*"],
            ),
            TestCert::new(
                "wildcard_insect",
                "wildcard_insect_rsa",
                &[
                    "ant.insect.hexapod",
                    "BEE.insect.hexapod",
                    "wasp.INSECT.hexapod",
                    "butterfly.insect.hexapod",
                ],
            ),
            TestCert::new("termite", "termite_rsa", &["termite.insect.hexapod"]),
            TestCert::new(
                "underwing",
                "underwing_ecdsa",
                &["underwing.insect.hexapod"],
            ),
        ];

        let certs =
            HashMap::from_iter(certs.into_iter().map(|cert| (cert.cert_name.clone(), cert)));

        CertStore { certs }
    }
}

enum CertType {
    Rsa,
    Ecdsa,
}

struct TestCase {
    // the certs loaded on the server. Order is important because the first
    // cert that is loaded for each type (ECDSA/RSA) will be the default
    server_certs: Vec<CertName>,
    client_sni: Option<&'static str>,
    // order is important and represents client preference. First is more preferred.
    client_support: Vec<CertType>,
    expected_cert: CertName,
    expect_hostname_match: bool,
}

#[test]
fn it_works() {
    let store = CertStore::from_sni_test_certs();
    assert_eq!(store.certs.len(), 15);
}
