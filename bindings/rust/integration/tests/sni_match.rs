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
