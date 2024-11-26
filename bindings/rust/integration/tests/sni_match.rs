use std::{
    any::{type_name, type_name_of_val},
    collections::HashMap,
    fmt::Debug,
};

use openssl::{nid::Nid, x509::X509};

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
    QualCnRattlesnakeCn,
    ManyAnimalsMixedCase,
    EmbeddedWildcard,
    NonEmptyLabelWildcard,
    TrailingWildcard,
    WildcardInsect,
    Termite,
    Underwing,
}

impl SniTestCert {
    const SNI_PEMS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tests/pems/sni/");

    fn path_prefix(&self) -> &'static str {
        match *self {
            SniTestCert::AlligatorRsa => "alligator",
            SniTestCert::AlligatorRsa2 => "second_alligator_rsa",
            SniTestCert::AlligatorEcdsa => "alligator_ecdsa",
            SniTestCert::BeaverRsa => "beaver",
            SniTestCert::ManyAnimalsRsa => "many_animal_sans_rsa",
            SniTestCert::NarwhalCn => "narwhal_cn",
            SniTestCert::OctopusCnPlatypusSan => "octopus_cn_platypus_san",
            SniTestCert::QualCnRattlesnakeCn => "quail_cn_rattlesnake_cn",
            SniTestCert::ManyAnimalsMixedCase => "many_animal_sans_mixed_case_rsa",
            SniTestCert::EmbeddedWildcard => "embedded_wildcard_rsa",
            SniTestCert::NonEmptyLabelWildcard => "non_empty_label_wildcard_rsa",
            SniTestCert::TrailingWildcard => "trailing_wildcard_rsa",
            SniTestCert::WildcardInsect => "wildcard_insect_rsa",
            SniTestCert::Termite => "termite_rsa",
            SniTestCert::Underwing => "underwing_ecdsa",
        }
    }

    fn x509(&self) -> X509 {
        let cert = std::fs::read(format!(
            "{}/{}_cert.pem",
            Self::SNI_PEMS_PATH,
            self.path_prefix()
        ))
        .unwrap();
        X509::from_pem(&cert).unwrap()
    }

    fn common_names(&self) -> Vec<String> {
        self.x509()
            .subject_name()
            .entries()
            .filter(|e| e.object().nid() == Nid::COMMONNAME)
            .map(|e| String::from_utf8(e.data().as_slice().to_owned()).unwrap())
            .collect()
    }

    fn sans(&self) -> Option<Vec<String>> {
        match self.x509().subject_alt_names() {
            Some(name) => Some(
                name.into_iter()
                    .map(|n| n.dnsname().unwrap().to_owned())
                    .collect(),
            ),
            None => None,
        }
    }
}

impl Debug for SniTestCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniTestCert")
            .field("common name", &self.common_names())
            .field("sans", &self.sans())
            .finish()
    }
}

enum AuthType {
    Rsa,
    Ecdsa,
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
    fn request_with_client_support(
        &self,
        sni: Option<&str>,
        client_support: Vec<AuthType>,
        expected_cert: SniTestCert,
    ) {
        // disable hostname validation on the client

        // the only trusted cert is the expected cert. So if something other than
        // the expected cert is returned, then the handshake will fail.
    }
}

#[test]
#[should_panic]
fn harness_sanity_check() {
    // ensure that returning a non-expected cert results in a failure
}

#[test]
fn cert_debug() {
    println!("{:#?}", SniTestCert::ManyAnimalsMixedCase);
    println!("{:#?}", SniTestCert::WildcardInsect);
    println!("{:#?}", SniTestCert::QualCnRattlesnakeCn);
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
    let setup = TestCase::new(
        vec![SniTestCert::AlligatorRsa, SniTestCert::AlligatorEcdsa],
        Some(SniTestCert::BeaverRsa),
    );

    // server returns the supported auth type
    // when
    //     - the server supports multiple auth types for the request domain
    //     - the client supports a single auth type
    // then
    //    -> the server chooses the client-supported option
    setup.request_with_client_support(
        Some("www.alligator.com"),
        vec![AuthType::Ecdsa],
        SniTestCert::AlligatorEcdsa,
    );
    setup.request_with_client_support(
        Some("www.alligator.com"),
        vec![AuthType::Rsa],
        SniTestCert::AlligatorRsa,
    );

    // server returns server preference auth type
    // when
    //     - the server supports multiple auth types AND
    //     - the client supports multiple auth types
    // then
    //     -> the server chooses the server-preferred option
    setup.request_with_client_support(
        Some("www.alligator.com"),
        // client prefers RSA
        vec![AuthType::Rsa, AuthType::Ecdsa],
        // but the server should return ECDSA
        // security policy X prefers ECDSA
        SniTestCert::AlligatorEcdsa,
    );
}

#[test]
fn match_priority() {
    // domain match has greater priority than client auth preferences

    // domain match prioritized even with invalid parameters
    // The server will prefer to return a matching certificate if it exists, even
    // if the client doesn't indicate support for that auth type.

    // we really need more tests for these behaviors in TLS 1.3 too
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
    {
        assert_eq!()
    }

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
