import collections

class Ciphers(object):
    """
    When referencing ciphers, use these class values.
    """
    ECDHE_ECDSA_AES128_GCM_SHA256 = "ECDHE_ECDSA_AES128_GCM_SHA256",
    ECDHE_ECDSA_AES128_SHA = "ECDHE_ECDSA_AES128_SHA",
    ECDHE_ECDSA_AES128_SHA256 = "ECDHE_ECDSA_AES128_SHA256",
    ECDHE_RSA_AES128_GCM_SHA256 = "ECDHE_RSA_AES128_GCM_SHA256",
    ECDHE_RSA_AES128_SHA = "ECDHE_RSA_AES128_SHA",
    ECDHE_RSA_AES128_SHA256 = "ECDHE_RSA_AES128_SHA256",
    AES128_GCM_SHA256 = "AES128_GCM_SHA256",

def make_test_case(key, cert_value):
    # TEST_SNI_CERT_DIRECTORY<key>_cert.pem
    pem_key = cert_value[0][len(TEST_SNI_CERT_DIRECTORY):-len("_cert.pem")]
    print(f"TestCase::new({key}, {pem_key}, &[{",".join(cert_value[3])}])")

TEST_SNI_CERT_DIRECTORY = "<CERT_DIRECTORY>"
# Server certificates used to test matching domain names client with server_name
# ( cert_path, private_key_path, domains[] )
SNI_CERTS = {
    "alligator": (
        TEST_SNI_CERT_DIRECTORY + "alligator_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "alligator_key.pem",
        ["www.alligator.com"]
    ),
    "second_alligator_rsa": (
        TEST_SNI_CERT_DIRECTORY + "second_alligator_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "second_alligator_rsa_key.pem",
        ["www.alligator.com"]
    ),
    "alligator_ecdsa": (
        TEST_SNI_CERT_DIRECTORY + "alligator_ecdsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "alligator_ecdsa_key.pem",
        ["www.alligator.com"]
    ),
    "beaver": (
        TEST_SNI_CERT_DIRECTORY + "beaver_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "beaver_key.pem",
        ["www.beaver.com"]
    ),
    "many_animals": (
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_rsa_key.pem",
        ["www.catfish.com",
         "www.dolphin.com",
         "www.elephant.com",
         "www.falcon.com",
         "www.gorilla.com",
         "www.horse.com",
         "www.impala.com",
         # "Simple hostname"
         "Jackal",
         "k.e.e.l.b.i.l.l.e.d.t.o.u.c.a.n",
         # SAN on this cert is actually "ladybug.ladybug"
         # Verify case insensitivity works as expected.
         "LADYBUG.LADYBUG",
         "com.penguin.macaroni"]
    ),
    "narwhal_cn": (
        TEST_SNI_CERT_DIRECTORY + "narwhal_cn_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "narwhal_cn_key.pem",
        ["www.narwhal.com"]
    ),
    "octopus_cn_platypus_san": (
        TEST_SNI_CERT_DIRECTORY + "octopus_cn_platypus_san_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "octopus_cn_platypus_san_key.pem",
        ["www.platypus.com"]
    ),
    "quail_cn_rattlesnake_cn": (
        TEST_SNI_CERT_DIRECTORY + "quail_cn_rattlesnake_cn_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "quail_cn_rattlesnake_cn_key.pem",
        ["www.quail.com", "www.rattlesnake.com"]
    ),
    "many_animals_mixed_case": (
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_mixed_case_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "many_animal_sans_mixed_case_rsa_key.pem",
        ["alligator.com",
         "beaver.com",
         "catFish.com",
         "WWW.dolphin.COM",
         "www.ELEPHANT.com",
         "www.Falcon.Com",
         "WWW.gorilla.COM",
         "www.horse.com",
         "WWW.IMPALA.COM",
         "WwW.jAcKaL.cOm"]
    ),
    "embedded_wildcard": (
        TEST_SNI_CERT_DIRECTORY + "embedded_wildcard_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "embedded_wildcard_rsa_key.pem",
        ["www.labelstart*labelend.com"]
    ),
    "non_empty_label_wildcard": (
        TEST_SNI_CERT_DIRECTORY + "non_empty_label_wildcard_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "non_empty_label_wildcard_rsa_key.pem",
        ["WILD*.middle.end"]
    ),
    "trailing_wildcard": (
        TEST_SNI_CERT_DIRECTORY + "trailing_wildcard_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "trailing_wildcard_rsa_key.pem",
        ["the.prefix.*"]
    ),
    "wildcard_insect": (
        TEST_SNI_CERT_DIRECTORY + "wildcard_insect_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "wildcard_insect_rsa_key.pem",
        ["ant.insect.hexapod",
         "BEE.insect.hexapod",
         "wasp.INSECT.hexapod",
         "butterfly.insect.hexapod"]
    ),
    "termite": (
        TEST_SNI_CERT_DIRECTORY + "termite_rsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "termite_rsa_key.pem",
        ["termite.insect.hexapod"]
    ),
    "underwing": (
        TEST_SNI_CERT_DIRECTORY + "underwing_ecdsa_cert.pem",
        TEST_SNI_CERT_DIRECTORY + "underwing_ecdsa_key.pem",
        ["underwing.insect.hexapod"]
    )
}




# Test cases for certificate selection.
# Test inputs: server certificates to load into s2nd, client SNI and capabilities, outputs are selected server cert
# and negotiated cipher.
MultiCertTest = collections.namedtuple(
    'MultiCertTest', 'description server_certs client_sni client_ciphers expected_cert expect_matching_hostname')
MULTI_CERT_TEST_CASES = [
    MultiCertTest(
        description="Test basic SNI match for default cert.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test basic SNI matches for non-default cert.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.beaver.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["beaver"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test default cert is selected when there are no SNI matches.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="not.a.match",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test default cert is selected when no SNI is sent.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni=None,
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test ECDSA cert is selected with matching domain and client only supports ECDSA.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_ECDSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test ECDSA cert selected when: domain matches for both ECDSA+RSA, client supports ECDSA+RSA "
                    " ciphers, ECDSA is higher priority on server side.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA,
                        Ciphers.ECDHE_ECDSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test domain match is highest priority. Domain matching ECDSA certificate should be selected"
                    " even if domain mismatched RSA certificate is available and RSA cipher is higher priority.",
        server_certs=[SNI_CERTS["beaver"], SNI_CERTS["alligator_ecdsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA256,
                        Ciphers.ECDHE_ECDSA_AES128_SHA256],
        expected_cert=SNI_CERTS["alligator_ecdsa"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test certificate with single SAN entry matching is selected before mismatched multi SAN cert",
        server_certs=[SNI_CERTS["many_animals"], SNI_CERTS["alligator"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
    # many_animals was the first cert added
    MultiCertTest(
        description="Test default cert with multiple sans and no SNI sent.",
        server_certs=[SNI_CERTS["many_animals"], SNI_CERTS["alligator"]],
        client_sni=None,
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["many_animals"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test certificate match with CN",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["narwhal_cn"]],
        client_sni="www.narwhal.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["narwhal_cn"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test SAN+CN cert can match using SAN.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["octopus_cn_platypus_san"]],
        client_sni="www.platypus.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["octopus_cn_platypus_san"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Test that CN is not considered for matching if the certificate contains SANs.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["octopus_cn_platypus_san"]],
        client_sni="www.octopus.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test certificate with multiple CNs can match.",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["quail_cn_rattlesnake_cn"]],
        client_sni="www.rattlesnake.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["quail_cn_rattlesnake_cn"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test cert with embedded wildcard is not treated as a wildcard.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["embedded_wildcard"]],
        client_sni="www.labelstartWILDCARDlabelend.com",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test non empty left label wildcard cert is not treated as a wildcard."\
                    " s2n only supports wildcards with a single * as the left label",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["non_empty_label_wildcard"]],
        client_sni="WILDCARD.middle.end",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Test cert with trailing * is not treated as wildcard.",
        server_certs=[SNI_CERTS["alligator"], SNI_CERTS["trailing_wildcard"]],
        client_sni="the.prefix.WILDCARD",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=False),
    MultiCertTest(
        description="Certificate with exact sni match(termite.insect.hexapod) is preferred over wildcard"\
                    " *.insect.hexapod",
        server_certs=[SNI_CERTS["wildcard_insect"],
                      SNI_CERTS["alligator"], SNI_CERTS["termite"]],
        client_sni="termite.insect.hexapod",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
        expected_cert=SNI_CERTS["termite"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="ECDSA Certificate with exact sni match(underwing.insect.hexapod) is preferred over RSA wildcard"\
                    " *.insect.hexapod when RSA ciphers are higher priority than ECDSA in server preferences.",
        server_certs=[SNI_CERTS["wildcard_insect"],
                      SNI_CERTS["alligator"], SNI_CERTS["underwing"]],
        client_sni="underwing.insect.hexapod",
        client_ciphers=[Ciphers.ECDHE_RSA_AES128_GCM_SHA256,
                        Ciphers.ECDHE_ECDSA_AES128_GCM_SHA256],
        expected_cert=SNI_CERTS["underwing"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Firstly loaded matching certificate should be selected among certificates with the same domain names",
        server_certs=[SNI_CERTS["alligator"],
                      SNI_CERTS["second_alligator_rsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.AES128_GCM_SHA256],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True),
    MultiCertTest(
        description="Firstly loaded matching certificate should be selected among matching+non-matching certificates",
        server_certs=[SNI_CERTS["beaver"], SNI_CERTS["alligator"],
                      SNI_CERTS["second_alligator_rsa"]],
        client_sni="www.alligator.com",
        client_ciphers=[Ciphers.AES128_GCM_SHA256],
        expected_cert=SNI_CERTS["alligator"],
        expect_matching_hostname=True)]
# Positive test for wildcard matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
    description="Test wildcard *.insect.hexapod matches subdomain " + specific_insect_domain,
    server_certs=[SNI_CERTS["alligator"], SNI_CERTS["wildcard_insect"]],
    client_sni=specific_insect_domain,
    client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
    expected_cert=SNI_CERTS["wildcard_insect"],
    expect_matching_hostname=True) for specific_insect_domain in SNI_CERTS["wildcard_insect"][2]])
# Positive test for basic SAN matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
    description="Match SAN " + many_animal_domain + " in many_animals cert",
    server_certs=[SNI_CERTS["alligator"], SNI_CERTS["many_animals"]],
    client_sni=many_animal_domain,
    client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
    expected_cert=SNI_CERTS["many_animals"],
    expect_matching_hostname=True) for many_animal_domain in SNI_CERTS["many_animals"][2]])
# Positive test for mixed cased SAN matches
MULTI_CERT_TEST_CASES.extend([MultiCertTest(
    description="Match SAN " + many_animal_domain +
    " in many_animals_mixed_case cert",
    server_certs=[SNI_CERTS["alligator"],
                  SNI_CERTS["many_animals_mixed_case"]],
    client_sni=many_animal_domain,
    client_ciphers=[Ciphers.ECDHE_RSA_AES128_SHA],
    expected_cert=SNI_CERTS["many_animals_mixed_case"],
    expect_matching_hostname=True) for many_animal_domain in SNI_CERTS["many_animals_mixed_case"][2]])

def make_test_case(key, cert_value):
    # TEST_SNI_CERT_DIRECTORY<key>_cert.pem
    pem_key = cert_value[0][len(TEST_SNI_CERT_DIRECTORY):-len("_cert.pem")]
    quoted_cert_values = [f'"{domain}"' for domain in cert_value[2]]
    print(f'TestCase::new("{key}", "{pem_key}", &[{",".join(quoted_cert_values)}])')

if __name__ == "__main__":
    for (key, value) in SNI_CERTS.items():
        make_test_case(key, value)
