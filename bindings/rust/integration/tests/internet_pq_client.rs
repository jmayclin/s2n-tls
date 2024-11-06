// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::config::Config;
use std::error::Error;
use tokio::net::TcpStream;

/// Purpose: ensure that we remain compatible with existing pq AWS deployments.
/// 
/// This test makes network calls over the public internet.
/// 
/// KMS is a notable service with PQ support. Assert that we successfully negotiate
/// with that service
#[tokio::test]
async fn pq_test() -> Result<(), Box<dyn Error>> {
    const DOMAIN: &str = "kms.us-east-1.amazonaws.com";
    const SOCKET_ADDR: (&str, u16) = (DOMAIN, 443);

    struct TestCase {
        s2n_security_policy: &'static str,
        expected_cipher: &'static str,
        expected_kem: Option<&'static str>,
    }

    const TEST_CASES: &[TestCase] = &[
        // TODO: ask the pq people why the no-pq cases have been left in 🧐
        TestCase {
            s2n_security_policy: "KMS-PQ-TLS-1-0-2020-07",
            expected_cipher: "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
            expected_kem: Some("kyber512r3"),
        },
        TestCase {
            s2n_security_policy: "KMS-PQ-TLS-1-0-2019-06",
            expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
            expected_kem: None,
        },
        TestCase {
            s2n_security_policy: "PQ-SIKE-TEST-TLS-1-0-2019-11",
            expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
            expected_kem: None,
        },
        TestCase {
            s2n_security_policy: "KMS-PQ-TLS-1-0-2020-02",
            expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
            expected_kem: None,
        },
        TestCase {
            s2n_security_policy: "PQ-SIKE-TEST-TLS-1-0-2020-02",
            expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
            expected_kem: None,
        },
    ];

    async fn test(test_case: &TestCase) -> Result<(), Box<dyn std::error::Error>> {
        // config will use the system trust store by default, which is sufficient
        let mut config = Config::builder();
        config.set_security_policy(&s2n_tls::security::Policy::from_version(
            test_case.s2n_security_policy,
        )?)?;

        let client = s2n_tls_tokio::TlsConnector::new(config.build()?);
        // open the TCP stream
        let stream = TcpStream::connect(SOCKET_ADDR).await?;
        // complete the TLS handshake
        let tls = client.connect(DOMAIN, stream).await?;

        assert_eq!(tls.as_ref().cipher_suite()?, test_case.expected_cipher);
        assert_eq!(tls.as_ref().kem_name()?, test_case.expected_kem);

        Ok(())
    }

    for test_case in TEST_CASES {
        test(test_case).await?
    }

    Ok(())
}
