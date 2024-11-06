// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http::{status, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use s2n_tls::config::Config;
use s2n_tls_hyper::connector::HttpsConnector;
use std::{error::Error, str::FromStr};
use tokio::net::TcpStream;
use tracing_subscriber::filter::LevelFilter;

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
            s2n_security_policy: "KMS-PQ-TLS-1-0-2020-07",
            expected_cipher: "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
            expected_kem: Some("kyber512r3"),
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

        // Create the TlsConnector based on the configuration.
        let client = s2n_tls_tokio::TlsConnector::new(config.build()?);

        // Connect to the server.
        let stream = TcpStream::connect(SOCKET_ADDR).await?;
        let tls = client.connect(DOMAIN, stream).await?;

        let conn = tls.as_ref();

        assert_eq!(conn.cipher_suite()?, test_case.expected_cipher);
        assert_eq!(conn.kem_name()?, test_case.expected_kem);

        Ok(())
    }

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .init();

    for test_case in TEST_CASES {
        test(test_case).await?
    }

    Ok(())
}
