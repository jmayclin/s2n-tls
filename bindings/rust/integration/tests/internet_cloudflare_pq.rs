// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{config::Config, error::ErrorType};
use std::error::Error;
use tokio::net::TcpStream;
use tracing::level_filters::LevelFilter;

/// Purpose: test PQ negotiation "in the wild". 
/// 
/// Some CDNs like CloudFlare will forcibly fail the conection for certain PQ 
/// configuration. We want to ensure that our default_pq policy is able to negotiate
/// with these CDNs, and we also want to make sure we more generally understand
/// their behavior
///
/// This test makes network calls over the public internet.
#[tokio::test]
async fn cloudflare_pq_test() -> Result<(), Box<dyn Error>> {
    const DOMAIN: &str = "cloudflare.com";
    const SOCKET_ADDR: (&str, u16) = (DOMAIN, 443);

    #[derive(Debug)]
    struct TestCase {
        s2n_security_policy: &'static str,
        successful_handshake: bool,
        expected_kem_group: Option<&'static str>,
    }

    const TEST_CASES: &[TestCase] = &[
        // default_pq only inlucdes support for standardized ML-KEM, which should
        // be successfully negotiated. While the default_pq policy may change, we
        // do always expect that it will successfully negotiate PQ with cloudflare.
        TestCase {
            s2n_security_policy: "default_pq",
            successful_handshake: true,
            expected_kem_group: Some("X25519MLKEM768"),
        },
        // 20241001_pq_mixed includes support for both standard and draft PQ. 
        // negotiation should be succesful.
        TestCase {
            s2n_security_policy: "20241001_pq_mixed",
            successful_handshake: true,
            expected_kem_group: Some("X25519MLKEM768"),
        },
        // KMS-PQ-TLS-1-0-2020-07 only includes support for draft versions of kyber,
        // which cloudflare does not support. Negotiation is expected to fail.
        TestCase {
            s2n_security_policy: "KMS-PQ-TLS-1-0-2020-07",
            successful_handshake: false,
            expected_kem_group: None,
        },
        TestCase {
            s2n_security_policy: "test_all_tls12",
            successful_handshake: false,
            expected_kem_group: None,
        },
        TestCase {
            s2n_security_policy: "test_all",
            successful_handshake: false,
            expected_kem_group: None,
        },
        // default doesn't support pq, and should also succeed.
        // TODO: switch to numbered policy
        TestCase {
            s2n_security_policy: "default",
            successful_handshake: true,
            expected_kem_group: None,
        },
    ];

    async fn test(test_case: &TestCase) -> Result<(), Box<dyn std::error::Error>> {
        // config will use the system trust store by default, which is sufficient
        let mut config = Config::builder();
        config.set_security_policy(&s2n_tls::security::Policy::from_version(
            test_case.s2n_security_policy,
        )?)?;

        tracing::info!("executing test case: {:#?}", test_case);

        let client = s2n_tls_tokio::TlsConnector::new(config.build()?);
        // open the TCP stream
        let stream = TcpStream::connect(SOCKET_ADDR).await?;
        // complete the TLS handshake
        let tls = client.connect(DOMAIN, stream).await;

        if test_case.successful_handshake {
            assert_eq!(
                tls.unwrap().as_ref().kem_group_name()?,
                test_case.expected_kem_group
            );
        } else {
            // CloudFlare behavior: If a client requests PQ but PQ can't be negotiated,
            // fail the handshake rather than falling back to classical key excahnge.
            assert_eq!(tls.unwrap_err().kind(), ErrorType::Alert);
        }

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
