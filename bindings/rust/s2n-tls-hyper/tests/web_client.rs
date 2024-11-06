// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http::{status, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use s2n_tls::config::Config;
use s2n_tls_hyper::connector::HttpsConnector;
use std::{error::Error, str::FromStr};
use tracing_subscriber::filter::LevelFilter;

#[tokio::test]
async fn http_get() -> Result<(), Box<dyn Error>> {
    struct TestCase {
        pub domain: &'static str,
        pub expected_status_code: u16,
    }

    impl TestCase {
        const fn new(domain: &'static str, expected_status_code: u16) -> Self {
            TestCase {
                domain,
                expected_status_code,
            }
        }
    }

    const TEST_CASES: &[TestCase] = &[
        // "https://www.akamai.com", HANGS?
        // "kms.us-east-1.amazonaws.com", NOT HTTP
        // "s3.us-west-2.amazonaws.com", NOT HTTP
        TestCase::new("https://www.amazon.com", 200),
        TestCase::new("https://www.apple.com", 200),
        TestCase::new("https://www.att.com", 200),
        TestCase::new("https://www.cloudflare.com", 200),
        TestCase::new("https://www.ebay.com", 200),
        TestCase::new("https://www.google.com", 200),
        TestCase::new("https://www.mozilla.org", 200),
        TestCase::new("https://www.netflix.com", 200),
        TestCase::new("https://www.openssl.org", 200),
        TestCase::new("https://www.t-mobile.com", 200),
        TestCase::new("https://www.verizon.com", 200),
        TestCase::new("https://www.wikipedia.org", 200),
        TestCase::new("https://www.yahoo.com", 200),
        TestCase::new("https://www.youtube.com", 200),

        TestCase::new("https://www.github.com", 301),
        TestCase::new("https://www.samsung.com", 301),
        TestCase::new("https://www.twitter.com", 301),

        TestCase::new("https://www.facebook.com", 302),
        TestCase::new("https://www.microsoft.com", 302),

        TestCase::new("https://www.ibm.com", 303),

        TestCase::new("https://www.f5.com/", 403),
    ];

    async fn get(test_case: &TestCase) -> Result<(), Box<dyn Error>> {
        let connector = HttpsConnector::new(Config::default());
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let uri = Uri::from_str(test_case.domain)?;
        let response = client.get(uri).await?;

        let expected_status = StatusCode::from_u16(test_case.expected_status_code).unwrap();
        assert_eq!(response.status(), expected_status);

        if expected_status == StatusCode::OK {
            let body = response.into_body().collect().await?.to_bytes();
            assert!(!body.is_empty());
        }

        Ok(())
    }

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .init();

    for case in TEST_CASES {
        tracing::info!("querying {}", case.domain);
        get(case).await?;
    }
    Ok(())
}

// #[tokio::test]
// async fn pq_test() -> Result<(), Box<dyn Error>> {
//     struct TestCase {
//         s2n_security_policy: &str,
//         expected_cipher: &str,
//         expected_kem: Option<&str>,
//     };

//     const TEST_CASES: &[TestCase] = &[
//         TestCase {
//             s2n_security_policy: "KMS_PQ_TLS_1_0_2019_06",
//             expected_cipher: "no",
//             expected_kem: None,
//         },
//         TestCase {
//             s2n_security_policy: "KMS_PQ_TLS_1_0_2019_06",
//             expected_cipher: "no",
//             expected_kem: None,
//         },
//         TestCase {
//             s2n_security_policy: "KMS_PQ_TLS_1_0_2019_06",
//             expected_cipher: "no",
//             expected_kem: None,
//         },
//     ];

//     const SECURITY_POLICIES: &[&str] = &[
//         KMS_PQ_TLS_1_0_2019_06,
//         PQ_SIKE_TEST_TLS_1_0_2019_11,
//         KMS_PQ_TLS_1_0_2020_07,
//         KMS_PQ_TLS_1_0_2020_02,
//         PQ_SIKE_TEST_TLS_1_0_2020_02,
//     ];
// }
