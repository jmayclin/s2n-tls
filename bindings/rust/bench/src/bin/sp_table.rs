use std::sync::atomic::AtomicU32;

use bench::scanner::{
    compliance::{ComplianceRegime, CryptoRecommendation20231130},
    params::{KeyExchange, KxGroup, Protocol, Sig, Signature},
    Report,
};
use rayon::prelude::*;
use strum::IntoEnumIterator;

struct Column {
    header: &'static str,
    query: fn(&Report) -> bool,
}

struct Table(Vec<Column>);

impl Table {
    fn ProtocolAndCipher() -> Self {
        let c = vec![
            Column {
                header: "TLS1.0",
                query: |report| report.protocols.contains(&Protocol::TLS_1_0),
            },
            Column {
                header: "TLS1.1",
                query: |report| report.protocols.contains(&Protocol::TLS_1_1),
            },
            Column {
                header: "TLS1.2",
                query: |report| report.protocols.contains(&Protocol::TLS_1_2),
            },
            Column {
                header: "TLS1.3",
                query: |report| report.protocols.contains(&Protocol::TLS_1_3),
            },
            Column {
                header: "AES-CBC",
                query: |report| {
                    report.supports_cipher("AES_128_CBC") || report.supports_cipher("AES_256_CBC")
                },
            },
            Column {
                header: "AES-GCM",
                query: |report| {
                    report.supports_cipher("AES_128_GCM") || report.supports_cipher("AES_256_GCM")
                },
            },
            Column {
                header: "CHACHAPOLY",
                query: |report| report.supports_cipher("CHACHA"),
            },
            Column {
                header: "3DES",
                query: |report| report.supports_cipher("3DES"),
            },
            Column {
                header: "RC4",
                query: |report| report.supports_cipher("RC4"),
            },
            Column {
                header: "DHE",
                query: |report| {
                    report
                        .groups
                        .iter()
                        .any(|g| g.key_exchange() == KeyExchange::DHE)
                },
            },
            Column {
                header: "ECDHE",
                query: |report| {
                    report
                        .groups
                        .iter()
                        .any(|g| g.key_exchange() == KeyExchange::ECDHE)
                },
            },
        ];
        Table(c)
    }

    fn Signature() -> Self {
        let c = vec![
            Column {
                header: "RSA PKCS1",
                query: |report| {
                    report.signatures.iter().any(|s| match s {
                        Signature::SignatureScheme(s) => s.get_sig() == Some(Sig::RSA),
                        Signature::SigHash(Sig::RSA, _) => true,
                        _ => false,
                    })
                },
            },
            Column {
                header: "ECDSA",
                query: |report| {
                    report.signatures.iter().any(|s| match s {
                        Signature::SignatureScheme(s) => s.get_sig() == Some(Sig::ECDSA),
                        Signature::SigHash(Sig::ECDSA, _) => true,
                        _ => false,
                    })
                },
            },
            Column {
                header: "SHA-1 Legacy",
                query: |report| report.supports_sha1(),
            },
            Column {
                header: "RSA PSS",
                query: |report| {
                    report.signatures.iter().any(|s| match s {
                        Signature::SignatureScheme(s) => s.get_sig() == Some(Sig::RSA_PSS),
                        Signature::SigHash(Sig::RSA_PSS, _) => true,
                        _ => false,
                    })
                },
            },
        ];
        Table(c)
    }

    fn Groups() -> Self {
        let c = vec![
            Column {
                header: "secp256r1",
                query: |report| report.groups.contains(&KxGroup::P_256),
            },
            Column {
                header: "secp384r1",
                query: |report| report.groups.contains(&KxGroup::P_384),
            },
            Column {
                header: "secp512r1",
                query: |report| report.groups.contains(&KxGroup::P_521),
            },
            Column {
                header: "x25519",
                query: |report| report.groups.contains(&KxGroup::X25519),
            },
        ];
        Table(c)
    }

    fn Compliance() -> Self {
        let c = vec![Column {
            header: CryptoRecommendation20231130::regime(),
            query: |report| CryptoRecommendation20231130::compliance(report).is_ok(),
        }];
        Table(c)
    }

    fn write(&self, policies: &Vec<Report>) {
        // + 2 for space on each side of the column
        let mut col_widths: Vec<usize> = self.0.iter().map(|c| c.header.len() + 2).collect();
        let first_width = policies.iter().map(|r| r.endpoint.len() + 2).max().unwrap();

        // write headers
        print!("|{}", Self::centered_token("version", first_width));
        for c in self.0.iter() {
            print!("| {} ", c.header);
        }
        println!("|");

        // write border
        print!("|{}", Self::separator_token(first_width));
        for w in col_widths.iter() {
            print!("|{}", Self::separator_token(*w));
        }
        println!("|");

        for report in policies {
            print!("|{}", Self::centered_token(&report.endpoint, first_width));
            for (c, width) in self.0.iter().zip(col_widths.iter()) {
                let mut token = vec![b' '; *width];
                let center = *width / 2;
                if (c.query)(report) {
                    token[center] = b'X';
                }
                print!("|{}", String::from_utf8(token).unwrap());
            }
            println!("|");
        }
        println!(""); // add a newline
    }

    fn centered_token(token: &str, width: usize) -> String {
        let token_width = token.len();
        let remaining = width - token_width;
        let left = vec![b' '; remaining / 2];
        let right = vec![b' '; remaining - left.len()];
        format!(
            "{}{}{}",
            String::from_utf8(left).unwrap(),
            token,
            String::from_utf8(right).unwrap()
        )
    }

    fn separator_token(width: usize) -> String {
        String::from_utf8(vec![b'-'; width]).unwrap()
    }
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init()
        .unwrap();
    let query = bench::scanner::QueryEngine::construct_engine();
    log::info!("Query engine capabilities: {:?}", query);

    let sp = vec![
        "default",
        "default_tls13",
        "default_fips",
        "20190214",
        "20170718",
        "20170405",
        "20170328",
        "20170210",
        "20160824",
        "20160804",
        "20160411",
        "20150306",
        "20150214",
        "20150202",
        "20141001",
        "20140601",
        "20190120",
        "20190121",
        "20190122",
        "20190801",
        "20190802",
        "20200207",
        "20230317",
        "rfc9151",
        "CloudFront-TLS-1-2-2021",
    ];

    let sp = vec![
        "default",
        "default_tls13",
        "default_fips",
        "20190214",
        "20230317",
        "rfc9151",
        "CloudFront-TLS-1-2-2021",
    ];

    let sp =  bench::scanner::security_policies::SECURITY_POLICIES;

    let total = sp.len();
    for p in sp {
        let res = query.inspect_security_policy(p);
    }
    let reports: Vec<Report> = Vec::new();
    return;
    //let progress = AtomicU32::new(total as u32);
    //let mut reports: Vec<Report> = sp
    //    .iter()
    //    .map(|sp| query.inspect_security_policy(*sp))
    //    .inspect(|r| {
    //        progress.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    //        println!("{:?} remaining", progress);
    //    })
    //    .collect();

    // TODO: I don't think this clone should be here
    reports.sort_by_key(|r| r.endpoint.clone());

    let protocol_and_cipher = Table::ProtocolAndCipher();
    protocol_and_cipher.write(&reports);

    // 20140601
    /*
        const struct s2n_security_policy security_policy_20140601 = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_20140601,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20140601,
            .ecc_preferences = &s2n_ecc_preferences_20140601,
        };
     */

    // 20141001
    /*
        const struct s2n_security_policy security_policy_20141001 = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_20141001,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20140601,
            .ecc_preferences = &s2n_ecc_preferences_20140601,
        };
     */
    // 20150202
    /*
        const struct s2n_security_policy security_policy_20150202 = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_20150202,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20140601,
            .ecc_preferences = &s2n_ecc_preferences_20140601,
        };
     */

    // 20150214
    /*
        const struct s2n_security_policy security_policy_20150214 = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_20150214,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20140601,
            .ecc_preferences = &s2n_ecc_preferences_20140601,
        };
     */

    // test_all
    /*
        const struct s2n_security_policy security_policy_test_all = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_all,
            .kem_preferences = &kem_preferences_all,
            .signature_preferences = &s2n_signature_preferences_20201021,
            .ecc_preferences = &s2n_ecc_preferences_test_all,
        };
     */

    //
    /*
        const struct s2n_security_policy security_policy_test_all_fips = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_test_all_fips,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20201021,
            .ecc_preferences = &s2n_ecc_preferences_20201021,
        };
     */

    // test_all_rsa_kex
    /*
        const struct s2n_security_policy security_policy_test_all_rsa_kex = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_test_all_rsa_kex,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20140601,
            .ecc_preferences = &s2n_ecc_preferences_20140601,
        };
     */

    // test_ecdsa_priority
    /*
        const struct s2n_security_policy security_policy_test_ecdsa_priority = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_ecdsa_priority,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20201021,
            .ecc_preferences = &s2n_ecc_preferences_test_all,
        };
    */

    // test_all_tls12
    /*
        const struct s2n_security_policy security_policy_test_all_tls12 = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_all_tls12,
            .kem_preferences = &kem_preferences_pq_tls_1_0_2021_05,
            .signature_preferences = &s2n_signature_preferences_20201021,
            .ecc_preferences = &s2n_ecc_preferences_20201021,
        };
     */

    let sigs = Table::Signature();
    sigs.write(&reports);

    let groups = Table::Groups();
    groups.write(&reports);

    let compliance = Table::Compliance();
    compliance.write(&reports);

    let crypo_report: Vec<(String, Result<(), Vec<String>>)> = reports
        .iter()
        .map(|r| (r.endpoint.clone(), CryptoRecommendation20231130::compliance(r)))
        .collect();

    std::fs::write(
        "sp-capabilities.json",
        serde_json::to_string_pretty(&reports).unwrap(),
    )
    .unwrap();

    std::fs::write(
        "sp-compliance.json",
        serde_json::to_string_pretty(&crypo_report).unwrap(),
    )
    .unwrap();
}
