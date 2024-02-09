use std::sync::atomic::AtomicU32;

use bench::scanner::{
    compliance::{ComplianceRegime, CryptoRecommendation20231130},
    params::{Cipher, KeyExchange, KxGroup, Protocol, Sig, Signature},
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
            Column {
                header: "RSA kx",
                query: |report| {
                    report
                        .ciphers
                        .iter()
                        .filter_map(|c| match c {
                            Cipher::Tls13(_) => None,
                            Cipher::Legacy(legacy) => Some(legacy),
                        })
                        .any(|c| c.key_exchange() == Some(KeyExchange::RSA))
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
        let col_widths: Vec<usize> = self.0.iter().map(|c| c.header.len() + 2).collect();
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
            // print a left aligned column padded to first_width characters
            //print!("|{:1$}", &report.endpoint, first_width);
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

    /// create a string containing a centered `token` where the entire string is
    /// `width`
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

    let reports: Vec<Report> =
        serde_json::from_slice(&std::fs::read("sp-capabilities.json").unwrap()).unwrap();

    let protocol_and_cipher = Table::ProtocolAndCipher();
    protocol_and_cipher.write(&reports);

    let sigs = Table::Signature();
    sigs.write(&reports);

    let groups = Table::Groups();
    groups.write(&reports);

    let compliance = Table::Compliance();
    compliance.write(&reports);

    let crypo_report: Vec<(String, Result<(), Vec<String>>)> = reports
        .iter()
        .map(|r| {
            (
                r.endpoint.clone(),
                CryptoRecommendation20231130::compliance(r),
            )
        })
        .collect();

    std::fs::write(
        "sp-compliance.json",
        serde_json::to_string_pretty(&crypo_report).unwrap(),
    )
    .unwrap();
}
