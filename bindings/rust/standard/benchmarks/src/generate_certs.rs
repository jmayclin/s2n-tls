// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generates depth-2 certificate chains (leaf → CA) for use in benchmarks.
//!
//! Each chain consists of:
//! - A self-signed CA certificate
//! - A leaf certificate signed by the CA, with SAN=localhost
//!
//! Generated algorithms:
//! - ECDSA P-384
//! - ML-DSA-44
//! - ML-DSA-87
//!
//! Usage:
//!     cargo run --bin generate-certs
//!
//! Output is written to `certs/` relative to the benchmarks crate root.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SignatureAlgorithm, PKCS_ECDSA_P384_SHA384, PKCS_ML_DSA_44,
    PKCS_ML_DSA_87,
};
use std::fs;
use std::path::Path;

struct CertChainConfig {
    dir_name: &'static str,
    algorithm: &'static SignatureAlgorithm,
}

const CONFIGS: &[CertChainConfig] = &[
    CertChainConfig {
        dir_name: "ecdsa_p384",
        algorithm: &PKCS_ECDSA_P384_SHA384,
    },
    CertChainConfig {
        dir_name: "mldsa44",
        algorithm: &PKCS_ML_DSA_44,
    },
    CertChainConfig {
        dir_name: "mldsa87",
        algorithm: &PKCS_ML_DSA_87,
    },
];

fn generate_chain(config: &CertChainConfig, output_dir: &Path) {
    let dir = output_dir.join(config.dir_name);
    fs::create_dir_all(&dir).unwrap();

    // Generate CA key pair and self-signed certificate
    let ca_key_pair = KeyPair::generate_for(config.algorithm).unwrap();

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CountryName, "US");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Benchmark CA");

    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

    // Generate leaf key pair and certificate signed by the CA
    let leaf_key_pair = KeyPair::generate_for(config.algorithm).unwrap();

    let mut leaf_params = CertificateParams::default();
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CountryName, "US");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];

    let ca_issuer = Issuer::from_params(&ca_params, &ca_key_pair);
    let leaf_cert = leaf_params.signed_by(&leaf_key_pair, &ca_issuer).unwrap();

    // Write CA cert
    let ca_cert_pem = ca_cert.pem();
    fs::write(dir.join("ca-cert.pem"), &ca_cert_pem).unwrap();

    // Write leaf chain (leaf + CA)
    let leaf_cert_pem = leaf_cert.pem();
    let chain_pem = format!("{}{}", leaf_cert_pem, ca_cert_pem);
    fs::write(dir.join("server-chain.pem"), &chain_pem).unwrap();

    // Write leaf private key
    let leaf_key_pem = leaf_key_pair.serialize_pem();
    fs::write(dir.join("server-key.pem"), &leaf_key_pem).unwrap();

    println!("Generated {} certs in {}", config.dir_name, dir.display());
}

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output_dir = crate_dir.join("certs");

    fs::create_dir_all(&output_dir).unwrap();

    for config in CONFIGS {
        generate_chain(config, &output_dir);
    }

    println!("\nAll certs generated in {}", output_dir.display());
}
