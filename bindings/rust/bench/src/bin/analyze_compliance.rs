use std::collections::HashMap;

use bench::scanner::{compliance::{ComplianceRegime, RFC9151}, Report};
use rayon::prelude::*;

/// The query.rs binary can be used to write a full list of the capabilities of
/// security policies.
fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init()
        .unwrap();

    // read in the report that was obtained by running `query_csv.rs`
    // "endpoint-capabilities.json"
    let reports = std::fs::read_to_string("endpoint-capabilities.json").unwrap();
    let reports: Vec<Report> = serde_json::from_str(&reports).unwrap();

    log::info!("there are {} distinct reports", reports.len());

    // fingerprint each report by it's capabilities and group them together. TLS
    // endpoints that share the same fingerprint are likely using the same TLS
    // termination configuration/solution.
    let mut fingerprints: HashMap<u64, Vec<Report>> = HashMap::new();
    for r in reports.iter() {
        fingerprints
            .entry(r.security_policy_fingerprint())
            .or_default()
            .push(r.clone());
    }

    log::info!("there are {} distinct fingerprints", fingerprints.len());

    // map from endpoints -> compliance
    let mut rfc9151: Vec<(Vec<String>, Result<(), Vec<String>>)> = Vec::new();
    for similar_reports in fingerprints.values() {
        let endpoints = similar_reports.iter().map(|r| r.endpoint.clone()).collect();
        let compliance = RFC9151::compliance(similar_reports.first().unwrap());
        rfc9151.push((endpoints, compliance));
    }

    std::fs::write(
        "rfc9151-compliance.json",
        serde_json::to_string_pretty(&rfc9151).unwrap(),
    ).unwrap();
}
