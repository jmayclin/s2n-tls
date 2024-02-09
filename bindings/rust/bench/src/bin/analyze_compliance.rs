use std::collections::HashMap;

use bench::scanner::Report;
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

    for (f, v) in fingerprints {
        if v.len() > 1 {
            log::info!("similar security policies");
            for sp in v {
                log::info!("\t{}", sp.endpoint);
            }
        }
    }

    for r in reports {
        std::fs::write(
            format!("capabilities/{}.json", r.endpoint),
            serde_json::to_string_pretty(&r).unwrap().as_bytes(),
        )
        .unwrap()
    }
}
