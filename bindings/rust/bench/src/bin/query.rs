use std::collections::HashMap;

use bench::scanner::Report;
use rayon::prelude::*;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init()
        .unwrap();
    let query = bench::scanner::QueryEngine::construct_engine();
    log::info!("Query engine capabilities: {:?}", query);

    let reports: Vec<Report> = bench::scanner::security_policies::SECURITY_POLICIES
        .par_iter()
        .map(|sp| query.inspect_security_policy(*sp))
        .collect();

    let mut fingerprints: HashMap<u64, Vec<Report>> = HashMap::new();
    for r in reports.iter() {
        fingerprints
            .entry(r.security_policy_fingerprint())
            .or_default()
            .push(r.clone());
    }

    log::info!(
        "there are {} security policies",
        bench::scanner::security_policies::SECURITY_POLICIES.len()
    );
    log::info!(
        "there are {} distinct security policies",
        fingerprints.len()
    );

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
