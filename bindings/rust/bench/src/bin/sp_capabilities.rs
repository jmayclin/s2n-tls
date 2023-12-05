use std::sync::atomic::AtomicU32;

use bench::scanner::{
    compliance::{ComplianceRegime, CryptoRecommendation20231130},
    params::{KeyExchange, KxGroup, Protocol, Sig, Signature},
    Report,
};
use rayon::prelude::*;

/// This script will generate the capability report for all security policies and
/// output the report to sp_capabilities.json. This json report can then be
/// deserialized for usage with other scripts using
/// ```
///     let mut reports: Vec<Report> =
///         serde_json::from_slice(&std::fs::read("sp-capabilities.json").unwrap()).unwrap();
/// ```
fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init()
        .unwrap();
    let query = bench::scanner::QueryEngine::construct_engine();
    log::info!("Query engine capabilities: {:?}", query);

    let sp = vec![
        "20230317",
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
        "20190120",
        "20190121",
        "20190122",
        "20190801",
        "20190802",
        "20200207",
        "rfc9151",
    ];

    //let sp = vec![
    //    "default",
    //    "default_tls13",
    //    "default_fips",
    //    "20190214",
    //    "20230317",
    //    "rfc9151",
    //    "CloudFront-TLS-1-2-2021",
    //];
    let sp = bench::scanner::security_policies::SECURITY_POLICIES;
    let mut sp = Vec::from_iter(sp.iter().cloned());
    sp.sort_by_key(|s| s.to_owned());


    let total = sp.len();

    let progress = AtomicU32::new(total as u32);
    let mut reports: Vec<Report> = sp
        .par_iter()
        .map(|sp| query.inspect_security_policy(*sp))
        .inspect(|r| {
            progress.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            println!("{:?} remaining", progress);
        })
        .collect();

    // TODO: I don't think this clone should be here
    // reports.sort_by_key(|r| r.endpoint.clone());

    std::fs::write(
        "sp-capabilities.json",
        serde_json::to_string_pretty(&reports).unwrap(),
    )
    .unwrap();
}
