use std::{
    cmp::max,
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use bench::scanner::{Report, MAX_ENDPOINT_TPS};
use rayon::prelude::*;

use rand::{seq::SliceRandom, thread_rng};

const TARGET_TPS: usize = 4000;
const CHECKPOINT_FREQUENCY: usize = 250;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init()
        .unwrap();
    let engine = bench::scanner::QueryEngine::construct_engine();
    let engine = Arc::new(engine);
    let endpoints = std::fs::read_to_string("endpoints.csv").unwrap();
    let mut endpoints: Vec<String> = endpoints
        .lines()
        // get the domain name
        .map(|s| s.split_once(",").unwrap().0)
        // remove the string quotes
        .map(|s| &s[1..(s.len() - 1)])
        .map(|s| s.to_string())
        .collect();
    endpoints.shuffle(&mut thread_rng());
    // println!("endpoint: {:?}", endpoints);
    let total_endpoints = endpoints.len();
    //let mut endpoints = endpoints[0..100].to_vec();

    let endpoints = Arc::new(Mutex::new(endpoints));

    let (tx, rx) = std::sync::mpsc::channel();

    let thread_pool_size = TARGET_TPS / MAX_ENDPOINT_TPS;
    let thread_pool_size = max(thread_pool_size, 1);
    log::info!("Thread Pool Size: {}", thread_pool_size);
    for i in 0..thread_pool_size {
        // create the clones to be moved into the thread
        let tx_handle = tx.clone();
        let queue_handle = Arc::clone(&endpoints);
        let engine_handle = Arc::clone(&engine);
        thread::spawn(move || {
            log::info!("thread {i} created");
            // just pause so I can more accurate count threads because I currently have
            // bad logging hygiene
            std::thread::sleep(Duration::from_secs(1));

            // get the next element to be queried, or return if there are none left
            // don't use let/while, because it holds the lock :(
            loop {
                let mut handle = queue_handle.lock().unwrap();
                let endpoint = match handle.pop() {
                    Some(e) => e,
                    None => return,
                };
                drop(handle);
                let start = std::time::Instant::now();
                let query_result = engine_handle.inspect_endpoint(&endpoint);
                log::info!(
                    "thread {i} sending a result for {endpoint}, the query took {:?} ms",
                    start.elapsed().as_millis()
                );
                tx_handle.send((endpoint, query_result)).unwrap();
            }
        });
    }
    drop(tx);

    let mut reports: HashMap<u64, Vec<Report>> = HashMap::new();
    let mut failures = Vec::new();

    let mut counter = 0;
    // recv will return none once all of the rx handles have been dropped
    // beware that some endpoints seems to have a 5 minute timeout set :(
    // TODO: handle the timeout on our side
    while let Ok((endpoint, result)) = rx.recv() {
        let report = match result {
            Ok(r) => r,
            Err(e) => {
                log::error!("failure for {}, {:?}", endpoint, e);
                failures.push((endpoint, format!("{:?}", e)));
                continue;
            }
        };

        counter += 1;

        reports
            .entry(report.security_policy_fingerprint())
            .or_default()
            .push(report);

        if counter % CHECKPOINT_FREQUENCY == 0 {
            log::info!("checkpoint: {counter}/{total_endpoints}");
            write_reports(&reports, &failures);
        }
    }
    write_reports(&reports, &failures);
}

fn write_reports(reports: &HashMap<u64, Vec<Report>>, failures: &Vec<(String, String)>) {
    let mut dump: Vec<Report> = reports
        .values()
        .map(|reports| reports.iter())
        .flatten()
        .cloned()
        .collect();
    dump.sort_by_key(|r| r.endpoint.clone());

    std::fs::write(
        "endpoint-capabilities.json",
        serde_json::to_string_pretty(&dump).unwrap(),
    )
    .unwrap();

    std::fs::write(
        "endpoint-lookup-failures.json",
        serde_json::to_string_pretty(&failures).unwrap(),
    )
    .unwrap();
}
