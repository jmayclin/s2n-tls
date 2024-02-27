use std::{
    cmp::max,
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use bench::scanner::{Report, MAX_ENDPOINT_TPS};
use rayon::prelude::*;

use rand::{seq::SliceRandom, thread_rng};

// with 16,000 -> network unreachable
// with 4,000 -> still some network unreachable errors
const TARGET_TPS: usize = 100;
const CHECKPOINT_FREQUENCY: usize = 250;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init()
        .unwrap();

    let query_start = Instant::now();

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

    // endpoints is a vec of String that is used as a queue for the worked threadpool.
    // After each worker thread has finished it's query, it will just pop off the next
    // element on `endpoints` and generate a report for that endpoint.
    let endpoints = Arc::new(Mutex::new(endpoints));

    // These are multi-producer, single-consumer channels. So each worker thread will
    // receive a "transmit" handle that it will use to submit the final endpoint report.
    // All of these reports will be received by the single main thread from the single
    // rx (receive) handle.
    let (tx, rx) = std::sync::mpsc::channel();

    // We set a "target TPS" for the entire instance to avoid being too spammy.
    // We also set a MAX_ENDPOINT_TPS which will make sure that we never overload
    // a single endpoint with too much traffic. This allows us to run our scan in
    // a highly parallel manner while minimizing the scan impact on endpoints.
    let mut thread_pool_size = TARGET_TPS / MAX_ENDPOINT_TPS;
    thread_pool_size = max(thread_pool_size, 1);
    log::info!("Thread Pool Size: {}", thread_pool_size);
    for i in 0..thread_pool_size {
        // create the clones to be moved into the thread
        let tx_handle = tx.clone();
        let queue_handle = Arc::clone(&endpoints);
        // The engine is never mutated, so we can easily share it among all the threads.
        // The engine is essentially a static list of capabilities that the underlying
        // libcrypto supports (which is the list of capabilities that we can query for)
        // Many threads can read from this memory at once without any safety issues.
        // The only reason that we don't use a raw reference is because of some fancy stuff
        // we do for local security policy scanning, which isn't used for internet endpoint
        // scanning.
        let engine_handle = Arc::clone(&engine);
        thread::spawn(move || {
            log::info!("thread {i} created");
            // When parallelism is set too high we get throttled by DNS. This 
            // creates some natural jitter/ramp up to appease the DNS gods.
            std::thread::sleep(Duration::from_secs(i as u64));

            // get the next element to be queried, or return if there are none left
            // don't use let/while, because it holds the lock :(
            loop {
                let mut handle = queue_handle.lock().unwrap();
                let endpoint = match handle.pop() {
                    Some(e) => e,
                    // if there are no elements left in the queue, then exit
                    None => return,
                };
                drop(handle);
                let start = std::time::Instant::now();
                let query_result = engine_handle.inspect_endpoint(&endpoint);
                log::info!(
                    "thread {i} finished query -> endpoint:{endpoint} duration:{:?} ms",
                    start.elapsed().as_millis()
                );
                tx_handle.send((endpoint, query_result)).unwrap();
            }
        });
    }
    drop(tx);

    let mut reports: Vec<Report> = Vec::new();
    let mut failures = Vec::new();

    // Here we collect all of the reports that the worker threads generate.
    // recv will return none once all of the rx handles have been dropped
    // beware that some endpoints seems to have a 5 minute timeout set :(
    // TODO: handle the timeout on our side
    while let Ok((endpoint, result)) = rx.recv() {
        let report = match result {
            Ok(r) => r,
            // We need to know if we aren't successfully looking at any endpoints,
            // so log the error to lookat later.
            Err(e) => {
                log::error!("failure for {}, {:?}", endpoint, e);
                failures.push((endpoint, format!("{:?}", e)));
                continue;
            }
        };

        reports.push(report);

        // Since it's nice to be able to look at things as they are happening, we
        // dump the reports to disk every CHECKPOINT_FREQUENCY reports.
        if reports.len() % CHECKPOINT_FREQUENCY == 0 {
            log::info!("checkpoint: {}/{total_endpoints}", reports.len());
            write_reports(&reports, &failures);
        }
    }
    write_reports(&reports, &failures);
    log::info!("finished querying {total_endpoints} in {} seconds", query_start.elapsed().as_secs());
}

fn write_reports(reports: &Vec<Report>, failures: &Vec<(String, String)>) {
    let mut dump: Vec<Report> = reports.clone();
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
