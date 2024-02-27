fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init()
        .unwrap();
    let query = bench::scanner::QueryEngine::construct_engine();
    let endpoint = "data.iot-fips.us-gov-west-1.amazonaws.com";
    let r = query.inspect_endpoint(endpoint).unwrap();
    r.cert_information();
    println!("{}", serde_json::to_string_pretty(&r).unwrap());
    log::info!("POLICY_NAME: {endpoint}");
}
