fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init()
        .unwrap();
    let query = bench::scanner::QueryEngine::construct_engine();
    let endpoint = "dynamodb.cn-north-1.amazonaws.com.cn";
    let r = query.inspect_endpoint(endpoint).unwrap();
    r.cert_information();
    println!("{:?}", serde_json::to_string(&r));
    log::info!("POLICY_NAME: {endpoint}");
}
