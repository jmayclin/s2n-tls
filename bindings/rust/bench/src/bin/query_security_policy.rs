fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init()
        .unwrap();
    let args: Vec<String> = std::env::args().collect();
    let security_policy = args.last().unwrap().trim();
    let query = bench::scanner::QueryEngine::construct_engine();
    let r = query.inspect_security_policy(&security_policy);
    println!("{}", serde_json::to_string_pretty(&r).unwrap());
}
