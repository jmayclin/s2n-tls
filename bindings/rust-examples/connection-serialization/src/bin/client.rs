use std::{
    error::Error,
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock,
    },
};

use connection_serialization::{client_config, DEFAULT_CA, PING_PONG_VOLLEYS};
use s2n_tls::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsConnector;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task,
};

const COUNTERS: usize = 1000;
const CLIENT_COUNT: usize = 5000;

/// NOTE: this ca is to be used for demonstration purposes only!
static LATENCY_COUNTER: LazyLock<Vec<AtomicU64>> = LazyLock::new(|| {
    let mut counters = Vec::new();
    for _ in 0..COUNTERS {
        counters.push(AtomicU64::new(0));
    }
    counters
});

async fn run_client(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // Create the TlsConnector based on the configuration.
    let mut client = TlsConnector::new(config);

    // Connect to the server.
    let stream = TcpStream::connect("127.0.0.1:9001").await?;
    let mut tls = client.connect("leaf", stream).await?;

    tls.read_exact(&mut [0; "ready".len()]).await.unwrap();

    for _ in 0..PING_PONG_VOLLEYS {
        tls.write_all(b"ping").await.unwrap();
        let reading = std::time::Instant::now();
        tls.read_exact(&mut [0; 4]).await.unwrap();
        let elapsed = reading.elapsed();
        // generally between 30 - 60 us
        let micros = elapsed.as_micros();
        let slot = (micros / 10) as usize;
        let slot = slot.min(COUNTERS - 1);
        (*LATENCY_COUNTER)[slot].fetch_add(1, Ordering::Relaxed);
        // println!("{elapsed:?}");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = client_config().unwrap();
    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..CLIENT_COUNT {
        join_set.spawn({
            let config = config.clone();
            async {
                run_client(config).await.unwrap();
            }
        });
    }
    join_set.join_all().await;

    let mut total_latency = 0;
    let mut total_samples = 0;
    for (index, count) in LATENCY_COUNTER.iter().enumerate() {
        let count = count.load(Ordering::Relaxed);
        println!("{} us -> {}", index * 10, count);

        total_latency += count * index as u64 * 10;
        total_samples += count;
    }

    println!("avg: {:?}", total_latency as f64 / total_samples as f64);

    Ok(())
}
