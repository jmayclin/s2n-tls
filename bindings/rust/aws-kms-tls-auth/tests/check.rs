use std::{
    sync::atomic::Ordering,
    time::{Duration, SystemTime},
};

use aws_kms_tls_auth::{
    handshake, make_client_config, make_server_config, mocked_kms_client, DecodeValue, PskIdentity,
    PskProvider, PskReceiver, KMS_KEY_ARN_A, KMS_KEY_ARN_B,
};
use s2n_tls::config::Config as S2NConfig;
use s2n_tls::error::Error as S2NError;
use s2n_tls_tokio::TlsStream;
use tokio::net::TcpStream;

const TICK_INCREMENT: Duration = Duration::from_secs(53 * 60);

trait S2NConnectionExtension {
    fn psk_identity(&self) -> PskIdentity;
}

impl S2NConnectionExtension for s2n_tls::connection::Connection {
    fn psk_identity(&self) -> PskIdentity {
        let size = self.negotiated_psk_identity_length().unwrap();
        let mut buf = vec![0u8; size as usize];
        self.negotiated_psk_identity(&mut buf).unwrap();
        PskIdentity::decode_from_exact(&buf).unwrap()
    }
}

struct TestCase<'a> {
    client_config: &'a S2NConfig,
    server_config: &'a S2NConfig,
    correct_state: Box<dyn Fn(u64, Result<TlsStream<TcpStream>, S2NError>) -> bool>,
}

impl<'a> TestCase<'a> {
    async fn assert_correct_state(&self, epoch_seconds: u64) {
        let result = handshake(self.client_config, self.server_config).await;
        (self.correct_state)(epoch_seconds, result);
    }
}

fn current_system_time() -> SystemTime {
    SystemTime::UNIX_EPOCH
        + Duration::from_secs(aws_kms_tls_auth::PSEUDO_EPOCH.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn check_tokio() {
    //let filter = tracing_subscriber::EnvFilter::new("aws_kms_tls_auth=trace");
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        //.with_env_filter(filter)
        .init();
    let current_time = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
    aws_kms_tls_auth::PSEUDO_EPOCH.store(current_time, Ordering::SeqCst);

    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(3_600 * 24)).await;
            tracing::info!(
                "current epoch: {:?}",
                aws_kms_tls_auth::PSEUDO_EPOCH.load(Ordering::SeqCst)
            )
        }
    });
    dbg!(aws_kms_tls_auth::PSEUDO_EPOCH.load(Ordering::SeqCst));

    let mut ticker = tokio::time::interval(TICK_INCREMENT);


    for _ in 0..100 {
        aws_kms_tls_auth::PSEUDO_EPOCH.fetch_add(TICK_INCREMENT.as_secs(), Ordering::SeqCst);
        ticker.tick().await;

        // case 1: always able to handshake, PSK is from current epoch
        tracing::info!("Ticker: {:?}", aws_kms_tls_auth::PSEUDO_EPOCH.load(Ordering::SeqCst));
    }

    assert!(false);

    // handshake(&client_config_b, &server_config).await.unwrap();
}
