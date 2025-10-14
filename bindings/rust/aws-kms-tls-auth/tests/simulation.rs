use std::{
    sync::atomic::Ordering,
    time::{Duration, SystemTime},
};

use aws_kms_tls_auth::{
    current_system_time, epoch_seconds, handshake, make_client_config, make_server_config, mocked_kms_client, DecodeValue, PskIdentity, PskProvider, PskReceiver, KMS_KEY_ARN_A, KMS_KEY_ARN_B
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
        //(self.correct_state)(epoch_seconds, result);
        assert!((self.correct_state)(epoch_seconds, result));
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn simulation() {
    let filter = tracing_subscriber::EnvFilter::new("aws_kms_tls_auth=trace");
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_env_filter(filter)
        .init();
    let current_time = epoch_seconds();
    // aws_kms_tls_auth::PSEUDO_EPOCH.store(current_time, Ordering::SeqCst);
    // dbg!(aws_kms_tls_auth::PSEUDO_EPOCH.load(Ordering::SeqCst));

    // server KMS client
    // - always successfully calls A
    // - successfully calls B, one failure at item 50 (should retry)
    // - fails all B calls at letter 60
    // happy path A client -> always handshakes successfully
    // happy path B client -> always handshakes successfully through 60 (make sure 50 was retrieved)
    // failing A client -> fails to retrieve A items after item 75, record first failure, and the time between
    // when it fully failed.

    let mut ticker = tokio::time::interval(TICK_INCREMENT);

    let psk_provider_a =
        PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_A.to_owned(), |_| {})
            .await
            .unwrap();
    // let psk_provider_b =
    //     PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_B.to_owned(), |_| {})
    //         .await
    //         .unwrap();
    let psk_receiver = PskReceiver::initialize(
        mocked_kms_client(),
        vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()],
        |_| {},
    )
    .await
    .unwrap();

    let client_config_a = make_client_config(psk_provider_a);
    // let client_config_b = make_client_config(psk_provider_b);
    let server_config = make_server_config(psk_receiver);

    let happy_path = TestCase {
        client_config: &client_config_a,
        server_config: &server_config,
        correct_state: Box::new(|epoch_second, result| {
            // handshake should always succeed
            let negotiated_psk = result.unwrap().as_ref().psk_identity();
            dbg!(negotiated_psk.key_epoch);
            dbg!(aws_kms_tls_auth::current_epoch());
            let current_epoch = aws_kms_tls_auth::current_epoch();
            let epoch_start = aws_kms_tls_auth::epoch_start(current_epoch);
            // rotation cushion
            dbg!(current_system_time().duration_since(epoch_start).unwrap());
            if current_system_time().duration_since(epoch_start).unwrap() < Duration::from_secs(60)
            {
                negotiated_psk.key_epoch == current_epoch - 1
            } else {
                negotiated_psk.key_epoch == current_epoch
            }
        }),
    };
    let current = tokio::time::Instant::now();
    for _ in 0..100 {
        // aws_kms_tls_auth::PSEUDO_EPOCH.fetch_add(TICK_INCREMENT.as_secs(), Ordering::SeqCst);
        ticker.tick().await;
        tracing::info!("elapsed in ticker: {:?}", current.elapsed());

        // case 1: always able to handshake, PSK is from current epoch
        tokio::time::resume();
        happy_path
            .assert_correct_state(aws_kms_tls_auth::epoch_seconds())
            .await;
        tokio::time::pause();

        // case 2: failure happens at some point, at which point the client is
        // sending an old PSK. Eventually the handshakes fail.

        // case 3:
        // let stream = handshake(&client_config_a, &server_config).await.unwrap();
        // let negotiated_psk = stream.as_ref().psk_identity();
        // println!("{}", negotiated_psk.key_epoch);
    }

    // handshake(&client_config_b, &server_config).await.unwrap();
}
