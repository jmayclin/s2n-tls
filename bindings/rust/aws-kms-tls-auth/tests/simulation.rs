use std::{sync::atomic::Ordering, time::{Duration, SystemTime}};

use aws_kms_tls_auth::{
    handshake, make_client_config, make_server_config, mocked_kms_client, DecodeValue, PskIdentity, PskProvider, PskReceiver, KMS_KEY_ARN_A, KMS_KEY_ARN_B
};

trait S2NConnectionExtension {
    fn psk_identity(&self) -> PskIdentity;
}

impl S2NConnectionExtension for s2n_tls::connection::Connection {
    fn psk_identity(&self) -> PskIdentity
    {
        let size = self.negotiated_psk_identity_length().unwrap();
        let mut buf = vec![0u8; size as usize];
        self.negotiated_psk_identity(&mut buf).unwrap();
        PskIdentity::decode_from_exact(&buf).unwrap()
    }
}

#[tokio::test]
async fn simulation() {
    let current_time = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
    aws_kms_tls_auth::EPOCH_SECONDS.store(current_time, Ordering::SeqCst);
    dbg!(aws_kms_tls_auth::EPOCH_SECONDS.load(Ordering::SeqCst));

    let mut ticker = tokio::time::interval(Duration::from_secs(53 * 60));

    let psk_provider_a =
        PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_A.to_owned(), |_| {})
            .await
            .unwrap();
    let psk_provider_b =
        PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_B.to_owned(), |_| {})
            .await
            .unwrap();
    let psk_receiver = PskReceiver::initialize(
        mocked_kms_client(),
        vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()],
        |_| {},
    )
    .await
    .unwrap();

    let client_config_a = make_client_config(psk_provider_a);
    let client_config_b = make_client_config(psk_provider_b);
    let server_config = make_server_config(psk_receiver);

    tokio::time::pause();
    loop {
        aws_kms_tls_auth::EPOCH_SECONDS.fetch_add(53 * 60, Ordering::SeqCst);
        ticker.tick().await;

        let stream = handshake(&client_config_a, &server_config).await.unwrap();
        let negotiated_psk = stream.as_ref().psk_identity();
        println!("{}", negotiated_psk.key_epoch);
    }
    

    handshake(&client_config_b, &server_config).await.unwrap();
}
