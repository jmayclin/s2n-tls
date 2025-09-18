// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{epoch_schedule, psk_derivation::EpochSecret, KeyArn};
use aws_sdk_kms::Client;
use rand::Rng;
use s2n_tls::{callbacks::ConnectionFuture, config::ConnectionInitializer};
use std::{
    cmp::min,
    collections::VecDeque,
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

#[derive(Debug)]
struct ProviderSecrets {
    key_arn: KeyArn,
    /// secret for the current epoch `n`
    current_secret: RwLock<Arc<EpochSecret>>,
    /// secrets for epoch `n + 1` and `n + 2`
    next_secrets: Mutex<VecDeque<EpochSecret>>,
}

impl ProviderSecrets {
    fn current_secret(&self) -> Arc<EpochSecret> {
        self.current_secret.read().unwrap().clone()
    }

    fn available_epochs(&self) -> Vec<u64> {
        let mut epochs: Vec<u64> = self
            .next_secrets
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.key_epoch)
            .collect();
        epochs.push(self.current_secret().key_epoch);
        epochs
    }

    fn newest_available_epoch(&self) -> Option<u64> {
        self.next_secrets
            .lock()
            .unwrap()
            .iter()
            .map(|epoch_secret| epoch_secret.key_epoch)
            .max()
    }

    /// fetch all keys that aren't already available
    /// The will almost always just fetch `this_epoch + 2`, unless key
    /// generation has failed for several days
    async fn fetch_secrets(
        &self,
        current_epoch: u64,
        kms_client: &Client,
        kms_smoothing_factor: u32,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Duration {
        let mut to_fetch = vec![current_epoch, current_epoch + 1, current_epoch + 2];
        let available = self.available_epochs();
        to_fetch.retain(|epoch| !available.contains(epoch));

        for epoch in to_fetch {
            match EpochSecret::fetch_epoch_secret(&kms_client, &self.key_arn, epoch).await {
                Ok(epoch_secret) => {
                    self.next_secrets.lock().unwrap().push_back(epoch_secret);
                }
                Err(e) => {
                    failure_notification(e);
                    // TODO: failure notification, and quit trying to fetch keys
                    // we rely on next_secrets being ordered
                    return Duration::from_secs(3_600);
                }
            }
        }

        let sleep = self
            .newest_available_epoch()
            .and_then(|next_fetch| epoch_schedule::until_fetch(next_fetch, kms_smoothing_factor));
        match sleep {
            Some(duration) => duration,
            None => Duration::from_secs(3_600),
        }
    }

    /// Attempt to update the current epoch secret.
    ///
    /// Returns the duration until the next orderly rotation should be attempted.
    fn rotate_secrets(&self, current_epoch: u64) -> Duration {
        let needs_rotation = self.current_secret().key_epoch < current_epoch;
        let rotation_key = self
            .next_secrets
            .lock()
            .unwrap()
            .iter()
            .find(|secret| secret.key_epoch == current_epoch)
            .cloned();

        if needs_rotation && rotation_key.is_some() {
            *self.current_secret.write().unwrap() = Arc::new(rotation_key.unwrap());
        }

        match epoch_schedule::until_epoch_start(current_epoch + 1) {
            Some(duration) => duration + Duration::from_secs(60),
            None => {
                // this might happen if secrets are fetched at the end of an epoch
                // and the epoch is very slow
                Duration::from_secs(3_600)
            }
        }
    }

    /// Remove old, unused secrets.
    ///
    /// This will not modify [`ProviderSecrets::current_secret`].
    fn drop_old_secrets(&self, current_epoch: u64) {
        self.next_secrets
            .lock()
            .unwrap()
            .retain(|secret| secret.key_epoch > current_epoch);
    }

    fn poll_update(&self) {}
}
#[derive(Debug)]
pub struct PskProvider {
    secret_state: Arc<ProviderSecrets>,
}

impl PskProvider {
    pub async fn initialize(
        kms_client: Client,
        key_arn: KeyArn,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let current_key_epoch = epoch_schedule::current_epoch();
        let current_secret =
            EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, current_key_epoch).await?;
        let mut next_secrets = VecDeque::new();
        next_secrets.push_back(
            EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, current_key_epoch + 1).await?,
        );
        next_secrets.push_back(
            EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, current_key_epoch + 2).await?,
        );

        let secret_state = ProviderSecrets {
            key_arn,
            current_secret: RwLock::new(Arc::new(current_secret)),
            next_secrets: Mutex::new(next_secrets),
        };
        let value = Self {
            secret_state: Arc::new(secret_state),
        };

        tokio::task::spawn({
            let secret_state = Arc::clone(&value.secret_state);
            async move {
                let kms_smoothing_factor = rand::rng().random_range(0..(24 * 3_600));
                loop {
                    let current_epoch = epoch_schedule::current_epoch();

                    let until_next_fetch = secret_state
                        .fetch_secrets(
                            current_epoch,
                            &kms_client,
                            kms_smoothing_factor,
                            &failure_notification,
                        )
                        .await;
                    let until_next_rotation = secret_state.rotate_secrets(current_epoch);
                    secret_state.drop_old_secrets(current_epoch);

                    tokio::time::sleep(min(until_next_fetch, until_next_rotation)).await;
                }
            }
        });
        Ok(value)
    }

    fn current_epoch_secret(&self) -> Arc<EpochSecret> {
        self.secret_state.current_secret.read().unwrap().clone()
    }

    // /// This loop is responsible for two items
    // /// key rotation: this is a local only action, and updates the `current_secret`
    // /// to the next epoch.
    // ///
    // /// key fetch: this is a network call to KMS to derive the next epoch secret
    // async fn epoch_secret_rotator(
    //     client_epoch_secrets: Arc<ProviderSecrets>,
    //     kms_client: Client,
    //     key_arn: KeyArn,
    //     failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    // ) {
    //     let kms_smoothing_factor = rand::rng().random_range(0..(24 * 3_600));
    //     loop {
    //         let this_epoch = epoch_schedule::current_epoch();

    //         // fetch the new keys
    //         {
    //             // fetch all keys that aren't already available
    //             // The will almost always just fetch `this_epoch + 2`, unless key
    //             // generation has failed for several days
    //             let mut to_fetch = vec![this_epoch, this_epoch + 1, this_epoch + 2];
    //             let available = client_epoch_secrets.available_epochs();
    //             to_fetch.retain(|epoch| !available.contains(epoch));

    //             for epoch in to_fetch {
    //                 match EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, epoch).await {
    //                     Ok(epoch_secret) => {
    //                         client_epoch_secrets
    //                             .next_secrets
    //                             .lock()
    //                             .unwrap()
    //                             .push_back(epoch_secret);
    //                     }
    //                     Err(e) => {
    //                         failure_notification(e);
    //                         // TODO: failure notification, and quit trying to fetch keys
    //                         // we rely on next_secrets being ordered
    //                         break;
    //                     }
    //                 }
    //             }
    //         }

    //         // rotate the current key
    //         {
    //             let current_key_epoch = client_epoch_secrets.current_secret().key_epoch;
    //             let needs_rotation = current_key_epoch < this_epoch;
    //             let rotation_key = client_epoch_secrets
    //                 .next_secrets
    //                 .lock()
    //                 .unwrap()
    //                 .iter()
    //                 .find(|secret| secret.key_epoch == this_epoch)
    //                 .cloned();

    //             if needs_rotation && rotation_key.is_some() {
    //                 *client_epoch_secrets.current_secret.write().unwrap() =
    //                     Arc::new(rotation_key.unwrap());
    //                 // drop all old keys
    //                 client_epoch_secrets
    //                     .next_secrets
    //                     .lock()
    //                     .unwrap()
    //                     .retain(|secret| secret.key_epoch > this_epoch);
    //             }
    //         }

    //         // sleep until the next event, fetching a new key or updating the current key
    //         {
    //             let until_next_rotation = {
    //                 let next_epoch = client_epoch_secrets.current_secret().key_epoch + 1;
    //                 let rotation_available = client_epoch_secrets
    //                     .next_secrets
    //                     .lock()
    //                     .unwrap()
    //                     .iter()
    //                     .any(|secret| secret.key_epoch == next_epoch);
    //                 match epoch_schedule::until_epoch_start(next_epoch) {
    //                     Some(duration) => Some(duration),
    //                     None => {
    //                         if rotation_available {
    //                             // immediately restart the loop, we want to rotate and
    //                             // the key is available. It's important to check that
    //                             // the key is actually available to prevent a hot loop.
    //                             continue;
    //                         } else {
    //                             None
    //                         }
    //                     }
    //                 }
    //             };

    //             let until_next_fetch = {
    //                 let next_fetched_epoch = client_epoch_secrets
    //                     .available_epochs()
    //                     .into_iter()
    //                     .max()
    //                     .map(|epoch| epoch + 1);
    //                 if let Some(next_fetched_epoch) = next_fetched_epoch {
    //                     if let Some(duration) =
    //                         epoch_schedule::until_fetch(next_fetched_epoch, kms_smoothing_factor)
    //                     {
    //                         duration
    //                     } else {
    //                         // we failed to fetch the key, so retry in an hour
    //                         Duration::from_secs(3_600)
    //                     }
    //                 } else {
    //                     Duration::from_secs(3_600)
    //                 }
    //             };

    //             let sleep_duration = match until_next_rotation {
    //                 Some(duration) => min(duration, until_next_fetch),
    //                 None => until_next_fetch,
    //             };
    //             tokio::time::sleep(sleep_duration).await;
    //         }
    //     }
    // }
}

impl ConnectionInitializer for PskProvider {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let psk = self.current_epoch_secret().new_connection_psk()?;
        connection.append_psk(&psk)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        test_utils::{
            configs_from_callbacks, handshake, mocked_kms_client, PskIdentityObserver,
            KMS_KEY_ARN_A,
        },
        PskProvider,
    };

    #[tokio::test]
    async fn random_session_id() {
        let psk_provider =
            PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_A.to_owned(), |_| {})
                .await
                .unwrap();
        let psk_capturer = PskIdentityObserver::default();
        let observer_handle = psk_capturer.clone();
        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_capturer);

        handshake(&client_config, &server_config).await.unwrap_err();
        handshake(&client_config, &server_config).await.unwrap_err();

        let observed_psks = observer_handle.0.lock().unwrap().clone();
        assert!(observed_psks[1].key_epoch - observed_psks[0].key_epoch <= 1);
        assert!(observed_psks[1].session_name != observed_psks[0].session_name);
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{
//         psk_parser::retrieve_psk_identities,
//         test_utils::{
//             configs_from_callbacks, decrypt_mocks, handshake, test_psk_provider, DECRYPT_OUTPUT_A,
//             DECRYPT_OUTPUT_B, GDK_OUTPUT_A, GDK_OUTPUT_B, KMS_KEY_ARN, OBFUSCATION_KEY,
//         },
//         DecodeValue, PskReceiver,
//     };
//     use aws_sdk_kms::{
//         operation::generate_data_key::GenerateDataKeyError,
//         types::error::builders::KeyUnavailableExceptionBuilder,
//     };
//     use aws_smithy_mocks::{mock, mock_client};
//     use std::{
//         collections::HashSet,
//         sync::atomic::{AtomicU64, Ordering},
//         time::Duration,
//     };

//     // the error doesn't implement clone, so we have to use this test helper
//     fn gdk_error() -> GenerateDataKeyError {
//         GenerateDataKeyError::KeyUnavailableException(
//             KeyUnavailableExceptionBuilder::default().build(),
//         )
//     }

//     #[tokio::test(start_paused = true)]
//     async fn key_rotation() {
//         let gdk_rule = mock!(aws_sdk_kms::Client::generate_data_key)
//             .sequence()
//             .output(|| GDK_OUTPUT_A.clone())
//             .output(|| GDK_OUTPUT_B.clone())
//             .build();
//         let gdk_client = mock_client!(aws_sdk_kms, [&gdk_rule]);

//         let psk_provider = PskProvider::initialize(
//             PskVersion::V1,
//             gdk_client,
//             KMS_KEY_ARN.to_string(),
//             OBFUSCATION_KEY.clone(),
//             |_| {},
//         )
//         .await
//         .unwrap();

//         let (_decrypt_rule, decrypt_client) = decrypt_mocks();
//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             vec![KMS_KEY_ARN.to_owned()],
//             vec![OBFUSCATION_KEY.clone()],
//         );

//         let last_update_handle = psk_provider.last_update_attempt.clone();
//         let creation_time = Instant::now();
//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

//         tokio::time::advance(Duration::from_secs(1)).await;

//         // on the first handshake, no update happened
//         handshake(&client_config, &server_config).await.unwrap();
//         assert_eq!(*last_update_handle.read().unwrap(), Some(creation_time));

//         tokio::time::advance(KEY_ROTATION_PERIOD).await;

//         // on the second handshake, an update is kicked off
//         assert_eq!(gdk_rule.num_calls(), 1);
//         handshake(&client_config, &server_config).await.unwrap();

//         // the update resulted in another generate data key call
//         while last_update_handle.read().unwrap().is_none() {
//             tokio::time::sleep(Duration::from_millis(1)).await;
//         }
//         assert_eq!(*last_update_handle.read().unwrap(), Some(Instant::now()));
//         assert_eq!(gdk_rule.num_calls(), 2);
//     }

//     #[tokio::test(start_paused = true)]
//     async fn failure_notification() {
//         // configure a PSK provider which will successfully generate the initial
//         // data key, fail twice, then succeed. Errors should increment the AtomicU64
//         // error handle.
//         let (psk_provider, gdk_rule, error_handle) = {
//             let gdk_rule = mock!(aws_sdk_kms::Client::generate_data_key)
//                 .sequence()
//                 .output(|| GDK_OUTPUT_A.clone())
//                 .error(gdk_error)
//                 .error(gdk_error)
//                 .output(|| GDK_OUTPUT_B.clone())
//                 .build();
//             let gdk_client = mock_client!(aws_sdk_kms, [&gdk_rule]);

//             let error_count = Arc::new(AtomicU64::default());
//             let error_handle = Arc::clone(&error_count);
//             let psk_provider = PskProvider::initialize(
//                 PskVersion::V1,
//                 gdk_client,
//                 KMS_KEY_ARN.to_string(),
//                 OBFUSCATION_KEY.clone(),
//                 move |_| {
//                     error_count.fetch_add(1, Ordering::Relaxed);
//                 },
//             )
//             .await
//             .unwrap();

//             (psk_provider, gdk_rule, error_handle)
//         };

//         // configure a PSK receiver capable of decrypting the two datakeys that
//         // the provider will generate.
//         let (psk_receiver, decrypt_rule) = {
//             let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt)
//                 .sequence()
//                 .output(|| DECRYPT_OUTPUT_A.clone())
//                 .output(|| DECRYPT_OUTPUT_B.clone())
//                 .build();
//             let decrypt_client = mock_client!(aws_sdk_kms, [&decrypt_rule]);
//             let psk_receiver = PskReceiver::initialize(
//                 decrypt_client,
//                 vec![KMS_KEY_ARN.to_owned()],
//                 vec![OBFUSCATION_KEY.clone()],
//             );
//             (psk_receiver, decrypt_rule)
//         };

//         let last_update_handle = psk_provider.last_update_attempt.clone();
//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

//         // Period 0: handshake is successful, using the initial PSK
//         {
//             handshake(&client_config, &server_config).await.unwrap();
//             assert_eq!(error_handle.load(Ordering::Relaxed), 0);
//             assert_eq!(decrypt_rule.num_calls(), 1);
//         }

//         tokio::time::advance(KEY_ROTATION_PERIOD).await;

//         // Period 1: GDK fails, and is logged
//         {
//             handshake(&client_config, &server_config).await.unwrap();
//             while last_update_handle.read().unwrap().is_none() {
//                 tokio::time::sleep(Duration::from_millis(1)).await;
//             }
//             assert_eq!(error_handle.load(Ordering::Relaxed), 1);
//             assert_eq!(*last_update_handle.read().unwrap(), Some(Instant::now()));
//             assert_eq!(gdk_rule.num_calls(), 2);
//         }

//         tokio::time::advance(Duration::from_secs(1)).await;

//         // Period 1+: GDK is not retried until KEY_ROTATION_PERIOD has elapsed
//         {
//             handshake(&client_config, &server_config).await.unwrap();
//             while last_update_handle.read().unwrap().is_none() {
//                 tokio::time::sleep(Duration::from_millis(1)).await;
//             }
//             assert_eq!(error_handle.load(Ordering::Relaxed), 1);
//             assert_eq!(gdk_rule.num_calls(), 2);
//         }

//         tokio::time::advance(KEY_ROTATION_PERIOD).await;

//         // Period 2: GDK fails, and is logged. The server is successfully handshaking
//         // with the initial PSK.
//         {
//             handshake(&client_config, &server_config).await.unwrap();
//             while last_update_handle.read().unwrap().is_none() {
//                 tokio::time::sleep(Duration::from_millis(1)).await;
//             }
//             assert_eq!(*last_update_handle.read().unwrap(), Some(Instant::now()));
//             assert_eq!(error_handle.load(Ordering::Relaxed), 2);
//             assert_eq!(decrypt_rule.num_calls(), 1);
//         }

//         tokio::time::advance(KEY_ROTATION_PERIOD).await;

//         // Period 3: GDK Succeeds, although it is not used for the current handshake
//         {
//             handshake(&client_config, &server_config).await.unwrap();
//             while last_update_handle.read().unwrap().is_none() {
//                 tokio::time::sleep(Duration::from_millis(1)).await;
//             }
//             assert_eq!(error_handle.load(Ordering::Relaxed), 2);
//             assert_eq!(decrypt_rule.num_calls(), 1);
//             assert_eq!(gdk_rule.num_calls(), 4);
//         }

//         // Period 3+: The next handshake uses the new PSK
//         {
//             handshake(&client_config, &server_config).await.unwrap();
//             while last_update_handle.read().unwrap().is_none() {
//                 tokio::time::sleep(Duration::from_millis(1)).await;
//             }
//             assert_eq!(error_handle.load(Ordering::Relaxed), 2);
//             assert_eq!(decrypt_rule.num_calls(), 2);
//         }
//     }

//     /// The PSK Identity should be unique per-connection because of the randomized
//     /// nonce
//     #[tokio::test]
//     async fn per_connection_psk_identity() -> anyhow::Result<()> {
//         const NUM_HANDSHAKES: usize = 5;
//         let psk_provider = test_psk_provider().await;
//         let (_decrypt_rule, decrypt_client) = decrypt_mocks();
//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             vec![KMS_KEY_ARN.to_owned()],
//             vec![OBFUSCATION_KEY.clone()],
//         );

//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);
//         let mut identities = Vec::new();
//         for _ in 0..NUM_HANDSHAKES {
//             let server = handshake(&client_config, &server_config).await.unwrap();
//             let client_hello = server.as_ref().client_hello()?;
//             let psks = retrieve_psk_identities(client_hello)?;
//             identities.push(psks);
//         }

//         let unique_identities: HashSet<PskIdentity> = identities
//             .into_iter()
//             .map(|psk| {
//                 assert_eq!(psk.list().len(), 1);
//                 psk.list().first().unwrap().clone().identity.take_blob()
//             })
//             .map(|blob| PskIdentity::decode_from_exact(&blob).unwrap())
//             .collect();

//         // all of the psk_identities should be unique (different nonces)
//         assert_eq!(unique_identities.len(), NUM_HANDSHAKES);

//         let expected_ciphertext = unique_identities
//             .iter()
//             .next()
//             .unwrap()
//             .deobfuscate_datakey(&[OBFUSCATION_KEY.clone()])
//             .unwrap();
//         let all_have_expected_ciphertext = unique_identities
//             .into_iter()
//             .map(|id| id.deobfuscate_datakey(&[OBFUSCATION_KEY.clone()]).unwrap())
//             .all(|ciphertext| ciphertext == expected_ciphertext);
//         assert!(all_have_expected_ciphertext);

//         Ok(())
//     }
// }
