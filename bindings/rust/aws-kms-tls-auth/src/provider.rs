// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::EncodeValue,
    psk_derivation::{EpochSecret, PskIdentity, PskVersion},
    KeyArn, KEY_ROTATION_PERIOD, PSK_SIZE,
};
use aws_lc_rs::rand::SecureRandom;
use aws_sdk_kms::{primitives::Blob, types::MacAlgorithmSpec, Client};
use s2n_tls::{callbacks::ConnectionFuture, config::ConnectionInitializer};
use std::{
    cmp::min, collections::VecDeque, fmt::Debug, ops::Deref, pin::Pin, sync::{Arc, Mutex, RwLock}, time::{Duration, SystemTime}
};
use tokio::time::Instant;


#[derive(Debug)]
struct SecretState {
    /// secret for the current epoch `n`
    current_secret: RwLock<Arc<EpochSecret>>,
    /// secrets for epoch `n + 1` and `n + 2`
    next_secrets: Mutex<VecDeque<EpochSecret>>,
}

impl SecretState {
    fn current_epoch_secret(&self) -> Arc<EpochSecret> {
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
        epochs.push(self.current_epoch_secret().key_epoch);
        epochs
    }

    /// The Duration between now and the start of key_epoch
    ///
    /// returns None if the epoch has already started
    fn until_epoch_start(key_epoch: u64) -> Option<Duration> {
        let epoch_start = SystemTime::UNIX_EPOCH + (KEY_ROTATION_PERIOD * (key_epoch as u32));
        epoch_start.duration_since(SystemTime::now()).ok()
    }

    /// The Duration between now and when the actor should make the network call
    /// to KMS to retrieve the secret from key_epoch.
    ///
    /// returns None if the fetch should already have occurred
    fn until_fetch(key_epoch: u64, kms_smoothing_factor: u32) -> Option<Duration> {
        // we always want to fetch the key at least one epoch (24 hours) before the
        // key is needed.
        let fetch_time = {
            let fetch_epoch = key_epoch - 2;

            let fetch_epoch_start =
                SystemTime::UNIX_EPOCH + (KEY_ROTATION_PERIOD * (fetch_epoch as u32));
            let fetch_time = fetch_epoch_start + Duration::from_secs(kms_smoothing_factor as u64);
            fetch_time
        };

        fetch_time.duration_since(SystemTime::now()).ok()
    }
}
#[derive(Debug)]
pub struct PskProvider {
    secret_state: Arc<SecretState>,
}

impl PskProvider {
    pub async fn initialize(
        kms_client: Client,
        key_arn: KeyArn,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let current_key_epoch = EpochSecret::current_epoch();
        let current_secret =
            EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, current_key_epoch).await?;
        let mut next_secrets = VecDeque::new();
        next_secrets.push_back(
            EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, current_key_epoch + 1).await?,
        );
        next_secrets.push_back(
            EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, current_key_epoch + 2).await?,
        );

        let kms_smoothing_factor = 5;
        let secret_state = SecretState {
            current_secret: RwLock::new(Arc::new(current_secret)),
            next_secrets: Mutex::new(next_secrets),
        };
        let value = Self {
            secret_state: Arc::new(secret_state),
        };

        tokio::task::spawn(Self::epoch_secret_rotator(
            Arc::clone(&value.secret_state),
            kms_client,
            key_arn,
            kms_smoothing_factor,
            failure_notification,
        ));
        Ok(value)
    }

    fn current_epoch_secret(&self) -> Arc<EpochSecret> {
        self.secret_state.current_secret.read().unwrap().clone()
    }

    /// This loop is responsible for two items
    /// key rotation: this is a local only action, and updates the `current_secret`
    /// to the next epoch.
    ///
    /// key fetch: this is a network call to KMS to derive the next epoch secret
    async fn epoch_secret_rotator(
        client_epoch_secrets: Arc<SecretState>,
        kms_client: Client,
        key_arn: KeyArn,
        kms_smoothing_factor: u32,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) {
        loop {
            let this_epoch = EpochSecret::current_epoch();

            // fetch the new keys
            {
                // fetch all keys that aren't already available
                // The will almost always just fetch `this_epoch + 2`, unless key
                // generation has failed for several days
                let mut to_fetch = vec![this_epoch, this_epoch + 1, this_epoch + 2];
                let available = client_epoch_secrets.available_epochs();
                to_fetch.retain(|epoch| !available.contains(epoch));

                for epoch in to_fetch {
                    match EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, epoch).await {
                        Ok(epoch_secret) => {
                            client_epoch_secrets
                                .next_secrets
                                .lock()
                                .unwrap()
                                .push_back(epoch_secret);
                        }
                        Err(e) => {
                            failure_notification(e);
                            // TODO: failure notification, and quit trying to fetch keys
                            // we rely on next_secrets being ordered
                            break;
                        }
                    }
                }
            }

            // rotate the current key
            {
                let current_key_epoch = client_epoch_secrets.current_epoch_secret().key_epoch;
                let needs_rotation = current_key_epoch < this_epoch;
                let rotation_key = client_epoch_secrets
                    .next_secrets
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|secret| secret.key_epoch == this_epoch)
                    .cloned();

                if needs_rotation && rotation_key.is_some() {
                    *client_epoch_secrets.current_secret.write().unwrap() =
                        Arc::new(rotation_key.unwrap());
                    // drop all old keys
                    client_epoch_secrets
                        .next_secrets
                        .lock()
                        .unwrap()
                        .retain(|secret| secret.key_epoch > this_epoch);
                }
            }

            // sleep until the next event, fetching a new key or updating the current key
            {
                let until_next_rotation = {
                    let next_epoch = client_epoch_secrets.current_epoch_secret().key_epoch + 1;
                    let rotation_available = client_epoch_secrets
                        .next_secrets
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|secret| secret.key_epoch == next_epoch);
                    match SecretState::until_epoch_start(next_epoch) {
                        Some(duration) => Some(duration),
                        None => {
                            if rotation_available {
                                // immediately restart the loop, we want to rotate and
                                // the key is available. It's important to check that
                                // the key is actually available to prevent a hot loop.
                                continue;
                            } else {
                                None
                            }
                        }
                    }
                };

                let until_next_fetch = {
                    let next_fetched_epoch = client_epoch_secrets
                        .available_epochs()
                        .into_iter()
                        .max()
                        .map(|epoch| epoch + 1);
                    if let Some(next_fetched_epoch) = next_fetched_epoch {
                        if let Some(duration) = SecretState::until_fetch(
                            next_fetched_epoch,
                            kms_smoothing_factor,
                        ) {
                            duration
                        } else {
                            // we failed to fetch the key, so retry in an hour
                            Duration::from_secs(3_600)
                        }
                    } else {
                        Duration::from_secs(3_600)
                    }
                };

                let sleep_duration = match until_next_rotation {
                    Some(duration) => min(duration, until_next_fetch),
                    None => until_next_fetch,
                };
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }
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
    use s2n_tls::callbacks::ClientHelloCallback;

    use crate::{psk_derivation::PskIdentity, test_utils::{self, configs_from_callbacks, handshake, mocked_kms_client, PskIdentityObserver, KMS_KEY_ARN_A}, PskProvider};


    #[tokio::test]
    async fn random_session_id() {
        let psk_provider = PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_A.to_owned(), |_|{}).await.unwrap();
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

// /// The `PskProvider` is used along with the [`PskReceiver`] to perform TLS
// /// 1.3 out-of-band PSK authentication, using PSK's generated from KMS.
// ///
// /// This struct can be enabled on a config with [`s2n_tls::config::Builder::set_connection_initializer`].
// ///
// /// The datakey is automatically rotated every 24 hours. Any errors in this rotation
// /// are reported through the configured `failure_notification` callback.
// ///
// /// Note that the "rotation check" only happens when a new connection is created.
// /// So if a new connection is only created every 2 hours, rotation might not be
// /// attempted until 26 hours have elapsed. This results in a 26 hour old PSK being
// /// used for the connection.
// ///
// /// ### ⚠️ WARNING ⚠️
// /// Because of the above behavior, this solution is not a good fit for
// /// extremely low tps scenarios. When performing ~ 1 connection per week or less,
// /// the low tps significantly slows key rotation. This does not cause any specific
// /// system failure, but long lived secrets do not align with cryptographic best
// /// practices.
// #[derive(Clone)]
// pub struct PskProvider {
//     /// The KMS client
//     kms_client: Client,
//     /// The KMS key arn that will be used to generate the datakey which are
//     /// used as TLS Psk's.
//     kms_key_arn: Arc<KeyArn>,
//     client_epoch_secrets: Arc<ClientEpochSecrets>,
//     failure_notification: Arc<dyn Fn(anyhow::Error) + Send + Sync>,
// }

// impl PskProvider {
//     /// Initialize a `PskProvider`.
//     ///
//     /// * `psk_version`: The PSK version that the PSK provider will use.
//     ///   Versions are backwards compatible but will not necessarily be forwards
//     ///   compatible. For further information see the "Versioning" section in the
//     ///   main module documentation.
//     /// * `kms_client`: The KMS client that will be used to make generateDataKey calls.
//     /// * `key`: The KeyArn which will be used in the API calls
//     /// * `obfuscation_key`: The key used to obfuscate any ciphertext details over the wire.
//     /// * `failure_notification`: A callback invoked if there is ever a failure
//     ///   when rotating the key.
//     ///
//     /// This method will call the KMS generate-data-key API to create the initial
//     /// PSK that will be used for TLS connections.
//     ///
//     /// Customers should emit metrics and alarm if there is a failure to rotate
//     /// the key. If the key fails to rotate, then the PskProvider will continue
//     /// using the existing key, and attempt rotation again after [`KEY_ROTATION_PERIOD`]
//     /// has elapsed.
//     ///
//     /// The `failure_notification` implementation will depend on a customer's specific
//     /// metrics/alarming configuration. As an example, if a customer is already
//     /// alarming on tracing `error` events then the following might be sufficient:
//     /// ```ignore
//     /// PskProvider::initialize(client, key, obfuscation_key, |error| {
//     ///     tracing::error!("failed to rotate key: {error}");
//     /// });
//     /// ```
//     ///
//     /// ### ⚠️ WARNING ⚠️
//     /// Failing to take action on the `failure_notification` will result in the
//     /// Provider continuing to use the same data key indefinitely. While this doesn't
//     /// cause any specific system failure, long lived secrets do not align with
//     /// cryptographic best practices. Longer lived secrets have a higher change
//     /// of exposure, so customers should ensure that they alarm and troubleshoot
//     /// rotation failures.
//     pub async fn initialize(
//         psk_version: PskVersion,
//         kms_client: Client,
//         key_arn: KeyArn,
//         failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
//     ) -> anyhow::Result<Self> {
//         debug_assert_eq!(psk_version, PskVersion::V2);
//         let secrets = ClientEpochSecrets::initialize(kms_client, key_arn, failure_notification).await?;
//         let value = Self {

//             last_update_attempt: Arc::new(RwLock::new(Some(Instant::now()))),
//             failure_notification: Arc::new(failure_notification),
//         };
//         Ok(value)
//     }

//     /// Check if a key update is needed. If it is, kick off a background task
//     /// to call KMS and create a new PSK.
//     fn maybe_trigger_key_update(&self) {
//         let last_update = match *self.last_update_attempt.read().unwrap() {
//             Some(update) => update,
//             None => {
//                 // update already in progress
//                 return;
//             }
//         };

//         if last_update.elapsed() >= KEY_ROTATION_PERIOD {
//             // because we released the lock above, we need to recheck the update
//             // status after acquiring the lock.
//             let mut reacquired_update = self.last_update_attempt.write().unwrap();
//             if reacquired_update.is_some() {
//                 *reacquired_update = None;
//                 tokio::spawn({
//                     let psk_provider = self.clone();
//                     async move {
//                         psk_provider.rotate_key().await;
//                     }
//                 });
//             }
//         }
//     }

//     // async fn rotate_key(&self) {
//     //     match Self::generate_datakey(&self.kms_client, &self.kms_key_arn).await {
//     //         Ok(psk) => {
//     //             *self.datakey.write().unwrap() = psk;
//     //         }
//     //         Err(e) => {
//     //             (self.failure_notification)(e);
//     //         }
//     //     }
//     //     *self.last_update_attempt.write().unwrap() = Some(Instant::now());
//     // }

//     // This method accepts owned arguments instead of `&self` so that the same
//     // code can be used in the constructor as well as the background updater.
//     /// Call the KMS `generate datakey` API to gather materials to be used as a TLS PSK.
//     async fn generate_datakey(client: &Client, key: &KeyArn, key_epoch: u64) -> anyhow::Result<Vec<u8>> {
//         let key_epoch = Self::current_key_epoch();
//         let data_key = client
//             .generate_mac()
//             .key_id(key.clone())
//             .mac_algorithm(MacAlgorithmSpec::HmacSha384)
//             .message(Blob::new(key_epoch.to_be_bytes()))
//             .send()
//             .await?;

//         match data_key.mac {
//             Some(mac) => Ok(mac.into_inner()),
//             // the KMS documentation implies that the ciphertext and plaintext
//             // fields are required, although the SDK does not model them as such
//             // https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html#API_GenerateMac_ResponseSyntax
//             None => anyhow::bail!("failed to retrieve the Mac from the GenerateMac operation"),
//         }
//     }
// }

// impl ConnectionInitializer for PskProvider {
//     fn initialize_connection(
//         &self,
//         connection: &mut s2n_tls::connection::Connection,
//     ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
//         let psk = self.daily_secret.read().unwrap().new_connection_psk()?;
//         connection.append_psk(&psk)?;
//         Ok(None)
//     }
// }

// impl Debug for PskProvider {
//     // we use a custom Debug implementation because the failure notification doesn't
//     // implement debug
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("PskProvider")
//             .field("kms_client", &self.kms_client)
//             .field("kms_key_arn", &self.kms_key_arn)
//             .field("obfuscation_key", &self.obfuscation_key)
//             .field("psk", &self.datakey)
//             .field("last_update_attempt", &self.last_update_attempt)
//             .finish()
//     }
// }

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
