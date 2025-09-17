// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::DecodeValue,
    epoch_schedule,
    psk_derivation::{EpochSecret, PskIdentity},
    psk_parser::retrieve_psk_identities,
    KeyArn, KEY_ROTATION_PERIOD, MAXIMUM_KEY_CACHE_SIZE,
};
use aws_sdk_kms::{primitives::Blob, Client};
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    error::Error as S2NError,
};
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Debug)]
struct SecretState {
    pub trusted_key_arns: Vec<KeyArn>,
    pub daily_secrets: RwLock<HashMap<u64, HashMap<KeyArn, EpochSecret>>>,
}

impl SecretState {
    fn new(trusted_key_arns: Vec<KeyArn>) -> Self {
        Self {
            trusted_key_arns,
            daily_secrets: Default::default(),
        }
    }
    
    fn find_match(&self, client_identity: PskIdentity) -> anyhow::Result<s2n_tls::psk::Psk> {
        println!("finding server match for {client_identity:?}");
        let read_lock = self.daily_secrets.read().unwrap();
        let key_map = match read_lock.get(&client_identity.key_epoch) {
            Some(key_map) => key_map,
            None => anyhow::bail!(
                "no keys found for client epoch {}",
                client_identity.key_epoch
            ),
        };

        for epoch_secret in key_map.values() {
            let psk_identity = PskIdentity::new(client_identity.session_name.blob(), epoch_secret)?;
            println!("constructed psk identity from {}: {psk_identity:?}", epoch_secret.key_arn);
            if psk_identity == client_identity {
                let psk_secret = epoch_secret.new_psk_secret(client_identity.session_name.blob());
                return EpochSecret::psk_from_parts(psk_identity, psk_secret)
                    .map_err(|e| anyhow::anyhow!("failed to construct psk {e}"));
            }
        }

        anyhow::bail!(
            "no matching kms binder found for session {}",
            hex::encode(client_identity.session_name.blob())
        );
    }

    fn insert_secret(&self, epoch_secret: EpochSecret) {
        self.daily_secrets
            .write()
            .unwrap()
            .entry(epoch_secret.key_epoch)
            .or_default()
            .insert(epoch_secret.key_arn.clone(), epoch_secret);
    }

    fn available_secrets(&self) -> Vec<(u64, KeyArn)> {
        self.daily_secrets
            .read()
            .unwrap()
            .iter()
            .map(|(epoch, arn_map)| arn_map.keys().map(|key_arn| (*epoch, key_arn.clone())))
            .flatten()
            .collect()
    }

    fn newest_available_epoch(&self) -> Option<u64> {
        self.daily_secrets.read().unwrap().keys().max().cloned()
    }

    fn drop_old_secrets(&self, current_epoch: u64) {
        self.daily_secrets
            .write()
            .unwrap()
            .retain(|epoch, _arn_map| *epoch >= current_epoch - 1);
    }

    async fn update_loop(
        &self,
        kms_client: &Client,
        current_epoch: u64,
        kms_smoothing_factor: u32,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Result<Duration, Duration> {
        let this_epoch = current_epoch;
        let mut fetch_failed = false;

        // fetch the new keys
        {
            // fetch all keys that aren't already available
            // The will almost always just fetch `this_epoch + 2`, unless key
            // generation has failed for several days
            let mut to_fetch: Vec<(u64, KeyArn)> = vec![this_epoch, this_epoch + 1, this_epoch + 2]
                .iter()
                .flat_map(|epoch| {
                    self.trusted_key_arns
                        .iter()
                        .cloned()
                        .map(|arn| (*epoch, arn))
                })
                .collect();

            let available: Vec<(u64, KeyArn)> = self.available_secrets();
            to_fetch.retain(|epoch| !available.contains(epoch));

            for (epoch, key_arn) in to_fetch {
                match EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, epoch).await {
                    Ok(epoch_secret) => {
                        self.insert_secret(epoch_secret);
                    }
                    Err(e) => {
                        fetch_failed = true;
                        failure_notification(
                            anyhow::anyhow!("failed to fetch {key_arn}").context(e),
                        );
                    }
                }
            }
        }

        // drop any keys 2 epochs or more old.
        self.drop_old_secrets(this_epoch);

        let next_fetched_epoch = self
            .newest_available_epoch()
            .map(|epoch| epoch + 1)
            .unwrap_or(this_epoch);

        if fetch_failed {
            Err(Duration::from_secs(3_600))
        } else {
            match epoch_schedule::until_fetch(next_fetched_epoch, kms_smoothing_factor) {
                Some(duration) => Ok(duration),
                None => {
                    // Unreachable: this should only happen if fetch_failed was
                    // true, in which case this branch isn't executed
                    Err(Duration::from_secs(3_600))
                }
            }
        }
    }
}

/// The `PskReceiver` is used along with the [`PskProvider`] to perform TLS
/// 1.3 out-of-band PSK authentication, using PSK's generated from KMS.
///
/// This struct can be enabled on a config with [`s2n_tls::config::Builder::set_client_hello_callback`].
#[derive(Debug)]
pub struct PskReceiver {
    // kms_client: Client,
    // daily secrets
    // key-epoch -> (KeyArn -> DailySecret)
    trusted_key_arns: Vec<KeyArn>,
    daily_secrets: Arc<SecretState>,
}

impl PskReceiver {
    /// Create a new PskReceiver.
    ///
    /// This will receive the ciphertext datakey identities from a TLS client hello,
    /// then decrypt them using KMS. This establishes a mutually authenticated TLS
    /// handshake between parties with IAM permissions to generate and decrypt data keys
    ///
    /// * `kms_client`: The KMS Client that will be used for the decrypt calls
    ///
    /// * `trusted_key_arns`: The list of KMS KeyArns that the PskReceiver will
    ///   accept PSKs from. This is necessary because an attacker could grant the
    ///   server decrypt permissions on AttackerKeyArn, but the PskReceiver should
    ///   _not_ trust any Psk's from AttackerKeyArn.
    ///
    /// * `obfuscation_keys`: The keys that will be used to deobfuscate the received
    ///   identities. The client `PskProvider` must be using one of the obfuscation
    ///   keys in this list. If the PskReceiver receives a Psk identity obfuscated
    ///   using a key _not_ on this list, then the handshake will fail.
    pub async fn initialize(
        kms_client: Client,
        trusted_key_arns: Vec<KeyArn>,
    ) -> anyhow::Result<Self> {
        // generate the needed keys
        let secret_state = SecretState::new(trusted_key_arns.clone());
        let kms_smoothing_factor = 5;
        let current_epoch = EpochSecret::current_epoch();
        if let Err(_) = secret_state
            .update_loop(&kms_client, current_epoch, kms_smoothing_factor, &|e| {})
            .await
        {
            anyhow::bail!("failed to fetch keys during startup");
        }

        // spawn the fetcher

        Ok(Self {
            // kms_client,
            trusted_key_arns,
            daily_secrets: Arc::new(secret_state),
        })
    }

    async fn fetch_keys(
        kms_client: Client,
        daily_secrets: Arc<SecretState>,
        kms_smoothing_factor: u32,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) {
        loop {
            let this_epoch = EpochSecret::current_epoch();
            let sleep_duration = match daily_secrets
                .update_loop(
                    &kms_client,
                    this_epoch,
                    kms_smoothing_factor,
                    &failure_notification,
                )
                .await
            {
                Ok(d) => d,
                Err(d) => d,
            };
            tokio::time::sleep(sleep_duration).await;
        }
    }
}

impl ClientHelloCallback for PskReceiver {
    fn on_client_hello(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        // parse the identity list from the client hello
        let client_hello = connection.client_hello()?;
        let identities = match retrieve_psk_identities(client_hello) {
            Ok(identities) => identities,
            Err(e) => {
                return Err(s2n_tls::error::Error::application(e.into()));
            }
        };

        // extract the identity bytes from the first PSK entry. We assume that we
        // are talking to a PskProvider, so we don't look at any additional entries.
        let psk_identity = match identities.list().first() {
            Some(id) => id.identity.blob(),
            None => {
                return Err(s2n_tls::error::Error::application(
                    "identities list was zero-length".into(),
                ))
            }
        };

        // parse the identity bytes to a PskIdentity
        let client_identity = PskIdentity::decode_from_exact(psk_identity)
            .map_err(|e| s2n_tls::error::Error::application(e.into()))?;
        println!("server received: {client_identity:?}");

        let psk = self
            .daily_secrets
            .find_match(client_identity)
            .map_err(|e| S2NError::application(e.into()))?;
        connection.append_psk(&psk)?;
        Ok(None)
    }
}

#[cfg(test)]
mod secret_state_tests {
    use crate::{
        epoch_schedule, psk_derivation::EpochSecret, receiver::SecretState, test_utils::{self, KMS_KEY_ARN_A, KMS_KEY_ARN_B}, PskReceiver
    };

    #[test]
    fn insert() {
        let secret_state = SecretState::new(vec![]);
        assert!(secret_state.daily_secrets.read().unwrap().is_empty());
        let secret_a = EpochSecret {
            key_arn: "arn:1235:abc".to_owned(),
            key_epoch: 31456,
            secret: b"some secret".to_vec(),
        };
        let secret_b = EpochSecret {
            key_arn: "arn:1235:abd".to_owned(),
            key_epoch: 31457,
            secret: b"some secret".to_vec(),
        };

        {
            secret_state.insert_secret(secret_a.clone());
            let epoch_map = secret_state.daily_secrets.read().unwrap();
            assert_eq!(epoch_map.len(), 1);
            assert_eq!(epoch_map.get(&secret_a.key_epoch).unwrap().len(), 1);
            assert_eq!(
                epoch_map
                    .get(&secret_a.key_epoch)
                    .unwrap()
                    .get(&secret_a.key_arn),
                Some(&secret_a)
            );
        }

        {
            secret_state.insert_secret(secret_b.clone());
            let epoch_map = secret_state.daily_secrets.read().unwrap();
            assert_eq!(epoch_map.len(), 2);
            assert_eq!(epoch_map.get(&secret_b.key_epoch).unwrap().len(), 1);
            assert_eq!(
                epoch_map
                    .get(&secret_b.key_epoch)
                    .unwrap()
                    .get(&secret_b.key_arn),
                Some(&secret_b)
            );
        }

        let available = secret_state.available_secrets();
        assert!(available.contains(&(secret_a.key_epoch, secret_a.key_arn)));
        assert!(available.contains(&(secret_b.key_epoch, secret_b.key_arn)));
        assert_eq!(available.len(), 2);
    }

    #[tokio::test]
    async fn matched_psk_positive() {
        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns)
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 3);

        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns)
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 6);
    }

    #[test]
    fn matched_psk_negatived() {}

    // old keys are removed

    // when there are keys to fetch, we fetch one for each KMS ARN

    // if any fetch fails then we try again in one hour, and keep trying until we
    // succeed, and then we don't wait the full duration

    // if no fetches fail then we don't try again until basically one day later

    // initialization fetch all of the keys
    #[tokio::test]
    async fn initialization_fetches_keys() {
        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns)
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 3);

        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns)
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 6);
    }

    #[tokio::test]
    async fn scheduled_key_fetch() {
        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned()];

        let current_epoch = epoch_schedule::current_epoch();
        let secret_state = SecretState::new(trusted_key_arns);
        assert_eq!(secret_state.available_secrets().len(), 0);
        // the first update fetches 3 secrets
        secret_state.update_loop(&kms_client, current_epoch, 5, &|e|{}).await.unwrap();
        let initial_keys = secret_state.available_secrets();
        assert_eq!(initial_keys.len(), 3);

        // calling it again without any elapsed time results in no activity
        secret_state.update_loop(&kms_client, current_epoch, 5, &|e|{}).await.unwrap();
        assert_eq!(secret_state.available_secrets(), initial_keys);
    }

    // initialize fails if any of the KMS calls fail
}
// #[cfg(test)]
// mod tests {
//     use crate::{
//         psk_derivation::PskVersion,
//         test_utils::{
//             configs_from_callbacks, decrypt_mocks, gdk_mocks, handshake, test_psk_provider,
//             CIPHERTEXT_DATAKEY_A, KMS_KEY_ARN,
//             PLAINTEXT_DATAKEY_A,
//         },
//         PskProvider,
//     };

//     use super::*;
//     use aws_sdk_kms::{operation::decrypt::DecryptError, types::error::InvalidKeyUsageException};
//     // https://docs.aws.amazon.com/sdk-for-rust/latest/dg/testing-smithy-mocks.html
//     use aws_smithy_mocks::{mock, mock_client};
//     use s2n_tls::config::ConnectionInitializer;

//     /// When a new identity isn't in the cache, we
//     /// 1. call KMS to decrypt it
//     /// 2. store the result in the PSK
//     /// When an identity is in the cache
//     /// 1. no calls are made to KMS to decrypt it
//     #[tokio::test]
//     async fn decrypt_path() {
//         let psk_provider = test_psk_provider().await;

//         let (decrypt_rule, decrypt_client) = decrypt_mocks();
//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             vec![KMS_KEY_ARN.to_owned()],
//             vec![OBFUSCATION_KEY.clone()],
//         );

//         let cache_handle = psk_receiver.key_cache.clone();

//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);
//         assert_eq!(decrypt_rule.num_calls(), 0);

//         handshake(&client_config, &server_config).await.unwrap();
//         assert_eq!(decrypt_rule.num_calls(), 1);
//         assert_eq!(
//             cache_handle.get(CIPHERTEXT_DATAKEY_A).unwrap().as_slice(),
//             PLAINTEXT_DATAKEY_A
//         );

//         // no additional decrypt calls, the cached key was used
//         handshake(&client_config, &server_config).await.unwrap();
//         assert_eq!(decrypt_rule.num_calls(), 1);
//     }

//     // if the key ARN isn't recognized, then the handshake fails
//     #[tokio::test]
//     async fn untrusted_key_arn() {
//         let psk_provider = test_psk_provider().await;

//         let (_decrypt_rule, decrypt_client) = decrypt_mocks();
//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             // use an ARN different from the one KMS will return
//             vec!["arn::wont-be-seen".to_string()],
//             vec![OBFUSCATION_KEY.clone()],
//         );

//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

//         let err = handshake(&client_config, &server_config).await.unwrap_err();
//         assert!(err.to_string().contains("untrusted KMS Key: arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab is not trusted"));
//     }

//     #[tokio::test]
//     async fn obfuscation_key_unavailable() {
//         let psk_provider = test_psk_provider().await;

//         // we configured the Psk Receiver with a different obfuscation key
//         let (decrypt_rule, decrypt_client) = decrypt_mocks();
//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             vec![KMS_KEY_ARN.to_owned()],
//             vec![ObfuscationKey::random_test_key()],
//         );

//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

//         let err = handshake(&client_config, &server_config).await.unwrap_err();
//         // unable to deobfuscate: f6c9d1107f9b86a7bfbf836458d0483e not available
//         assert!(err.to_string().starts_with("unable to deobfuscate: "));
//         assert!(err.to_string().ends_with("not available"));

//         // we should not have attempted to decrypt the key
//         assert_eq!(decrypt_rule.num_calls(), 0)
//     }

//     // when the map is at capacity, old items are evicted when new ones are added
//     #[tokio::test]
//     async fn cache_max_capacity() {
//         let (decrypt_rule, decrypt_client) = decrypt_mocks();
//         let (_gdk_rule, gdk_client) = gdk_mocks();

//         let obfuscation_key = ObfuscationKey::random_test_key();
//         let psk_provider = PskProvider::initialize(
//             PskVersion::V1,
//             gdk_client,
//             KMS_KEY_ARN.to_string(),
//             obfuscation_key.clone(),
//             |_| {},
//         )
//         .await
//         .unwrap();

//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             vec![KMS_KEY_ARN.to_owned()],
//             vec![obfuscation_key],
//         );

//         let cache_handle = psk_receiver.key_cache.clone();
//         for i in 0..MAXIMUM_KEY_CACHE_SIZE {
//             cache_handle.insert(i.to_be_bytes().to_vec(), i.to_be_bytes().to_vec());
//         }
//         cache_handle.run_pending_tasks();
//         assert_eq!(cache_handle.entry_count(), MAXIMUM_KEY_CACHE_SIZE as u64);

//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

//         assert_eq!(decrypt_rule.num_calls(), 0);
//         handshake(&client_config, &server_config).await.unwrap();
//         assert_eq!(decrypt_rule.num_calls(), 1);

//         cache_handle.run_pending_tasks();
//         assert_eq!(cache_handle.entry_count(), MAXIMUM_KEY_CACHE_SIZE as u64);
//     }

//     // when the decrypt operation fails, the handshake should also fail
//     #[tokio::test]
//     async fn decrypt_error() {
//         let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt).then_error(|| {
//             DecryptError::InvalidKeyUsageException(InvalidKeyUsageException::builder().build())
//         });
//         let decrypt_client = mock_client!(aws_sdk_kms, [&decrypt_rule]);

//         let psk_provider = test_psk_provider().await;

//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             vec![KMS_KEY_ARN.to_owned()],
//             vec![OBFUSCATION_KEY.clone()],
//         );

//         let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

//         let decrypt_error = handshake(&client_config, &server_config).await.unwrap_err();
//         assert!(decrypt_error.to_string().contains("service error"));
//     }

//     /// When an old PskIdentity is received, the handshake should fail, and no
//     /// decrypt calls should be made.
//     #[tokio::test]
//     async fn receiver_rejects_old_identity() {
//         const OLD_IDENTITY: &[u8] = include_bytes!("../resources/psk_identity.bin");
//         struct OldIdentityInitializer;
//         impl ConnectionInitializer for OldIdentityInitializer {
//             fn initialize_connection(
//                 &self,
//                 connection: &mut s2n_tls::connection::Connection,
//             ) -> Result<Option<Pin<Box<(dyn ConnectionFuture)>>>, s2n_tls::error::Error>
//             {
//                 let psk =
//                     psk_from_material(OLD_IDENTITY, b"doesn't matter, should fail before using")?;
//                 connection.append_psk(&psk)?;
//                 Ok(None)
//             }
//         }

//         let (decrypt_rule, decrypt_client) = decrypt_mocks();
//         let psk_receiver = PskReceiver::initialize(
//             decrypt_client,
//             vec![KMS_KEY_ARN.to_owned()],
//             vec![CONSTANT_OBFUSCATION_KEY.clone()],
//         );

//         let (client_config, server_config) =
//             configs_from_callbacks(OldIdentityInitializer, psk_receiver);
//         let too_old_error = handshake(&client_config, &server_config).await.unwrap_err();
//         assert_eq!(decrypt_rule.num_calls(), 0);
//         assert!(too_old_error.to_string().contains("too old"));
//     }
// }
