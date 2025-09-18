// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::DecodeValue,
    epoch_schedule,
    psk_derivation::{EpochSecret, PskIdentity},
    psk_parser::retrieve_psk_identities,
    KeyArn, ONE_HOUR,
};
use aws_sdk_kms::Client;
use rand::Rng;
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    error::Error as S2NError,
};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Debug)]
struct ReceiverSecrets {
    pub trusted_key_arns: Vec<KeyArn>,
    pub daily_secrets: RwLock<HashMap<u64, HashMap<KeyArn, EpochSecret>>>,
}

impl ReceiverSecrets {
    fn new(trusted_key_arns: Vec<KeyArn>) -> Self {
        Self {
            trusted_key_arns,
            daily_secrets: Default::default(),
        }
    }

    /// Given a decoded client_identity, try to find an EpochSecret that was used
    /// to produce it. This requires generating the corresponding PskIdentity for
    /// all of the trusted KMS keys.
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
            if psk_identity == client_identity {
                let psk_secret =
                    epoch_secret.new_psk_secret(client_identity.session_name.blob())?;
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

    /// Return a list of all the (epoch, key_arn) EpochSecrets that are available
    fn available_secrets(&self) -> Vec<(u64, KeyArn)> {
        self.daily_secrets
            .read()
            .unwrap()
            .iter()
            .flat_map(|(epoch, arn_map)| arn_map.keys().map(|key_arn| (*epoch, key_arn.clone())))
            .collect()
    }

    fn newest_available_epoch(&self) -> Option<u64> {
        self.daily_secrets.read().unwrap().keys().max().cloned()
    }

    async fn fetch_secrets(
        &self,
        kms_client: &Client,
        current_epoch: u64,
        kms_smoothing_factor: u32,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Result<Duration, Duration> {
        // fetch all keys that aren't already available
        // The will almost always just fetch `this_epoch + 2`, unless key
        // generation has failed for several days
        let mut fetch_failed = false;
        let mut to_fetch: Vec<(u64, KeyArn)> = {
            [
                current_epoch - 1,
                current_epoch,
                current_epoch + 1,
                current_epoch + 2,
            ]
            .iter()
            .flat_map(|epoch| {
                self.trusted_key_arns
                    .iter()
                    .cloned()
                    .map(|arn| (*epoch, arn))
            })
            .collect()
        };

        let available: Vec<(u64, KeyArn)> = self.available_secrets();
        to_fetch.retain(|epoch| !available.contains(epoch));

        for (epoch, key_arn) in to_fetch {
            match EpochSecret::fetch_epoch_secret(kms_client, &key_arn, epoch).await {
                Ok(epoch_secret) => {
                    self.insert_secret(epoch_secret);
                }
                Err(e) => {
                    fetch_failed = true;
                    failure_notification(anyhow::anyhow!("failed to fetch {key_arn}").context(e));
                }
            }
        }

        if fetch_failed {
            println!("fetch failed");
            return Err(ONE_HOUR);
        }

        let sleep_duration = self.newest_available_epoch().and_then(|fetch_epoch| {
            epoch_schedule::until_fetch(fetch_epoch + 1, kms_smoothing_factor)
        });
        match sleep_duration {
            Some(duration) => Ok(duration),
            None => Err(ONE_HOUR),
        }
    }

    /// Drop all of the unneeded secrets.
    ///
    /// If the current epoch is `n`, any key from epoch `n - 2` or earlier will
    /// be dropped.
    fn cleanup_old_secrets(&self, current_epoch: u64) {
        self.daily_secrets
            .write()
            .unwrap()
            .retain(|epoch, _arn_map| *epoch >= current_epoch - 1);
    }

    async fn poll_update(
        &self,
        kms_client: &Client,
        current_epoch: u64,
        kms_smoothing_factor: u32,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Result<Duration, Duration> {
        let sleep_duration = self
            .fetch_secrets(
                &kms_client,
                current_epoch,
                kms_smoothing_factor,
                failure_notification,
            )
            .await;
        self.cleanup_old_secrets(current_epoch);
        sleep_duration
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
    daily_secrets: Arc<ReceiverSecrets>,
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
    ///   accept PSKs from. Applications should avoid trusting large (1000+) numbers
    ///   of KMS keys, because the PskReceiver has to do brute force linear matching
    ///   to find the KMS key that was used for a client identity. This costs ~ 300ns
    ///   per trusted key, and thus is negligible for small amounts of trusted keys.
    pub async fn initialize(
        kms_client: Client,
        trusted_key_arns: Vec<KeyArn>,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let secret_state = Arc::new(ReceiverSecrets::new(trusted_key_arns.clone()));
        // TODO: fix the smoothing here.
        let kms_smoothing_factor = 5;
        let current_epoch = epoch_schedule::current_epoch();
        if let Err(_) = secret_state
            .fetch_secrets(
                &kms_client,
                current_epoch,
                kms_smoothing_factor,
                &failure_notification,
            )
            .await
        {
            anyhow::bail!("failed to fetch keys during startup");
        }

        // spawn the fetcher
        let secret_handle = Arc::clone(&secret_state);
        tokio::spawn(async move {
            let kms_smoothing_factor = rand::rng().random_range(0..(24 * 3_600));
            loop {
                let this_epoch = epoch_schedule::current_epoch();
                let sleep_duration = secret_handle
                    .fetch_secrets(
                        &kms_client,
                        this_epoch,
                        kms_smoothing_factor,
                        &failure_notification,
                    )
                    .await;
                secret_handle.cleanup_old_secrets(this_epoch);

                let sleep_duration = match sleep_duration {
                    Ok(d) => d,
                    Err(d) => d,
                };
                tokio::time::sleep(sleep_duration).await;
            }
        });

        Ok(Self {
            trusted_key_arns,
            daily_secrets: secret_state,
        })
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
        epoch_schedule,
        psk_derivation::EpochSecret,
        receiver::ReceiverSecrets,
        test_utils::{self, KMS_KEY_ARN_A, KMS_KEY_ARN_B},
        PskReceiver,
    };

    #[test]
    fn insert() {
        let secret_state = ReceiverSecrets::new(vec![]);
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
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns, |_| {})
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 4);

        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns, |_| {})
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 8);
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
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns, |_| {})
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 4);

        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns, |_| {})
            .await
            .unwrap();
        assert_eq!(receiver.daily_secrets.available_secrets().len(), 8);
    }

    #[tokio::test]
    async fn receiver_secret_fetch() {
        const KMS_SMOOTHING: u32 = 5;
        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned()];

        let current_epoch = epoch_schedule::current_epoch();
        let secret_state = ReceiverSecrets::new(trusted_key_arns);
        assert_eq!(secret_state.available_secrets().len(), 0);
        // the first update fetches 3 secrets
        secret_state
            .fetch_secrets(&kms_client, current_epoch, KMS_SMOOTHING, &|_| {})
            .await
            .unwrap();
        let initial_keys = secret_state.available_secrets();
        assert_eq!(initial_keys.len(), 4);

        // calling it again without any elapsed time results in no activity
        secret_state
            .fetch_secrets(&kms_client, current_epoch, KMS_SMOOTHING, &|_| {})
            .await
            .unwrap();

        // calling it in a new epoch results in a new key being fetched
        secret_state
            .fetch_secrets(&kms_client, current_epoch + 1, KMS_SMOOTHING, &|_| {})
            .await
            .unwrap();
        assert_eq!(secret_state.available_secrets().len(), 5);
        assert!(secret_state
            .available_secrets()
            .iter()
            .any(|(epoch, _arn)| *epoch == current_epoch + 1));
        assert!(secret_state
            .available_secrets()
            .iter()
            .any(|(epoch, _arn)| *epoch == current_epoch));

        // skipping time results in 2 keys being fetched
        secret_state
            .fetch_secrets(&kms_client, current_epoch + 3, KMS_SMOOTHING, &|_| {})
            .await
            .unwrap();
        assert_eq!(secret_state.available_secrets().len(), 4);
        assert!(secret_state
            .available_secrets()
            .iter()
            .all(|(epoch, _arn)| *epoch != current_epoch));
    }

    #[tokio::test]
    async fn cleanup_old_secrets() {
        const KMS_SMOOTHING: u32 = 5;
        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned()];

        let current_epoch = epoch_schedule::current_epoch();
        let secret_state = ReceiverSecrets::new(trusted_key_arns);
        assert_eq!(secret_state.available_secrets().len(), 0);
        // first load secrets
        secret_state
            .fetch_secrets(&kms_client, current_epoch, KMS_SMOOTHING, &|_| {})
            .await
            .unwrap();
        assert_eq!(secret_state.available_secrets().len(), 4);

        // calling drop immediately doesn't have any impact
        secret_state.cleanup_old_secrets(current_epoch);
        assert_eq!(secret_state.available_secrets().len(), 4);
        let oldest = secret_state
            .available_secrets()
            .iter()
            .map(|(epoch, secret)| *epoch)
            .min()
            .unwrap();

        // calling drop immediately doesn't have any impact
        secret_state.cleanup_old_secrets(current_epoch + 1);
        assert_eq!(secret_state.available_secrets().len(), 3);
        assert!(secret_state
            .available_secrets()
            .iter()
            .all(|(epoch, secret)| *epoch != oldest));
    }

    #[tokio::test]
    async fn failure_notification() {
        // call the secret store with a failing thing.
        // first succeed

        // then fail
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
