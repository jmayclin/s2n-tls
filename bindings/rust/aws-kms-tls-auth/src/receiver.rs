// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::DecodeValue,
    psk_derivation::{EpochSecret, PskIdentity},
    psk_parser::retrieve_psk_identities,
    KeyArn, KEY_ROTATION_PERIOD, MAXIMUM_KEY_CACHE_SIZE,
};
use aws_sdk_kms::{primitives::Blob, Client};
use moka::sync::Cache;
use pin_project::pin_project;
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    error::Error as S2NError,
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    task::Poll,
};

/// DecryptFuture wraps a future from the SDK into a format that s2n-tls understands
/// and can poll.
///
/// Specifically, it implements ConnectionFuture for the interior future type.
#[pin_project]
struct DecryptFuture<F> {
    #[pin]
    future: F,
}

impl<F> DecryptFuture<F>
where
    F: 'static + Send + Sync + Future<Output = anyhow::Result<s2n_tls::psk::Psk>>,
{
    pub fn new(future: F) -> Self {
        DecryptFuture { future }
    }
}

impl<F> s2n_tls::callbacks::ConnectionFuture for DecryptFuture<F>
where
    F: 'static + Send + Sync + Future<Output = anyhow::Result<s2n_tls::psk::Psk>>,
{
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut s2n_tls::connection::Connection,
        ctx: &mut core::task::Context,
    ) -> std::task::Poll<Result<(), S2NError>> {
        let this = self.project();
        let psk = match this.future.poll(ctx) {
            Poll::Ready(Ok(psk)) => psk,
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(s2n_tls::error::Error::application(
                    e.into_boxed_dyn_error(),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        connection.append_psk(&psk)?;
        Poll::Ready(Ok(()))
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
    daily_secrets: RwLock<HashMap<u64, HashMap<KeyArn, EpochSecret>>>,
    // // obfuscation_keys: Vec<ObfuscationKey>,
    // /// The key_cache maps from the ciphertext datakey to the plaintext datakey.
    // /// It has a bounded size, and will also evict items after 2 * KEY_ROTATION_PERIOD
    // /// has elapsed.
    // key_cache: Cache<Vec<u8>, Vec<u8>>,
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
        let current_epoch = EpochSecret::current_epoch();
        let mut secrets: HashMap<u64, HashMap<String, EpochSecret>> = HashMap::new();
        for epoch in current_epoch..=(current_epoch + 2) {
            let epoch_secrets = secrets.entry(epoch).or_default();
            for key_arn in trusted_key_arns.iter() {
                let key = EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, epoch).await?;
                epoch_secrets.insert(key.key_arn.clone(), key);
            }
        }

        // spawn the fetcher

        Ok(Self {
            // kms_client,
            trusted_key_arns,
            daily_secrets: RwLock::new(secrets),
        })
    }

    async fn fetch_keys(
        kms_client: Client,
        trusted_key_arns: Vec<KeyArn>,
        daily_secrets: Arc<RwLock<HashMap<u64, HashMap<KeyArn, EpochSecret>>>>,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) {
        let mut failed_to_fetch: VecDeque<(u64, KeyArn)> = VecDeque::new();

        loop {
            let this_epoch = EpochSecret::current_epoch();

            // fetch the new keys
            {
                // fetch all keys that aren't already available
                // The will almost always just fetch `this_epoch + 2`, unless key
                // generation has failed for several days
                let mut to_fetch = vec![this_epoch, this_epoch + 1, this_epoch + 2];
                let available: Vec<u64> = daily_secrets.read().unwrap().keys().cloned().collect();
                to_fetch.retain(|epoch| !available.contains(epoch));

                for epoch in to_fetch {
                    for key_arn in trusted_key_arns.iter() {
                        match EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, epoch).await {
                            Ok(epoch_secret) => {
                                daily_secrets
                                    .write()
                                    .unwrap()
                                    .entry(epoch)
                                    .or_default()
                                    .insert(key_arn.clone(), epoch_secret);
                            }
                            Err(e) => {
                                failed_to_fetch.push_back((epoch, key_arn.clone()));
                                failure_notification(e);
                            }
                        }
                    }
                }
            }

            // remove all of the expired keys
            {
                // from the map

                // from the failed keys
            }

            //
            {
                // check if we should quit trying because they have expired
            }

            // sleep until they need to be fetched
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

        let all_daily_secrets = self.daily_secrets.read().unwrap();
        let this_epoch_secrets = all_daily_secrets.get(&client_identity.key_epoch).ok_or(
            s2n_tls::error::Error::application(
                format!("key_epoch {} is not available", client_identity.key_epoch).into(),
            ),
        )?;

        // we could just leave the "matching" logic to s2n-tls, but prefer to handle
        // it ourselves for better observability/errors
        for daily_secret in this_epoch_secrets.values() {
            let psk_identity = PskIdentity::new(client_identity.session_name.blob(), daily_secret)
                .map_err(|e| s2n_tls::error::Error::application(e.into()))?;
            println!("secret checking against {psk_identity:?}");
            if psk_identity == client_identity {
                let psk_secret = daily_secret.new_psk_secret(client_identity.session_name.blob());
                let psk = EpochSecret::psk_from_parts(psk_identity, psk_secret)?;
                connection.append_psk(&psk)?;
                return Ok(None);
            }
        }

        Err(s2n_tls::error::Error::application(
            format!(
                "no matching KMS key for client with session: {}",
                hex::encode(client_identity.session_name.blob())
            )
            .into(),
        ))
    }
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
