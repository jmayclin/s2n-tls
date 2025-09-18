#![allow(dead_code)]
// allow dead code for piece-wise commits

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The KMS TLS PSK Provider provides a way to get a mutually authenticated TLS
//! connection using IAM credentials, KMS, and the external PSK feature of TLS 1.3.
//!
//! The client must have IAM credentials that allow `generate-datakey` API calls
//! for some KMS Key.
//!
//! The server must have IAM credentials that allow `decrypt` calls.
//!
//! ## Generate Data Key
//! The client first calls generate data key. The plaintext datakey is used as the
//! PSK secret, and is the input for [`s2n_tls::psk::Builder::set_secret`]. The
//! ciphertext datakey is set as the PSK identity (sort of, see PSK Identity section).
//!
//! ## Decrypt
//! The client then connects to the server, sending the PSK as part of its client
//! hello. The server then retrieves the PSK identity (ciphertext datakey) from the
//! client hello and calls the KMS decrypt API to retrieve the plaintext datakey.
//!
//! At this point it can construct the same PSK that the client used, so the handshake
//! is able to continue and complete successfully.
//!
//! ## Caching
//! The server component [`PskReceiver`] will cache successfully decrypted ciphertexts.
//! This means that the first handshake from a new client will result in a network
//! call to KMS, but future handshakes from that client will be able to retrieve
//! the plaintext datakey from memory.
//!
//! Note that this cache is bounded to a size of [`MAXIMUM_KEY_CACHE_SIZE`].
//!
//! ## Rotation
//! The client component [`PskProvider`] will automatically rotate the PSK. This
//! is controlled by the [`KEY_ROTATION_PERIOD`] which is currently 24 hours.
//!
//! ## PSK Identity
//! The ciphertext datakey is not directly used as the PSK identity. Because PSK
//! identities can be observed on the wire, the ciphertext is first encrypted using
//! the obfuscation key. This prevents any possible data leakage of ciphertext details.
//!
//! ## Deployment Concerns
//! The obfuscation key that the [`PskProvider`] is configured with must also
//! be supplied to the [`PskReceiver`]. Otherwise handshakes will fail.
//!
//! The KMS Key ARN that the [`PskProvider`] is configured with must be supplied
//! to the [`PskReceiver`]. Otherwise handshakes will fail.
//!
//! Note that the [`PskReceiver`] supports lists for both of these items, so
//! zero-downtime migrations are possible. _Example_: if the client fleet wanted
//! to switch from Key A to Key B it would go through the following stages
//! 1. clients -> [A]     server -> [A]
//! 2. clients -> [A]     server -> [A & B]
//! 3. clients -> [A][B], server -> [A & B]
//! 4. clients ->    [B], server -> [A & B]
//! 5. clients ->    [B], server ->     [B]
//!
//! ## Versioning
//!
//! [`PskVersion`] changes are backwards compatible, but not necessarily forwards
//! compatible.
//!
//! > Note that crate versions and formats below are an example only. There are no
//! > PskVersion changes currently planned. When a new PskVersion is made available
//! > it will be communicated by marking the old PskVersion as `#[deprecated]`.
//!
//! Example:
//! - `PskVersion::V1`: available in `0.0.1`
//! - `PskVersion::V2`: available in `0.0.2`
//!
//! A [`PskReceiver`] will support all available `PskVersion`s, and does not have
//! an explicitly configured version. The `PskReceiver` from `0.0.2` will be able
//! to handshake with V1 and V2 configured clients. The `PskReceiver` from `0.0.1`
//! will only be able to handshake V1 configured clients.
//!
//! A [`PskProvider`] has an explicitly configured `PskVersion`. The `PskProvider`
//! from `0.0.2` can be configured to send `PskVersion::V1` xor `PskVersion::V2`.
//! The `PskProvider` from `0.0.1` can only be configured with `PskVersion::V1`.
//!
//! Consider a fleet of clients and server that is currently using `PskVersion::V1`
//! with crate version `0.0.1`. Upgrading to `PskVersion::V2` would require the
//! following steps:
//!
//! 1. Deploy `0.0.2` across all clients and server. This will allow all `PskReceiver`s
//!    to understand both `PskVersion::V1` and `PskVersion::V2`.
//! 2. Enable `PskVersion::V2` on the `PskProvider` through the `psk_version`
//!    argument in [`PskProvider::initialize`]. Because all of the servers understand
//!    both V1 and V2 formats this can be deployed without any downtime.
//!
//! Note that these steps MUST NOT overlap. A `0.0.1` `PskReceiver` will fail to
//! handshake with a `PskProvider` configured to send `PskVersion::V2`.

mod codec;
mod epoch_schedule;
mod prefixed_list;
mod provider;
mod psk_derivation;
mod psk_parser;
mod receiver;
#[cfg(test)]
pub(crate) mod test_utils;

use aws_lc_rs::hkdf;
use s2n_tls::error::Error as S2NError;
use std::{
    time::{Duration},
};

pub type KeyArn = String;
pub use provider::PskProvider;
pub use psk_derivation::PskVersion;
pub use receiver::PskReceiver;

// We have "pub" use statement so these can be fuzz tested
pub use codec::DecodeValue;
pub use psk_parser::PresharedKeyClientHello;

const PSK_SIZE: usize = 32;
const SHA384_DIGEST_SIZE: usize = 48;

/// The key is automatically rotated every period. Currently 24 hours.
const EPOCH_DURATION: Duration = Duration::from_secs(3_600 * 24);

#[cfg(test)]
mod tests {
    use crate::{SHA384_DIGEST_SIZE};
    use aws_lc_rs::{digest::SHA384};

    /// `key_len()` and `nonce_len()` aren't const functions, so we define
    /// our own constants to let us use those values in things like array sizes.
    #[test]
    fn constant_check() {
        assert_eq!(SHA384_DIGEST_SIZE, SHA384.output_len());
    }
}

#[cfg(test)]
mod integration_tests {
    use aws_config::Region;
    use aws_sdk_kms::Client;

    use crate::test_utils::{configs_from_callbacks, handshake, KMS_KEY_ARN_A, KMS_KEY_ARN_B};

    use super::*;

    const KEY_ARN: &str =
        "arn:aws:kms:us-west-2:109149295617:key/c45d0b28-52c4-489d-b926-ed85f9d97c3c";

    pub async fn test_kms_client() -> Client {
        let shared_config = aws_config::from_env()
            .region(Region::new("us-west-2"))
            .load()
            .await;
        Client::new(&shared_config)
    }

    #[tokio::test]
    async fn test_handshake() {
        let kms_client = test_kms_client().await;
        let key_arn = KEY_ARN.to_owned();

        let client_psk_provider =
            PskProvider::initialize(kms_client.clone(), key_arn.clone(), |e| {})
                .await
                .unwrap();
        println!("client psk provider: {client_psk_provider:?}");
        let server_psk_receiver = PskReceiver::initialize(kms_client, vec![key_arn], |_| {})
            .await
            .unwrap();
        println!("{server_psk_receiver:?}");

        let (client_config, server_config) =
            configs_from_callbacks(client_psk_provider, server_psk_receiver);
        handshake(&client_config, &server_config).await.unwrap();
        handshake(&client_config, &server_config).await.unwrap();
    }

    #[tokio::test]
    async fn basic_handshake() {
        let psk_provider_a = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_A.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_provider_b = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_B.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_receiver = PskReceiver::initialize(
            test_utils::mocked_kms_client(),
            vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()],
            |_| {},
        )
        .await
        .unwrap();

        let client_config_a = test_utils::make_client_config(psk_provider_a);
        let client_config_b = test_utils::make_client_config(psk_provider_b);
        let server_config = test_utils::make_server_config(psk_receiver);

        handshake(&client_config_a, &server_config).await.unwrap();
        handshake(&client_config_b, &server_config).await.unwrap();
    }

    /// if the server only trusts key a, then a handshake with a psk from key b
    /// will fail
    #[tokio::test]
    async fn untrusted_key_arn() {
        let psk_provider_a = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_A.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_provider_b = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_B.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_receiver = PskReceiver::initialize(
            test_utils::mocked_kms_client(),
            vec![KMS_KEY_ARN_A.to_owned()],
            |_| {},
        )
        .await
        .unwrap();

        let client_config_a = test_utils::make_client_config(psk_provider_a);
        let client_config_b = test_utils::make_client_config(psk_provider_b);
        let server_config = test_utils::make_server_config(psk_receiver);

        handshake(&client_config_a, &server_config).await.unwrap();
        let err = handshake(&client_config_b, &server_config)
            .await
            .unwrap_err()
            .to_string();
        // e.g. "no matching kms binder found for session c69d62609826836e718a7f1509effbde"
        assert!(err.contains("no matching kms binder found for session "));
    }
}
