use crate::{
    codec::EncodeValue,
    identity::{KmsTlsPskIdentity, ObfuscationKey},
    psk_from_material, KeyArn, KEY_ROTATION_PERIOD, PSK_SIZE,
};
use aws_sdk_kms::Client;
use s2n_tls::{callbacks::ConnectionFuture, config::ConnectionInitializer};
use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    time::Instant,
};

// The KmsPskProvider can be used to
#[derive(Debug, Clone)]
pub struct KmsPskProvider {
    /// The KMS client
    client: Client,
    /// The KMS key arn that will be used to generate the datakey which are
    /// used as TLS Psk's.
    kms_key_arn: Arc<KeyArn>,
    /// The key used to obfuscate the ciphertext datakey from KMS.
    ///
    /// KMS ciphertexts have observable regularities in their structure. Obfuscating
    /// the identity prevents any of that from being observable over the wire.
    obfuscation_key: Arc<ObfuscationKey>,
    /// The current Psk being set on all new connections
    ///
    /// The lock is necessary because this is updated every 24 hours by the
    /// background updater.
    psk: Arc<RwLock<s2n_tls::psk::Psk>>,
    /// The last time the key was updated. If `None`, then a key update is in progress.
    last_update: Arc<RwLock<Option<Instant>>>,
}

impl KmsPskProvider {
    pub async fn initialize(
        client: Client,
        key: KeyArn,
        obfuscation_key: ObfuscationKey,
    ) -> anyhow::Result<Self> {
        let psk = Self::generate_psk(&client, &key, &obfuscation_key).await?;

        let value = Self {
            client: client.clone(),
            kms_key_arn: Arc::new(key),
            obfuscation_key: Arc::new(obfuscation_key),
            psk: Arc::new(RwLock::new(psk)),
            last_update: Arc::new(RwLock::new(Some(Instant::now()))),
        };
        Ok(value)
    }

    /// Check if a key update is needed. If it is, kick off a background task
    /// to call KMS and create a new PSK.
    fn maybe_trigger_key_update(&self) {
        let last_update = match *self.last_update.read().unwrap() {
            Some(update) => update,
            None => {
                // update already in progress
                return;
            }
        };

        let current_time = Instant::now();
        if current_time > last_update
            && last_update.saturating_duration_since(current_time) > KEY_ROTATION_PERIOD
        {
            // because we released the lock above, we need to recheck the update
            // status after acquiring the lock.
            let mut reacquired_update = self.last_update.write().unwrap();
            if reacquired_update.is_none() {
            } else {
                *reacquired_update = None;
                tokio::spawn({
                    let psk_provider = self.clone();
                    async move {
                        psk_provider.rotate_key(last_update).await;
                    }
                });
            }
        }
    }

    pub async fn rotate_key(&self, previous_update: Instant) {
        match Self::generate_psk(&self.client, &self.kms_key_arn, &self.obfuscation_key).await {
            Ok(psk) => {
                *self.psk.write().unwrap() = psk;
                *self.last_update.write().unwrap() = Some(Instant::now());
            }
            Err(e) => {
                // we failed to update the PSK. Restore the previous update and let
                // someone else try.
                tracing::error!("failed to create PSK from KMS {e}");
                *self.last_update.write().unwrap() = Some(previous_update);
            }
        }
    }

    // This method accepts owned arguments instead of `&self` so that the same
    // code can be used in the constructor as well as the background updater.
    /// Call the KMS `generate datakey` API to gather materials to be used as a TLS PSK.
    async fn generate_psk(
        client: &Client,
        key: &KeyArn,
        obfuscation_key: &ObfuscationKey,
    ) -> anyhow::Result<s2n_tls::psk::Psk> {
        let data_key = client
            .generate_data_key()
            .key_id(key.clone())
            .number_of_bytes(PSK_SIZE as i32)
            .send()
            .await
            .unwrap();

        let plaintext_datakey = data_key.plaintext().cloned().unwrap().into_inner();
        let ciphertext_datakey = data_key.ciphertext_blob().cloned().unwrap().into_inner();

        let psk_identity = KmsTlsPskIdentity::new(&ciphertext_datakey, obfuscation_key);
        let psk_identity_bytes = psk_identity.encode_to_vec()?;
        let psk = psk_from_material(&psk_identity_bytes, &plaintext_datakey)?;
        Ok(psk)
    }
}

impl ConnectionInitializer for KmsPskProvider {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let psk = self.psk.read().unwrap();
        connection.append_psk(&psk).unwrap();
        self.maybe_trigger_key_update();
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    // update happen
    #[tokio::test]
    async fn key_rotation() {
        // after creating, one call

        // after handshake, still only one generate datakey call

        // set the last update time to something more than KEY_ROTATION_PERIOD ago

        // then we observe another call to generate data key.
        // this is kicked off in a background thread that we don't have any way
        // of tracking so, so we might have to sleep a little bit
    }

    // generate datakey error
}
