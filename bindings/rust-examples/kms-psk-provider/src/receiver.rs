use crate::{
    client_hello_parser::{
        ClientHello, ExtensionType, HandshakeMessageHeader, PresharedKeyClientHello, PskIdentity,
    },
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    identity::{KmsTlsPskIdentity, ObfuscationKey},
    prefixed_list::{PrefixedBlob, PrefixedList},
    psk_from_material, retrieve_identities, KeyArn,
};
use aws_config::meta::region::RegionProviderChain;
use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM};
use aws_sdk_kms::{
    config::Region,
    error::{DisplayErrorContext, SdkError},
    meta::PKG_VERSION,
    operation::decrypt::DecryptError,
    primitives::Blob,
    Client, Error,
};
use pin_project::pin_project;
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture, PskSelectionCallback},
    config::ConnectionInitializer,
    error::Error as S2NError,
};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
    io::ErrorKind,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::Poll,
    time::{Duration, Instant},
};
use tokio::runtime::Handle;

#[pin_project]
struct KmsGenerateFuture<F> {
    #[pin]
    future: F,
}

impl<F> KmsGenerateFuture<F>
where
    F: 'static + Send + Sync + Future<Output = anyhow::Result<s2n_tls::psk::Psk>>,
{
    pub fn new(future: F) -> Self {
        KmsGenerateFuture { future }
    }
}

impl<F> s2n_tls::callbacks::ConnectionFuture for KmsGenerateFuture<F>
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
                tracing::error!("{e}");
                return Poll::Ready(Err(s2n_tls::error::Error::application("oops".into())))
            }
            Poll::Pending => return Poll::Pending,
        };
        tracing::info!("set psk on connection");
        connection.append_psk(&psk)?;
        Poll::Ready(Ok(()))
    }
}

pub struct KmsPskReceiver {
    client: Client,
    obfuscation_keys: Vec<ObfuscationKey>,
    trusted_key_arns: Arc<Vec<KeyArn>>,
    // map from ciphertext data key to plaintext data key
    // TODO: how do we evict the old keys?
    // trusted_kms_keys: HashSet<KeyId>,
    // https://crates.io/crates/ordermap
    /// Map from the ciphertext datakey to the plaintext datakey
    key_cache: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    decrypt_count: u64,
    cache_hit_count: u64,
}

impl KmsPskReceiver {
    /// Create a new KmsPskReceiver.
    ///
    /// This will receive the ciphertext datakey identities from a TLS client hello,
    /// then decrypt them using KMS. This establishes a mutually authenticated TLS
    /// handshake between parties with IAM permissions to generate and decrypt data keys
    ///
    /// * `client`: The KMS Client that will be used for the decrypt calls
    /// * `obfuscation_keys`: The keys that will be used to deobfuscate the received
    ///                       identities. The client `KmsPskProvider` must be using
    ///                       one of the obfuscation keys in this list. If the KmsPskReciever
    ///                       receives a Psk identity obfuscated using a key _not_
    ///                       on this list, then the handshake will fail.
    /// * `trusted_key_arns`: The list of KMS KeyIds that the KmsPskReceiver will
    ///                      accept PSKs from. This is necessary because an attacker
    ///                      could grant the server decrypt permissions on AttackerKeyArn,
    ///                      but the KmsPskReceiver should _not_ trust any Psk's
    ///                      from AttackerKeyArn.
    pub fn new(
        client: Client,
        obfuscation_keys: Vec<ObfuscationKey>,
        trusted_key_arns: Vec<KeyArn>,
    ) -> Self {
        Self {
            client,
            obfuscation_keys,
            trusted_key_arns: Arc::new(trusted_key_arns),
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            decrypt_count: 0,
            cache_hit_count: 0,
        }
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SdkError<DecryptError>> {
        let decrypted = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(ciphertext))
            .send()
            .await?;
        let plaintext = decrypted.plaintext().cloned().unwrap().into_inner();
        Ok(plaintext)
    }

    /// This is the main async future that s2n-tls polls.
    ///
    /// It will
    /// 1. decrypt the ciphertext_datakey
    /// 2. check that the decrypted material is associated with a trusted key id
    /// 3. cache the decrypted material in the key cache
    /// 4. return an s2n-tls psk
    ///
    /// All of the arguments are owned to satisfy the `'static` bound that s2n-tls
    /// requires on connection futures.
    async fn kms_decrypt_and_update(
        psk_identity: Vec<u8>,
        ciphertext_datakey: Vec<u8>,
        client: Client,
        trusted_key_ids: Arc<Vec<KeyArn>>,
        key_cache: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    ) -> anyhow::Result<s2n_tls::psk::Psk> {
        let ciphertext_datakey_clone = ciphertext_datakey.clone();
        tracing::info!("querying KMS");
        let decrypted = tokio::spawn(async move {
            client
            .decrypt()
            .ciphertext_blob(Blob::new(ciphertext_datakey_clone))
            .send()
            .await
        }).await??;

        tracing::info!("result from kms: {:?}", decrypted);

        let associated_key_id = decrypted.key_id.as_ref().unwrap();
        if !trusted_key_ids.contains(associated_key_id) {
            anyhow::bail!("untrusted KMS Key: {associated_key_id} is not trusted");
        }

        let plaintext_datakey = decrypted.plaintext.unwrap().into_inner();
        key_cache
            .write()
            .unwrap()
            .insert(ciphertext_datakey, plaintext_datakey.clone());

        // remove up to 2 old keys

        let psk = psk_from_material(&psk_identity, &plaintext_datakey).unwrap();

        Ok(psk)
    }
}

impl ClientHelloCallback for KmsPskReceiver {
    fn on_client_hello(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let client_hello = connection.client_hello()?;
        tracing::info!("retrieved client hello");
        let identities = match retrieve_identities(client_hello) {
            Ok(identities) => identities,
            Err(e) => {
                tracing::error!("{e}");
                return Err(s2n_tls::error::Error::application(Box::new(e)))
            },
        };
        tracing::info!("retrieved identities");

        // we only look at the first identity
        let psk_identity = match identities.list().first() {
            Some(id) => id.identity.blob(),
            None => {
                return Err(s2n_tls::error::Error::application(
                    "identities list was zero-length".into(),
                ))
            }
        };
        tracing::info!("de-obfuscating {}", hex::encode(psk_identity));


        let (identity, remaining) = KmsTlsPskIdentity::decode_from(psk_identity).unwrap();
        let ciphertext_datakey = identity
            .deobfuscate_datakey(&self.obfuscation_keys)
            .map_err(|e| s2n_tls::error::Error::application(e.into()))?;

        tracing::info!("deobfuscated identity: {}", hex::encode(&ciphertext_datakey));

        let read_lock = self.key_cache.read().unwrap();
        let maybe_plaintext = read_lock.get(&ciphertext_datakey).cloned();
        drop(read_lock);

        // If
        if let Some(plaintext_datakey) = maybe_plaintext {
            let psk = psk_from_material(psk_identity, &plaintext_datakey)?;
            connection.append_psk(&psk)?;
            return Ok(None);
        } else {
            let future = Self::kms_decrypt_and_update(
                psk_identity.to_vec(),
                ciphertext_datakey,
                self.client.clone(),
                self.trusted_key_arns.clone(),
                self.key_cache.clone(),
            );
            let wrapped = KmsGenerateFuture::new(future);
            Ok(Some(Box::pin(wrapped)))
        }
    }
}
