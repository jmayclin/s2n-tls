//! We unwrap our RwLocks because we have no way of recovering from a poisoned mutex.

mod client_hello_parser;
mod codec;
mod identity;
mod prefixed_list;
mod receiver;

use crate::{
    client_hello_parser::{
        ClientHello, ExtensionType, HandshakeMessageHeader, PresharedKeyClientHello, PskIdentity,
    },
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::{PrefixedBlob, PrefixedList},
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
use identity::{KmsTlsPskIdentity, ObfuscationKey};
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture, PskSelectionCallback},
    config::ConnectionInitializer,
    error::Error as S2NError,
};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    io::ErrorKind,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::runtime::Handle;

const MAXIMUM_KEY_CACHE_SIZE: usize = 100_000;
const PSK_SIZE: usize = 32;
const AES_256_GCM_KEY_LEN: usize = 32;
const AES_256_GCM_NONCE_LEN: usize = 12;

type KeyArn = String;

fn psk_from_material(identity: &[u8], secret: &[u8]) -> Result<s2n_tls::psk::Psk, S2NError> {
    let mut psk = s2n_tls::psk::Psk::builder()?;
    psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
    psk.set_identity(identity)?;
    psk.set_secret(secret)?;
    Ok(psk.build()?)
}


/// retrieve the PskIdentity items from the Psk extension in the ClientHello.
fn retrieve_identities(
    client_hello: &s2n_tls::client_hello::ClientHello,
) -> std::io::Result<PrefixedList<PskIdentity, u16>> {
    let bytes = client_hello.raw_message()?;
    let buffer = bytes.as_slice();
    // we trust s2n-tls to have correctly parsed the ClientHello :)
    // let (handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
    // tracing::info!("parsed handshake header {handshake_header:?}");
    let (client_hello, buffer) = ClientHello::decode_from(buffer)?;
    tracing::info!("parsing client hello: {client_hello:#?}");

    let psks = client_hello
        .extensions
        .list()
        .iter()
        .find(|e| e.extension_type == ExtensionType::PreSharedKey);

    match psks {
        Some(extension) => {
            let (identities, buffer) =
                PresharedKeyClientHello::decode_from(extension.extension_data.blob())?;
            Ok(identities.identities)
        }
        None => Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "client hello did not contain PSKs".to_owned(),
        )),
    }
}


// used by the client to create the KMS PSK
#[derive(Debug, Clone)]
pub struct KmsPskProvider {
    /// The KMS client
    client: Client,
    /// The KMS KeyId that will be used to generate the datakey which are
    /// used as TLS Psk's.
    kms_key_arn: Arc<KeyArn>,
    /// The key used to obfuscate the ciphertext datakey from KMS.
    ///
    /// KMS Ciphertexts have observable regularities in their structure. Obfuscating
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
    /// The key is automatically rotated every period. Currently 24 hours.
    const KEY_ROTATION_PERIOD: Duration = Duration::from_secs(3_600 * 24);

    pub async fn initialize(
        client: &Client,
        key: KeyArn,
        obfuscation_key: ObfuscationKey,
    ) -> anyhow::Result<Self> {
        let psk = Self::create(client, &key, &obfuscation_key).await?;

        // delay update
        // adding a delay to the update will smooth out traffic to KMS, and makes
        // it less likely that KMS throttles us

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
        let last_update = match self.last_update.read().unwrap().clone() {
            Some(update) => update,
            None => {
                // update already in progress
                return;
            }
        };

        let current_time = Instant::now();
        if current_time > last_update
            && last_update.saturating_duration_since(current_time) > Self::KEY_ROTATION_PERIOD
        {
            // because we released the lock above, we need to recheck the update
            // status after acquiring the lock.
            let mut reacquired_update = self.last_update.write().unwrap();
            if reacquired_update.is_none() {
                return;
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
        match Self::create(&self.client, &self.kms_key_arn, &self.obfuscation_key).await {
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
    async fn create(
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

        let psk_identity = KmsTlsPskIdentity::new(&ciphertext_datakey, &obfuscation_key);
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
        tracing::info!("appending PSK to the client");
        connection.append_psk(&psk).unwrap();
        self.maybe_trigger_key_update();
        Ok(None)
    }
}


#[cfg(test)]
mod tests {
    use s2n_tls::security::Policy;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use crate::receiver::KmsPskReceiver;

    use super::*;

    async fn make_key(client: &Client) -> Result<(), Error> {
        let resp = client.create_key().send().await?;

        let id = resp.key_metadata.as_ref().unwrap().key_id();

        println!("Key: {}", id);

        Ok(())
    }

    /// get a KMS key arn if one is available.
    ///
    /// This is just used for testing. Production use cases should be specifying a
    /// KeyId with the permissions configured such that client and server roles have
    /// the correct permissions.
    async fn get_existing_kms_key(client: &Client) -> Option<KeyArn> {
        let output = client.list_keys().send().await.unwrap();
        let key = output.keys().first();
        key.map(|key| key.key_arn().unwrap().to_string())
    }

    async fn create_kms_key(client: &Client) -> KeyArn {
        panic!("it should already be here!");
        let resp = client.create_key().send().await.unwrap();
        resp.key_metadata.as_ref().unwrap().key_id().to_string()
    }

    async fn get_kms_key(client: &Client) -> KeyArn {
        if let Some(key) = get_existing_kms_key(client).await {
            key
        } else {
            create_kms_key(client).await
        }
    }

    async fn test_kms_client() -> Client {
        let shared_config = aws_config::from_env()
            .region(Region::new("us-west-2"))
            .load()
            .await;
        Client::new(&shared_config)
    }

    #[tokio::test]
    async fn create_a_key() {
        println!("KMS client version: {}", PKG_VERSION);
        println!();

        let shared_config = aws_config::from_env()
            .region(Region::new("us-west-2"))
            .load()
            .await;
        let client = Client::new(&shared_config);

        let key_id = get_kms_key(&client).await;

        println!("Key: {}", key_id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_hello_cb_handshake() -> Result<(), S2NError> {
        let obfuscation_key = ObfuscationKey::random_test_key();

        tracing_subscriber::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
            .init();

        let client = test_kms_client().await;
        // e.g. 1baeeaaf-bccf-4e0e-8920-8b38d20bc40d
        let key_id = get_kms_key(&client).await;
        tracing::info!("gonna trust {key_id}");

        let client_psk_provider =
            KmsPskProvider::initialize(&client, key_id.clone(), obfuscation_key.clone())
                .await
                .unwrap();

        let server_psk_receiver =
            KmsPskReceiver::new(client.clone(), vec![obfuscation_key], vec![key_id]);

        let mut server_config = s2n_tls::config::Builder::new();
        server_config.set_client_hello_callback(server_psk_receiver)?;
        server_config.set_security_policy(&s2n_tls::security::DEFAULT_TLS13)?;

        let mut client_config = s2n_tls::config::Builder::new();
        client_config.set_connection_initializer(client_psk_provider)?;
        client_config.set_security_policy(&s2n_tls::security::DEFAULT_TLS13)?;

        let client = s2n_tls_tokio::TlsConnector::new(client_config.build()?);
        let server = s2n_tls_tokio::TlsAcceptor::new(server_config.build()?);

        // Bind to an address and listen for connections.
        // ":0" can be used to automatically assign a port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        println!("Listening on {:?}", addr);

        let server = tokio::task::spawn(async move {
            loop {
                // Wait for a client to connect.
                let (stream, peer_addr) = listener.accept().await.unwrap();
                println!("Connection from {:?}", peer_addr);

                // Spawn a new task to handle the connection.
                // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
                // because the TLS handshake can be slow.
                let server = server.clone();
                tokio::spawn(async move {
                    let mut tls = server.accept(stream).await?;
                    println!("{:#?}", tls);

                    tls.shutdown().await?;
                    println!("Connection from {:?} closed", peer_addr);

                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                });
            }
        });

        // request 1
        {
            let stream = TcpStream::connect(addr).await.unwrap();
            // request a TLS connection on the TCP stream while setting the sni
            let tls = client.connect("localhost", stream).await.unwrap();
            println!("{:#?}", tls);
        }

        // request 2: cached key
        {
            let stream = TcpStream::connect(addr).await.unwrap();
            // request a TLS connection on the TCP stream while setting the sni
            let tls = client.connect("localhost", stream).await.unwrap();
            println!("{:#?}", tls);
        }

        Ok(())
    }

    // incorrect obfuscation key, correct key ID -> failed handshake

    // correct obfuscation key, but key ID is not trusted -> failed

    //

    // TODO
    // - obfuscation test (obfuscate, and deobfuscation, and make sure not equal)
    // - round trip parsing
    // - parsing a checked in format
    // - also it should be possible to staple multiple of these things together.

    #[test]
    fn constant_check() {
        assert_eq!(AES_256_GCM_KEY_LEN, AES_256_GCM.key_len());
        assert_eq!(AES_256_GCM_NONCE_LEN, AES_256_GCM.nonce_len());
    }
}
