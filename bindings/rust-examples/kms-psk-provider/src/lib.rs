mod client_hello_parser;
mod codec;
mod prefixed_list;

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    io::ErrorKind,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
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
use s2n_tls::{callbacks::ClientHelloCallback, error::Error as S2NError};
use s2n_tls::{
    callbacks::{ConnectionFuture, PskSelectionCallback},
    config::ConnectionInitializer,
};
use tokio::runtime::Handle;

use crate::{
    client_hello_parser::{
        ClientHello, ExtensionType, HandshakeMessageHeader, PresharedKeyClientHello, PskIdentity,
    },
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::{PrefixedBlob, PrefixedList},
};

struct ObfuscationKey {
    name: Vec<u8>,
    material: Vec<u8>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct KmsTlsPskIdentity {
    version: KmsPskFormat,
    obfuscation_key_name: PrefixedBlob<u16>,
    nonce: [u8; 12],
    // the KMS datakey ciphertext, encrypted under the obfuscation key
    obfuscated_identity: PrefixedBlob<u16>,
}

impl EncodeValue for KmsTlsPskIdentity {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.version)?;
        buffer.encode_value(&self.obfuscation_key_name)?;
        buffer.encode_value(&self.nonce)?;
        buffer.encode_value(&self.obfuscated_identity)?;
        Ok(())
    }
}

impl DecodeValue for KmsTlsPskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (version, buffer) = buffer.decode_value()?;
        let (obfuscation_key_name, buffer) = buffer.decode_value()?;
        let (nonce, buffer) = buffer.decode_value()?;
        let (obfuscated_identity, buffer) = buffer.decode_value()?;

        let value = Self {
            version,
            obfuscation_key_name,
            nonce,
            obfuscated_identity,
        };

        Ok((value, buffer))
    }
}

impl KmsTlsPskIdentity {
    /// Create a KmsTlsPskIdentity
    ///
    /// * `ciphertext_data_key`: The ciphertext returned from the KMS generateDataKey
    ///                          API.
    /// * `obfuscation_key`: The key that will be used to obfuscate the ciphertext,
    ///                      preventing any details about the ciphertext from being
    ///                      read on the wire.
    pub fn new(mut ciphertext_data_key: Vec<u8>, obfuscation_key: &ObfuscationKey) -> Self {
        let key = RandomizedNonceKey::new(&AES_256_GCM, &obfuscation_key.material).unwrap();
        let nonce = key
            .seal_in_place_append_tag(Aad::empty(), &mut ciphertext_data_key)
            .unwrap();
        let nonce_bytes = nonce.as_ref();

        Self {
            version: KmsPskFormat::V1,
            obfuscation_key_name: PrefixedBlob::new(obfuscation_key.name.clone()),
            nonce: *nonce_bytes,
            obfuscated_identity: PrefixedBlob::new(ciphertext_data_key),
        }
    }

    pub fn obfuscation_key_name(&self) -> &[u8] {
        self.obfuscation_key_name.blob()
    }

    /// de-obfuscate the Psk Identity, returning the datakey ciphertext to be decrypted
    /// with KMS.
    pub fn deobfuscate_datakey(
        &self,
        available_obfuscation_keys: &[ObfuscationKey],
    ) -> anyhow::Result<Vec<u8>> {
        let maybe_key = available_obfuscation_keys
            .iter()
            .find(|key| key.name == self.obfuscation_key_name.blob());
        let obfuscation_key = match maybe_key {
            Some(key) => key,
            None => {
                anyhow::bail!(
                    "unable to deobfuscate: {} not available",
                    hex::encode(self.obfuscation_key_name.blob()),
                )
            }
        };

        let key = RandomizedNonceKey::new(&AES_256_GCM, &obfuscation_key.material)?;

        let mut in_out = Vec::from(self.obfuscated_identity.blob());
        key.open_in_place(Nonce::from(&self.nonce), Aad::empty(), &mut in_out)?;
        Ok(in_out)
    }
}

async fn make_key(client: &Client) -> Result<(), Error> {
    let resp = client.create_key().send().await?;

    let id = resp.key_metadata.as_ref().unwrap().key_id();

    println!("Key: {}", id);

    Ok(())
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
enum KmsPskFormat {
    V1 = 1,
}

impl EncodeValue for KmsPskFormat {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        let byte = *self as u8;
        buffer.encode_value(&byte)?;
        Ok(())
    }
}

impl DecodeValue for KmsPskFormat {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, buffer) = u8::decode_from(buffer)?;
        match value {
            1 => Ok((Self::V1, buffer)),
            _ => Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("{value} in not a valid KmsPskFormat"),
            )),
        }
    }
}

fn psk_from_material(identity: &[u8], secret: &[u8]) -> Result<s2n_tls::psk::Psk, S2NError> {
    let mut psk = s2n_tls::psk::Psk::builder()?;
    psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
    psk.set_identity(identity)?;
    psk.set_secret(secret)?;
    Ok(psk.build()?)
}

const PSK_SIZE: usize = 32;

struct KmsPskReceiver {
    client: Client,
    obfuscation_keys: Vec<ObfuscationKey>,
    trusted_key_ids: Arc<Vec<KeyId>>,
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
    /// This will receive the datakey ciphertext identities from a TLS client hello,
    /// then decrypt them using KMS. This establishes a mutually authenticated TLS
    /// handshake between parties with IAM permissions to generate and decrypt data keys
    ///
    /// * `client`: The KMS Client that will be used for the decrypt calls
    /// * `obfuscation_keys`: The keys that will be used to deobfuscate the received
    ///                       identities. The client `KmsPskProvider` must be using
    ///                       one of the obfuscation keys in this list. If the KmsPskReciever
    ///                       receives a Psk identity obfuscated using a key _not_
    ///                       on this list, then the handshake will fail.
    /// * `trusted_key_ids`: The list of KMS KeyIds that the KmsPskReceiver will
    ///                      accept PSKs from. This is necessary because an attacker
    ///                      could grant the server decrypt permissions on AttackerKeyId,
    ///                      but the KmsPskReceiver should _not_ trust any Psk's
    ///                      from AttackerKeyId.
    fn new(
        client: Client,
        obfuscation_keys: Vec<ObfuscationKey>,
        trusted_key_ids: Vec<KeyId>,
    ) -> Self {
        Self {
            client,
            obfuscation_keys,
            trusted_key_ids: Arc::new(trusted_key_ids),
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

    // given some Psk Identity
    // async fn decrypt_psk_identity(psk_identity: Vec<u8>) -> Vec<u8>
}

/// retrieve the PskIdentity items from the Psk extension in the ClientHello.
fn retrieve_identities(
    client_hello: &s2n_tls::client_hello::ClientHello,
) -> std::io::Result<PrefixedList<PskIdentity, u16>> {
    let bytes = client_hello.raw_message()?;
    let buffer = bytes.as_slice();
    // we trust s2n-tls to have correctly parsed the ClientHello :)
    let (_handshake_header, buffer) = HandshakeMessageHeader::decode_from(buffer)?;
    let (client_hello, buffer) = ClientHello::decode_from(buffer)?;

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

impl ClientHelloCallback for KmsPskReceiver {
    fn on_client_hello(
        // this method takes an immutable reference to self to prevent the
        // Config from being mutated by one connection and then used in another
        // connection, leading to undefined behavior
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let client_hello = connection.client_hello()?;
        let identities = match retrieve_identities(client_hello) {
            Ok(identities) => identities,
            Err(e) => return Err(s2n_tls::error::Error::application(Box::new(e))),
        };

        // we only look at the first identity
        let psk_identity = match identities.list().first() {
            Some(id) => id.identity.blob(),
            None => {
                return Err(s2n_tls::error::Error::application(
                    "identities list was zero-length".into(),
                ))
            }
        };

        let (identity, remaining) = KmsTlsPskIdentity::decode_from(psk_identity).unwrap();
        let ciphertext_datakey = identity
            .deobfuscate_datakey(&self.obfuscation_keys)
            .map_err(|e| s2n_tls::error::Error::application(e.into()))?;


        let read_lock = self.key_cache.read().unwrap();
        let maybe_plaintext = read_lock.get(&ciphertext_datakey).cloned();
        drop(read_lock);

        if let Some(plaintext_datakey) = maybe_plaintext {
            let psk = psk_from_material(psk_identity, &plaintext_datakey)?;
            connection.append_psk(&psk)?;
            return Ok(None);
        } else {
            // decrypt the ciphertext

            // cache the decryption
            // check if there is anything to be removed
        }

        let plaintext = tokio::task::block_in_place(|| {
            Handle::current().block_on(async move { self.decrypt(psk_identity).await })
        });
        let plaintext = match plaintext {
            Ok(p) => p,
            Err(decryt_error) => {
                // The DisplayErrorContext is required to get a useful error
                // message: https://docs.aws.amazon.com/sdk-for-rust/latest/dg/error-handling.html
                tracing::error!(
                    "decryption failed, rejecting connection {:?}",
                    DisplayErrorContext(&decryt_error)
                );
                return Err(s2n_tls::error::Error::application(Box::new(decryt_error)));
            }
        };
        // cache the identity in the decrypted map
        // TODO: limit
        self.key_cache
            .write()
            .unwrap()
            .insert(psk_identity.to_vec(), plaintext.clone());

        let psk = {
            let mut psk = s2n_tls::psk::Psk::builder().unwrap();
            psk.set_hmac(s2n_tls::enums::PskHmac::SHA384).unwrap();
            psk.set_identity(psk_identity).unwrap();
            psk.set_secret(&plaintext).unwrap();
            psk.build().unwrap()
        };
        connection.append_psk(&psk).unwrap();

        Ok(None)
    }
}

impl PskSelectionCallback for KmsPskReceiver {
    fn select_psk(
        &self,
        connection: &mut s2n_tls::connection::Connection,
        psk_list: &mut s2n_tls::callbacks::OfferedPskListRef,
    ) {
        // read the first PSK off the wire. We only accept the client sending a
        // single PSK
        let mut identities = psk_list.identities().unwrap();
        let id = identities.next().unwrap();
        let ciphertext = id.unwrap();

        tracing::info!("server got ciphertext: {}", hex::encode(&ciphertext));

        // check the cache for the key
        let read_lock = self.key_cache.read().unwrap();
        let maybe_plaintext = read_lock.get(ciphertext).cloned();
        drop(read_lock);

        // the hashmap contain the key
        let plaintext = match maybe_plaintext {
            Some(plaintext) => {
                println!("got key from cache");
                plaintext.clone()
            }
            None => {
                println!("decrypting ciphertext");
                let plaintext = tokio::task::block_in_place(|| {
                    Handle::current().block_on(async move { self.decrypt(ciphertext).await })
                });
                let plaintext = match plaintext {
                    Ok(p) => p,
                    Err(decryt_error) => {
                        // The DisplayErrorContext is required to get a useful error
                        // message: https://docs.aws.amazon.com/sdk-for-rust/latest/dg/error-handling.html
                        tracing::error!(
                            "decryption failed, rejecting connection {:?}",
                            DisplayErrorContext(&decryt_error)
                        );
                        return;
                    }
                };
                // cache the identity in the decrypted map
                self.key_cache
                    .write()
                    .unwrap()
                    .insert(ciphertext.to_vec(), plaintext.clone());
                plaintext
            }
        };
        tracing::info!("server got plaintext: {}", hex::encode(&plaintext));

        let psk = {
            let mut psk = s2n_tls::psk::Psk::builder().unwrap();
            psk.set_hmac(s2n_tls::enums::PskHmac::SHA384).unwrap();
            psk.set_identity(ciphertext).unwrap();
            psk.set_secret(&plaintext).unwrap();
            psk.build().unwrap()
        };
        connection.append_psk(&psk).unwrap();
        identities.choose_current_psk().unwrap();

        return;
    }
}

// used by the client to create the KMS PSK
struct KmsPskProvider {
    /// The KMS client
    client: Client,
    /// The KMS KeyId that will be used to generate the datakey which are
    /// used as TLS Psk's.
    kms_key_id: KeyId,
    /// The key used to obfuscate the ciphertext datakey from KMS.
    ///
    /// KMS Ciphertexts have observable regularities in their structure. Obfuscating
    /// the identity prevents any of that from being observable over the wire.
    obfuscation_key: ObfuscationKey,
    /// The current Psk being set on all new connections
    ///
    /// The lock is necessary because this is updated every 24 hours by the
    /// background updater.
    psk: RwLock<s2n_tls::psk::Psk>,
    // TODO: background updated task
}

// pub(crate) type ConnectionFutureResult = Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;

impl ConnectionInitializer for KmsPskProvider {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let psk = self.psk.read().unwrap();
        connection.append_psk(&psk).unwrap();
        Ok(None)
    }
}

impl KmsPskProvider {
    pub async fn initialize(
        client: &Client,
        key: KeyId,
        obfuscation_key: ObfuscationKey,
    ) -> anyhow::Result<Self> {
        let psk = Self::create(client, &key, &obfuscation_key).await?;
        let value = Self {
            client: client.clone(),
            kms_key_id: key,
            obfuscation_key,
            psk: RwLock::new(psk),
        };
        Ok(value)
    }

    // it's inconvenient, but this method accepts arguments instead of `&self` so
    // that the same code can be used in the constructor as well as the background
    // updater
    async fn create(
        client: &Client,
        key: &KeyId,
        obfuscation_key: &ObfuscationKey,
    ) -> anyhow::Result<s2n_tls::psk::Psk> {
        let data_key = client
            .generate_data_key()
            .key_id(key.clone())
            .number_of_bytes(PSK_SIZE as i32)
            .send()
            .await
            .unwrap();

        let plaintext = data_key.plaintext().cloned().unwrap().into_inner();
        let ciphertext = data_key.ciphertext_blob().cloned().unwrap().into_inner();

        let psk_identity = KmsTlsPskIdentity::new(ciphertext, &obfuscation_key);

        let psk = psk_from_material(psk_identity, &plaintext)?;
        Ok(psk)
    }

    // need private create psk function

    fn create_psk(&self) -> s2n_tls::psk::Psk {
        let mut psk = s2n_tls::psk::Builder::new().unwrap();
        psk.set_hmac(s2n_tls::enums::PskHmac::SHA384).unwrap();
        psk.set_identity(&self.ciphertext_datakey).unwrap();
        psk.set_secret(&self.plaintext_datakey).unwrap();
        psk.build().unwrap()
    }
}

type KeyId = String;

/// get a KMS key ID if one is available.
///
/// This is just used for testing. Production use cases should be specifying a
/// KeyId with the permissions configured such that client and server roles have
/// the correct permissions.
async fn get_existing_kms_key(client: &Client) -> Option<KeyId> {
    let output = client.list_keys().send().await.unwrap();
    let key = output.keys().first();
    key.map(|key| key.key_id().unwrap().to_string())
}

async fn create_kms_key(client: &Client) -> KeyId {
    panic!("it should already be here!");
    let resp = client.create_key().send().await.unwrap();
    resp.key_metadata.as_ref().unwrap().key_id().to_string()
}

async fn get_kms_key(client: &Client) -> KeyId {
    if let Some(key) = get_existing_kms_key(client).await {
        key
    } else {
        create_kms_key(client).await
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use s2n_tls::security::Policy;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
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
    async fn psk_selection_handshake() -> Result<(), S2NError> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
            .init();

        let shared_config = aws_config::from_env()
            .region(Region::new("us-west-2"))
            .load()
            .await;
        let client = Client::new(&shared_config);

        let key_id = get_kms_key(&client).await;

        let client_psk_provider = KmsPskProvider::create(&client, key_id.clone()).await;
        let server_psk_recevier = KmsPskReceiver::new(client.clone());

        let mut server_config = s2n_tls::config::Builder::new();
        server_config.set_psk_selection_callback(server_psk_recevier)?;
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
            let mut tls = match client.connect("localhost", stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    println!("error during handshake: {:?}", e);
                    return Ok(());
                }
            };
            println!("{:#?}", tls);
        }

        // request 2: cached key
        {
            let stream = TcpStream::connect(addr).await.unwrap();
            // request a TLS connection on the TCP stream while setting the sni
            let mut tls = match client.connect("localhost", stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    println!("error during handshake: {:?}", e);
                    return Ok(());
                }
            };
            println!("{:#?}", tls);
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_hello_cb_handshake() -> Result<(), S2NError> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
            .init();

        let shared_config = aws_config::from_env()
            .region(Region::new("us-west-2"))
            .load()
            .await;
        let client = Client::new(&shared_config);

        let key_id = get_kms_key(&client).await;

        let client_psk_provider = KmsPskProvider::create(&client, key_id.clone()).await;
        let server_psk_recevier = KmsPskReceiver::new(client.clone());

        let mut server_config = s2n_tls::config::Builder::new();
        server_config.set_client_hello_callback(server_psk_recevier)?;
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
            let mut tls = match client.connect("localhost", stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    println!("error during handshake: {:?}", e);
                    return Ok(());
                }
            };
            println!("{:#?}", tls);
        }

        // request 2: cached key
        {
            let stream = TcpStream::connect(addr).await.unwrap();
            // request a TLS connection on the TCP stream while setting the sni
            let mut tls = match client.connect("localhost", stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    println!("error during handshake: {:?}", e);
                    return Ok(());
                }
            };
            println!("{:#?}", tls);
        }

        Ok(())
    }

    // TODO 
    // - obfuscation test (obfuscate, and deobfuscation, and make sure not equal)
    // - round trip parsing
    // - parsing a checked in format
    // - also it should be possible to staple multiple of these things together.
}
