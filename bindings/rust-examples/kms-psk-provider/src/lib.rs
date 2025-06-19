use std::{
    collections::HashMap,
    hash::Hash,
    pin::Pin,
    sync::{Mutex, RwLock},
};

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::{config::Region, error::{DisplayErrorContext, SdkError}, meta::PKG_VERSION, operation::decrypt::DecryptError, primitives::Blob, Client, Error};
use s2n_tls::error::Error as S2NError;
use s2n_tls::{
    callbacks::{ConnectionFuture, PskSelectionCallback},
    config::ConnectionInitializer,
};
use tokio::runtime::Handle;

async fn make_key(client: &Client) -> Result<(), Error> {
    let resp = client.create_key().send().await?;

    let id = resp.key_metadata.as_ref().unwrap().key_id();

    println!("Key: {}", id);

    Ok(())
}

enum KmsPskFormat {
    V1,
}



const PSK_SIZE: usize = 32;

struct KmsPskReceiver {
    client: Client,
    // map from ciphertext data key to plaintext data key
    // TODO: how do we evict the old keys?
    // trusted_kms_keys: HashSet<KeyId>,
    key_cache: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl KmsPskReceiver {
    fn new(client: Client) -> Self {
        Self {
            client,
            key_cache: RwLock::new(HashMap::new()),
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
                        tracing::error!("decryption failed, rejecting connection {:?}", DisplayErrorContext(&decryt_error));
                        return;
                    },
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
    // I think this should probably hold a reference to the client? and then refresh
    // itself after 24 hours have passed?
    // does it need to spawn a tokio task, and wrap the datakey and ciphertext in a mutex?
    // that seems like the correct thing to do
    client: Client,
    kms_key_id: KeyId,
    plaintext_datakey: Vec<u8>,
    ciphertext_datakey: Vec<u8>,
}

// pub(crate) type ConnectionFutureResult = Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;

impl ConnectionInitializer for KmsPskProvider {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let psk = self.create_psk();
        println!("created a psk with identity: {:?}", psk);
        connection.append_psk(&psk).unwrap();
        Ok(None)
    }
}

impl KmsPskProvider {
    async fn create(client: &Client, key: KeyId) -> Self {
        let data_key = client
            .generate_data_key()
            .key_id(key.clone())
            .number_of_bytes(PSK_SIZE as i32)
            .send()
            .await
            .unwrap();

        let plaintext = data_key.plaintext().cloned().unwrap().into_inner();
        let ciphertext = data_key.ciphertext_blob().cloned().unwrap().into_inner();
        tracing::info!("plaintext key is {}", hex::encode(&plaintext));
        tracing::info!("ciphertext key is {}", hex::encode(&ciphertext));

        Self {
            client: client.clone(),
            kms_key_id: key,
            plaintext_datakey: plaintext,
            ciphertext_datakey: ciphertext,
        }
    }

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
    async fn handshake() -> Result<(), S2NError> {
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
}
