//! We unwrap our RwLocks because we have no way of recovering from a poisoned mutex.

mod client_hello_parser;
mod codec;
mod identity;
mod prefixed_list;
mod provider;
mod receiver;
#[cfg(test)]
pub(crate) mod test_utils;

use crate::{
    client_hello_parser::{ClientHello, ExtensionType, PresharedKeyClientHello, PskIdentity},
    codec::DecodeValue,
    prefixed_list::PrefixedList,
};
use s2n_tls::error::Error as S2NError;
use std::{io::ErrorKind, time::Duration};

pub use provider::KmsPskProvider;
pub use receiver::KmsPskReceiver;

const MAXIMUM_KEY_CACHE_SIZE: usize = 100_000;
const PSK_SIZE: usize = 32;
const AES_256_GCM_KEY_LEN: usize = 32;
const AES_256_GCM_NONCE_LEN: usize = 12;
/// The key is automatically rotated every period. Currently 24 hours.
const KEY_ROTATION_PERIOD: Duration = Duration::from_secs(3_600 * 24);

type KeyArn = String;

fn psk_from_material(identity: &[u8], secret: &[u8]) -> Result<s2n_tls::psk::Psk, S2NError> {
    let mut psk = s2n_tls::psk::Psk::builder()?;
    psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
    psk.set_identity(identity)?;
    psk.set_secret(secret)?;
    psk.build()
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
    if !buffer.is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "malformed client hello",
        ));
    }

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

#[cfg(test)]
mod tests {
    use aws_lc_rs::aead::AES_256_GCM;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::{
        identity::ObfuscationKey,
        test_utils::{
            async_handshake, configs_from_callbacks, existing_kms_key, get_kms_key, test_kms_client,
        },
        KmsPskProvider, KmsPskReceiver,
    };

    /// sanity check for our testing environment
    #[tokio::test]
    async fn retrieve_key() {
        let client = test_kms_client().await;
        let key_arn = existing_kms_key(&client).await;
        assert!(key_arn.is_some());
    }

    #[tokio::test]
    async fn network_kms_integ_test() -> Result<(), s2n_tls::error::Error> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::INFO)
            .init();
        let obfuscation_key = ObfuscationKey::random_test_key();

        let client = test_kms_client().await;
        let key_arn = get_kms_key(&client).await;

        let client_psk_provider =
            KmsPskProvider::initialize(client.clone(), key_arn.clone(), obfuscation_key.clone())
                .await
                .unwrap();

        let server_psk_receiver =
            KmsPskReceiver::new(client.clone(), vec![obfuscation_key], vec![key_arn]);

        let (client_config, server_config) =
            configs_from_callbacks(client_psk_provider, server_psk_receiver);

        // one handshake for the decrypt code path, another for the
        // cached code path
        async_handshake(&client_config, &server_config)
            .await
            .unwrap();
        async_handshake(&client_config, &server_config)
            .await
            .unwrap();

        Ok(())
    }

    /// `key_len()` and `nonce_len()` aren't const functions, so we define
    /// our own constants to let us use those values in things like array sizes.
    #[test]
    fn constant_check() {
        assert_eq!(AES_256_GCM_KEY_LEN, AES_256_GCM.key_len());
        assert_eq!(AES_256_GCM_NONCE_LEN, AES_256_GCM.nonce_len());
    }
}
