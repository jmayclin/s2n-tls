use aws_config::Region;
use aws_lc_rs::aead::AES_256_GCM;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::receiver::KmsPskReceiver;

use super::*;

/// get a KMS key arn if one is available.
///
/// This is just used for testing. Production use cases should be specifying a
/// KeyId with the permissions configured such that client and server roles have
/// the correct permissions.
pub async fn existing_kms_key(client: &Client) -> Option<KeyArn> {
    let output = client.list_keys().send().await.unwrap();
    let key = output.keys().first();
    key.map(|key| key.key_arn().unwrap().to_string())
}

async fn create_kms_key(client: &Client) -> KeyArn {
    panic!("it should already be here!");
    let resp = client.create_key().send().await.unwrap();
    resp.key_metadata
        .as_ref()
        .unwrap()
        .arn()
        .unwrap()
        .to_string()
}

pub async fn get_kms_key(client: &Client) -> KeyArn {
    if let Some(key) = existing_kms_key(client).await {
        key
    } else {
        create_kms_key(client).await
    }
}

pub async fn test_kms_client() -> Client {
    let shared_config = aws_config::from_env()
        .region(Region::new("us-west-2"))
        .load()
        .await;
    Client::new(&shared_config)
}

/// Handshake two configs over localhost sockets, returning any errors encountered.
///
/// The server error is preferred if available.
pub async fn async_handshake(
    client_config: &s2n_tls::config::Config,
    server_config: &s2n_tls::config::Config,
) -> Result<(), S2NError> {
    const SERVER_MESSAGE: &[u8] = b"hello from server";
    let client = s2n_tls_tokio::TlsConnector::new(client_config.clone());
    let server = s2n_tls_tokio::TlsAcceptor::new(server_config.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::task::spawn(async move {
        let (stream, _peer_addr) = listener.accept().await.unwrap();
        let mut tls = server.accept(stream).await?;
        tls.write_all(SERVER_MESSAGE).await.unwrap();
        tls.shutdown().await.unwrap();
        Ok::<(), S2NError>(())
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut client_result = client.connect("localhost", stream).await;
    if let Ok(tls) = client_result.as_mut() {
        let mut buffer = [0; SERVER_MESSAGE.len()];
        tls.read_exact(&mut buffer).await.unwrap();
        assert_eq!(buffer, SERVER_MESSAGE);
        tls.shutdown().await.unwrap();
    }

    // check the server status first, because it has the interesting errors
    server.await.unwrap()?;
    client_result?;

    Ok(())
}
