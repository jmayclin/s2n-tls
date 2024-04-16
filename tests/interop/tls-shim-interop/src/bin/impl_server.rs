// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::{
    error::Error,
    fs,
    net::{Ipv4Addr, SocketAddrV4},
};
use tokio::net::TcpListener;

use common::InteropTest;

const GB: usize = 1_000_000_000;

fn get_config(
    _test: InteropTest,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<s2n_tls::config::Config, Box<dyn Error>> {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(cert_pem, key_pem)?;
    Ok(config.build()?)
}

async fn run_server(
    config: s2n_tls::config::Config,
    port: u16,
    _test: InteropTest,
) -> Result<(), Box<dyn Error>> {
    let server = TlsAcceptor::new(config);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
    let addr = listener
        .local_addr()
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_owned());
    tracing::info!("Listening on {}", addr);

    loop {
        // Wait for a client to connect.
        let (stream, peer_addr) = listener.accept().await?;
        tracing::info!("Connection from {:?}", peer_addr);

        // Spawn a new task to handle the connection.
        // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
        // because the TLS handshake can be slow.
        let server = server.clone();
        tokio::spawn(async move {
            let _tls = server.accept(stream).await?;
            // let target = 100; // Gb
            // let allowed_records = (target * GB / 8_192) as u64; // 8_192 is default s2n record size;
            // //tls.as_mut().set_encryption_limit(allowed_records).unwrap();
            // tracing::info!("{:#?}", tls);

            // // read in the initial message
            // let mut buffer = vec![0x56; 1_000_000];
            // let read = tls.read(buffer.as_mut_slice()).await.unwrap();

            // assert_eq!(read, "gimme data".len());
            // assert_eq!(&buffer[0..read], "gimme data".as_bytes());
            // tracing::info!("the java client said hello to me. Nice fellow");

            // // write 200 Gb to client
            // for i in 0..(200 * 1_000) {
            //     //let update = tls.as_ref().key_updates().unwrap();
            //     if i % (25 * 1_000) == 0 {
            //         //tls.as_mut().request_key_update(s2n_tls::enums::PeerKeyUpdate::KeyUpdateNotRequested).unwrap();
            //     }
            //     //tracing::info!("writing mb {}, send and recv updates: {:?}", i, update);
            //     tls.write_all(&buffer).await.unwrap();
            // }

            // tls.write_all("thats all for now folks".as_bytes()).await.unwrap();

            // tls.shutdown().await?;
            // tracing::info!("Connection from {:?} closed", peer_addr);

            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (test, port) = common::parse_server_arguments();
    let cert_pem = fs::read(common::pem_file_path(common::PemType::ServerChain))?;
    let key_pem = fs::read(common::pem_file_path(common::PemType::ServerKey))?;

    let config = get_config(test, &cert_pem, &key_pem)?;
    run_server(config, port, test).await?;
    Ok(())
}
