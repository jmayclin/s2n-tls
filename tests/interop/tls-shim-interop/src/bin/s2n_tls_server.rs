// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, enums::Mode, pool::ConfigPoolBuilder, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use tls_shim_interop::{s2n_tls_shim::ShimS2nTls, ServerTLS};
use tracing::Level;
use std::{env, error::Error, fs, net::{Ipv4Addr, SocketAddr, SocketAddrV4}, process::exit};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

use common::InteropTest;

async fn run_server<Tls: ServerTLS<TcpStream>>(config: Tls::Config, port: u16, test: InteropTest) -> Result<(), Box<dyn Error>> {
    let server = Tls::acceptor(config);

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
        let server_clone = server.clone();
        let handle = tokio::spawn(async move {
            let tls = Tls::accept(&server_clone, stream).await?;
            Tls::handle_server_connection(test, tls).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
        let res = handle.await?.unwrap();
        break;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .init();
    
    let (test, port) = common::parse_server_arguments();
    let cert_pem = fs::read(common::pem_file_path(common::PemType::ServerChain))?;
    let key_pem = fs::read(common::pem_file_path(common::PemType::ServerKey))?;
    let config = match <ShimS2nTls as ServerTLS<TcpStream>>::get_server_config(test, &cert_pem, &key_pem)? {
        Some(c) => c,
        // if the test case isn't supported, return 127
        None => exit(127),
    };
    run_server::<ShimS2nTls>(config, port, test).await?;
    Ok(())
}
