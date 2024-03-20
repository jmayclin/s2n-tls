// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, enums::Mode, pool::ConfigPoolBuilder, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use tls_shim_interop::{ServerTls, ShimS2nTls};
use std::{env, error::Error, fs, net::{Ipv4Addr, SocketAddr, SocketAddrV4}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

use common::InteropTest;

const GB: usize = 1_000_000_000;

async fn run_server<Tls: ServerTls>(config: Tls::Config, port: u16, test: InteropTest) -> Result<(), Box<dyn Error>> {
    let server = Tls::acceptor(config);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
    let addr = listener
        .local_addr()
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_owned());
    println!("Listening on {}", addr);

    loop {
        // Wait for a client to connect.
        let (stream, peer_addr) = listener.accept().await?;
        println!("Connection from {:?}", peer_addr);

        // Spawn a new task to handle the connection.
        // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
        // because the TLS handshake can be slow.
        let server_clone = server.clone();
        tokio::spawn(async move {
            let mut tls = Tls::accept(&server_clone, stream).await?;
            //let mut tls = server.accept(stream).await?;
            let handle_fut = Tls::handle_connection(tls);
            handle_fut.await.unwrap();
            //Tls::handle_connection(tls).await.unwrap();
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (test, port) = common::parse_server_arguments();
    let cert_pem = fs::read(common::pem_file_path(common::PemType::ServerChain))?;
    let key_pem = fs::read(common::pem_file_path(common::PemType::ServerKey))?;
    let config = ShimS2nTls::get_config(test, &cert_pem, &key_pem)?.unwrap();
    run_server::<ShimS2nTls>(config, port, test).await?;
    Ok(())
}
