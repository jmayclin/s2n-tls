// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    process::exit,
};
use tls_shim_interop::{s2n_tls_shim::S2NShim, ServerTLS};
use tokio::net::{TcpListener, TcpStream};
use tracing::Level;

use common::InteropTest;

// if you try and make `run_server` accept a generic type <Tls: ServerTls<Stream>> then the rust compiler type inference
// will get very confused, and it will complain about the futures returns by the async traits not being send.
async fn run_server(
    config: <S2NShim as ServerTLS<TcpStream>>::Config,
    port: u16,
    test: InteropTest,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = <S2NShim as ServerTLS<TcpStream>>::acceptor(config);

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
    let (stream, peer_addr) = listener.accept().await?;
    tracing::info!("Connection from {:?}", peer_addr);

    let tls = <S2NShim as ServerTLS<TcpStream>>::accept(&server, stream).await?;
    <S2NShim as ServerTLS<TcpStream>>::handle_server_connection(test, tls).await?;

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
    let config =
        match <S2NShim as ServerTLS<TcpStream>>::get_server_config(test, &cert_pem, &key_pem)? {
            Some(c) => c,
            // if the test case isn't supported, return 127
            None => exit(127),
        };
    if let Err(e) = run_server(config, port, test).await {
        tracing::error!("test scenario failed: {:?}", e);
        exit(1);
    }
    Ok(())
}
