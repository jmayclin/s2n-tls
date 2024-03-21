// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, enums::Mode, pool::ConfigPoolBuilder, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::{
    env,
    error::Error,
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};
use tls_shim_interop::{rustls_shim::RustlsShim, s2n_tls_shim::ShimS2nTls, ClientTLS};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use common::InteropTest;

async fn run_client<Tls: ClientTLS<TcpStream>>(
    config: Tls::Config,
    port: u16,
    test: InteropTest,
) -> Result<(), Box<dyn Error>> {
    let client = Tls::connector(config);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let transport_stream =
        TcpStream::connect(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;

    let tls = Tls::connect(&client, transport_stream).await.unwrap();
    Tls::handle_client_connection(test, tls).await.unwrap();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (test, port) = common::parse_server_arguments();
    let ca_cert = fs::read(common::pem_file_path(common::PemType::CaCert))?;
    let config = <RustlsShim as ClientTLS<TcpStream>>::get_client_config(test, &ca_cert)?.unwrap();
    run_client::<RustlsShim>(config, port, test).await?;
    Ok(())
}
