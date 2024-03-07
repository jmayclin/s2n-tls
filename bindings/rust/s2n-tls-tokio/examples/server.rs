// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, enums::Mode, pool::ConfigPoolBuilder, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, fs};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

/// NOTE: this certificate and key are to be used for demonstration purposes only!
const DEFAULT_CERT: &str = "/home/ec2-user/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem";
const DEFAULT_KEY: &str = "/home/ec2-user/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-key.pem";

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(short, long, requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    #[clap(short, long, default_value_t = String::from("127.0.0.1:9004"))]
    addr: String,
}

async fn run_server(cert_pem: &[u8], key_pem: &[u8], addr: &str) -> Result<(), Box<dyn Error>> {
    // Set up the configuration for new connections.
    // Minimally you will need a certificate and private key.
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(cert_pem, key_pem)?;
    //config.set_ke

    // Create a connection pool to reuse connections.
    let mut pool = ConfigPoolBuilder::new(Mode::Server, config.build()?);
    pool.set_max_pool_size(10);

    // Create the TlsAcceptor based on the pool.
    let server = TlsAcceptor::new(pool.build());

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let listener = TcpListener::bind(&addr).await?;
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
        let server = server.clone();
        tokio::spawn(async move {
            let mut tls = server.accept(stream).await?;
            println!("{:#?}", tls);

            // read in the initial message
            let mut buffer = vec![0x56; 1_000_000];
            let read = tls.read(buffer.as_mut_slice()).await.unwrap();

            assert_eq!(read, "gimme data".len());
            assert_eq!(&buffer[0..read], "gimme data".as_bytes());
            println!("the java client said hello to me. Nice fellow");

            // write 200 Gb to client
            for i in 0..(200 * 1_000) {
                let update = tls.as_ref().key_updates().unwrap();
                println!("writing mb {}, send and recv updates: {:?}", i, update);
                tls.write_all(&buffer).await.unwrap();
            }



            tls.shutdown().await?;
            println!("Connection from {:?} closed", peer_addr);

            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let cert_pem = fs::read(args.cert)?;
    let key_pem = fs::read(args.key)?;
    run_server(&cert_pem, &key_pem, &args.addr).await?;
    Ok(())
}
