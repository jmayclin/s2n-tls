// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use std::{error::Error, pin::Pin};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{ServerTLS};


pub struct OpensslShim;

impl std::fmt::Display for OpensslShim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s2n-tls")
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + core::fmt::Debug> ServerTLS<T> for OpensslShim {
    type Config = openssl::ssl::SslAcceptorBuilder;
    type Acceptor = openssl::ssl::SslAcceptor;
    type Stream = tokio_openssl::SslStream<T>;

    fn get_server_config(
        test: InteropTest,
        cert_pem_path: &str,
        key_pem_path: &str,
    ) -> Result<Option<Self::Config>, Box<dyn Error>> {
        if test == InteropTest::LargeDataDownloadWithFrequentKeyUpdates {
            return Ok(None);
        }
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file(key_pem_path, SslFiletype::PEM)?;
        acceptor
            .set_certificate_chain_file(cert_pem_path)?;
        Ok(Some(acceptor))
    }

    fn acceptor(config: Self::Config) -> Self::Acceptor {
        config.build()
    }

    async fn accept(
        server: &Self::Acceptor,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn Error + Send + Sync>> {
        let ssl = openssl::ssl::Ssl::new(server.context()).unwrap();
        let mut ssl_stream = Self::Stream::new(ssl, transport_stream)?;
        Pin::new(&mut ssl_stream).accept().await.unwrap();
        Ok(ssl_stream)
    }
}
