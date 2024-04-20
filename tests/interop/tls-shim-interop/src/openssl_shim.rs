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

    async fn handle_server_initiated_reneg(
            stream: &mut Self::Stream,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // at this point, the connection has already had a handshake

        // read in the clients initial message
        let mut client_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
        stream.read(&mut client_greeting_buffer).await?;
        assert_eq!(client_greeting_buffer, CLIENT_GREETING.as_bytes());

        // When called from the server side, SSL_renegotiate() and SSL_renegotiate_abbreviated() 
        // behave identically. They both schedule a request for a new handshake to be sent to the 
        // client. The next time an IO operation is performed then the same checks as on the client 
        // side are performed and then, if appropriate, the request is sent. 
        stream.ssl().renegotiate();
        // try a single byte read to trigger the renegotiate
        stream.read(&mut[0]);

        // we are now waiting for the client to acknowledge the renegotiation 
        // request and actually _do_ the renegotiation. Then it will write the
        // client_finished message.
        let mut client_ready_to_close = vec![0; CLIENT_FINISHED.as_bytes().len()];
        stream.read(&mut client_ready_to_close).await?;
        assert_eq!(client_read_to_close, CLIENT_FINISHED);

        Ok(())
    }
}



///// our own bindings for openssl connection
