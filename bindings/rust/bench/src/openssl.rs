// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    get_cert_path,
    harness::{
        get_ca_path, CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup, Mode,
        TlsBenchConfig, TlsConnection,
    },
    scanner::{params::Cipher, TlsQuery},
    PemType::*,
};
use openssl::ssl::{
    ErrorCode, Ssl, SslContext, SslFiletype, SslMethod, SslRef, SslSession, SslSessionCacheMode,
    SslStream, SslVerifyMode, SslVersion,
};
use std::{
    error::Error,
    io::{Read, Write},
    sync::{Arc, Mutex},
};

// Creates session ticket callback handler
#[derive(Clone, Default)]
pub struct SessionTicketStorage {
    stored_ticket: Arc<Mutex<Option<SslSession>>>,
}

pub struct OpenSslConnection {
    connected_buffer: ConnectedBuffer,
    connection: SslStream<ConnectedBuffer>,
}

impl OpenSslConnection {
    pub fn connection(&self) -> &SslRef {
        self.connection.ssl()
    }
}

impl Drop for OpenSslConnection {
    fn drop(&mut self) {
        // shutdown must be called for session resumption to work
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_set_session.html
        let _result = self.connection.shutdown();
    }
}

pub struct OpenSslConfig {
    config: SslContext,
    session_ticket_storage: SessionTicketStorage,
}

impl OpenSslConfig {
    /// used for endpoint scanning
    /// An Err return value generally indicates that you are trying to configure
    /// something that openssl doesn't support.
    pub fn tls_security_query(query: &crate::scanner::TlsQuery) -> Result<Self, Box<dyn Error>> {
        // if interest is a tls 13 cipher, only tls13 should be allowed
        // if interest is a legacy cipher, only tls10 - tls12 should be allowed
        // if interest is a sig scheme, only tls13 should be allowed
        // if interest is a sig hash, only tls10 - tls12 should be allowed
        let TlsQuery {
            interest: _,
            protocols,
            ciphers,
            curves,
            signatures,
        } = query;

        let mut context = openssl::ssl::SslContext::builder(SslMethod::tls_client()).unwrap();
        context.set_security_level(0);

        // signatures and ciphers are protocol dependent.
        let max_proto = protocols.iter().max().unwrap().ossl_version();
        let min_proto = protocols.iter().min().unwrap().ossl_version();
        context.set_max_proto_version(Some(max_proto))?;
        context.set_min_proto_version(Some(min_proto))?;
        log::trace!("set the proto version max, min, {:?}", protocols);

        let (tls13_ciphers, legacy_ciphers): (Vec<Cipher>, Vec<Cipher>) =
            ciphers.iter().partition(|c| match c {
                Cipher::Tls13(_) => true,
                Cipher::Legacy(_) => false,
            });

        let tls13_ciphers = tls13_ciphers
            .into_iter()
            .map(|c| match c {
                Cipher::Tls13(inner) => inner,
                _ => panic!(),
            })
            .map(|c| format!("{:?}", c))
            .collect::<Vec<String>>()
            .join(":");
        if !tls13_ciphers.is_empty() {
            context.set_ciphersuites(&tls13_ciphers)?;
            log::trace!("set the 13 ciphers: {:?}", tls13_ciphers);
        }

        let legacy_ciphers = legacy_ciphers
            .into_iter()
            .map(|c| match c {
                Cipher::Legacy(legacy) => legacy,
                _ => panic!(),
            })
            .map(|c| c.openssl())
            .collect::<Vec<&str>>()
            .join(":");
        log::trace!("setting cipher list with this value<{}>", legacy_ciphers);
        if !legacy_ciphers.is_empty() {
            context.set_cipher_list(&legacy_ciphers)?;
            log::trace!("set the legacy ciphers: {:?}", legacy_ciphers);
        }

        // https://www.openssl.org/docs/man3.1/man3/SSL_CTX_set1_groups.html
        let curves = curves
            .iter()
            .map(|c| format!("{}", c))
            .collect::<Vec<String>>()
            .join(":");
        log::trace!("setting the groups list to {:?}", curves);
        context.set_groups_list(&curves)?;
        log::trace!("set the curves: {:?}", curves);

        // https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set1_sigalgs.html
        let signatures = signatures
            .iter()
            .map(|s| format!("{}", s))
            .collect::<Vec<String>>()
            .join(":");
        log::trace!("setting the sigalgs {:?}", signatures);
        context.set_sigalgs_list(&signatures)?;
        log::trace!("set the sigalgs {:?}", signatures);

        // load in all of the CA certs

        context.set_ca_file(get_ca_path()).unwrap();
        context.set_verify(SslVerifyMode::NONE);

        Ok(Self {
            config: context.build(),
            session_ticket_storage: SessionTicketStorage::default(),
        })
    }

    pub fn create(&self) -> Ssl {
        Ssl::new(&self.config).unwrap()
    }
}

impl TlsBenchConfig for OpenSslConfig {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        let cipher_suite = match crypto_config.cipher_suite {
            CipherSuite::AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        };

        let ec_key = match crypto_config.kx_group {
            KXGroup::Secp256R1 => "P-256",
            KXGroup::X25519 => "X25519",
        };

        let ssl_method = match mode {
            Mode::Client => SslMethod::tls_client(),
            Mode::Server => SslMethod::tls_server(),
        };

        let session_ticket_storage = SessionTicketStorage::default();

        let mut builder = SslContext::builder(ssl_method)?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_ciphersuites(cipher_suite)?;
        builder.set_groups_list(ec_key)?;

        match mode {
            Mode::Client => {
                builder.set_ca_file(get_cert_path(CACert, crypto_config.sig_type))?;
                builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);

                match handshake_type {
                    HandshakeType::MutualAuth => {
                        builder.set_certificate_chain_file(get_cert_path(
                            ClientCertChain,
                            crypto_config.sig_type,
                        ))?;
                        builder.set_private_key_file(
                            get_cert_path(ClientKey, crypto_config.sig_type),
                            SslFiletype::PEM,
                        )?;
                    }
                    HandshakeType::Resumption => {
                        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
                        // do not attempt to define the callback outside of an
                        // expression directly passed into the function, because
                        // the compiler's type inference doesn't work for this
                        // scenario
                        // https://github.com/rust-lang/rust/issues/70263
                        builder.set_new_session_callback({
                            let sts = session_ticket_storage.clone();
                            move |_, ticket| {
                                let _ = sts.stored_ticket.lock().unwrap().insert(ticket);
                            }
                        });
                    }
                    HandshakeType::ServerAuth => {}
                }
            }
            Mode::Server => {
                builder.set_certificate_chain_file(get_cert_path(
                    ServerCertChain,
                    crypto_config.sig_type,
                ))?;
                builder.set_private_key_file(
                    get_cert_path(ServerKey, crypto_config.sig_type),
                    SslFiletype::PEM,
                )?;

                if handshake_type == HandshakeType::MutualAuth {
                    builder.set_ca_file(get_cert_path(CACert, crypto_config.sig_type))?;
                    builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);
                }
                if handshake_type == HandshakeType::Resumption {
                    builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
                }
            }
        }
        Ok(Self {
            config: builder.build(),
            session_ticket_storage,
        })
    }
}

impl TlsConnection for OpenSslConnection {
    type Config = OpenSslConfig;

    fn name() -> String {
        let version_num = openssl::version::number() as u64;
        let patch: u8 = (version_num >> 4) as u8;
        let fix = (version_num >> 12) as u8;
        let minor = (version_num >> 20) as u8;
        let major = (version_num >> 28) as u8;
        format!(
            "openssl{}.{}.{}{}",
            major,
            minor,
            fix,
            (b'a' + patch - 1) as char
        )
    }

    fn new_from_config(
        config: &Self::Config,
        connected_buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>> {
        // check if there is a session ticket available
        // a session ticket will only be available if the Config was created
        // with session resumption enabled
        let maybe_ticket = config
            .session_ticket_storage
            .stored_ticket
            .lock()
            .unwrap()
            .take();
        if let Some(ticket) = &maybe_ticket {
            let _result = unsafe { config.config.add_session(ticket) };
        }

        let mut connection = Ssl::new(&config.config)?;
        if let Some(ticket) = &maybe_ticket {
            unsafe { connection.set_session(ticket)? };
        }

        let connection = SslStream::new(connection, connected_buffer.clone())?;
        Ok(Self {
            connected_buffer,
            connection,
        })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        let result = if self.connection.ssl().is_server() {
            self.connection.accept()
        } else {
            self.connection.connect()
        };

        // treat blocking (`ErrorCode::WANT_READ`) as `Ok`, expected during handshake
        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.code() != ErrorCode::WANT_READ {
                    //println!("{:?}", err.ssl_error());
                    Err(err.into())
                } else {
                    Ok(())
                }
            }
        }
    }

    fn handshake_completed(&self) -> bool {
        self.connection.ssl().is_init_finished()
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        let cipher_suite = self
            .connection
            .ssl()
            .current_cipher()
            .expect("Handshake not completed")
            .name();
        match cipher_suite {
            "TLS_AES_128_GCM_SHA256" => CipherSuite::AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384" => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection
            .ssl()
            .version2() // version() -> &str is deprecated, version2() returns an enum instead
            .expect("Handshake not completed")
            == SslVersion::TLS1_3
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut write_offset = 0;
        while write_offset < data.len() {
            write_offset += self.connection.write(&data[write_offset..data.len()])?;
            self.connection.flush()?; // make sure internal buffers don't fill up
        }
        Ok(())
    }

    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data.len() {
            read_offset += self.connection.read(&mut data[read_offset..data_len])?
        }
        Ok(())
    }

    /// With OpenSSL's API, not possible after connection initialization:
    /// In order to shrink buffers owned by the connection, config has to built
    /// with `builder.set_mode(SslMode::RELEASE_BUFFERS);`, which tells the
    /// connection to release buffers only when it's idle
    fn shrink_connection_buffers(&mut self) {}

    fn shrink_connected_buffer(&mut self) {
        self.connected_buffer.shrink();
    }

    fn connected_buffer(&self) -> &ConnectedBuffer {
        &self.connected_buffer
    }

    fn resumed_connection(&self) -> bool {
        self.connection.ssl().session_reused()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sig_alg_error_reporting() {
        let mut context = openssl::ssl::SslContext::builder(SslMethod::tls_client()).unwrap();

        // ideally this would return an error message like
        // "RSA-PSS+SHA1 isn't defined you incompetent child"
        let res = context.set_sigalgs_list("RSA-PSS+SHA1");
        assert!(res.is_err());
        // this means there is no useful information :(
        assert!(res.unwrap_err().errors().len() == 0);
    }
}
