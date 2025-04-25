use std::{borrow::BorrowMut, time::SystemTime};

use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslStream, SslVersion};

use crate::{
    harness::{TlsConfigBuilder, ViewIO},
    openssl::SessionTicketStorage as OSSLTicketStorage,
    openssl_extension::SslStreamExtension,
    s2n_tls::SessionTicketStorage as S2NTicketStorage,
    Mode, OpenSslConnection, S2NConnection, SigType, TlsConnPair,
};

use super::{ConfigBuilderPair, TestUtils as _};

use s2n_tls::{config::Config as S2NConfig, error::Error as S2NError, security::Policy};

const KEY_NAME: &str = "InsecureTestKey";
const KEY_VALUE: [u8; 16] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3];

fn s2n_client_resumption_config(cert: SigType) -> (S2NTicketStorage, S2NConfig) {
    let ticket_storage = S2NTicketStorage::default();
    let client_config = {
        let mut config = s2n_tls::config::Builder::new_integration_config(Mode::Client);
        config
            .set_security_policy(&Policy::from_version("test_all").unwrap())
            .unwrap();
        config.set_trust(cert);
        config.enable_session_tickets(true);
        config.set_session_ticket_callback(ticket_storage.clone());
        config.build().unwrap()
    };
    (ticket_storage, client_config)
}

fn s2n_server_resumption_config(cert: SigType) -> S2NConfig {
    let mut config = s2n_tls::config::Builder::new_integration_config(Mode::Server);
    config
        .set_security_policy(&Policy::from_version("test_all").unwrap())
        .unwrap();
    config.set_chain(cert);
    config.enable_session_tickets(true);
    config
        .add_session_ticket_key(
            KEY_NAME.as_bytes(),
            KEY_VALUE.as_slice(),
            // use a time that we are sure is in the past to
            // make the key immediately available
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
    config.build().unwrap()
}

fn openssl_client_resumption_config(
    cert: SigType,
    protocol_version: SslVersion,
) -> (OSSLTicketStorage, SslContext) {
    let session_ticket_storage = OSSLTicketStorage::default();
    let mut builder = SslContextBuilder::new_integration_config(Mode::Client);
    builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::CLIENT);
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
    builder.set_security_level(0);
    builder
        .set_min_proto_version(Some(protocol_version))
        .unwrap();
    builder
        .set_max_proto_version(Some(protocol_version))
        .unwrap();
    (session_ticket_storage, builder.build())
}

#[test]
fn s2n_client_resumption_with_openssl() {
    const PROTOCOL_VERSIONS: &[SslVersion] = &[
        SslVersion::TLS1_3,
        SslVersion::TLS1_2,
        SslVersion::TLS1_1,
        SslVersion::TLS1,
    ];

    fn s2n_client_case(protocol: SslVersion) -> Result<(), Box<dyn std::error::Error>> {
        let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);
        // openssl enables session resumption by default
        let server_config = {
            let mut builder = SslContextBuilder::new(SslMethod::tls_server())?;
            builder.set_chain(SigType::Rsa2048);
            builder.set_security_level(0);
            builder.set_min_proto_version(Some(protocol));
            builder.set_max_proto_version(Some(protocol));
            builder.build()
        };

        // initial handshake to generate session ticket
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;

        // test with resumption
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        let ticket = ticket_storage.get_ticket();
        assert!(!ticket.is_empty());
        pair.client.connection.set_session_ticket(&ticket)?;
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;
        Ok(())
    }

    PROTOCOL_VERSIONS.into_iter().for_each(|version| {
        s2n_client_case(*version).unwrap();
    });
}

#[test]
fn s2n_server_resumption_with_openssl() {
    const PROTOCOL_VERSIONS: &[SslVersion] = &[
        SslVersion::TLS1_3,
        SslVersion::TLS1_2,
        SslVersion::TLS1_1,
        SslVersion::TLS1,
    ];

    fn s2n_server_case(version: SslVersion) -> Result<(), Box<dyn std::error::Error>> {
        println!("version: {:?}", version);
        let server_config = s2n_server_resumption_config(SigType::Rsa2048);
        let (ticket_storage, client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, version);

        // initial handshake to generate session ticket
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;

        // test with resumption
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        let ticket = ticket_storage.get_ticket();
        unsafe { pair.client.connection.mut_ssl().set_session(&ticket)? };
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;
        Ok(())
    }

    PROTOCOL_VERSIONS.into_iter().for_each(|version| {
        s2n_server_case(*version).unwrap();
    });
}
