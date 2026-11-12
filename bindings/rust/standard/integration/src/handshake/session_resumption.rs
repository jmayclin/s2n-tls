// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::capability_check::{required_capability, Capability};
use crate::utilities::session_tickets::{
    raw_version_assign, replace_ticket, ClientSession, ResumptionState, SerializedFormat,
    ServerTicket, TicketKey,
};
use s2n_codec::DecoderBuffer;
use std::time::SystemTime;

use openssl::ssl::{SslContextBuilder, SslMethod, SslVersion};

use tls_harness::{
    cohort::{
        openssl::SessionTicketStorage as OSSLTicketStorage,
        s2n_tls::SessionTicketStorage as S2NTicketStorage, OpenSslConfig, OpenSslConnection,
        S2NConfig, S2NConnection,
    },
    harness::{TlsConfigBuilder, TlsInfo},
    openssl_extension::SslStreamExtension,
    Mode, SigType, TlsConnPair,
};

use s2n_tls::security::Policy;

const KEY_NAME: &str = "InsecureTestKey";
const KEY_VALUE: [u8; 16] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3];
const PROTOCOL_VERSIONS: &[SslVersion] = &[
    SslVersion::TLS1,
    SslVersion::TLS1_1,
    SslVersion::TLS1_2,
    SslVersion::TLS1_3,
];
const NUM_RESUMED_RECONNECTS: usize = 5;

type S2NConnPair = TlsConnPair<S2NConnection, S2NConnection>;

/// Builds an s2n-tls client configuration with session ticket support enabled,
/// returning both the config and the associated ticket storage.
fn s2n_client_resumption_config(cert: SigType) -> (S2NTicketStorage, S2NConfig) {
    // Use the 20190801 security policy since it supports TLS 1.0–1.3, which this
    // test relies on to validate resumption behavior across protocol versions.
    s2n_client_resumption_config_with_policy(cert, "20190801")
}

/// Same as [`s2n_client_resumption_config`], with a caller-chosen security policy.
fn s2n_client_resumption_config_with_policy(
    cert: SigType,
    policy: &str,
) -> (S2NTicketStorage, S2NConfig) {
    let ticket_storage = S2NTicketStorage::default();
    let client_config = {
        let mut config = s2n_tls::config::Builder::new_test_config(Mode::Client);
        config
            .set_security_policy(&Policy::from_version(policy).unwrap())
            .unwrap();
        config.set_trust(cert);
        config.enable_session_tickets(true).unwrap();
        config
            .set_session_ticket_callback(ticket_storage.clone())
            .unwrap();
        config.build().unwrap().into()
    };
    (ticket_storage, client_config)
}

/// Builds an s2n-tls server configuration with session tickets enabled and a
/// custom test ticket key installed.
fn s2n_server_resumption_config(cert: SigType, key_value: &[u8]) -> S2NConfig {
    let mut config = s2n_tls::config::Builder::new_test_config(Mode::Server);
    // Use the 20190801 security policy since it supports TLS 1.0–1.3, which this
    // test relies on to validate resumption behavior across protocol versions.
    config
        .set_security_policy(&Policy::from_version("20190801").unwrap())
        .unwrap();
    config.set_chain(cert);
    config.enable_session_tickets(true).unwrap();
    config
        .add_session_ticket_key(
            KEY_NAME.as_bytes(),
            key_value,
            // Use a timestamp in the past so the key is immediately valid.
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
    config.build().unwrap().into()
}

/// Builds an OpenSSL client config that stores the negotiated session for later
/// resumption, constrained to a single protocol version.
fn openssl_client_resumption_config(
    cert: SigType,
    protocol_version: SslVersion,
) -> (OSSLTicketStorage, OpenSslConfig) {
    let session_ticket_storage = OSSLTicketStorage::default();
    let mut builder = SslContextBuilder::new_test_config(Mode::Client);
    builder.set_trust(cert);
    builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::CLIENT);

    // The session callback must be defined inline to satisfy type inference.
    // See: https://github.com/rust-lang/rust/issues/70263
    builder.set_new_session_callback({
        let sts = session_ticket_storage.clone();
        move |_, ticket| {
            let _ = sts.stored_ticket.lock().unwrap().insert(ticket);
        }
    });

    builder
        .set_min_proto_version(Some(protocol_version))
        .unwrap();
    builder
        .set_max_proto_version(Some(protocol_version))
        .unwrap();

    (session_ticket_storage, builder.build().into())
}

/// Verifies that an s2n-tls client can resume sessions established with an
/// OpenSSL server across supported protocol versions.
#[test]
fn s2n_client_resumption_with_openssl() {
    fn s2n_client_case(protocol: SslVersion) -> Result<(), Box<dyn std::error::Error>> {
        let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);

        let server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new_test_config(Mode::Server);
            builder.set_chain(SigType::Rsa2048);
            builder.set_min_proto_version(Some(protocol))?;
            builder.set_max_proto_version(Some(protocol))?;
            builder.build()
        });

        // Initial handshake to generate a session ticket.
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;

        // Resume using the previously issued ticket.
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        let ticket = ticket_storage.get_ticket();
        assert!(!ticket.is_empty());
        pair.client
            .connection_mut()
            .set_session_ticket(&ticket)
            .unwrap();
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        assert!(pair.client.connection_mut().resumed());
        pair.shutdown()?;
        Ok(())
    }

    PROTOCOL_VERSIONS.iter().for_each(|version| {
        if *version == SslVersion::TLS1_3 {
            required_capability(&[Capability::Tls13], || {
                s2n_client_case(SslVersion::TLS1_3).unwrap();
            });
        } else {
            s2n_client_case(*version).unwrap();
        }
    });
}

/// Verifies that an s2n-tls server can resume sessions established with an
/// OpenSSL client across supported protocol versions.
#[test]
fn s2n_server_resumption_with_openssl() {
    fn s2n_server_case(version: SslVersion) -> Result<(), Box<dyn std::error::Error>> {
        let server_config = s2n_server_resumption_config(SigType::Rsa2048, &KEY_VALUE);
        let (ticket_storage, client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, version);

        // Initial handshake to generate a session ticket.
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;

        // Resume using the stored OpenSSL session.
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        let ticket = ticket_storage.get_ticket();
        unsafe { pair.client.connection.mut_ssl().set_session(&ticket)? };
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        assert!(pair.server.connection_mut().resumed());
        pair.shutdown()?;
        Ok(())
    }

    PROTOCOL_VERSIONS.iter().for_each(|version| {
        if *version == SslVersion::TLS1_3 {
            required_capability(&[Capability::Tls13], || {
                s2n_server_case(SslVersion::TLS1_3).unwrap();
            });
        } else {
            s2n_server_case(*version).unwrap();
        }
    });
}

/// Verifies native s2n↔s2n session resumption behavior in isolation.
/// This serves as a stable baseline independent of OpenSSL.
#[test]
fn s2n_client_resumption_with_s2n_server() {
    let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);
    let server_config = s2n_server_resumption_config(SigType::Rsa2048, &KEY_VALUE);

    // Initial handshake to generate a session ticket.
    let mut pair: TlsConnPair<S2NConnection, S2NConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    assert!(!pair.client.connection().resumed());
    assert!(!pair.server.connection().resumed());
    pair.shutdown().unwrap();

    // Resume using the stored session ticket.
    let mut pair: TlsConnPair<S2NConnection, S2NConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    let ticket = ticket_storage.get_ticket();
    assert!(!ticket.is_empty());
    pair.client
        .connection_mut()
        .set_session_ticket(&ticket)
        .unwrap();
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    assert!(pair.client.connection().resumed());
    assert!(pair.server.connection().resumed());

    pair.shutdown().unwrap();
}

/// Verifies that an s2n-tls client can use the same session ticket
/// to establish multiple resumed connections to an OpenSSL server.
#[test]
fn s2n_client_reuses_ticket_tls13() {
    required_capability(&[Capability::Tls13], || {
        let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);

        let server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new_test_config(Mode::Server);
            builder.set_chain(SigType::Rsa2048);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder.build()
        });

        // Initial full handshake to mint the ticket
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        pair.round_trip_assert(10_000).unwrap();
        pair.shutdown().unwrap();

        // Extract the ticket
        let ticket = ticket_storage.get_ticket();
        assert!(!ticket.is_empty());

        // Use the same ticket to assert on ticket reusability
        for _ in 0..NUM_RESUMED_RECONNECTS {
            let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
                TlsConnPair::from_configs(&client_config, &server_config);

            // Set the same ticket on the s2n connection before handshake
            pair.client
                .connection_mut()
                .set_session_ticket(&ticket)
                .unwrap();

            pair.handshake().unwrap();
            pair.round_trip_assert(10_000).unwrap();

            assert!(pair.client.connection().resumed());
            assert!(pair.server.connection.ssl().session_reused());

            pair.shutdown().unwrap();
        }
    });
}

/// Verifies that an invalid session ticket cannot be used to resume
/// a connection on an s2n-tls server, and that the connection falls back to a full
/// handshake.
#[test]
fn invalid_ticket_falls_back_to_full_handshake() {
    required_capability(&[Capability::Tls13], || {
        // Step 1: OpenSSL client ↔ OpenSSL server handshake to generate a session
        let (openssl_ticket_storage, openssl_client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, SslVersion::TLS1_3);

        let openssl_server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
            builder.set_chain(SigType::Rsa2048);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder.build()
        });

        // Extract the OpenSSL session from the client
        let openssl_session = {
            let mut openssl_pair: TlsConnPair<OpenSslConnection, OpenSslConnection> =
                TlsConnPair::from_configs(&openssl_client_config, &openssl_server_config);
            openssl_pair.handshake().unwrap();
            openssl_pair.round_trip_assert(10_000).unwrap();
            openssl_pair.shutdown().unwrap();
            openssl_ticket_storage.get_ticket()
        };

        // Create OpenSSL client ↔ s2n server connection
        let s2n_server_config = s2n_server_resumption_config(SigType::Rsa2048, &KEY_VALUE);

        // Create a fresh OpenSSL client config for the second connection
        let (_, fresh_openssl_client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, SslVersion::TLS1_3);

        // Install the invalid session into the client and attempt connection
        let resumed = {
            let mut mixed_pair: TlsConnPair<OpenSslConnection, S2NConnection> =
                TlsConnPair::from_configs(&fresh_openssl_client_config, &s2n_server_config);

            unsafe {
                mixed_pair
                    .client
                    .connection
                    .mut_ssl()
                    .set_session(&openssl_session)
                    .unwrap();
            }

            mixed_pair.handshake().unwrap();
            mixed_pair.round_trip_assert(10_000).unwrap();

            // Assert that resumption failed (full handshake occurred)
            let resumed = mixed_pair.server.connection().resumed();
            mixed_pair.shutdown().unwrap();
            resumed
        };

        assert!(!resumed);
    });
}

/// Verifies that a session ticket encrypted under a different STEK
/// falls back to a full handshake.
#[test]
fn mismatched_stek_falls_back_to_full_handshake() {
    required_capability(&[Capability::Tls13], || {
        // Create first s2n server with default STEK
        let server_config_1 = s2n_server_resumption_config(SigType::Rsa2048, &KEY_VALUE);

        // Create second s2n server with different STEK
        const DIFFERENT_KEY_VALUE: [u8; 16] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6];
        let server_config_2 = s2n_server_resumption_config(SigType::Rsa2048, &DIFFERENT_KEY_VALUE);

        // Create OpenSSL client config constrained to TLS 1.3
        let (ticket_storage, client_config) = {
            let session_ticket_storage = OSSLTicketStorage::default();
            let mut builder = SslContextBuilder::new_test_config(Mode::Client);
            builder.set_trust(SigType::Rsa2048);
            builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::CLIENT);

            builder.set_new_session_callback({
                let sts = session_ticket_storage.clone();
                move |_, ticket| {
                    let _ = sts.stored_ticket.lock().unwrap().insert(ticket);
                }
            });

            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();

            (session_ticket_storage, builder.build().into())
        };

        // Step 1: Establish session with first server and get ticket
        let ticket = {
            let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
                TlsConnPair::from_configs(&client_config, &server_config_1);
            pair.handshake().unwrap();
            pair.round_trip_assert(10_000).unwrap();

            // Verify this is a full handshake (not resumed)
            assert!(!pair.client.resumed_connection());
            assert!(!pair.server.connection().resumed());

            pair.shutdown().unwrap();
            ticket_storage.get_ticket()
        };

        // Step 2: Try to resume with second server using ticket from first server
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config_2);

        // Set the ticket from server 1 on the OpenSSL client
        unsafe {
            pair.client
                .connection
                .mut_ssl()
                .set_session(&ticket)
                .unwrap();
        }

        pair.handshake().unwrap();
        pair.round_trip_assert(10_000).unwrap();

        // Verify that resumption failed (full handshake occurred) due to STEK mismatch
        assert!(!pair.client.resumed_connection());
        assert!(!pair.server.connection().resumed());

        pair.shutdown().unwrap();
    });
}

/// Verifies that an s2n-tls client rejects a serialized session whose state
/// version is not one it understands.
#[test]
fn invalid_version_on_client() {
    fn run_case(protocol: SslVersion, expected_version: SerializedFormat) {
        let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);
        let server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new_test_config(Mode::Server);
            builder.set_chain(SigType::Rsa2048);
            builder.set_min_proto_version(Some(protocol)).unwrap();
            builder.set_max_proto_version(Some(protocol)).unwrap();
            builder.build()
        });

        // Do a handshake and get the serialized session.
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        pair.round_trip_assert(10_000).unwrap();
        pair.shutdown().unwrap();
        let session = ticket_storage.get_ticket();

        let parsed = ClientSession::deserialize(&session).unwrap();
        assert_eq!(parsed.state.version(), expected_version);
        let version_offset = parsed.state_offset();
        assert_eq!(session[version_offset], expected_version as u8);

        // Sanity check: assigning the expected version leaves the session as it
        // was, and it is accepted.
        let mut unchanged = session.clone();
        raw_version_assign(&mut unchanged[version_offset..], expected_version as u8);
        assert_eq!(unchanged, session);
        let mut conn: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        conn.client
            .connection_mut()
            .set_session_ticket(&unchanged)
            .unwrap();

        let set_session_err = |version: u8| {
            let mut modified = session.clone();
            raw_version_assign(&mut modified[version_offset..], version);

            let mut conn: TlsConnPair<S2NConnection, OpenSslConnection> =
                TlsConnPair::from_configs(&client_config, &server_config);
            conn.client
                .connection_mut()
                .set_session_ticket(&modified)
                .map(|_| ())
                .expect_err(&format!(
                    "version {version} should be rejected (protocol {protocol:?})"
                ))
        };

        set_session_err(expected_version as u8 + 1);
        set_session_err(expected_version as u8 - 1);
    }

    run_case(SslVersion::TLS1_2, SerializedFormat::Tls12V3);
    required_capability(&[Capability::Tls13], || {
        run_case(SslVersion::TLS1_3, SerializedFormat::Tls13V2);
    });
}

/// Verifies that an s2n-tls server does not resume from a ticket whose resumption
/// state has an invalid version, and falls back to a full handshake.
///
/// The ticket is encrypted by the server, so the test decrypts it with the session
/// ticket key, changes the version byte of the state, and encrypts it again.
#[test]
fn invalid_version_on_server() {
    // `client_policy` decides the negotiated version: 20170210 has no TLS1.3 cipher
    // suites, so the client can only negotiate TLS1.2 with the 20190801 server.
    fn run_case(client_policy: &str, expected_version: SerializedFormat) {
        let stek = TicketKey::derive(KEY_NAME.as_bytes(), &KEY_VALUE).unwrap();
        let (ticket_storage, client_config) =
            s2n_client_resumption_config_with_policy(SigType::Rsa2048, client_policy);
        let server_config = s2n_server_resumption_config(SigType::Rsa2048, &KEY_VALUE);

        // Do a handshake and get the client's serialized session.
        let mut pair: S2NConnPair = TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        // TLS1.3 tickets are sent after the handshake, so the client has to read.
        pair.round_trip_assert(10_000).unwrap();
        pair.shutdown().unwrap();
        let session = ticket_storage.get_ticket();

        // Decrypt the server's ticket to get the state that the server will parse.
        let parsed = ClientSession::deserialize(&session).unwrap();
        let server_ticket = ServerTicket::deserialize(&parsed.ticket).unwrap();
        let state = server_ticket.decrypt(&stek).unwrap();
        let server_state: ResumptionState = DecoderBuffer::new(&state).decode_exact().unwrap();
        assert_eq!(server_state.version(), expected_version);
        assert_eq!(state[0], expected_version as u8);

        // Connects a client holding `state` in a ticket encrypted by the server key.
        let resumption_with_state = |state: &[u8]| {
            let ticket = server_ticket.reencrypt(&stek, state).unwrap().serialize();
            let session = replace_ticket(&session, &ticket).unwrap();

            let mut pair: S2NConnPair = TlsConnPair::from_configs(&client_config, &server_config);
            pair.client
                .connection_mut()
                .set_session_ticket(&session)
                .unwrap();
            pair.handshake().unwrap();
            pair.round_trip_assert(10_000).unwrap();

            let is_resumed = {
                let is_resumed = pair.client.connection().resumed();
                // sanity check, client & server agree
                assert_eq!(pair.server.connection().resumed(), is_resumed);
                is_resumed
            };

            pair.shutdown().unwrap();
            is_resumed
        };

        // sanity check: assigning the expected version leaves the state as it was,
        // and the non-tampered state resumes
        let mut unchanged = state.clone();
        raw_version_assign(&mut unchanged, expected_version as u8);
        assert_eq!(unchanged, state);
        assert!(resumption_with_state(&unchanged));

        for version in [expected_version as u8 + 1, expected_version as u8 - 1] {
            let mut modified = state.clone();
            raw_version_assign(&mut modified, version);
            assert!(!resumption_with_state(&modified));
        }
    }

    run_case("20170210", SerializedFormat::Tls12V3);
    required_capability(&[Capability::Tls13], || {
        run_case("20190801", SerializedFormat::Tls13V2);
    });
}
