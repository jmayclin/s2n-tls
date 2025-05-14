use std::{thread::sleep, time::Duration};

use itertools::iproduct;
use openssl::{
    ssl::{SslContextBuilder, SslVersion},
    version,
};

use crate::{
    harness::{TestPairIO, TlsConfigBuilder, TlsConnIo, TlsImpl},
    openssl::OsslImpl,
    openssl_extension::SslContextExtension,
    rustls::RustlsImpl,
    s2n_tls::S2NConfig,
    tests::TestUtils,
    Mode, OpenSslConnection, S2NConnection, SigType, TlsConnPair,
};

use super::ConfigBuilderPair;

#[test]
fn send_buffer_min_size() {
    // we can successfully use the minimum buffer size
    let minimum_buffer_size = 1034;
    let mut s2n_config = s2n_tls::config::Builder::new();
    let result = s2n_config.set_send_buffer_size(minimum_buffer_size);
    assert!(result.is_ok());

    // anything smaller is invalid
    let invalid_buffer_size = minimum_buffer_size - 1;
    let mut s2n_config = s2n_tls::config::Builder::new();
    let result = s2n_config.set_send_buffer_size(invalid_buffer_size);
    assert!(result.is_err());
}

// #[test]
// fn sslv3() {
//     println!("OpenSSL version: {}", version::version());
//     println!("OpenSSL version number: {:x}", version::number());
//     println!("OpenSSL built flags: {}", version::built_on());

//     let mut configs: ConfigBuilderPair<SslContextBuilder, SslContextBuilder> =
//         ConfigBuilderPair::default();
//     configs.set_cert(SigType::Rsa2048);
//     configs.server.set_protocol(SslVersion::SSL3);
//     configs.client.set_protocol(SslVersion::SSL3);
//     let mut connection: TlsConnPair<OpenSslConnection, OpenSslConnection> =
//         configs.connection_pair();
//     println!(
//         "SSL version: {:?}",
//         connection.client.connection.ssl().version_str()
//     );
//     println!(
//         "Available protocols: {:?}",
//         connection.client.connection.ssl()
//     );
//     connection.handshake().unwrap();
// }

/// Feature: s2n_config_set_send_buffer_size
///
/// Replaces: test_buffered_send.py
#[test]
fn buffered_send() {
    #[derive(Debug, Copy, Clone)]
    enum FragPref {
        LowLatency,
        Throughput,
    }

    /// kilobyte
    const KB: u32 = 1024;
    const TEST_DATA: usize = 2 << 14;

    /// How do these interact? Why are there so many knobs?
    const BUFFER_SIZES: &[u32] = &[1034, KB * 2, KB * 17, KB * 35, KB * 512];
    const FRAGMENT_PREFERENCES: &[Option<FragPref>] =
        &[Some(FragPref::LowLatency), Some(FragPref::Throughput), None];
    const PROTOCOLS: &[SslVersion] = &[
        SslVersion::TLS1_3,
        SslVersion::TLS1_2,
        SslVersion::TLS1_1,
        SslVersion::TLS1,
        SslVersion::SSL3,
    ];

    fn s2n_client_case<Server: TlsImpl>(
        send_buffer_size: u32,
        fragment_preference: Option<FragPref>,
        version: SslVersion,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, Server::ConfigBuilder> =
            ConfigBuilderPair::default();
        configs.set_cert(SigType::Rsa2048);
        configs.server.set_protocol(version);
        configs.client.set_send_buffer_size(send_buffer_size)?;

        let mut conn_pair: TlsConnPair<S2NConnection, Server::Connection> =
            configs.connection_pair();
        if let Some(preference) = fragment_preference {
            match preference {
                FragPref::LowLatency => conn_pair.client.connection.prefer_low_latency()?,
                FragPref::Throughput => conn_pair.client.connection.prefer_throughput()?,
            };
        };

        conn_pair.handshake()?;
        conn_pair.round_trip_assert(TEST_DATA)?;
        conn_pair.shutdown()?;
        Ok(())
    }

    fn s2n_server_case<Client: TlsImpl>(
        send_buffer_size: u32,
        fragment_preference: Option<FragPref>,
        version: SslVersion,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut configs: ConfigBuilderPair<Client::ConfigBuilder, s2n_tls::config::Builder> =
            ConfigBuilderPair::default();
        configs.set_cert(SigType::Rsa2048);
        configs.client.set_protocol(version);
        configs.server.set_send_buffer_size(send_buffer_size)?;

        let mut conn_pair: TlsConnPair<Client::Connection, S2NConnection> =
            configs.connection_pair();
        if let Some(preference) = fragment_preference {
            match preference {
                FragPref::LowLatency => conn_pair.server.connection.prefer_low_latency()?,
                FragPref::Throughput => conn_pair.server.connection.prefer_throughput()?,
            };
        };

        conn_pair.handshake()?;
        conn_pair.round_trip_assert(TEST_DATA)?;
        conn_pair.shutdown()?;
        Ok(())
    }

    // openssl
    iproduct!(FRAGMENT_PREFERENCES, BUFFER_SIZES, PROTOCOLS).for_each(
        |(fragment, buffer, version)| {
            println!("{:?}, {:?}, {:?}", fragment, buffer, version);
            s2n_client_case::<OsslImpl>(*buffer, *fragment, *version).unwrap();
            s2n_server_case::<OsslImpl>(*buffer, *fragment, *version).unwrap();
        },
    );

    // rustls
    iproduct!(
        FRAGMENT_PREFERENCES,
        BUFFER_SIZES,
        [SslVersion::TLS1_3, SslVersion::TLS1_2]
    )
    .for_each(|(fragment, buffer, version)| {
        println!("{:?}, {:?}, {:?}", fragment, buffer, version);
        s2n_client_case::<RustlsImpl>(*buffer, *fragment, version).unwrap();
        s2n_client_case::<RustlsImpl>(*buffer, *fragment, version).unwrap();
    });
}

/// Feature: s2n_connection_prefer_low_latency()
///
/// "Prefer low latency" causes s2n-tls to use smaller record sizes. This is a wire
/// format change, so we use an integration test to make sure things remain correct.
#[test]
fn prefer_low_latency() {
    let mut builder = ConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
    builder.set_cert(crate::SigType::Rsa2048);
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = builder.connection_pair();

    // configure s2n-tls server connection to prefer low latency
    pair.server.connection.prefer_low_latency().unwrap();

    assert!(pair.handshake().is_ok());
    assert!(pair.round_trip_assert(16_000).is_ok());
    pair.shutdown().unwrap();
}

/// Correctness: s2n-tls correctly handles different record sizes
///
/// We configure an openssl client to use a variety of record sizes to confirm
/// that s2n-tls correctly handles the differently sized records. This is done by
/// with the `SSL_CTX_set_max_send_fragment` openssl API.
/// https://docs.openssl.org/3.0/man3/SSL_CTX_set_split_send_fragment/#synopsis
#[test]
fn fragmentation() {
    const FRAGMENT_TEST_CASES: [usize; 5] = [512, 2048, 8192, 12345, 16384];

    fn test_case(client_frag_length: usize) {
        let mut builder =
            ConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        builder.set_cert(crate::SigType::Rsa2048);
        builder.client.set_max_send_fragment(client_frag_length);
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = builder.connection_pair();

        assert!(pair.handshake().is_ok());
        assert!(pair.round_trip_assert(16_000).is_ok());
        pair.shutdown().unwrap();
    }

    FRAGMENT_TEST_CASES
        .into_iter()
        .for_each(|frag_length| test_case(frag_length));
}

/// Feature: s2n_connection_set_dynamic_record_threshold()
///
/// Note that the resize threshold is only counting application data, not handshake
/// messages.
///
/// The amount of data is chosen so that we don't have to worry about "remainder"
/// data
#[test]
fn dynamic_record_sizing() -> Result<(), Box<dyn std::error::Error>> {
    const RESIZE_THRESHOLD: usize = 16_000;
    const SMALL_RECORD_SIZE: usize = 1_500;
    // Chosen so the final record is always more than 1,500, which makes assertions easier.
    const APP_DATA_SIZE: usize = 100_000;

    fn test_case<C: TlsConnIo, S: TlsConnIo>(
        mut pair: TlsConnPair<C, S>,
        s2n_tls_role: Mode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        pair.handshake()?;
        let client_handshake_total = pair.io.total_bytes_sent(s2n_tls_role);
        println!("client handshake total: {:?}", client_handshake_total);

        // initial ramp up: should start with small records, then switch to large records
        pair.round_trip_assert(APP_DATA_SIZE)?;

        let mut total_sent = 0;
        for record in pair.io.writes(s2n_tls_role) {
            if total_sent < (RESIZE_THRESHOLD + client_handshake_total) {
                assert!(record.len() < SMALL_RECORD_SIZE)
            } else {
                assert!(record.len() > SMALL_RECORD_SIZE)
            }
            total_sent += record.len();
        }
        pair.io.transcript.as_ref().unwrap().borrow_mut().clear();

        // steady state: there should not be any small records
        pair.round_trip_assert(APP_DATA_SIZE)?;

        for record in pair.io.writes(s2n_tls_role) {
            assert!(record.len() > SMALL_RECORD_SIZE);
        }
        pair.io.transcript.as_ref().unwrap().borrow_mut().clear();

        // timeout threshold: the connection should now have to "ramp up" again
        sleep(Duration::from_secs(2));
        pair.round_trip_assert(APP_DATA_SIZE)?;

        let mut total_sent = 0;
        for record in pair.io.writes(s2n_tls_role) {
            if total_sent < RESIZE_THRESHOLD {
                assert!(record.len() < SMALL_RECORD_SIZE)
            } else {
                assert!(record.len() > SMALL_RECORD_SIZE)
            }
            total_sent += record.len();
        }
        pair.shutdown()?;
        Ok(())
    }

    // s2n-tls server
    let mut builder = ConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
    builder.set_cert(crate::SigType::Rsa2048);
    let (client, server) = builder.build();
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
        TlsConnPair::from_configs_with_io(&client, &server, TestPairIO::new_with_recording());
    pair.server
        .connection
        .set_dynamic_record_threshold(RESIZE_THRESHOLD as u32, 1)?;
    test_case(pair, Mode::Server)?;

    // pair.handshake()?;
    // let client_handshake_total = pair.io.total_bytes_sent(Mode::Server);
    // println!("client handshake total: {:?}", client_handshake_total);

    // // initial ramp up: should start with small records, then switch to large records
    // pair.round_trip_assert(APP_DATA_SIZE)?;

    // let mut total_sent = 0;
    // for record in pair.io.writes(Mode::Server) {
    //     if total_sent < (RESIZE_THRESHOLD + client_handshake_total) {
    //         assert!(record.len() < SMALL_RECORD_SIZE)
    //     } else {
    //         assert!(record.len() > SMALL_RECORD_SIZE)
    //     }
    //     total_sent += record.len();
    // }
    // pair.io.transcript.as_ref().unwrap().borrow_mut().clear();

    // // steady state: there should not be any small records
    // pair.round_trip_assert(APP_DATA_SIZE)?;

    // for record in pair.io.writes(Mode::Server) {
    //     assert!(record.len() > SMALL_RECORD_SIZE);
    // }
    // pair.io.transcript.as_ref().unwrap().borrow_mut().clear();

    // // timeout threshold: the connection should now have to "ramp up" again
    // sleep(Duration::from_secs(5));
    // pair.round_trip_assert(APP_DATA_SIZE)?;

    // let mut total_sent = 0;
    // for record in pair.io.writes(Mode::Server) {
    //     if total_sent < RESIZE_THRESHOLD {
    //         assert!(record.len() < SMALL_RECORD_SIZE)
    //     } else {
    //         assert!(record.len() > SMALL_RECORD_SIZE)
    //     }
    //     total_sent += record.len();
    // }

    Ok(())
}
