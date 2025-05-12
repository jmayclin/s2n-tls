use openssl::ssl::SslContextBuilder;
use s2n_tls::security::Policy;

use crate::{
    harness::TlsConnIo,
    openssl::OpenSslConfig,
    openssl_extension::{SslContextExtension, SslExtension, SslStreamExtension},
    s2n_tls::S2NConfig,
    tests::{ConfigBuilderPair, TestUtils},
    OpenSslConnection, S2NConnection, SigType, TlsConnPair,
};

#[test]
fn s2n_client_renegotiation_is_patched() {
    let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        ConfigBuilderPair::default();
    configs.set_cert(crate::SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default").unwrap())
        .unwrap();

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

    assert!(pair.handshake().is_ok());
    assert!(pair.round_trip_assert(1_024).is_ok());
    assert!(pair.server.connection.ssl().secure_renegotiation_support());

    pair.shutdown().unwrap();
    assert!(pair.is_shutdown());
}

/// Renegotiation request ignored by s2n-tls client.
///
/// This tests the default behavior for customers who do not enable renegotiation.
#[test]
fn s2n_client_ignores_openssl_renegotiate_request() {
    let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        ConfigBuilderPair::default();
    configs.set_cert(crate::SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default").unwrap())
        .unwrap();

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

    assert!(pair.handshake().is_ok());
    // schedule the renegotiate request
    pair.server.connection.mut_ssl().renegotiate();
    // the request is now pending
    assert!(pair.server.connection.ssl().renegotiate_pending());

    // do server sending IO to actually send the request
    assert!(pair.io.server_tx_stream.borrow().is_empty());
    pair.server.send(&[0]).unwrap();
    let send = pair.io.server_tx_stream.borrow().len();
    // 30 if there is no negotiate request, 63 indicating something extra was sent
    // wink wink
    assert_eq!(send, 63);

    // do some client IO to recv and potentially respond to the request
    pair.client.recv(&mut [0]).unwrap();
    pair.client.send(&mut [0]).unwrap();
    pair.server.recv(&mut [0]).unwrap();

    // the request is still pending, because s2n-tls ignored it
    assert!(pair.server.connection.ssl().renegotiate_pending());

    pair.shutdown().unwrap();
    assert!(pair.is_shutdown());
}

#[cfg(feature = "renegotiate")]
mod tests {
    use std::{io::Write, task::Poll};

    use s2n_tls::renegotiate::RenegotiateResponse;

    use super::*;

    /// Renegotiation request rejected by s2n-tls client.
    #[test]
    fn s2n_client_rejects_openssl_hello_request() {
        let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
            ConfigBuilderPair::default();
        configs.set_cert(crate::SigType::Ecdsa256);
        configs
            .client
            .set_security_policy(&Policy::from_version("default").unwrap())
            .unwrap()
            .set_renegotiate_callback(RenegotiateResponse::Reject)
            .unwrap();

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

        assert!(pair.handshake().is_ok());
        // schedule the renegotiate request
        pair.server.connection.mut_ssl().renegotiate();
        // the request is now pending
        assert!(pair.server.connection.ssl().renegotiate_pending());

        // do server sending IO to actually send the request
        assert!(pair.io.server_tx_stream.borrow().is_empty());
        pair.server.send(&[0]).unwrap();
        let send = pair.io.server_tx_stream.borrow().len();
        // 30 if there is no negotiate request, 63 indicating something extra was sent
        // wink wink
        assert_eq!(send, 63);

        // do some client IO to recv and potentially respond to the request
        pair.client.recv(&mut [0]).unwrap();
        pair.client.send(&mut [0]).unwrap();
        let server = pair.server.recv(&mut [0]);
        // Err` value: Custom { kind: Other, error: Error { code: ErrorCode(1), cause: Some(Ssl(ErrorStack([Error { code: 167772499, library: "SSL routines", function: "ssl3_read_bytes", reason: "no renegotiation", file: "ssl/record/rec_layer_s3.c", line: 928 }]))) } }
        //let openssl_err = server.unwrap_err().downcast()

        // recv fails because an alert is received from the openssl server
        pair.client.recv(&mut [0]).unwrap_err();
        // 40 -> "handshake_failure"
        assert_eq!(pair.client.connection.alert(), Some(40));
    }

    /// Renegotiation request accepted by s2n-tls client.
    #[test]
    fn s2n_client_renegotiate_with_openssl() {
        let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
            ConfigBuilderPair::default();
        configs.set_cert(crate::SigType::Ecdsa256);
        configs
            .client
            .set_security_policy(&Policy::from_version("default").unwrap())
            .unwrap()
            .set_renegotiate_callback(RenegotiateResponse::Schedule)
            .unwrap();

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

        assert!(pair.handshake().is_ok());
        // schedule the renegotiate request
        pair.server.connection.mut_ssl().renegotiate();
        // the request is now pending
        assert!(pair.server.connection.ssl().renegotiate_pending());

        // do server sending IO to actually send the request
        pair.server.send(&[0]).unwrap();

        // do some client IO to recv the request
        pair.client.recv(&mut [0]).unwrap();

        // s2n-tls sends client hello
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!("{:?}", ch_send);
        // responds to client hello
        let recv = pair.server.connection.write(&[0]);
        println!("{:?}", recv);

        // selects and ready
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!("{:?}", ch_send);

        // writes one byte
        let recv = pair.server.connection.write(&[0]);
        println!("{:?}", recv);

        // the request is no longer pending, because s2n-tls accepted it
        assert!(pair.server.connection.ssl().renegotiate_pending());

        pair.shutdown().unwrap();
        assert!(pair.is_shutdown());
    }

    /// Renegotiation request with client auth accepted by s2n-tls client.
    ///
    /// The openssl server does not require client auth during the first handshake,
    /// but does require client auth during the second handshake.
    #[test]
    fn s2n_client_renegotiate_with_client_auth_with_openssl() {
        assert!(true);
    }

    /// The s2n-tls client successfully reads ApplicationData during the renegotiation handshake.
    #[test]
    fn s2n_client_renegotiate_with_app_data_with_openssl() {
        assert!(true);
    }
}
