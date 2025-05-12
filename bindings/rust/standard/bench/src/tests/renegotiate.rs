use std::io::Write;

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

use crate::PemType;

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

    // schedule and send the renegotiate request
    pair.server.connection.mut_ssl().renegotiate();
    let _ = pair.server.connection.write(&[]);
    assert_eq!(33, pair.io.server_tx_stream.borrow().len());
    assert!(pair.server.connection.ssl().renegotiate_pending());

    // do some client IO to recv and potentially respond to the request
    pair.round_trip_assert(1_024).unwrap();
    pair.round_trip_assert(1_024).unwrap();

    // the request is still pending, because s2n-tls ignored it
    assert!(pair.server.connection.ssl().renegotiate_pending());

    pair.shutdown().unwrap();
    assert!(pair.is_shutdown());
}

// https://docs.openssl.org/3.3/man3/SSL_key_update/#description

#[cfg(feature = "renegotiate")]
mod tests {
    use std::{
        io::{Read as _, Write},
        task::Poll,
    };

    use openssl::ssl::SslVerifyMode;
    use s2n_tls::{enums::ClientAuthType, renegotiate::RenegotiateResponse};

    use crate::harness::{read_to_bytes, TlsConfigBuilder};

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
    fn s2n_client_renegotiate_with_openssl() -> Result<(), Box<dyn std::error::Error>> {
        let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
            ConfigBuilderPair::default();
        configs.set_cert(crate::SigType::Ecdsa256);
        configs
            .client
            .set_security_policy(&Policy::from_version("default").unwrap())?
            .set_renegotiate_callback(RenegotiateResponse::Schedule)?;

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

        assert!(pair.handshake().is_ok());

        // schedule the renegotiate request
        pair.server.connection.mut_ssl().renegotiate();
        assert!(pair.server.connection.ssl().renegotiate_pending());

        // send the renegotiate request
        let ossl_io = pair.server.connection.write(&[]);
        println!(
            "openssl sends renegotiate request {:?} {:#?}",
            ossl_io, pair.io
        );

        // read the renegotiate request & send the renegotiation client hello
        let s2n_tls_io = pair.client.connection.poll_recv(&mut [0]);
        println!(
            "s2n-tls reads renegotiate request & sends client hello {:?}, {:#?}",
            s2n_tls_io, pair.io
        );

        // send the server hello
        let recv = pair.server.connection.read(&mut [0]);
        println!("openssl sends server hello {:?}, {:#?}", recv, pair.io);

        // client sends key material + finished
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!(
            "s2n-tls sends key material + finished {:?}, {:#?}",
            ch_send, pair.io
        );

        // server sends finished
        let recv = pair.server.connection.read(&mut [0]);
        println!("openssl sends finished {:?}, {:#?}", recv, pair.io);

        // client reads finished
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!("s2n-tls reads finished {:?}, {:#?}", ch_send, pair.io);

        // the request is no longer pending, because s2n-tls accepted it
        assert!(!pair.server.connection.ssl().renegotiate_pending());

        // data can be sent
        pair.round_trip_assert(1_024).unwrap();

        // assert!(false);

        pair.shutdown().unwrap();
        assert!(pair.is_shutdown());

        Ok(())
    }

    /// Renegotiation request with client auth accepted by s2n-tls client.
    ///
    /// The openssl server does not require client auth during the first handshake,
    /// but does require client auth during the second handshake.
    #[test]
    fn s2n_client_renegotiate_with_client_auth_with_openssl() -> Result<(), Box<dyn std::error::Error>> {
        
        let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
            ConfigBuilderPair::default();
        configs.set_cert(SigType::Ecdsa256);
        configs
            .client
            .set_security_policy(&Policy::from_version("default")?)?
            .set_renegotiate_callback(RenegotiateResponse::Schedule)?
            .set_client_auth_type(ClientAuthType::Optional)?
            .load_pem(
                read_to_bytes(PemType::ClientCertChain, SigType::Ecdsa256).as_slice(),
                read_to_bytes(PemType::ClientKey, SigType::Ecdsa256).as_slice(),
            )?;
        configs.server.set_trust(SigType::Ecdsa256);

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

        assert!(pair.handshake().is_ok());

        // mercurial: decide that we now require client auth
        pair.server
            .connection
            .mut_ssl()
            .set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);

        // schedule the renegotiate request
        pair.server.connection.mut_ssl().renegotiate();
        assert!(pair.server.connection.ssl().renegotiate_pending());

        // send the renegotiate request
        let ossl_io = pair.server.connection.write(&[]);
        println!(
            "openssl sends renegotiate request {:?} {:#?}",
            ossl_io, pair.io
        );

        // read the renegotiate request & send the renegotiation client hello
        let s2n_tls_io = pair.client.connection.poll_recv(&mut [0]);
        println!(
            "s2n-tls reads renegotiate request & sends client hello {:?}, {:#?}",
            s2n_tls_io, pair.io
        );

        // send the server hello
        let recv = pair.server.connection.read(&mut [0]);
        println!("openssl sends server hello {:?}, {:#?}", recv, pair.io);

        // client sends key material + finished
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!(
            "s2n-tls sends key material + finished {:?}, {:#?}",
            ch_send, pair.io
        );

        // server sends finished
        let recv = pair.server.connection.read(&mut [0]);
        println!("openssl sends finished {:?}, {:#?}", recv, pair.io);

        // client reads finished
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!("s2n-tls reads finished {:?}, {:#?}", ch_send, pair.io);

        // the request is no longer pending, because s2n-tls accepted it
        assert!(!pair.server.connection.ssl().renegotiate_pending());

        // data can be sent
        pair.round_trip_assert(1_024).unwrap();

        // assert!(false);

        pair.shutdown().unwrap();
        assert!(pair.is_shutdown());

        Ok(())
    }

    /// The s2n-tls client successfully reads ApplicationData during the renegotiation handshake.
    #[test]
    fn s2n_client_renegotiate_with_app_data_with_openssl() {
        const BEFORE_SERVER_HELLO: &[u8] = b"after client hello, before server hello";
        const AFTER_SERVER_HELLO: &[u8] = b"after server hello, before finished";
        
        let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
            ConfigBuilderPair::default();
        configs.set_cert(SigType::Ecdsa256);
        configs
            .client
            .set_security_policy(&Policy::from_version("default")?)?
            .set_renegotiate_callback(RenegotiateResponse::Schedule)?
            .set_client_auth_type(ClientAuthType::Optional)?
            .load_pem(
                read_to_bytes(PemType::ClientCertChain, SigType::Ecdsa256).as_slice(),
                read_to_bytes(PemType::ClientKey, SigType::Ecdsa256).as_slice(),
            )?;
        configs.server.set_trust(SigType::Ecdsa256);

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

        assert!(pair.handshake().is_ok());

        // mercurial: decide that we now require client auth
        pair.server
            .connection
            .mut_ssl()
            .set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);

        // schedule the renegotiate request
        pair.server.connection.mut_ssl().renegotiate();
        assert!(pair.server.connection.ssl().renegotiate_pending());

        // send the renegotiate request
        let ossl_io = pair.server.connection.write(&[]);
        println!(
            "openssl sends renegotiate request {:?} {:#?}",
            ossl_io, pair.io
        );

        // read the renegotiate request & send the renegotiation client hello
        let s2n_tls_io = pair.client.connection.poll_recv(&mut [0]);
        println!(
            "s2n-tls reads renegotiate request & sends client hello {:?}, {:#?}",
            s2n_tls_io, pair.io
        );

        // send application data
        let recv = pair.server.connection.write(BEFORE_SERVER_HELLO);
        println!("openssl sends app data before hello {:?}, {:#?}", recv, pair.io);


        // send the server hello
        let recv = pair.server.connection.read(&mut [0]);
        println!("openssl sends server hello {:?}, {:#?}", recv, pair.io);

        let recv = pair.server.connection.write(AFTER_SERVER_HELLO);
        println!("openssl sends app data before hello {:?}, {:#?}", recv, pair.io);

        // client sends key material + finished
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!(
            "s2n-tls sends key material + finished {:?}, {:#?}",
            ch_send, pair.io
        );

        // server sends finished
        let recv = pair.server.connection.read(&mut [0]);
        println!("openssl sends finished {:?}, {:#?}", recv, pair.io);

        // client reads finished
        let ch_send = pair.client.connection.poll_recv(&mut [0]);
        println!("s2n-tls reads finished {:?}, {:#?}", ch_send, pair.io);

        // the request is no longer pending, because s2n-tls accepted it
        assert!(!pair.server.connection.ssl().renegotiate_pending());

        // data can be sent
        pair.round_trip_assert(1_024).unwrap();

        // assert!(false);

        pair.shutdown().unwrap();
        assert!(pair.is_shutdown());

        Ok(())    }
}
