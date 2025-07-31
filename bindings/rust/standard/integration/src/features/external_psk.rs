use std::{ffi::CString, io::Write};

use openssl::ssl::{SslContextBuilder, SslRef};
use s2n_tls::{enums::PskHmac, psk::Psk};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    openssl_extension::SslContextExtension,
    SigType, TlsConnPair,
};

const TEST_PSK_IDENTITY: &[u8] = b"test psk identity for openssl/s2n-tls";
const TEST_PSK_SECRET: &[u8] = b"this is the very secret value for the test";

fn openssl_client_cb(
    connection: &mut SslRef,
    hint: Option<&[u8]>,
    mut identity: &mut [u8],
    mut secret: &mut [u8],
) -> Result<usize, openssl::error::ErrorStack> {
    println!("max identity was {}", identity.len());
    println!("max secret was {}", secret.len());
    let null_terminated_identity = CString::new(TEST_PSK_IDENTITY).unwrap();
    identity.write_all(null_terminated_identity.as_bytes());
    secret.write_all(TEST_PSK_SECRET);
    Ok(TEST_PSK_SECRET.len())
}

// s2n_client_openssl_server

/// s2n-tls must correctly handle padded records.
///
/// Record padding is new in TLS 1.3
///
/// We configure an openssl peer to use padded records using `SSL_CTX_set_block_padding`.
/// This function will pad records to a multiple of the supplied `pad_to` size.
/// https://docs.openssl.org/1.1.1/man3/SSL_CTX_set_record_padding_callback/
/// https://docs.openssl.org/1.0.2/man3/SSL_CTX_set_psk_client_callback/
/// https://docs.openssl.org/1.0.2/man3/SSL_CTX_use_psk_identity_hint/

#[test]
fn s2n_client_success() {}

#[test]
fn s2n_server_success() {
    // SHA256
    {
        // openssl chooses to send a SHA256 PSK binder by default
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            // set
            configs.client.set_psk_client_callback(openssl_client_cb);

            configs.connection_pair()
        };

        let mut s2n_psk = Psk::builder().unwrap();
        s2n_psk.set_identity(TEST_PSK_IDENTITY);
        s2n_psk.set_secret(TEST_PSK_SECRET);
        s2n_psk.set_hmac(PskHmac::SHA256);

        pair.server
            .connection
            .append_psk(&s2n_psk.build().unwrap())
            .unwrap();

        pair.handshake().unwrap();
        assert_eq!(pair.get_negotiated_cipher_suite(), "TLS_AES_128_GCM_SHA256");
    }

    // OpenSSL client only supports the SHA384 cipher while s2n-tls only supports 
    // a SHA256 PSK
    // The s2n-tls server should return a CIPHER_NOT_SUPPORTED error message, because
    // it won't be able to negotiate any SHA384 ciphers. 
    {
        // openssl chooses to send a SHA256 PSK binder by default
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            // set
            configs.client.set_psk_client_callback(openssl_client_cb);
            configs.client.set_ciphersuites("TLS_AES_256_GCM_SHA384").unwrap();

            configs.connection_pair()
        };

        let mut s2n_psk = Psk::builder().unwrap();
        s2n_psk.set_identity(TEST_PSK_IDENTITY);
        s2n_psk.set_secret(TEST_PSK_SECRET);
        s2n_psk.set_hmac(PskHmac::SHA256);

        pair.server
            .connection
            .append_psk(&s2n_psk.build().unwrap())
            .unwrap();

        let handshake_err = pair.handshake().unwrap_err();

        // the debug impl contains the "S2N" specific error code
        let error_text = format!("{handshake_err:?}");
        assert!(error_text.contains("S2N_ERR_CIPHER_NOT_SUPPORTED"));
    }

    // OpenSSL client only supports the SHA384 cipher while s2n-tls only supports 
    // a SHA384 PSK: THIS SHOULD SUCCEED BUT IT DOES NOT WHAT HAVE THEY (WE?) DONE
    {
        // openssl chooses to send a SHA256 PSK binder by default
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            // set
            configs.client.set_psk_client_callback(openssl_client_cb);
            configs.client.set_ciphersuites("TLS_AES_256_GCM_SHA384").unwrap();

            configs.connection_pair()
        };

        let mut s2n_psk = Psk::builder().unwrap();
        s2n_psk.set_identity(TEST_PSK_IDENTITY);
        s2n_psk.set_secret(TEST_PSK_SECRET);
        s2n_psk.set_hmac(PskHmac::SHA384);

        pair.server
            .connection
            .append_psk(&s2n_psk.build().unwrap())
            .unwrap();

        let handshake_err = pair.handshake().unwrap_err();

        println!("error text is :{handshake_err:?}");
        // error text is :Error { code: 402653194, name: "S2N_ERR_SAFETY", message: "a safety check failed", kind: InternalError, source: Library, debug: "Error encountered in lib/tls/s2n_psk.c:449", errno: "Success" }
        // this should be succeeding :( but instead openssl is setting the wrong
        // PSK HMAC :(
    }
}

// As a control, we want to confirm that s2n-tls will correctly restrict it's selected
// cipher suites based on the configure HMAC.
#[test]
fn s2n_self_talk() {
    // SHA256 PSK HMAC w/ TLS_AES_128_GCM_SHA256
    let (client_config, server_config) =
        TlsConfigBuilderPair::<s2n_tls::config::Builder, s2n_tls::config::Builder>::default()
            .build();

    for psk_hmac in [PskHmac::SHA256, PskHmac::SHA384] {
        let s2n_psk = {
            let mut s2n_psk = Psk::builder().unwrap();
            s2n_psk.set_identity(TEST_PSK_IDENTITY);
            s2n_psk.set_secret(TEST_PSK_SECRET);
            s2n_psk.set_hmac(psk_hmac.clone());
            s2n_psk.build().unwrap()
        };

        let mut pair: TlsConnPair<S2NConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.server.connection.append_psk(&s2n_psk).unwrap();
        pair.client.connection.append_psk(&s2n_psk).unwrap();

        pair.handshake().unwrap();
        let selected_cipher = pair.get_negotiated_cipher_suite();
        match psk_hmac {
            PskHmac::SHA256 => assert_eq!(selected_cipher, "TLS_AES_128_GCM_SHA256"),
            PskHmac::SHA384 => assert_eq!(selected_cipher, "TLS_AES_256_GCM_SHA384"),
            unknown => panic!("unhandled psk hmac {unknown:?}"),
        }
    }
}
