use openssl::ssl::SslContextBuilder;

use crate::{
    openssl::OpenSslConfig,
    openssl_extension::SslContextExtension,
    s2n_tls::S2NConfig,
    tests::{ConfigBuilderPair, TestUtils},
    OpenSslConnection, S2NConnection, SigType, TlsConnPair,
};

/// Correctness: s2n-tls correctly handles padded records
///
/// Record padding is new in TLS 1.3
///
/// We configure an openssl client to add padding records using
/// `SSL_CTX_set_block_padding`. This function will pad records to a multiple
/// of the supplied `pad_to` size.
/// https://docs.openssl.org/1.1.1/man3/SSL_CTX_set_record_padding_callback/
#[test]
fn record_padding() {
    const SEND_SIZES: [usize; 6] = [1, 10, 100, 1_000, 5_000, 10_000];
    const PAD_TO_CASES: [usize; 4] = [512, 1_024, 4_096, 16_000];

    fn s2n_server_case(pad_to: usize) {
        let mut configs: ConfigBuilderPair<SslContextBuilder, s2n_tls::config::Builder> =
            ConfigBuilderPair::default();
        configs.set_cert(crate::SigType::Ecdsa256);
        configs.client.set_block_padding(pad_to);

        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = configs.connection_pair();

        assert!(pair.handshake().is_ok());
        for send in SEND_SIZES {
            assert!(pair.round_trip_assert(send).is_ok());
        }

        pair.shutdown().unwrap();
    }

    fn s2n_client_case(pad_to: usize) {
        let mut configs: ConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
            ConfigBuilderPair::default();
        configs.set_cert(SigType::Rsa4096);
        configs.server.set_block_padding(pad_to);

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

        assert!(pair.handshake().is_ok());
        for send in SEND_SIZES {
            assert!(pair.round_trip_assert(send).is_ok());
        }

        pair.shutdown().unwrap();
    }

    PAD_TO_CASES.into_iter().for_each(|pad_to| {
        s2n_server_case(pad_to);
        s2n_client_case(pad_to);
    });
}
