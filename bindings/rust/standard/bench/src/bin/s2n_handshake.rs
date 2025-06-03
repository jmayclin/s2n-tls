use bench::{harness::TlsBenchConfig, s2n_tls::S2NConfig, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode, S2NConnection, SigType, TlsConnPair};

// CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --bin=s2n_handshake

fn main() {
    let crypto_config = CryptoConfig::new(CipherSuite::default(), KXGroup::Secp256R1, SigType::Rsa2048);
    let client_config = S2NConfig::make_config(Mode::Client, crypto_config, HandshakeType::ServerAuth).unwrap();
    let server_config = S2NConfig::make_config(Mode::Server, crypto_config, HandshakeType::ServerAuth).unwrap();

    for _i in 0..10000 {
        let mut pair: TlsConnPair<S2NConnection, S2NConnection> = TlsConnPair::from_configs(&client_config, &server_config);
        let res = pair.handshake();
        assert!(res.is_ok());
        assert!(pair.handshake_completed());
    }
}