// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::TlsBenchConfig, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode,
    OpenSslConnection, RustlsConnection, S2NConnection, SigType, TlsConnPair, TlsConnection,
    PROFILER_FREQUENCY,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};
use pprof::criterion::{Output, PProfProfiler};
use strum::IntoEnumIterator;

fn bench_handshake_for_library<T>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    handshake_type: HandshakeType,
    kx_group: KXGroup,
    sig_type: SigType,
) where
    T: TlsConnection,
    T::Config: TlsBenchConfig,
{
    // make configs before benching to reuse
    let crypto_config = CryptoConfig::new(CipherSuite::default(), kx_group, sig_type);
    let client_config =
        T::Config::make_config(Mode::Client, crypto_config, handshake_type).unwrap();
    let server_config =
        T::Config::make_config(Mode::Server, crypto_config, handshake_type).unwrap();

    // generate all harnesses (TlsConnPair structs) beforehand so that benchmarks
    // only include negotiation and not config/connection initialization
    bench_group.bench_function(T::name(), |b| {
        b.iter_batched_ref(
            || -> TlsConnPair<T, T> { TlsConnPair::from_configs(&client_config, &server_config) },
            |conn_pair| {
                conn_pair.handshake().unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_handshake_for_psk(bench: &mut Criterion) {
    let psk = ExternalPsk::new(b"12312414", b"98172398173981279387192387").unwrap();
    let mut config = s2n_tls::config::Config::builder();
    config.set_security_policy(&DEFAULT_TLS13).unwrap();
    let config = config.build().unwrap();

    // make configs before benching to reuse
    let server_config = S2NConfig {
        mode: Mode::Server,
        config: config.clone(),
        ticket_storage: SessionTicketStorage::default(),
    };

    let client_config = S2NConfig {
        mode: Mode::Client,
        config: config.clone(),
        ticket_storage: SessionTicketStorage::default(),
    };

    // generate all harnesses (TlsConnPair structs) beforehand so that benchmarks
    // only include negotiation and not config/connection initialization
    bench.bench_function("s2n-psk", |b| {
        b.iter_batched_ref(
            || -> TlsConnPair<S2NConnection, S2NConnection> {
                let connected_buffer = ConnectedBuffer::default();
                
                let mut client = S2NConnection::new_from_config(
                    &client_config,
                    connected_buffer.clone_inverse(),
                ).unwrap();
                client.mut_connection().append_psk(&psk).unwrap();


                let mut server = S2NConnection::new_from_config(&server_config, connected_buffer).unwrap();
                server.mut_connection().append_psk(&psk).unwrap();
                TlsConnPair::wrap(client, server)
            },
            |conn_pair| {
                // harnesses with certain parameters fail to initialize for
                // some past versions of s2n-tls, but missing data can be
                // visually interpolated in the historical performance graph
                conn_pair.handshake().unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_handshake_with_params(
    bench_group: &mut BenchmarkGroup<WallTime>,
    handshake_type: HandshakeType,
    kx_group: KXGroup,
    sig_type: SigType,
) {
    bench_handshake_for_library::<S2NConnection>(bench_group, handshake_type, kx_group, sig_type);
    bench_handshake_for_library::<RustlsConnection>(
        bench_group,
        handshake_type,
        kx_group,
        sig_type,
    );
    bench_handshake_for_library::<OpenSslConnection>(
        bench_group,
        handshake_type,
        kx_group,
        sig_type,
    );
}

pub fn bench_handshake_types(c: &mut Criterion) {
    for handshake_type in HandshakeType::iter() {
        let mut bench_group = c.benchmark_group(format!("handshake-{handshake_type:?}"));
        bench_handshake_with_params(
            &mut bench_group,
            handshake_type,
            KXGroup::default(),
            SigType::default(),
        );
    }
}

pub fn bench_handshake_kx_groups(c: &mut Criterion) {
    for kx_group in KXGroup::iter() {
        let mut bench_group = c.benchmark_group(format!("handshake-{kx_group:?}"));
        bench_handshake_with_params(
            &mut bench_group,
            HandshakeType::default(),
            kx_group,
            SigType::default(),
        );
    }
}

pub fn bench_handshake_sig_types(c: &mut Criterion) {
    for sig_type in SigType::iter() {
        let mut bench_group = c.benchmark_group(format!("handshake-{sig_type:?}"));
        bench_handshake_with_params(
            &mut bench_group,
            HandshakeType::default(),
            KXGroup::default(),
            sig_type,
        );
    }
}

criterion_group! {
    name = benches;
    // profile 100 samples/sec
    config = Criterion::default().with_profiler(PProfProfiler::new(PROFILER_FREQUENCY, Output::Flamegraph(None)));
    targets = bench_handshake_types, bench_handshake_kx_groups, bench_handshake_sig_types, bench_handshake_for_psk
}
criterion_main!(benches);
