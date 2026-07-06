// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Benchmark measuring the overhead of the metrics subscriber on handshake events.
//!
//! Compares handshake latency with and without an `AggregatedMetricsSubscriber`
//! attached, isolating the cost of event processing.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use s2n_tls::{
    config::Builder,
    security::DEFAULT_TLS13,
    testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler, TestPair},
};
use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, MetricRecord, TelemetrySink,
};

/// A no-op sink that discards records, so we measure only the subscriber overhead.
#[derive(Clone)]
struct NoopSink;

impl TelemetrySink for NoopSink {
    fn export_record(&self, _record: &MetricRecord) {}
}

/// RSA 2048 cert chain from the permutations test fixtures.
fn rsa_2048_keypair() -> CertKeyPair {
    CertKeyPair::from_path(
        "permutations/rsae_pkcs_2048_sha256/",
        "server-chain",
        "server-key",
        "ca-cert",
    )
}

fn server_builder() -> Builder {
    let keypair = rsa_2048_keypair();
    let mut builder = Builder::new();
    builder.set_security_policy(&DEFAULT_TLS13).unwrap();
    builder.load_pem(keypair.cert(), keypair.key()).unwrap();
    builder.with_system_certs(false).unwrap();
    builder
}

fn client_config() -> s2n_tls::config::Config {
    let keypair = rsa_2048_keypair();
    let mut builder = Builder::new();
    builder.set_security_policy(&DEFAULT_TLS13).unwrap();
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .unwrap();
    builder.with_system_certs(false).unwrap();
    builder.trust_pem(keypair.ca_cert()).unwrap();
    builder.build().unwrap()
}

fn bench_metrics_subscriber_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics-subscriber-overhead");

    let client_cfg = client_config();

    // Baseline: handshake without subscriber
    let server_config_baseline = server_builder().build().unwrap();

    group.bench_function("handshake/no-subscriber", |b| {
        b.iter_batched_ref(
            || TestPair::from_configs(&client_cfg, &server_config_baseline),
            |pair| pair.handshake().unwrap(),
            BatchSize::SmallInput,
        );
    });

    // With subscriber: handshake with AggregatedMetricsSubscriber attached
    let attribution = Attribution {
        service: "bench".to_owned(),
        resource: "bench".to_owned(),
        component: "bench".to_owned(),
    };
    let subscriber = AggregatedMetricsSubscriber::new(NoopSink, attribution);
    let server_config_with_subscriber = {
        let mut builder = server_builder();
        builder.set_event_subscriber(subscriber.clone()).unwrap();
        builder.build().unwrap()
    };

    group.bench_function("handshake/with-subscriber", |b| {
        b.iter_batched_ref(
            || TestPair::from_configs(&client_cfg, &server_config_with_subscriber),
            |pair| pair.handshake().unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_metrics_subscriber_overhead);
criterion_main!(benches);
