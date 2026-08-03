// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks comparing individual poll_send calls vs. DataCoalescer-based
//! vectored send vs. native s2n_sendv for s2n-tls.
//!
//! Scenario: 100 x 1KB payloads written from client to server.

use benchmarks::{CryptoConfig, HandshakeType, PsuedoVectoredSend, TlsBenchConfig};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::io::IoSlice;
use std::task::Poll;
use tls_harness::{
    cohort::S2NConnection,
    Mode, TlsConnPair, TlsConnection,
};

const NUM_PAYLOADS: usize = 100;
const PAYLOAD_SIZE: usize = 1024;
const TOTAL_BYTES: usize = NUM_PAYLOADS * PAYLOAD_SIZE;
const LARGE_RECORD: usize = 16_384;

pub fn bench_vectored_send(c: &mut Criterion) {
    // Pre-allocate all data outside the hot loop
    let payloads: Vec<[u8; PAYLOAD_SIZE]> = (0..NUM_PAYLOADS)
        .map(|i| [i as u8; PAYLOAD_SIZE])
        .collect();
    let slices: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
    let io_slices: Vec<IoSlice> = payloads.iter().map(|p| IoSlice::new(p)).collect();
    let mut recv_buf = vec![0u8; TOTAL_BYTES];

    let crypto_config = CryptoConfig::default();
    let client_config = <S2NConnection as TlsConnection>::Config::make_config(
        Mode::Client,
        crypto_config,
        HandshakeType::default(),
    )
    .unwrap();
    let server_config = <S2NConnection as TlsConnection>::Config::make_config(
        Mode::Server,
        crypto_config,
        HandshakeType::default(),
    )
    .unwrap();

    let mut group = c.benchmark_group("vectored-send-100x1kb");
    group.throughput(Throughput::Bytes(TOTAL_BYTES as u64));

    // Case 1: Individual poll_send calls in a loop
    group.bench_function("poll_send_loop", |b| {
        b.iter_batched_ref(
            || {
                let mut pair =
                    TlsConnPair::<S2NConnection, S2NConnection>::from_configs(
                        &client_config,
                        &server_config,
                    );
                pair.handshake().unwrap();
                pair.round_trip_transfer(&mut vec![0u8; TOTAL_BYTES]).unwrap();
                pair
            },
            |pair| {
                let conn = pair.client_mut().connection_mut();
                for payload in &payloads {
                    let mut written = 0;
                    while written < payload.len() {
                        match conn.poll_send(&payload[written..]) {
                            Poll::Ready(Ok(n)) => written += n,
                            Poll::Ready(Err(e)) => panic!("send error: {e}"),
                            Poll::Pending => panic!("unexpected pending"),
                        }
                    }
                    assert!(conn.poll_flush().is_ready());
                }
                pair.server_mut().recv(&mut recv_buf).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Case 2: DataCoalescer with 8KB buffer (default s2n-tls record size)
    group.bench_function("coalesced_8kb", |b| {
        b.iter_batched_ref(
            || {
                let mut pair =
                    TlsConnPair::<S2NConnection, S2NConnection>::from_configs(
                        &client_config,
                        &server_config,
                    );
                pair.handshake().unwrap();
                pair.round_trip_transfer(&mut vec![0u8; TOTAL_BYTES]).unwrap();
                pair
            },
            |pair| {
                let conn = pair.client_mut().connection_mut();
                match conn.poll_send_vector(&slices) {
                    Poll::Ready(Ok(n)) => assert_eq!(n, TOTAL_BYTES),
                    Poll::Ready(Err(e)) => panic!("send error: {e}"),
                    Poll::Pending => panic!("unexpected pending"),
                }
                assert!(conn.poll_flush().is_ready());
                pair.server_mut().recv(&mut recv_buf).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Case 3: DataCoalescer with 16KB buffer + prefer_throughput for 16KB records
    group.bench_function("coalesced_16kb", |b| {
        b.iter_batched_ref(
            || {
                let mut pair =
                    TlsConnPair::<S2NConnection, S2NConnection>::from_configs(
                        &client_config,
                        &server_config,
                    );
                pair.handshake().unwrap();
                pair.client_mut().connection_mut().prefer_throughput().unwrap();
                pair.round_trip_transfer(&mut vec![0u8; TOTAL_BYTES]).unwrap();
                pair
            },
            |pair| {
                let conn = pair.client_mut().connection_mut();
                match conn.poll_send_vector_with_buffer::<LARGE_RECORD>(&slices) {
                    Poll::Ready(Ok(n)) => assert_eq!(n, TOTAL_BYTES),
                    Poll::Ready(Err(e)) => panic!("send error: {e}"),
                    Poll::Pending => panic!("unexpected pending"),
                }
                assert!(conn.poll_flush().is_ready());
                pair.server_mut().recv(&mut recv_buf).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Case 4: Native s2n_sendv with default record size
    group.bench_function("sendv_native_8kb", |b| {
        b.iter_batched_ref(
            || {
                let mut pair =
                    TlsConnPair::<S2NConnection, S2NConnection>::from_configs(
                        &client_config,
                        &server_config,
                    );
                pair.handshake().unwrap();
                pair.round_trip_transfer(&mut vec![0u8; TOTAL_BYTES]).unwrap();
                pair
            },
            |pair| {
                let conn = pair.client_mut().connection_mut();
                match conn.poll_sendv(&io_slices) {
                    Poll::Ready(Ok(n)) => assert_eq!(n, TOTAL_BYTES),
                    Poll::Ready(Err(e)) => panic!("send error: {e}"),
                    Poll::Pending => panic!("unexpected pending"),
                }
                assert!(conn.poll_flush().is_ready());
                pair.server_mut().recv(&mut recv_buf).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Case 5: Native s2n_sendv with 16KB records (prefer_throughput)
    group.bench_function("sendv_native_16kb", |b| {
        b.iter_batched_ref(
            || {
                let mut pair =
                    TlsConnPair::<S2NConnection, S2NConnection>::from_configs(
                        &client_config,
                        &server_config,
                    );
                pair.handshake().unwrap();
                pair.client_mut().connection_mut().prefer_throughput().unwrap();
                pair.round_trip_transfer(&mut vec![0u8; TOTAL_BYTES]).unwrap();
                pair
            },
            |pair| {
                let conn = pair.client_mut().connection_mut();
                match conn.poll_sendv(&io_slices) {
                    Poll::Ready(Ok(n)) => assert_eq!(n, TOTAL_BYTES),
                    Poll::Ready(Err(e)) => panic!("send error: {e}"),
                    Poll::Pending => panic!("unexpected pending"),
                }
                assert!(conn.poll_flush().is_ready());
                pair.server_mut().recv(&mut recv_buf).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group! {benches, bench_vectored_send}
criterion_main!(benches);
