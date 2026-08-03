// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests confirming the record behavior of `poll_send`.
//!
//! These tests verify:
//! 1. When sending small slices of bytes, each `poll_send` produces its own
//!    TLS record (one record per call).
//! 2. When sending a large slice of bytes, a single `poll_send` call writes
//!    the entire payload across multiple records in one shot.

use openssl::ssl::SslContextBuilder;
use std::task::Poll;
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair
};

/// When `poll_send` is called with a buffer < record size, it will
/// - consume the entire buffer
/// - produce one record
/// - invoke the write cb one time
#[test]
fn small_sends_produce_one_record_each() {
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
        let configs =
            TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        configs.connection_pair()
    };

    pair.handshake().unwrap();
    pair.io.enable_recording();

    let small_slice = [1; 10];
    let num_sends = 20;
    for _ in 0..num_sends {
        let result = pair.server.connection_mut().poll_send(&small_slice);
        assert!(matches!(result, Poll::Ready(Ok(10))));
    }

    let record_count = pair.io.server_record_sizes().len();
    // One record per poll_send call.
    assert_eq!(record_count, num_sends);
    let write_calls = pair
        .io
        .server_write_count
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(write_calls, record_count);
}

/// When `poll_send` is called with a large buffer >> record size, it will
/// - consume the entire buffer
/// - produce multiple records
/// - internally invoke the write cb multiple times
#[test]
fn large_send_writes_all_records_at_once() {
    /// maximum record size is 16kb
    const LARGE_DATA_SIZE: usize = 100_000;
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
        let configs =
            TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        configs.connection_pair()
    };

    pair.handshake().unwrap();
    pair.io.enable_recording();

    let large_data: Vec<u8> = vec![1; LARGE_DATA_SIZE];

    // A single poll_send should accept the entire buffer.
    let result = pair.server.connection_mut().poll_send(&large_data);
    assert!(matches!(result, Poll::Ready(Ok(LARGE_DATA_SIZE))));
    // the call should produce many records
    let record_count = pair.io.server_record_sizes().len();
    assert!(record_count > 1);
    // poll_send internally called the IO write callback once per record
    let write_calls = pair
        .io
        .server_write_count
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(write_calls, record_count);
}
