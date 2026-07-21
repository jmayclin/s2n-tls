// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that deterministic randomness works for fuzzing.
//!
//! We forcibly reinitialize the thread-local CTR-DRBGs with known entropy
//! by reaching into aws-lc internals, then verify that two client hellos
//! generated on separate threads are byte-for-byte identical.

use s2n_tls::{
    config,
    security::Policy,
    testing::{self, TestPair},
};
use std::{sync::OnceLock, task::Poll};

extern "C" {
    #[link_name = "aws_lc_0_39_0_CRYPTO_get_thread_local"]
    fn CRYPTO_get_thread_local(index: u32) -> *mut core::ffi::c_void;

    #[link_name = "aws_lc_0_39_0_CTR_DRBG_init"]
    fn CTR_DRBG_init(
        drbg: *mut core::ffi::c_void,
        entropy: *const u8,
        personalization: *const u8,
        personalization_len: usize,
    ) -> i32;

    #[link_name = "aws_lc_0_39_0_RAND_bytes"]
    fn RAND_bytes(out: *mut u8, len: usize) -> i32;

    #[link_name = "aws_lc_0_39_0_RAND_public_bytes"]
    fn RAND_public_bytes(out: *mut u8, len: usize) -> i32;
}

const OPENSSL_THREAD_LOCAL_PRIVATE_RAND: u32 = 5;
const OPENSSL_THREAD_LOCAL_PUBLIC_RAND: u32 = 6;
const CTR_DRBG_ENTROPY_LEN: usize = 48;

unsafe fn fuzz_reset_rand() {
    let mut dummy = [0u8; 1];
    RAND_bytes(dummy.as_mut_ptr(), dummy.len());
    RAND_public_bytes(dummy.as_mut_ptr(), dummy.len());

    let zero_entropy = [0u8; CTR_DRBG_ENTROPY_LEN];
    for key in [OPENSSL_THREAD_LOCAL_PRIVATE_RAND, OPENSSL_THREAD_LOCAL_PUBLIC_RAND] {
        let state = CRYPTO_get_thread_local(key);
        if !state.is_null() {
            CTR_DRBG_init(state, zero_entropy.as_ptr(), core::ptr::null(), 0);
        }
    }
}

fn get_config() -> &'static config::Config {
    static CONFIG: OnceLock<config::Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        s2n_tls::init::init();
        let mut builder =
            testing::config_builder(&Policy::from_version("default_tls13").unwrap()).unwrap();
        builder.enable_quic().unwrap();
        builder.build().unwrap()
    })
}

fn generate_client_hello_on_new_thread(config: &'static config::Config) -> Vec<u8> {
    std::thread::spawn(move || {
        unsafe { fuzz_reset_rand() };

        let mut pair = TestPair::from_config(config);
        pair.server.enable_quic().unwrap();
        pair.client.enable_quic().unwrap();
        assert!(matches!(pair.client.poll_negotiate(), Poll::Pending));

        let bytes: Vec<u8> = pair.io.client_tx_stream.borrow().iter().copied().collect();
        bytes
    })
    .join()
    .unwrap()
}

/// The expected client hello random bytes when the DRBG is reset to zero
/// entropy. This constant can be used to confirm determinism across processes.
const EXPECTED_CLIENT_HELLO_RANDOM: [u8; 32] = [
    145, 97, 143, 233, 154, 143, 148, 32, 73, 123, 36, 111, 115, 91, 39, 160,
    25, 7, 138, 157, 60, 166, 178, 160, 1, 174, 192, 185, 224, 126, 104, 11,
];

#[test]
fn deterministic_client_hello() {
    let config = get_config();

    let first = generate_client_hello_on_new_thread(config);
    let second = generate_client_hello_on_new_thread(config);

    assert_eq!(
        first, second,
        "client hellos differ — deterministic DRBG reset is not working"
    );

    assert_eq!(
        &first[6..38],
        EXPECTED_CLIENT_HELLO_RANDOM,
        "client hello random doesn't match expected constant — \
         determinism may be broken across processes"
    );
}
