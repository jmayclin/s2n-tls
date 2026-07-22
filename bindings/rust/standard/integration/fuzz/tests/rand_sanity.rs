// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sanity checks for the deterministic DRBG reset.

extern "C" {
    #[link_name = "aws_lc_0_43_0_CRYPTO_get_thread_local"]
    fn CRYPTO_get_thread_local(index: u32) -> *mut core::ffi::c_void;

    #[link_name = "aws_lc_0_43_0_CTR_DRBG_init"]
    fn CTR_DRBG_init(
        drbg: *mut core::ffi::c_void,
        entropy: *const u8,
        personalization: *const u8,
        personalization_len: usize,
    ) -> i32;

    #[link_name = "aws_lc_0_43_0_RAND_bytes"]
    fn RAND_bytes(out: *mut u8, len: usize) -> i32;
}

const OPENSSL_THREAD_LOCAL_PRIVATE_RAND: u32 = 5;
const OPENSSL_THREAD_LOCAL_PUBLIC_RAND: u32 = 6;
const CTR_DRBG_ENTROPY_LEN: usize = 48;

// Force the linker to include aws-lc-sys (pulled in via s2n-tls)
use s2n_tls as _;

unsafe fn fuzz_reset_rand() {
    let zero_entropy = [0u8; CTR_DRBG_ENTROPY_LEN];
    for key in [OPENSSL_THREAD_LOCAL_PRIVATE_RAND, OPENSSL_THREAD_LOCAL_PUBLIC_RAND] {
        let state = CRYPTO_get_thread_local(key);
        if !state.is_null() {
            CTR_DRBG_init(state, zero_entropy.as_ptr(), core::ptr::null(), 0);
        }
    }
}

fn rand_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    unsafe { RAND_bytes(buf.as_mut_ptr(), buf.len()) };
    buf
}

fn rand_bytes_on_thread(len: usize, reset: bool) -> Vec<u8> {
    std::thread::spawn(move || {
        // Force DRBG init
        rand_bytes(1);
        if reset {
            unsafe { fuzz_reset_rand() };
        }
        rand_bytes(len)
    })
    .join()
    .unwrap()
}

/// Without reset, two threads should produce different output.
#[test]
fn without_reset_differs() {
    let a = rand_bytes_on_thread(32, false);
    let b = rand_bytes_on_thread(32, false);
    assert_ne!(a, b, "expected different output without reset");
}

/// With reset, two threads should produce identical output.
#[test]
fn with_reset_matches() {
    let a = rand_bytes_on_thread(32, true);
    let b = rand_bytes_on_thread(32, true);
    assert_eq!(a, b, "expected identical output after reset");
}

/// After reset, the first RAND_bytes call should be deterministic,
/// and a second call should produce different bytes (DRBG advances).
#[test]
fn reset_then_sequential_calls_differ() {
    let (first, second) = std::thread::spawn(|| {
        rand_bytes(1); // init
        unsafe { fuzz_reset_rand() };
        let a = rand_bytes(32);
        let b = rand_bytes(32);
        (a, b)
    })
    .join()
    .unwrap();

    assert_ne!(first, second, "sequential calls should differ");
}

/// Multiple resets on the same thread should produce the same sequence.
#[test]
fn multiple_resets_same_sequence() {
    let (seq1, seq2) = std::thread::spawn(|| {
        rand_bytes(1); // init
        unsafe { fuzz_reset_rand() };
        let a1 = rand_bytes(32);
        let a2 = rand_bytes(32);

        unsafe { fuzz_reset_rand() };
        let b1 = rand_bytes(32);
        let b2 = rand_bytes(32);

        ((a1, a2), (b1, b2))
    })
    .join()
    .unwrap();

    assert_eq!(seq1.0, seq2.0, "first call after reset should match");
    assert_eq!(seq1.1, seq2.1, "second call after reset should match");
}

/// DRBG is not initialized before first RAND_bytes — reset should be a no-op,
/// so two threads should produce different output.
#[test]
fn reset_before_init_is_noop() {
    let get_bytes = || {
        std::thread::spawn(|| {
            unsafe { fuzz_reset_rand() };
            rand_bytes(32)
        })
        .join()
        .unwrap()
    };

    let a = get_bytes();
    let b = get_bytes();
    assert_ne!(a, b, "reset before init should be a no-op — output should differ");
}
