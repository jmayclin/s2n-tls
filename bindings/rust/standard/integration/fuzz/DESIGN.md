# Memory Amplification Fuzz Testing — Design Document

## Overview

This fuzz test feeds arbitrary bytes to an s2n-tls server and asserts that peak
memory allocation stays below a threshold (200 KB). It uses cargo-fuzz
(libFuzzer) with dhat-rs for allocation tracking. The server runs in QUIC mode
so fuzz input is processed as plaintext handshake messages without TLS record
layer framing.

## Corpus Generation

The fuzzer needs realistic seed inputs to bootstrap coverage. We generate corpus
files by running actual TLS 1.3 QUIC handshakes and recording the client's
bytes:

- **`tls13_quic_handshake`**: Client bytes from a standard server-auth handshake
  (ClientHello + Finished, ~221 bytes).
- **`tls13_quic_mtls_handshake`**: Client bytes from an mTLS handshake
  (ClientHello + Certificate + CertificateVerify + Finished, ~2163 bytes).

The client and server run on separate threads so each gets its own thread-local
DRBG, both reset to the same known state. This makes the corpus deterministic
and replayable.

To verify the corpus is valid, we replay the recorded client bytes against a
server (also on its own thread with the same DRBG state) and assert the server
produces byte-identical output to the original handshake. This confirms the
corpus represents a real handshake that the server can process.

## Deterministic Randomness

### Motivation

libFuzzer works by mutating inputs and observing which mutations increase code
coverage. If the server's behavior depends on randomness (key shares, nonces,
etc.), the same input can trigger different code paths on different iterations.
This confuses the coverage feedback loop — the fuzzer can't distinguish "this
mutation found a new path" from "the RNG happened to produce different output."

Pinning the randomness makes the server's behavior a pure function of the fuzz
input, which lets libFuzzer make reliable progress.

### Implementation

aws-lc uses two thread-local CTR-DRBG instances per thread: one for
`RAND_bytes` (private) and one for `RAND_public_bytes` (public). These are
lazily initialized on first use and seeded from the OS entropy source plus
optional CPU jitter entropy and hardware RNG prediction resistance.

We make the DRBGs deterministic by:

1. **Disabling CPU jitter entropy** (`DISABLE_CPU_JITTER_ENTROPY`): The local
   aws-lc-sys build detects `--cfg fuzzing` in `CARGO_ENCODED_RUSTFLAGS` and
   defines this flag. Without it, the jitter entropy source and hardware RNG
   (`rndr` on aarch64) mix non-deterministic entropy into every DRBG reseed,
   making the DRBG state unpredictable even after a reset.

2. **Forcibly reinitializing the DRBGs** (`fuzz_reset_rand`): Before each fuzz
   iteration, we:
   - Call `RAND_bytes` and `RAND_public_bytes` to force both DRBGs to
     initialize (they're lazily created on first use; resetting an
     uninitialized DRBG is a no-op).
   - Use `CRYPTO_get_thread_local` to get pointers to the thread-local DRBG
     state structs. The first field of `rand_thread_local_state` is
     `CTR_DRBG_STATE drbg`, so we cast the pointer directly.
   - Call `CTR_DRBG_init` with zero entropy to reset each DRBG to a known
     state.

   This is done via `extern "C"` declarations with `#[link_name]` attributes
   to reference the prefix-mangled aws-lc symbols (e.g.,
   `aws_lc_0_39_0_CRYPTO_get_thread_local`).

### Why not `RAND_reset_for_fuzzing`?

aws-lc provides `RAND_reset_for_fuzzing` (compiled under
`BORINGSSL_UNSAFE_DETERMINISTIC_MODE`) which resets the deterministic
`CRYPTO_sysrand` counter. However, this only affects the entropy *source* — the
DRBG's internal state persists and is also influenced by hardware RNG prediction
resistance during reseeds. Directly reinitializing the DRBG with `CTR_DRBG_init`
bypasses the entire entropy pipeline and produces a fully deterministic state.

## Testing the Deterministic Randomness

We built a layered testing approach, starting from low-level RAND_bytes behavior
and working up to full handshake replay:

### 1. RAND_bytes sanity checks (`rand_sanity.rs`)

Five tests that verify the fundamental DRBG reset behavior:

- **`without_reset_differs`**: Two threads without reset produce different
  `RAND_bytes` output. Confirms the baseline is non-deterministic.
- **`with_reset_matches`**: Two threads that each call `fuzz_reset_rand` then
  `RAND_bytes` produce identical output. Confirms the reset works.
- **`reset_then_sequential_calls_differ`**: After a reset, sequential
  `RAND_bytes` calls produce different bytes. Confirms the DRBG advances.
- **`multiple_resets_same_sequence`**: Resetting twice on the same thread
  produces the same sequence both times. Confirms reset is idempotent.
- **`reset_before_init_is_noop`**: Calling `fuzz_reset_rand` before any
  `RAND_bytes` call is a no-op — two threads that do this produce different
  output. This test caught a bug where the corpus generation was calling reset
  before the DRBGs were initialized, resulting in non-deterministic behavior.

### 2. Client hello determinism (`deterministic_rand.rs`)

Generates a TLS 1.3 QUIC ClientHello on two separate threads (each with its own
DRBG, reset to zero entropy) and asserts byte-for-byte equality. Also checks the
client hello random bytes against a pinned constant
(`EXPECTED_CLIENT_HELLO_RANDOM`) to detect cross-process determinism regressions.

### 3. Full handshake transcript replay (`generate_corpus.rs`)

Runs a complete handshake with client and server on separate threads, recording
the full transcript (client bytes and server bytes per round trip). Then replays
the client bytes against a fresh server (on its own thread with the same DRBG
state) and asserts the server produces byte-identical output at each round.

This is the strongest test — it confirms that the entire server handshake path
(key generation, signature computation, key derivation) is fully deterministic
after a DRBG reset.

## Coverage Instrumentation

The s2n-tls C code is compiled with clang and
`-fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp` when the sanitizer
runtime is present (detected via `-Zsanitizer` in RUSTFLAGS). This gives
libFuzzer coverage feedback from the C handshake parser, not just the Rust
wrapper code. The counter count increased from ~46K (Rust only) to ~59K (Rust +
C) after enabling this.

## Memory Tracking

The fuzz target uses `dhat::Alloc` as the global allocator and creates a fresh
`dhat::Profiler` per iteration (following the pattern from the existing
`aws-kms-tls-auth` fuzz targets). aws-lc's memory allocations are routed through
the same allocator via `CRYPTO_set_mem_functions` with a tagged allocator that
prefixes each allocation with its size (needed because aws-lc's `free` callback
doesn't provide the allocation size). After each iteration, `dhat::HeapStats`
reports the peak allocation, which is checked against the 200 KB threshold.
