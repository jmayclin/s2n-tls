# Memory Amplification Fuzz Tests

Fuzz tests that check for overly large allocations in s2n-tls. These use
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) with
[dhat-rs](https://github.com/nnethercote/dhat-rs) to track memory usage.

## server_handshake

Feeds arbitrary bytes to an s2n-tls server connection (in QUIC mode, so the
handshake messages are plaintext) and asserts that peak memory allocation never
exceeds 200 KB. This guards against memory amplification attacks where a small
malicious input causes disproportionately large server-side allocations.

### Running

```sh
# Install cargo-fuzz if you haven't already
cargo install cargo-fuzz

# Run the fuzzer
cargo +nightly fuzz run server_handshake -- -max_len=100000 -jobs=31


# Run with a max input length and iteration count
cargo fuzz run server_handshake -- -max_len=65536 -runs=10000
```

### Deterministic randomness

The fuzz target resets the aws-lc DRBG to a known state before each iteration
so that the server's behavior depends only on the fuzz input. This is done by
directly reinitializing the thread-local CTR-DRBG via `CRYPTO_get_thread_local`
and `CTR_DRBG_init`. The `DISABLE_CPU_JITTER_ENTROPY` define (applied by the
local aws-lc-sys build when `--cfg fuzzing` is detected) prevents hardware
entropy from being mixed in during reseeds.

### Coverage instrumentation

When built under `cargo fuzz`, the s2n-tls C code is compiled with clang and
`-fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp` so that
libFuzzer gets coverage feedback from the C handshake parser, not just the
Rust code.

## Tests

```sh
# Verify deterministic randomness is working
RUSTFLAGS="--cfg fuzzing" cargo +nightly test --test deterministic_rand

# Regenerate the seed corpus from a real handshake
RUSTFLAGS="--cfg fuzzing" cargo +nightly test --test generate_corpus
```

## Dependencies

This crate uses a local checkout of `aws-lc-sys` (at `~/workspace/aws-lc-rs`)
which adds `DISABLE_CPU_JITTER_ENTROPY` when fuzzing is detected. The
`[patch.crates-io]` section in `Cargo.toml` redirects all aws-lc-sys references
to this local copy.
