# Benchmark Certificates

These certificates are used by the `handshake_s2n_tls` benchmark. Each directory
contains a depth-2 certificate chain (leaf → CA) for a specific signature algorithm.

## Regenerating

If you need to regenerate the certificates (e.g. after they expire or to change
parameters), run:

```bash
cargo run --bin generate-certs
```

from the `bindings/rust/standard` workspace directory.
