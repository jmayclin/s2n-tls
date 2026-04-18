# Cert Parsing Context

## Project
`s2n-tls/bindings/rust/standard/s2n-tls-metrics-subscriber` — a telemetry provider for s2n-tls.

## What we built
A zero-dependency DER certificate parser at `src/parsing/cert.rs` that extracts key type, signature algorithm, serial, issuer, and subject from X.509 DER-encoded certificates. It uses `s2n-codec`'s `DecoderBuffer`/`DecoderValue` for bounds-checked parsing.

## Architecture

### Public API
- `parse_cert(der: &[u8]) -> Result<CertInfo, DecoderError>` — key type + signature only
- `parse_leaf(der: &[u8]) -> Result<LeafCertInfo, DecoderError>` — full leaf info (serial, issuer, subject, key, sig)

### Types
- `KeyType` — flat enum: `Rsa1024`, `Rsa2048`, `Rsa3072`, `Rsa4096`, `RsaPss2048/3072/4096`, `Secp256r1`, `Secp384r1`, `Secp521r1`, `Unknown(String)`
  - Has a `DecoderValue` impl that decodes from SPKI content
  - EC keys resolve from the named curve OID parameter (no BIT STRING parsing needed)
  - RSA/RSA-PSS parse the BIT STRING to extract modulus size
  - Ed25519/Ed448 intentionally not handled (fall to Unknown)
- `SignatureAlgorithm` — enum: `RsaPkcsSha1/256/384/512`, `RsaPss` (hash not decoded from params), `EcdsaSha256/384/512`, `Unknown(String)`
  - Constructed via `from_oid()` with OID constants as associated consts
- `CertInfo` — `{ key: KeyType, signature: SignatureAlgorithm }`
- `LeafCertInfo` — `{ serial: Vec<u8>, issuer: Vec<u8>, common_name: Vec<u8>, cert: CertInfo }`
  - `issuer` and `common_name` are raw DER bytes (not decoded strings)

### DER codec module (`der_codec`)
Custom DER parsing types using `s2n_codec::DecoderValue`:
- `DerLength` — DER length field (short form < 0x80, long form with `from_be_bytes`)
- `Tlv` — tag-length-value (tag byte + DerLength + content slice)
- `OidComponent` — base-128 varint with `checked_shl`/`checked_add` overflow protection
- `OidRoot` — first two OID arcs packed together (handles arc 2 with large second components via varint)
- `decode_oid()` — returns `Result<String, DecoderError>`, properly propagates errors
- `ParsedCert` — walks the DER cert structure: outer SEQUENCE → TBSCertificate → version/serial/sigAlg/issuer/validity/subject/SPKI
- `KeyType` DecoderValue impl — decodes from SPKI content

All magic numbers are named constants: `TAG_SEQUENCE`, `TAG_OID`, `TAG_CONTEXT_0`, `DER_LENGTH_SHORT_FORM_MAX`, `DER_LENGTH_LONG_FORM_MASK`, `OID_VARINT_CONTINUATION`, `OID_VARINT_DATA_MASK`, plus OID constants for key/curve/signature algorithms.

## Known limitations
- RSA-PSS signature doesn't report the hash algorithm (it's in the AlgorithmIdentifier parameters, not the OID)
- `common_name` field is actually raw DER subject bytes, not a decoded CN string
- Ed25519/Ed448 not handled (mapped to Unknown)
- OID components use `u32` (overflow returns `LengthCapacityExceeded`)

## Performance
Benchmarked at ~840ns/cert in release mode. Compared against:
- webpki: ~334ns (but doesn't decode key/sig)
- x509-parser: ~5.7µs
- x509-cert: ~13.5µs  
- openssl (aws-lc backend): ~21.7µs

SHA-256 of a cert is ~1µs, so caching parsed results isn't worth it — just re-parse.

## File locations
- `src/parsing/cert.rs` — the cert parser (main file)
- `src/parsing/mod.rs` — registers `pub(crate) mod cert`
- `src/lib.rs` — old `mod cert` was removed
- `Cargo.toml` — only dependency is `s2n-codec` (already existed). Removed x509-parser, x509-cert, der, openssl, openssl-sys, rustls-webpki, rustls-pki-types that were added during exploration.

## Tests (9 total, in `parsing::cert::tests`)
All use `parse_leaf` with exact assertions on serial bytes, key type enum, signature enum, and that raw DER subject contains "localhost":
- `rsa_2048_sha256`, `rsa_2048_sha384`, `rsa_4096_sha512`
- `ecdsa_p256_sha256`, `ecdsa_p384_sha256`
- `rsa_pss_2048_sha256`
- `parse_cert_rejects_garbage`, `parse_cert_rejects_empty`, `parse_cert_rejects_truncated`

Test helper `handshake_leaf_der` builds a config from scratch (not `config_builder`) to avoid the "multiple default certificates per auth type" error.

## DER encoding notes discussed
- DER length: short form (< 0x80 = byte IS the length) vs long form (>= 0x80, low 7 bits = number of subsequent big-endian length bytes). 0x80 indefinite length is invalid in DER.
- OID encoding: first byte packs two arcs as `first*40 + second`. Arc 2 can overflow into multi-byte varint. Remaining components are base-128 varints (high bit = continuation flag, low 7 bits = data).
- RSA public key BIT STRING contains SEQUENCE { INTEGER(modulus), INTEGER(exponent) }. Modulus may have leading 0x00 sign padding byte.
- EC SPKI AlgorithmIdentifier has the named curve OID as a parameter — no need to parse the BIT STRING.
