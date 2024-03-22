# Interop Tests
## Goal
The goal of the tests in this category is to test interoperability with other TLS implementations. 

## Why Another Framework
> s2n-tls already has unit tests, integration tests, and _more_ integration tests in the rust bindings. Why is it necessary to write new ones?

Well it's true that our existing test frameworks are capable of reproducing and asserting on most issues, the goal is to find issues before we are aware of them. Our existing integration tests have some very limiting and specific assumptions that are not found in existing applications.

Our [integrationv2](../integrationv2/README.md) tests use `s2nd` as a server component which has an "echo" io loop which will always alterate reads with writes. In contrast, most applications servers will drive `send` to it's completion before pausing to read again.

Our [benchmark harnesses](../../bindings/rust/bench/README.md) communicate using shared memory rather than using an actual TCP connection. This means that it will be unable to reproduce issues related to TCP socket buffers/flow control, since a write to shared memory won't fail until you have written enough to cause an out-of-memory error.

We hope to expand these tests to cover a wide variety of implementations in the future, including 

## Structure
The interop tests are largely inspired by the work done by the [Quic Interop Runner](https://interop.seemann.io). Currently their feature set is significantly smaller.

The only available client implementations are
- s2n-tls
- rustls
- java
And the only server implementation is
- s2n-tls

The interop runner defines a number of test cases. Binaries are invoked with the following arguments
```
client_binary $TEST_CASE $SERVER_PORT
```
```
server_binary $TEST_CASE $SERVER_PORT
```

## Tests
All tests currently use TLS 1.3. Acceptable cipher suites/groups are not specified

- Handshake (`handshake`): 
- Large Data Download (`large_data_download`): 

### Future Tests

- Resumption
    - example incompatability: https://github.com/aws/s2n-tls/issues/4124
- Early Data
- OOB PSK
- Client Hello Retry
    - example incompatability: https://github.com/rustls/rustls/issues/1373
- Small TCP Packet

## Certificates

tests certificates are available in [interop/certificates](certificates). Clients should trust `ca-certificate.pem`, and servers should send the full `server-chain.pem`.
