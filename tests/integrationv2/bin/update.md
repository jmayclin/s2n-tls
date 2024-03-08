# Working Hypothesis
This appears to be an issue with the JVM TLS implementation. TLS 1.3 allows for KeyUpdate messages to be sent, which updates the key to maintain security even after large quantities of data have been sent. The JVM is pessimistic and requests a `request_update` message to the peer once 137 Gb have been received. It then waits for the requested key update to happen before reading any more data. However, TLS servers are don't actually "read" the `request_update` message.
```rust
# do the handshake
server_tls.handshake()

# read the application request
server_tls.read()
while (bytes_sent < file_length) {
   // read is never called in this loop, so the request_update message
   // is never processed
   server_tls.send()
}
```
This manifests to customers as a "hung" connection that is eventually closed with a timeout error.

The JVM behavior is in violation of the implementation note from the [TLS 1.3 RFC](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.3)
> Note that implementations may receive an arbitrary number of messages between sending a KeyUpdate with request_update set to "update_requested" and receiving the peer's KeyUpdate, because those messages may already be in flight.

## Impact
Any requests to S3 which
- download a file larger than 137 Gb
- use a Java SDK
- which uses the JVM TLS implementation
will fail to complete with a timeout error.

I expect all JVM versions to be impacted. My reproduction efforts used Corretto 21, and customers user agents indicate JVM 11 usage, so it seems safe to assume that this issue effects the TLS 1.3 implementation of all Corretto JDKs.

## Reproduction
There is a minimal reproduction of this between a simple TLS client and server, without
JLBRelay or any HTTP involved. The results of those scenarios are as follows.

| Client | Server | Successful Large Download |
|--------|--------|-------------|
|  java  | s2n-tls|    ❌      |
|  java  | openssl|    ❌      |
|  java  |  rustls|    ❌      |
| openssl| s2n-tls|    ✅      |
| rustls | s2n-tls|    ✅      |

The minimal examples to reproduce can be found on [maycj's branch of s2n-tls](https://github.com/aws/s2n-tls/compare/main...jmayclin:s2n-tls:jvm-key-update-test). Some details are hard coded right now, so if you want to run them locally please ping `@maycj``
