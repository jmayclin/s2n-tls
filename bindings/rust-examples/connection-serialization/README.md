# Connection Serialization

This example shows how connection serialization can bu used to effectively offload all TLS secret materials to a different process.

Ths TLSHandshaker runs in it's own process. This allows all TLS materials (e.g. private key, resumption secrets) to be stored separately from the main application server.

The BusinessServer is responsible for listening to new TCP connections. When a new connection is opened it starts in TCP mode. At this point it forwards all of the received TCP packets (which contain TLS records) to the TLSHandshaker over a unix domain socket. The TLSHandshaker responds with the TLS records that should be sent back to the client.

Eventually the TLSHandshaker has received enough TLS records that the handshake is complete. At this point it serializes the s2n-tls connection, and sends it back to the main process. Then the connection is "rehydrated" and the main process can read/write TLS records.