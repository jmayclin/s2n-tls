# Proposed Events for s2n-tls

This document outlines the proposed events to be added to the s2n-tls library to improve observability and debugging capabilities. Each event will be added to the appropriate file in the `tls/` directory (excluding `tls/extensions`).

## Event Format

Each event will follow this format in the code:
```c
{
    char event_log_buffer[256];
    sprintf(event_log_buffer, "[event description with relevant data]");
    s2n_event_log_cb("[LEVEL]", event_log_buffer);
}
```

Where `[LEVEL]` is one of:
- `TRACE`: Detailed tracing information
- `DEBUG`: Debug-level information
- `INFO`: Informational messages
- `WARNING`: Warning conditions
- `ERROR`: Error conditions

## Events by File

### tls/s2n_handshake_io.c

1. **Handshake Message Transition**
   - Example: `"Handshake message transition: CLIENT_HELLO -> SERVER_HELLO"`
   - File: `tls/s2n_handshake_io.c`
   - Line: Around line 1000, in `s2n_advance_message()`
   - Level: `INFO`

2. **Handshake Type Selection**
   - Example: `"Selected handshake type: NEGOTIATED|FULL_HANDSHAKE|TLS12_PERFECT_FORWARD_SECRECY"`
   - File: `tls/s2n_handshake_io.c`
   - Line: After handshake type is determined in `s2n_conn_set_handshake_type()`
   - Level: `INFO`

3. **Handshake Completion**
   - Example: `"Handshake completed successfully"`
   - File: `tls/s2n_handshake_io.c`
   - Line: When `ACTIVE_STATE(conn).writer == 'B'` in `s2n_negotiate_impl()`
   - Level: `INFO`

### tls/s2n_record_read.c

1. **Record Received**
   - Example: `"Received record: type=APPLICATION_DATA, version=TLS1.2, length=1024"`
   - File: `tls/s2n_record_read.c`
   - Line: In `s2n_record_header_parse()` after parsing header
   - Level: `DEBUG`

2. **Record Decryption**
   - Example: `"Decrypted record: type=APPLICATION_DATA, length=1016"`
   - File: `tls/s2n_record_read.c`
   - Line: In `s2n_record_parse()` after decryption
   - Level: `DEBUG`

3. **TLS1.3 Record Type**
   - Example: `"TLS1.3 inner content type: HANDSHAKE"`
   - File: `tls/s2n_record_read.c`
   - Line: In `s2n_tls13_parse_record_type()` after determining the actual record type
   - Level: `DEBUG`

### tls/s2n_record_write.c

1. **Record Sending**
   - Example: `"Sending record: type=APPLICATION_DATA, version=TLS1.2, length=1024"`
   - File: `tls/s2n_record_write.c`
   - Line: In `s2n_record_write_protocol_version()` after determining record version
   - Level: `DEBUG`

2. **Record Encryption**
   - Example: `"Encrypted record: type=APPLICATION_DATA, original_length=1016, encrypted_length=1024"`
   - File: `tls/s2n_record_write.c`
   - Line: In `s2n_record_writev()` before writing the encrypted record
   - Level: `DEBUG`

3. **Maximum Fragment Size**
   - Example: `"Maximum fragment size: 16384 bytes"`
   - File: `tls/s2n_record_write.c`
   - Line: In `s2n_record_max_write_payload_size()` after determining max size
   - Level: `DEBUG`

### tls/s2n_alerts.c

1. **Alert Sent**
   - Example: `"Sending alert: level=FATAL, description=HANDSHAKE_FAILURE"`
   - File: `tls/s2n_alerts.c`
   - Line: In `s2n_queue_writer_close_alert_warning()` or similar functions
   - Level: `WARNING`

2. **Alert Received**
   - Example: `"Received alert: level=FATAL, description=BAD_CERTIFICATE"`
   - File: `tls/s2n_alerts.c`
   - Line: In `s2n_process_alert_fragment()`
   - Level: `WARNING`

### tls/s2n_client_hello.c

1. **Client Hello Parsing**
   - Example: `"Parsing ClientHello: legacy_version=TLS1.2, random_data=<first 8 bytes>, session_id_len=32"`
   - File: `tls/s2n_client_hello.c`
   - Line: In `s2n_parse_client_hello()` after collecting the client hello
   - Level: `INFO`

2. **Client Cipher Suites**
   - Example: `"ClientHello contains 15 cipher suites"`
   - File: `tls/s2n_client_hello.c`
   - Line: In `s2n_client_hello_parse_raw()` after parsing cipher suites
   - Level: `DEBUG`

3. **Client Extensions**
   - Example: `"ClientHello contains 8 extensions"`
   - File: `tls/s2n_client_hello.c`
   - Line: In `s2n_client_hello_parse_raw()` after parsing extensions
   - Level: `DEBUG`

4. **Server Name Indication**
   - Example: `"SNI hostname: example.com"`
   - File: `tls/s2n_client_hello.c`
   - Line: In `s2n_client_hello_get_server_name()` when SNI is present
   - Level: `INFO`

### tls/s2n_server_hello.c

1. **Server Hello Creation**
   - Example: `"Creating ServerHello: version=TLS1.2, cipher_suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`
   - File: `tls/s2n_server_hello.c`
   - Line: In `s2n_server_hello_send()` before sending
   - Level: `INFO`

2. **Server Hello Processing**
   - Example: `"Processing ServerHello: version=TLS1.2, cipher_suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`
   - File: `tls/s2n_server_hello.c`
   - Line: In `s2n_server_hello_recv()` after parsing
   - Level: `INFO`

### tls/s2n_cipher_suites.c

1. **Cipher Suite Selection**
   - Example: `"Selected cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`
   - File: `tls/s2n_cipher_suites.c`
   - Line: In `s2n_set_cipher_as_tls_server()` after selection
   - Level: `INFO`

2. **Cipher Suite Parameters**
   - Example: `"Cipher suite parameters: key_exchange=ECDHE, authentication=RSA, encryption=AES_128_GCM, mac=SHA256"`
   - File: `tls/s2n_cipher_suites.c`
   - Line: After cipher suite selection
   - Level: `DEBUG`

### tls/s2n_server_cert.c

1. **Certificate Chain Sent**
   - Example: `"Sending certificate chain: length=3, total_size=4096 bytes"`
   - File: `tls/s2n_server_cert.c`
   - Line: In `s2n_server_cert_send()` before sending
   - Level: `INFO`

2. **Certificate Chain Received**
   - Example: `"Received certificate chain: length=2, total_size=3072 bytes"`
   - File: `tls/s2n_server_cert.c`
   - Line: In `s2n_server_cert_recv()` after parsing
   - Level: `INFO`

### tls/s2n_server_cert_verify.c

1. **Certificate Verification**
   - Example: `"Verifying server certificate: subject=CN=example.com"`
   - File: `tls/s2n_server_cert_verify.c`
   - Line: In verification function
   - Level: `INFO`

2. **Certificate Verification Result**
   - Example: `"Certificate verification result: SUCCESS"`
   - File: `tls/s2n_server_cert_verify.c`
   - Line: After verification
   - Level: `INFO`

### tls/s2n_client_cert.c

1. **Client Certificate Request**
   - Example: `"Requesting client certificate: auth_type=REQUIRED"`
   - File: `tls/s2n_client_cert.c`
   - Line: In request function
   - Level: `INFO`

2. **Client Certificate Received**
   - Example: `"Received client certificate: subject=CN=client.example.com"`
   - File: `tls/s2n_client_cert.c`
   - Line: After receiving certificate
   - Level: `INFO`

3. **Client Certificate Validation**
   - Example: `"Client certificate validation: status=VALID"`
   - File: `tls/s2n_client_cert.c`
   - Line: After validation
   - Level: `INFO`

### tls/s2n_client_cert_verify.c

1. **Client Certificate Verification**
   - Example: `"Verifying client certificate signature: algorithm=RSA_SHA256"`
   - File: `tls/s2n_client_cert_verify.c`
   - Line: Before verification
   - Level: `INFO`

2. **Client Certificate Verification Result**
   - Example: `"Client certificate verification result: SUCCESS"`
   - File: `tls/s2n_client_cert_verify.c`
   - Line: After verification
   - Level: `INFO`

### tls/s2n_client_key_exchange.c

1. **Client Key Exchange Processing**
   - Example: `"Processing client key exchange: key_exchange_algorithm=ECDHE"`
   - File: `tls/s2n_client_key_exchange.c`
   - Line: In processing function
   - Level: `INFO`

2. **Pre-Master Secret Generation**
   - Example: `"Generated pre-master secret: length=48 bytes"`
   - File: `tls/s2n_client_key_exchange.c`
   - Line: After generation
   - Level: `DEBUG`

### tls/s2n_server_key_exchange.c

1. **Server Key Exchange Parameters**
   - Example: `"Sending server key exchange: curve=SECP256R1"`
   - File: `tls/s2n_server_key_exchange.c`
   - Line: Before sending
   - Level: `INFO`

2. **Server Key Exchange Signature**
   - Example: `"Server key exchange signature: algorithm=RSA_SHA256, length=256 bytes"`
   - File: `tls/s2n_server_key_exchange.c`
   - Line: After signing
   - Level: `DEBUG`

### tls/s2n_client_finished.c

1. **Client Finished Message**
   - Example: `"Processing client finished message: verify_data_length=12"`
   - File: `tls/s2n_client_finished.c`
   - Line: In processing function
   - Level: `INFO`

2. **Client Finished Verification**
   - Example: `"Client finished verification: SUCCESS"`
   - File: `tls/s2n_client_finished.c`
   - Line: After verification
   - Level: `INFO`

### tls/s2n_server_finished.c

1. **Server Finished Message**
   - Example: `"Sending server finished message: verify_data_length=12"`
   - File: `tls/s2n_server_finished.c`
   - Line: Before sending
   - Level: `INFO`

2. **Server Finished Verification**
   - Example: `"Server finished verification: SUCCESS"`
   - File: `tls/s2n_server_finished.c`
   - Line: After verification
   - Level: `INFO`

### tls/s2n_resume.c

1. **Session Resumption Attempt**
   - Example: `"Attempting session resumption: session_id_length=32"`
   - File: `tls/s2n_resume.c`
   - Line: In resumption function
   - Level: `INFO`

2. **Session Resumption Result**
   - Example: `"Session resumption result: SUCCESS"`
   - File: `tls/s2n_resume.c`
   - Line: After attempt
   - Level: `INFO`

3. **Session Ticket Processing**
   - Example: `"Processing session ticket: length=512 bytes"`
   - File: `tls/s2n_resume.c`
   - Line: During ticket processing
   - Level: `DEBUG`

### tls/s2n_server_new_session_ticket.c

1. **New Session Ticket Creation**
   - Example: `"Creating new session ticket: lifetime=86400 seconds"`
   - File: `tls/s2n_server_new_session_ticket.c`
   - Line: Before creation
   - Level: `INFO`

2. **Session Ticket Sent**
   - Example: `"Sent session ticket: length=512 bytes"`
   - File: `tls/s2n_server_new_session_ticket.c`
   - Line: After sending
   - Level: `DEBUG`

### tls/s2n_ocsp_stapling.c

1. **OCSP Stapling Status**
   - Example: `"OCSP stapling status: ENABLED"`
   - File: `tls/s2n_ocsp_stapling.c`
   - Line: During status check
   - Level: `INFO`

2. **OCSP Response**
   - Example: `"OCSP response: status=GOOD, length=1024 bytes"`
   - File: `tls/s2n_ocsp_stapling.c`
   - Line: When processing response
   - Level: `INFO`

### tls/s2n_psk.c

1. **PSK Selection**
   - Example: `"Selected PSK: identity_hash=0x1a2b3c4d, mode=RESUMPTION"`
   - File: `tls/s2n_psk.c`
   - Line: After selection
   - Level: `INFO`

2. **PSK Binding**
   - Example: `"PSK binding verification: SUCCESS"`
   - File: `tls/s2n_psk.c`
   - Line: After verification
   - Level: `INFO`

### tls/s2n_early_data.c

1. **Early Data Status**
   - Example: `"Early data status: ACCEPTED, max_size=16384 bytes"`
   - File: `tls/s2n_early_data.c`
   - Line: When status is determined
   - Level: `INFO`

2. **Early Data Processing**
   - Example: `"Processing early data: received=1024 bytes, remaining=15360 bytes"`
   - File: `tls/s2n_early_data.c`
   - Line: During processing
   - Level: `DEBUG`

### tls/s2n_x509_validator.c

1. **Certificate Validation**
   - Example: `"Validating certificate: subject=CN=example.com, issuer=CN=Example CA"`
   - File: `tls/s2n_x509_validator.c`
   - Line: Before validation
   - Level: `INFO`

2. **Certificate Validation Result**
   - Example: `"Certificate validation result: VALID, verification_depth=3"`
   - File: `tls/s2n_x509_validator.c`
   - Line: After validation
   - Level: `INFO`

3. **Certificate Validation Error**
   - Example: `"Certificate validation error: HOSTNAME_MISMATCH, expected=example.com, found=other.com"`
   - File: `tls/s2n_x509_validator.c`
   - Line: On validation error
   - Level: `ERROR`

### tls/s2n_key_update.c

1. **Key Update Request**
   - Example: `"Key update requested: update_type=UPDATE_NOT_REQUESTED"`
   - File: `tls/s2n_key_update.c`
   - Line: When request is made
   - Level: `INFO`

2. **Key Update Processing**
   - Example: `"Processing key update: update_type=UPDATE_REQUESTED"`
   - File: `tls/s2n_key_update.c`
   - Line: During processing
   - Level: `INFO`

### tls/s2n_shutdown.c

1. **Shutdown Initiated**
   - Example: `"TLS shutdown initiated: mode=CLIENT"`
   - File: `tls/s2n_shutdown.c`
   - Line: At start of shutdown
   - Level: `INFO`

2. **Close Notify Alert**
   - Example: `"Sending close_notify alert"`
   - File: `tls/s2n_shutdown.c`
   - Line: Before sending alert
   - Level: `DEBUG`

3. **Shutdown Complete**
   - Example: `"TLS shutdown complete: graceful=true"`
   - File: `tls/s2n_shutdown.c`
   - Line: At end of shutdown
   - Level: `INFO`

### tls/s2n_send.c

1. **Data Sending**
   - Example: `"Sending application data: requested=1024 bytes, actual=1024 bytes"`
   - File: `tls/s2n_send.c`
   - Line: During send operation
   - Level: `DEBUG`

2. **Send Buffer Status**
   - Example: `"Send buffer status: available=16384 bytes, used=1024 bytes"`
   - File: `tls/s2n_send.c`
   - Line: After buffer update
   - Level: `TRACE`

### tls/s2n_recv.c

1. **Data Receiving**
   - Example: `"Receiving application data: requested=1024 bytes, available=512 bytes"`
   - File: `tls/s2n_recv.c`
   - Line: During receive operation
   - Level: `DEBUG`

2. **Receive Buffer Status**
   - Example: `"Receive buffer status: available=512 bytes, requested=1024 bytes"`
   - File: `tls/s2n_recv.c`
   - Line: After buffer check
   - Level: `TRACE`

### tls/s2n_connection.c

1. **Connection Creation**
   - Example: `"Creating new connection: mode=SERVER, protocol_version=TLS1.3"`
   - File: `tls/s2n_connection.c`
   - Line: In `s2n_connection_new()`
   - Level: `INFO`

2. **Connection Configuration**
   - Example: `"Connection configuration: cipher_pref=default, security_policy=default"`
   - File: `tls/s2n_connection.c`
   - Line: After configuration
   - Level: `DEBUG`

3. **Connection Close**
   - Example: `"Closing connection: handshake_completed=true, bytes_processed=10240"`
   - File: `tls/s2n_connection.c`
   - Line: In close function
   - Level: `INFO`

### tls/s2n_handshake_transcript.c

1. **Transcript Hash Update**
   - Example: `"Updating transcript hash: message_type=CLIENT_HELLO, hash_algorithm=SHA256"`
   - File: `tls/s2n_handshake_transcript.c`
   - Line: During update
   - Level: `DEBUG`

2. **Transcript Hash Result**
   - Example: `"Transcript hash result: hash_algorithm=SHA256, first_bytes=0x1a2b3c4d"`
   - File: `tls/s2n_handshake_transcript.c`
   - Line: After computation
   - Level: `TRACE`

### tls/s2n_tls13_handshake.c

1. **TLS1.3 Handshake State**
   - Example: `"TLS1.3 handshake state: CLIENT_HELLO -> SERVER_HELLO"`
   - File: `tls/s2n_tls13_handshake.c`
   - Line: During state transition
   - Level: `INFO`

2. **TLS1.3 Key Schedule**
   - Example: `"TLS1.3 key schedule update: stage=HANDSHAKE, hash_algorithm=SHA256"`
   - File: `tls/s2n_tls13_handshake.c`
   - Line: During key schedule update
   - Level: `DEBUG`

### tls/s2n_tls13_key_schedule.c

1. **Key Derivation**
   - Example: `"Deriving TLS1.3 keys: stage=APPLICATION_TRAFFIC, direction=CLIENT_TO_SERVER"`
   - File: `tls/s2n_tls13_key_schedule.c`
   - Line: During key derivation
   - Level: `DEBUG`

2. **Secret Update**
   - Example: `"Updated TLS1.3 secret: type=TRAFFIC_SECRET, direction=SERVER_TO_CLIENT"`
   - File: `tls/s2n_tls13_key_schedule.c`
   - Line: After update
   - Level: `DEBUG`

## Conclusion

This document outlines a comprehensive set of events to be added to the s2n-tls library. These events will provide valuable insights into the TLS handshake process, record handling, and other important aspects of TLS connections, making it easier to debug issues and understand the library's behavior.
