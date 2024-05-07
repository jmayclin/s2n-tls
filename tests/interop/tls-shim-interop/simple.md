

client
0. handshake
1. read 10 bytes
2. close (close notify + close TCP)

server
0. handshake
1. write 10 bytes (`stream.write_all(&buf)`)
2. close <- we ignore errors on close here (have a separate github issue open for this)

actually 256 Gb, not 10 bytes. 
does not fail for smaller amounts of data

```
handshake              , S2nTls    , S2nTls    , 🥳
handshake              , S2nTls    , Rustls    , 🥳
handshake              , S2nTls    , Java      , 🥳
handshake              , S2nTls    , Go        , 🥳
handshake              , OpenSSL   , S2nTls    , 🥳
handshake              , OpenSSL   , Rustls    , 🥳
handshake              , OpenSSL   , Java      , 🥳
handshake              , OpenSSL   , Go        , 🥳
greeting               , S2nTls    , S2nTls    , 🥳
greeting               , S2nTls    , Rustls    , 🥳
greeting               , S2nTls    , Java      , 🥳
greeting               , S2nTls    , Go        , 🥳
greeting               , OpenSSL   , S2nTls    , 🥳
greeting               , OpenSSL   , Rustls    , 🥳
greeting               , OpenSSL   , Java      , 🥳
greeting               , OpenSSL   , Go        , 🥳
large_data_download    , S2nTls    , S2nTls    , 🥳
large_data_download    , S2nTls    , Rustls    , 🥳
large_data_download    , S2nTls    , Java      , 💔 # different failure
large_data_download    , S2nTls    , Go        , 💔
large_data_download    , OpenSSL   , S2nTls    , 🥳
large_data_download    , OpenSSL   , Rustls    , 🥳
large_data_download    , OpenSSL   , Java      , 💔 # different failure
large_data_download    , OpenSSL   , Go        , 💔
large_data_download_with_frequent_key_updates, S2nTls    , S2nTls    , 🥳
large_data_download_with_frequent_key_updates, S2nTls    , Rustls    , 🥳
large_data_download_with_frequent_key_updates, S2nTls    , Java      , 💔
large_data_download_with_frequent_key_updates, S2nTls    , Go        , 💔
large_data_download_with_frequent_key_updates, OpenSSL   , S2nTls    , 🥳
large_data_download_with_frequent_key_updates, OpenSSL   , Rustls    , 🥳
large_data_download_with_frequent_key_updates, OpenSSL   , Java      , 💔
large_data_download_with_frequent_key_updates, OpenSSL   , Go        , 💔
mtls_request_response  , S2nTls    , S2nTls    , 🥳
mtls_request_response  , S2nTls    , Rustls    , 🥳
mtls_request_response  , S2nTls    , Java      , 🚧
mtls_request_response  , S2nTls    , Go        , 🥳
mtls_request_response  , OpenSSL   , S2nTls    , 🥳
mtls_request_response  , OpenSSL   , Rustls    , 🥳
mtls_request_response  , OpenSSL   , Java      , 🚧
mtls_request_response  , OpenSSL   , Go        , 🥳
```


Java Error
```
2024-05-06T23:12:17.630514Z ERROR s2n_tls_server: test scenario failed: Custom { kind: BrokenPipe, error: Error { code: 67108864, name: "S2N_ERR_IO", message: "underlying I/O operation failed, check system errno", kind: IOError, source: Library, debug: "Error encountered in lib/utils/s2n_io.c:28", errno: "Broken pipe" } }
```

Go Error
```
2024-05-06T23:10:41.319783Z ERROR s2n_tls_server: test scenario failed: Custom { kind: ConnectionReset, error: Error { code: 67108864, name: "S2N_ERR_IO", message: "underlying I/O operation failed, check system errno", kind: IOError, source: Library, debug: "Error encountered in lib/utils/s2n_io.c:28", errno: "Connection reset by peer" } }
```
