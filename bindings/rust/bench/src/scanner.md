## Scanner Goal
The goal of the scanner is to roughly answer "what IANA parameters fully describe this connection?". The structure of that answer depends on the TLS version that is being used.

// Signatures are used in two places for TLS.
// They are use to verify certificates chains answering
// the question of "what the public certificate that the server presented me signed by a CA that I trust".
// Given the public key of a CA that we trust, we can verify that the signature on the server authentication
// certificate is valid.
// Signatures are also used to prove that the Server has the private key associated with the public certificate
// that it provided to the client. The server will first hash a transcript of the handshake, and then sign that hash
// with the private key.

// In TLS 1.2, there is a SignatureAlgorithm extension. https://www.rfc-editor.org/rfc/rfc8446
// The signature algorithm defines a tuple of a hash algorithm and a signature algorithm
// enum {
//     none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
//     sha512(6), (255)
// } HashAlgorithm;
//
// enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
//   SignatureAlgorithm;
//
// struct {
//       HashAlgorithm hash;
//       SignatureAlgorithm signature;
// } SignatureAndHashAlgorithm;
//
// SignatureAndHashAlgorithm
//   supported_signature_algorithms<2..2^16-2>;

// In TLS 1.3 there is a SignatureScheme extension.
// The "extension_data" field of these extensions contains a
// SignatureSchemeList value:
//
//    enum {
//        /* RSASSA-PKCS1-v1_5 algorithms */
//        rsa_pkcs1_sha256(0x0401),
//        rsa_pkcs1_sha384(0x0501),
//        rsa_pkcs1_sha512(0x0601),
//
//        /* ECDSA algorithms */
//        ecdsa_secp256r1_sha256(0x0403),
//        ecdsa_secp384r1_sha384(0x0503),
//        ecdsa_secp521r1_sha512(0x0603),
//
//        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
//        rsa_pss_rsae_sha256(0x0804),
//        rsa_pss_rsae_sha384(0x0805),
//        rsa_pss_rsae_sha512(0x0806),
//
//        /* EdDSA algorithms */
//        ed25519(0x0807),
//        ed448(0x0808),
//
//        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
//        rsa_pss_pss_sha256(0x0809),
//        rsa_pss_pss_sha384(0x080a),
//        rsa_pss_pss_sha512(0x080b),
//
//        /* Legacy algorithms */
//        rsa_pkcs1_sha1(0x0201),
//        ecdsa_sha1(0x0203),
//
//        /* Reserved Code Points */
//        private_use(0xFE00..0xFFFF),
//        (0xFFFF)
//    } SignatureScheme;
// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3

// supports session resumption

Audience: Readers who are aware of the control flow and general ideas behind TLS, but who are not familiar with the cryptographic implementation details.
This document discusses the various cryptographic algorithims used by TLS. The goal of this document is to provide the necessary context to allow a reader to decipher our security policy documentation. This document assumes that the reader is generally familiar with the semantics of the TLS handshake but not familiar with the

## Cryptographic primitives
There are 3 types of cryptographic primitives that may be used in TLS.

### asymmetric encryption
With asymmetric encryption, information is encrypted with a public key, but can only be decrypted with a private key. An example of asymmetric encryption used in TLS is RSA encryption.
### asymmetric signing
With assymetric signing,
### symmetric encryption

### cryptographic hash ?


## Cryptographic Systems

### RSA
Encryption

Signing

Padding

### Elliptic Curve Cryptographic

### Finite Field Cryptography

# TLS Cryptography Uses

## Key Exchange
### Overview
The TLS Handshake has a "Key Exchange" portion. Key Exchange algorithms allow two peers to exchange public information over an untrusted channel to obtain a shared secret. This shared secret is then used as a key for Application Data Encryption.

### RSA Key Exchange

### Diffie Hellman

### Crypto-System
*finite field*:

*elliptic curve*:

### Parameter Sourcing
*static or fixed*:

*ephemeral*:


###

## Certificate Verification

Certificate verification answers the following two questions.
"Does the server

## Application Data Encryption



## Resources
https://timtaubert.de/blog/2016/07/the-evolution-of-signatures-in-tls/: This is an excellent blog post
