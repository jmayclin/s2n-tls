//! This module defines "extension" trait to add our own bindings to the openssl
//! crate. Ideally all of this logic would live _in_ the openssl crate, but they
//! don't always accept PRs
//! - add signature type retrieval functions: https://github.com/sfackler/rust-openssl/pull/2164
//! - Add helper to return &mut SslRef from stream: https://github.com/sfackler/rust-openssl/pull/2223

use openssl::ssl::{SslContextBuilder};
use openssl_sys::SSL_CTX;

extern "C" {
    /// ```c
    /// int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size);
    /// ```
    pub fn SSL_CTX_set_block_padding(ctx: *mut SSL_CTX, block_size: usize) -> std::ffi::c_int;
}

pub trait SslContextExtension {
    fn set_block_padding(&mut self, block_size: usize);
}

impl SslContextExtension for SslContextBuilder {
    fn set_block_padding(&mut self, block_size: usize) {
        unsafe {
            // > The SSL_CTX_set_block_padding() and SSL_set_block_padding() functions 
            // > return 1 on success or 0 if block_size is too large.
            // > https://docs.openssl.org/master/man3/SSL_CTX_set_record_padding_callback
            let res = SSL_CTX_set_block_padding(self.as_ptr(), block_size as _);
            assert_eq!(res, 1);

        }
    }
}

