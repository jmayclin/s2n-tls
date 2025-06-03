//! This module defines "extension" trait to add our own bindings to the openssl
//! crate. Ideally all of this logic would live _in_ the openssl crate, but they
//! don't really accept PRs
//! - add signature type retrieval functions: https://github.com/sfackler/rust-openssl/pull/2164
//! - Add helper to return &mut SslRef from stream: https://github.com/sfackler/rust-openssl/pull/2223

// # define SSL_CTX_set_max_send_fragment(ctx,m) \
//         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)

use std::{ffi::c_long, os::raw::c_void};

use openssl::ssl::{SslContext, SslContextBuilder, SslRef, SslStream};
use openssl_sys::SSL_CTX;

// very tediously, we need to import exactly the same verion of ForeignType as
// ossl because we need this trait impl to access the raw pointers on all of the
// openssl types.
use foreign_types_shared::{ForeignType, ForeignTypeRef};

// expose the macro as a function
fn SSL_CTX_set_max_send_fragment(ctx: *mut SSL_CTX, m: c_long) -> c_long {
    // # define SSL_CTRL_SET_MAX_SEND_FRAGMENT          52
    const SSL_CTRL_SET_MAX_SEND_FRAGMENT: std::ffi::c_int = 52;

    // TODO: assert on the return value
    unsafe {
        openssl_sys::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_SEND_FRAGMENT, m, std::ptr::null_mut())
    }
}

// expose macro as a function
// # define SSL_get_secure_renegotiation_support(ssl) \
//         SSL_ctrl((ssl), SSL_CTRL_GET_RI_SUPPORT, 0, NULL)
// # define SSL_CTRL_GET_RI_SUPPORT                 76
fn SSL_get_secure_renegotiation_support(ssl: *mut openssl_sys::SSL) -> std::ffi::c_long {
    const SSL_CTRL_GET_RI_SUPPORT: std::ffi::c_int = 76;
    unsafe { openssl_sys::SSL_ctrl(ssl, SSL_CTRL_GET_RI_SUPPORT, 0, std::ptr::null_mut()) }
}
extern "C" {
    // int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size);
    pub fn SSL_CTX_set_block_padding(ctx: *mut SSL_CTX, block_size: usize) -> std::ffi::c_int;
    // pub fn SSL_CTX_set_block_padding(ctx: *mut c_void, block_size: usize) -> std::ffi::c_int;

    pub fn SSLv3_method() -> *const openssl_sys::SSL_METHOD;

    pub fn SSL_renegotiate_pending(ssl: *mut openssl_sys::SSL) -> std::ffi::c_int;
    pub fn SSL_renegotiate(ssl: *mut openssl_sys::SSL) -> std::ffi::c_int;
}

// #[derive(Copy, Clone)]
// pub struct SslMethod(*const ffi::SSL_METHOD);

// impl SslMethod {
//     /// Support all versions of the TLS protocol.
//     #[corresponds(TLS_method)]
//     pub fn tls() -> SslMethod {
//         unsafe { SslMethod(TLS_method()) }
//     }

pub trait SslContextExtension {
    fn set_max_send_fragment(&mut self, max_send_fragment: usize);

    // fn set_block_padding(&mut self, block_size: usize);
}

impl SslContextExtension for SslContextBuilder {
    fn set_max_send_fragment(&mut self, max_send_fragment: usize) {
        SSL_CTX_set_max_send_fragment(self.as_ptr(), max_send_fragment as _);
    }

    // fn set_block_padding(&mut self, block_size: usize) {
    //     unsafe {
    //         SSL_CTX_set_block_padding(self.as_ptr(), block_size as _);
    //     }
    // }
}
/// context.set_block_padding(512);
/// SSL_CTX_set_block_padding(context.as_ptr(), 512);
pub trait SslStreamExtension {
    fn mut_ssl(&mut self) -> &mut SslRef;
}

impl<T> SslStreamExtension for SslStream<T> {
    /// PR open upstream: https://github.com/sfackler/rust-openssl/pull/2223
    #[allow(invalid_reference_casting)]
    fn mut_ssl(&mut self) -> &mut SslRef {
        unsafe { &mut *(self.ssl() as *const openssl::ssl::SslRef as *mut openssl::ssl::SslRef) }
    }
}

pub trait SslExtension {
    /// Returns `true` if the peer supports secure renegotiation and 0 if it does not.
    ///
    /// Probably better to say "returns true" if the peer is patched against insecure
    /// renegotiation.
    fn secure_renegotiation_support(&self) -> bool;

    fn renegotiate_pending(&self) -> bool;

    /// Schedule a renegotiate request to be sent on the next io.
    fn renegotiate(&mut self);
}

impl SslExtension for openssl::ssl::SslRef {
    fn secure_renegotiation_support(&self) -> bool {
        let result = SSL_get_secure_renegotiation_support(self.as_ptr());
        match result {
            1 => true,
            0 => false,
            _ => unreachable!("openssl documentation lied. It Lied!"),
        }
    }

    fn renegotiate_pending(&self) -> bool {
        match unsafe { SSL_renegotiate_pending(self.as_ptr()) } {
            1 => true,
            0 => false,
            _ => unreachable!("openssl documentation lied."),
        }
    }

    fn renegotiate(&mut self) {
        // https://docs.openssl.org/3.3/man3/SSL_key_update/#return-values
        let result = unsafe { SSL_renegotiate(self.as_ptr()) };
        assert_eq!(result, 1);
    }
}
