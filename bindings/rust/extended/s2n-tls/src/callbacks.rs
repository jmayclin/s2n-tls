// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utilities to handle passing Rust code to s2n-tls's C callbacks.
//!
//! s2n-tls uses callbacks to temporarily return control to the application
//! and allow the application to execute custom code.
//!
//! To use a callback in your application, just implement the trait for the
//! target callback type and pass your implementation to the appropriate
//! connection or config method. For example, you can implement
//! [`ClientHelloCallback`] and pass that implementation to
//! [config::Builder::set_client_hello_callback()](`crate::config::Builder::set_client_hello_callback()`)
//! in order to execute custom logic after an s2n-tls server receives a client hello.
//!
//! s2n-tls callbacks come in two flavors:
//! * "sync" callbacks return an immediate result and will block the task
//!   performing the handshake until they return success or failure. See
//!   [`VerifyHostNameCallback`] as an example.
//! * "async" callbacks return a [Poll](`core::task::Poll`) and should not block the task performing the handshake.
//!   They will be polled until they return [Poll::Ready](`core::task::Poll::Ready`).
//!   [Connection::waker()](`crate::connection::Connection::waker()`)
//!   can be used to register the task for wakeup. See [`ClientHelloCallback`] as an example.

use crate::{config::Context, connection::Connection, error::Fallible};
use core::{mem::ManuallyDrop, ptr::NonNull, time::Duration};
use s2n_tls_sys::{
    s2n_connection, s2n_offered_psk, s2n_offered_psk_free, s2n_offered_psk_get_identity,
    s2n_offered_psk_list, s2n_offered_psk_list_choose_psk, s2n_offered_psk_list_has_next,
    s2n_offered_psk_list_next,
};
use std::{ptr::addr_of_mut, slice};

mod async_cb;
pub use async_cb::*;

mod client_hello;
pub use client_hello::*;

mod session_ticket;
pub use session_ticket::*;

mod pkey;
pub use pkey::*;

/// Convert the connection pointer provided to a callback into a Connection
/// and Context useable with the Rust bindings.
///
/// # Safety
///
/// This must ONLY be used for connection pointers provided to callbacks,
/// which can be assumed to point to valid Connections because the
/// callbacks were configured through the Rust bindings.
pub(crate) unsafe fn with_context<F, T>(conn_ptr: *mut s2n_connection, action: F) -> T
where
    F: FnOnce(&mut Connection, &mut Context) -> T,
{
    let raw = NonNull::new(conn_ptr).expect("connection should not be null");
    let mut conn = Connection::from_raw(raw);
    let mut config = conn.config().expect("config should not be null");
    let context = config.context_mut();
    let r = action(&mut conn, context);
    // Since this is a callback, it receives a pointer to the connection
    // but doesn't own that connection or control its lifecycle.
    // Do not drop / free the connection.
    let _ = ManuallyDrop::new(conn);
    r
}

/// A trait for the callback used to verify host name(s) during X509
/// verification.
///
/// The implementation should verify the certificate host name and return `true`
/// if the name is valid, `false` otherwise.
pub trait VerifyHostNameCallback: 'static + Send + Sync {
    fn verify_host_name(&self, host_name: &str) -> bool;
}

/// A trait for the callback used to retrieve the system / wall clock time.
pub trait WallClock: 'static + Send + Sync {
    fn get_time_since_epoch(&self) -> Duration;
}

/// A trait for the callback used to retrieve the monotonic time.
pub trait MonotonicClock: 'static + Send + Sync {
    fn get_time(&self) -> Duration;
}

/// Invoke the user provided VerifyHostNameCallback on the host_name.
///
/// # Safety
///
/// The caller must ensure that the memory underlying host_name is a valid
/// slice.
pub(crate) unsafe fn verify_host(
    host_name: *const ::libc::c_char,
    host_name_len: usize,
    handler: &mut Box<dyn VerifyHostNameCallback>,
) -> u8 {
    let host_name = host_name as *const u8;
    let host_name = core::slice::from_raw_parts(host_name, host_name_len);

    match core::str::from_utf8(host_name) {
        Ok(host_name_str) => handler.verify_host_name(host_name_str) as u8,
        Err(_) => 0, // If the host name can't be parsed, fail closed.
    }
}

pub(crate) struct OfferedPskListWrapper(s2n_offered_psk_list);

impl OfferedPskListWrapper {
    fn has_next(&self) -> bool {
        unsafe { s2n_offered_psk_list_has_next(self.as_ptr()) }
    }

    pub(crate) fn choose_psk(&mut self, psk: &OfferedPsk) -> Result<(), crate::error::Error> {
        let mut_psk = psk as *const OfferedPsk as *const s2n_offered_psk as *mut s2n_offered_psk;
        unsafe { s2n_offered_psk_list_choose_psk(self.as_mut_ptr(), mut_psk).into_result()? };
        Ok(())
    }

    fn as_ptr(&self) -> *const s2n_offered_psk_list {
        self as *const OfferedPskListWrapper as *const s2n_offered_psk_list
    }

    fn as_mut_ptr(&mut self) -> *mut s2n_offered_psk_list {
        self as *mut OfferedPskListWrapper as *mut s2n_offered_psk_list
    }
}

// This does not implement the standard iterator trait, because the standard iterator
// trait requires that all objects returned from the iterator must be alive at the
pub struct OfferedPskList<'callback> {
    pub(crate) psk: Box<OfferedPsk>,
    pub(crate) list: &'callback mut OfferedPskListWrapper,
}

impl<'callback> OfferedPskList<'callback> {
    pub fn next<'item>(&'item mut self) -> Option<&'item OfferedPsk> {
        if !self.list.has_next() {
            return None;
        } else {
            let psk_ptr = self.psk.as_mut() as *mut OfferedPsk as *mut s2n_offered_psk;
            unsafe {
                s2n_offered_psk_list_next(self.list.as_mut_ptr(), psk_ptr)
                    .into_result()
                    .unwrap();
            }
            Some(&self.psk)
        }
    }

    pub fn choose_current_psk(self) -> Result<(), crate::error::Error> {
        self.list.choose_psk(&self.psk)
    }
}

pub struct OfferedPsk(s2n_offered_psk);

impl OfferedPsk {
    pub fn identity(&self) -> Result<&[u8], crate::error::Error> {
        let mut identity_buffer: *mut u8 = std::ptr::null::<u8>() as *mut u8;
        let mut size = 0;
        unsafe {
            s2n_offered_psk_get_identity(self.as_ptr(), addr_of_mut!(identity_buffer), &mut size)
                .into_result()?
        };
        Ok(unsafe { slice::from_raw_parts(identity_buffer, size as usize) })
    }

    fn as_ptr(&self) -> *const s2n_offered_psk {
        self as *const OfferedPsk as *const s2n_offered_psk
    }
}

impl Drop for OfferedPsk {
    fn drop(&mut self) {
        let mut offered_psk: *mut s2n_offered_psk = &mut self.0;
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe { s2n_offered_psk_free(std::ptr::addr_of_mut!(offered_psk)).into_result() };
    }
}

pub trait PskSelectionCallback: 'static + Send + Sync {
    fn choose_psk(&self, conn: &mut Connection, psk_list: OfferedPskList);
}
