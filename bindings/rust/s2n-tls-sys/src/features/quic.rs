/* automatically generated by rust-bindgen 0.65.1 */


// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0


#![allow(unused_imports, non_camel_case_types)]

use libc::{iovec, FILE, off_t};

use crate::api::*;


extern "C" {
    pub fn s2n_config_enable_quic(config: *mut s2n_config) -> ::libc::c_int;
}
extern "C" {
    pub fn s2n_connection_enable_quic(conn: *mut s2n_connection) -> ::libc::c_int;
}
extern "C" {
    pub fn s2n_connection_is_quic_enabled(conn: *mut s2n_connection) -> bool;
}
extern "C" {
    pub fn s2n_connection_are_session_tickets_enabled(conn: *mut s2n_connection) -> bool;
}
extern "C" {
    pub fn s2n_connection_set_quic_transport_parameters(
        conn: *mut s2n_connection,
        data_buffer: *const u8,
        data_len: u16,
    ) -> ::libc::c_int;
}
extern "C" {
    pub fn s2n_connection_get_quic_transport_parameters(
        conn: *mut s2n_connection,
        data_buffer: *mut *const u8,
        data_len: *mut u16,
    ) -> ::libc::c_int;
}
pub mod s2n_secret_type_t {
    pub type Type = ::libc::c_uint;
    pub const CLIENT_EARLY_TRAFFIC_SECRET: Type = 0;
    pub const CLIENT_HANDSHAKE_TRAFFIC_SECRET: Type = 1;
    pub const SERVER_HANDSHAKE_TRAFFIC_SECRET: Type = 2;
    pub const CLIENT_APPLICATION_TRAFFIC_SECRET: Type = 3;
    pub const SERVER_APPLICATION_TRAFFIC_SECRET: Type = 4;
    pub const EXPORTER_SECRET: Type = 5;
}
pub type s2n_secret_cb = ::core::option::Option<
    unsafe extern "C" fn(
        context: *mut ::libc::c_void,
        conn: *mut s2n_connection,
        secret_type: s2n_secret_type_t::Type,
        secret: *mut u8,
        secret_size: u8,
    ) -> ::libc::c_int,
>;
extern "C" {
    pub fn s2n_connection_set_secret_callback(
        conn: *mut s2n_connection,
        cb_func: s2n_secret_cb,
        ctx: *mut ::libc::c_void,
    ) -> ::libc::c_int;
}
extern "C" {
    pub fn s2n_error_get_alert(error: ::libc::c_int, alert: *mut u8) -> ::libc::c_int;
}
extern "C" {
    pub fn s2n_recv_quic_post_handshake_message(
        conn: *mut s2n_connection,
        blocked: *mut s2n_blocked_status::Type,
    ) -> ::libc::c_int;
}
