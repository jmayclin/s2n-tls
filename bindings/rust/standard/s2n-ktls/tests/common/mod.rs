// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for generating real s2n-tls serialized connection blobs.
//!
//! These live in a `common` module included by the integration tests. s2n-tls
//! is a dev-dependency only; nothing here is part of the public crate.

#![allow(dead_code)]

use std::os::fd::RawFd;

use s2n_tls::{
    enums::SerializationVersion,
    security::Policy,
    testing::{config_builder, TestPair},
};

/// A completed handshake plus both peers' serialized connection blobs.
pub struct SerializedPair {
    pub pair: TestPair,
    pub client_blob: Vec<u8>,
    pub server_blob: Vec<u8>,
    /// Negotiated protocol version, captured before serialization (which wipes
    /// the connection's crypto state).
    pub negotiated_version: s2n_tls::enums::Version,
    /// Negotiated cipher suite name, captured before serialization.
    pub cipher_name: String,
}

/// Complete a handshake using `policy_name` for both peers and serialize both
/// connections into V1 blobs.
pub fn serialized_pair(policy_name: &str) -> SerializedPair {
    let policy = Policy::from_version(policy_name).unwrap();

    let mut builder = config_builder(&policy).unwrap();
    builder
        .set_serialization_version(SerializationVersion::V1)
        .unwrap();
    let config = builder.build().unwrap();

    let mut pair = TestPair::from_config(&config);
    pair.handshake().unwrap();

    // Capture negotiated parameters before serializing, since
    // s2n_connection_serialize wipes the crypto state afterward.
    let negotiated_version = pair.server.actual_protocol_version().unwrap();
    let cipher_name = pair.server.cipher_suite().unwrap().to_string();

    let client_blob = serialize(&pair.client);
    let server_blob = serialize(&pair.server);

    SerializedPair {
        pair,
        client_blob,
        server_blob,
        negotiated_version,
        cipher_name,
    }
}

fn serialize(conn: &s2n_tls::connection::Connection) -> Vec<u8> {
    let len = conn.serialization_length().unwrap();
    let mut blob = vec![0u8; len];
    conn.serialize(&mut blob).unwrap();
    blob
}

/// Build a config for the given policy with V1 serialization enabled. Suitable
/// for driving a real-socket handshake.
pub fn serializable_config(policy_name: &str) -> s2n_tls::config::Config {
    let policy = Policy::from_version(policy_name).unwrap();
    let mut builder = config_builder(&policy).unwrap();
    builder
        .set_serialization_version(SerializationVersion::V1)
        .unwrap();
    builder.build().unwrap()
}

/// Build a config for the given policy without serialization (a normal peer).
pub fn plain_config(policy_name: &str) -> s2n_tls::config::Config {
    let policy = Policy::from_version(policy_name).unwrap();
    config_builder(&policy).unwrap().build().unwrap()
}

/// A blocking `recv` callback that reads from a raw fd. Used to drive an
/// s2n-tls connection over a real socket in tests.
///
/// # Safety
/// `ctx` must be a valid pointer to a `RawFd` that outlives the connection.
pub unsafe extern "C" fn recv_cb(ctx: *mut libc::c_void, data: *mut u8, len: u32) -> libc::c_int {
    let fd = *(ctx as *const RawFd);
    let ret = libc::read(fd, data as *mut libc::c_void, len as usize);
    ret as libc::c_int
}

/// A blocking `send` callback that writes to a raw fd.
///
/// # Safety
/// `ctx` must be a valid pointer to a `RawFd` that outlives the connection.
pub unsafe extern "C" fn send_cb(ctx: *mut libc::c_void, data: *const u8, len: u32) -> libc::c_int {
    let fd = *(ctx as *const RawFd);
    let ret = libc::write(fd, data as *const libc::c_void, len as usize);
    ret as libc::c_int
}
