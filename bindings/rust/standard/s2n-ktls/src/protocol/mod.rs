// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure, I/O-free protocol logic for kTLS.
//!
//! This module contains everything needed to turn an s2n-tls serialized
//! connection blob into the kernel `crypto_info` structures, without touching
//! any sockets or performing any system calls:
//!
//! - [`serialization`]: parse and re-emit the s2n-tls "V1" serialized
//!   connection format.
//! - [`key_schedule`]: re-derive record keys and IVs from the serialized
//!   secrets.
//! - [`crypto_info`]: build the kernel `tls12_crypto_info_aes_gcm_*` byte
//!   layouts consumed by `setsockopt(SOL_TLS, ...)`.

pub mod crypto_info;
pub mod key_schedule;
pub mod serialization;
