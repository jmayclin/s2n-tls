// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    callbacks::VerifyHostNameCallback, config::*, connection, enums::Blinding, security,
};
use alloc::{collections::VecDeque, sync::Arc};
use bytes::Bytes;
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
};

// The utilities module is not pub, and contains no tests
// This ensures that any testing structs live clearly under the `testing::UtilityStruct`
// path
mod utilities;

pub use utilities::*;

pub mod client_hello;
pub mod resumption;
pub mod s2n_tls;
