// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// consider a platform service, offering resources A, B, and C
// option 1: platform visibility -> aggregated across A, B, C
// option 2: platform visibility -> aggregated across A, B, C, but with per customer information in CloudWatch Logs.

mod cloudwatchlogs_exporter;
mod emf_emitter;
mod record;
mod static_lists;
mod subscriber;
#[cfg(test)]
mod test_utils;

pub use crate::record::MetricRecord;
pub use subscriber::AggregatedMetricsSubscriber;
pub use emf_emitter::EmfEmitter;