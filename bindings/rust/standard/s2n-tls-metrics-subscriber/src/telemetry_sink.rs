// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::record::MetricRecord;
use std::sync::Arc;

/// Trait abstracting the write destination for metric records.
///
/// Implementations receive a [`MetricRecord`] (which implements `Serialize` and
/// `metrique_writer::Entry`) and decide how to serialize and deliver it — for
/// example as JSON to stdout, CBOR to S3, etc.
pub trait TelemetrySink: Send + Sync + 'static {
    /// Write a single metric record.
    fn write_record(&self, record: &MetricRecord) -> std::io::Result<()>;
}

/// Blanket impl so that an `Arc<T>` can be used wherever a `TelemetrySink` is
/// expected. This is necessary because the subscriber stores the sink inside an
/// `Arc` and needs to call `write_record` through it.
impl<T: TelemetrySink> TelemetrySink for Arc<T> {
    fn write_record(&self, record: &MetricRecord) -> std::io::Result<()> {
        (**self).write_record(record)
    }
}
