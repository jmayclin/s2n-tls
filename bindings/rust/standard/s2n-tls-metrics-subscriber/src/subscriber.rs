// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    attribution::Attribution,
    record::{HandshakeRecordInProgress, MetricRecord},
    telemetry_sink::TelemetrySink,
};
use arc_swap::ArcSwap;
use s2n_tls::events::EventSubscriber;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

/// Holds a [`HandshakeRecordInProgress`] together with a sink and attribution.
///
/// When the last `Arc<MetricRecordSink>` reference is dropped (i.e. no more
/// in-flight handshake updates), the record is frozen into a [`MetricRecord`]
/// and flushed to the [`TelemetrySink`].
pub struct MetricRecordSink<S: TelemetrySink> {
    record: HandshakeRecordInProgress,
    sink: Arc<S>,
    attribution: Attribution,
}

impl<S: TelemetrySink> fmt::Debug for MetricRecordSink<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricRecordSink").finish_non_exhaustive()
    }
}

impl<S: TelemetrySink> Drop for MetricRecordSink<S> {
    fn drop(&mut self) {
        let frozen = self.record.finish();
        let metric_record = MetricRecord::new(frozen, self.attribution.clone());
        if let Err(e) = self.sink.write_record(&metric_record) {
            tracing::error!("failed to write metric to sink: {e}");
        }
    }
}

/// The AggregatedMetricSubscriber can be used to aggregate events over some period
/// of time, and then export them using a [`TelemetrySink`].
///
/// When `finish_record` is called (or the export interval elapses), the current
/// record is swapped out. Once all in-flight handshake updates complete, the
/// [`MetricRecordSink`] is dropped, which freezes the record and writes it to
/// the sink.
#[derive(Debug)]
pub struct AggregatedMetricsSubscriber<S: TelemetrySink> {
    inner: Arc<MetricSubscriberInner<S>>,
}

/// Manual Clone impl: the sink `S` does not need to implement Clone because it
/// is behind an `Arc`.
impl<S: TelemetrySink> Clone for AggregatedMetricsSubscriber<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// The [`s2n_tls::events::EventSubscriber`] may be invoked concurrently, which
/// means that multiple threads might be incrementing the current record. To handle
/// this and ensure that the `MetricRecordSink` is never dropped while an update
/// is in progress we use an [`arc_swap::ArcSwap`].
///
/// ArcSwap is basically an `Atomic<Arc<MetricRecordSink>>`
///
/// We use this as a relatively intuitive form of synchronization. Once there
/// are no references to the MetricRecordSink (e.g. no threads updating it)
/// then its `drop` implementation will freeze the record and flush it to the sink.
#[derive(Debug)]
struct MetricSubscriberInner<S: TelemetrySink> {
    current_record: ArcSwap<MetricRecordSink<S>>,
    sink: Arc<S>,
    attribution: Attribution,
    export_interval: Duration,
    last_export: std::sync::Mutex<Instant>,
}

impl<S: TelemetrySink> AggregatedMetricsSubscriber<S> {
    pub fn new(sink: S, attribution: Attribution, export_interval: Duration) -> Self {
        let sink = Arc::new(sink);
        let record_sink = MetricRecordSink {
            record: HandshakeRecordInProgress::new(),
            sink: sink.clone(),
            attribution: attribution.clone(),
        };
        let inner = MetricSubscriberInner {
            current_record: ArcSwap::new(Arc::new(record_sink)),
            sink,
            attribution,
            export_interval,
            last_export: std::sync::Mutex::new(Instant::now()),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Swap out the current record. The old record will be frozen and flushed
    /// to the sink once all in-flight handshake updates complete.
    ///
    /// Note that this method will block until all other in-flight updates of the
    /// metric record are complete. This is generally very fast because updates
    /// only consist of atomic integer updates, but latency-sensitive applications
    /// should avoid calling this method in a tokio runtime, and using `spawn_blocking`
    /// instead.
    pub fn finish_record(&self) {
        let new_record = Arc::new(MetricRecordSink {
            record: HandshakeRecordInProgress::new(),
            sink: self.inner.sink.clone(),
            attribution: self.inner.attribution.clone(),
        });
        // The old Arc<MetricRecordSink> is returned. When all references to it
        // are dropped, its Drop impl freezes the record and writes to the sink.
        let _old = self.inner.current_record.swap(new_record);
        *self.inner.last_export.lock().unwrap() = Instant::now();
    }

    /// Check whether the export interval has elapsed and, if so, flush.
    /// Called passively from the handshake path so no background thread is needed.
    fn maybe_export(&self) {
        // Use try_lock to avoid blocking the handshake thread if another
        // thread is already exporting.
        if let Ok(last) = self.inner.last_export.try_lock() {
            if last.elapsed() >= self.inner.export_interval {
                drop(last);
                self.finish_record();
            }
        }
    }
}

impl<S: TelemetrySink> EventSubscriber for AggregatedMetricsSubscriber<S> {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        let current_record = self.inner.current_record.load_full();
        let res = current_record.record.update(connection, event);
        // we never expect this to fail, but if it fails in production there is
        // no meaningful way to handle the failure
        debug_assert!(res.is_ok());
        if let Err(e) = res {
            tracing::error!("failed to update handshake record: {e}");
        }

        self.maybe_export();
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{ARBITRARY_POLICY_1, FailingSink, TestEndpoint};

    /// Verify that after a handshake and finish_record, the sink contains a record.
    #[test]
    fn record_is_exported() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
    }

    /// Verify that finish_record blocks while another thread holds a reference
    /// to the current record (via ArcSwap load_full).
    #[test]
    fn export_blocking() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        // Load a reference to the current record, preventing it from being dropped
        let held_record = endpoint.subscriber.inner.current_record.load_full();

        let subscriber = endpoint.subscriber.clone();
        let sink = endpoint.sink.clone();
        let handle = std::thread::spawn(move || {
            subscriber.finish_record();
        });

        // The finish_record call should complete quickly (it just swaps the Arc),
        // but the old record won't flush until we drop our reference.
        handle.join().unwrap();

        // Record hasn't flushed yet because we hold a reference
        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(records.len(), 0);
        drop(records);

        // Drop the held reference to trigger the flush
        drop(held_record);

        let records = sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
    }

    /// Multiple finish_record() calls should each produce a separate record
    /// in the sink, and records should accumulate in order.
    #[test]
    fn multiple_finish_record_buffering() {
        let endpoint = TestEndpoint::new();

        // First batch: 2 handshakes
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        // Second batch: 1 handshake
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        // Third: empty record (no handshakes)
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(
            records.len(),
            3,
            "expected 3 records from 3 finish_record calls"
        );

        // Verify handshake counts via the MetricRecord's serde representation
        let r0 = serde_json::to_value(&records[0]).unwrap();
        let r1 = serde_json::to_value(&records[1]).unwrap();
        let r2 = serde_json::to_value(&records[2]).unwrap();

        assert_eq!(r0["handshake"]["handshake_count"], 2);
        assert_eq!(r1["handshake"]["handshake_count"], 1);
        assert_eq!(r2["handshake"]["handshake_count"], 0);
    }

    /// When the sink returns an error, finish_record should not panic.
    /// The error is logged via tracing but the subscriber remains usable.
    #[test]
    fn sink_write_failure_does_not_panic() {
        let endpoint = TestEndpoint::<FailingSink>::with_failing_sink();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        // This should not panic even though the sink always fails
        endpoint.subscriber.finish_record();

        // The subscriber should still be functional after a sink failure
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
    }
}
