// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
};

use crate::record::{HandshakeRecord, HandshakeRecordInProgress, MetricRecord};
use arc_swap::ArcSwap;
use brass_aphid_wire_messages::codec::DecodeValue;
use s2n_tls::events::EventSubscriber;

#[derive(Debug)]
struct ExportPipeline<E> {
    metric_receiver: Receiver<HandshakeRecord>,
    exporter: E,
}

/// The AggregatedMetricSubscriber can be used to aggregate events over some period
/// of time, and then export them using an [`Exporter`].
///
/// The [`s2n_tls::events::EventSubscriber`] may be invoked concurrently, which
/// means that multiple threads might be incrementing the current record. To handle
/// this and ensure that the `S2NMetricRecord` is never flushed while an update
/// is in progress we use an [`arc_swap::ArcSwap`].
///
/// ArcSwap is basically an `Atomic<Arc<S2NMetricRecord>>`
///
/// We use this as a relatively intuitive form of synchronization. Once there
/// are no references to the S2NMetricRecord (e.g. no threads updating it) then
/// its [`S2NMetricRecord::drop`] will write it to the channel, where it can then
/// be read by the export pipeline.
#[derive(Debug, Clone)]
pub struct AggregatedMetricsSubscriber<E> {
    inner: Arc<MetricSubscriberInner<E>>,
}

#[derive(Debug)]
struct MetricSubscriberInner<E> {
    current_record: ArcSwap<HandshakeRecordInProgress>,
    /// This handle is not directly used, but is used when constructing new S2NMetricRecord
    /// items
    tx_handle: Sender<HandshakeRecord>,

    // the mutex is necessary because s2n-tls callbacks must be Send + Sync
    export_pipeline: Mutex<ExportPipeline<E>>,
}

impl<E: Exporter + Send + Sync> AggregatedMetricsSubscriber<E> {
    pub fn new(exporter: E) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        let record = HandshakeRecordInProgress::new(tx.clone());

        let export_pipe = ExportPipeline {
            metric_receiver: rx,
            exporter,
        };
        let inner = MetricSubscriberInner {
            current_record: ArcSwap::new(Arc::new(record)),
            tx_handle: tx,
            export_pipeline: Mutex::new(export_pipe),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Finish aggregation of the record and export it.
    ///
    /// Note that this method will block until all other in-flight updates of the
    /// metric record are complete. This is generally very fast because updates
    /// only consist of atomic integer updates, but latency-sensitive applications
    /// should avoid calling this method in a tokio runtime, and using `spawn_blocking`
    /// instead.
    pub fn finish_record(&self) {
        let export_pipeline = self.inner.export_pipeline.lock().unwrap();
        let new_record = Arc::new(HandshakeRecordInProgress::new(self.inner.tx_handle.clone()));

        let old_record = self.inner.current_record.swap(new_record);
        // On drop, the record will be "frozen" and written to the channel
        // This might not happen immediately because other threads might also hold
        // a reference to the metric record
        drop(old_record);

        // This will block the thread until the record is received.
        let handshake = export_pipeline.metric_receiver.recv().unwrap();
        export_pipeline
            .exporter
            .export(MetricRecord::new(handshake));
    }
}

impl<E: Send + Sync + 'static> EventSubscriber for AggregatedMetricsSubscriber<E> {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        let current_record = self.inner.current_record.load_full();
        current_record.update(connection, event);
    }
}

pub trait Exporter {
    /// export a record to some sink.
    ///
    /// Most metrics API will have some synchronous call where drop appends it to
    /// some queue which is written in the background.
    ///
    /// E.g. this might call CloudWatch
    fn export(&self, metric_record: MetricRecord);
}

impl Exporter for mpsc::Sender<MetricRecord> {
    fn export(&self, metric_record: MetricRecord) {
        self.send(metric_record).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use s2n_tls::{
        security::{Policy, DEFAULT, DEFAULT_TLS13},
        testing::{build_config, config_builder, TestPair},
    };

    use crate::cloudwatchlogs_exporter::CloudWatchExporter;

    use super::*;

    #[test]
    fn it_works() {
        let (tx, rx) = mpsc::channel();
        let subscriber = AggregatedMetricsSubscriber::new(tx);
        let subscriber_handle = subscriber.clone();

        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber).unwrap();
            config.build().unwrap()
        };
        let client_config = build_config(&DEFAULT_TLS13).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();

        assert!(rx.try_recv().is_err());
        subscriber_handle.finish_record();
        let event = rx.recv().unwrap();
        println!("{event:?}");
    }

    struct TestEndpoint {
        config: s2n_tls::config::Config,
        subscriber: AggregatedMetricsSubscriber<Sender<MetricRecord>>,
        exporter: CloudWatchExporter,
    }

    impl TestEndpoint {
        async fn initialize(resource: &str, policy: &Policy) -> Self {
            let (exporter, tx) =
                CloudWatchExporter::initialize("test_server".to_owned(), Some(resource.to_owned()))
                    .await;
            let subscriber = AggregatedMetricsSubscriber::new(tx);

            let config = {
                let mut config = config_builder(policy).unwrap();
                config.set_event_subscriber(subscriber.clone()).unwrap();
                config.build().unwrap()
            };

            Self {
                config,
                subscriber,
                exporter,
            }
        }

        fn client_handshake(&self, client_policy: &Policy) {
            let client_config = build_config(client_policy).unwrap();
            let mut pair = TestPair::from_configs(&client_config, &self.config);
            pair.handshake();
        }
    }

    /// Emit EMF records to obtain
    /// 1. aggregate platform metrics
    /// 2. with optional resource-level information available through cloudwatch
    ///    insights.
    ///
    /// This results in a single e.g. TLS_AES_128_GCM_SHA256 counter for aggregate
    /// platform traffic, but per-resource breakdowns can still be accomplished
    /// through a cloudwatch insights query
    ///
    /// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format.html
    ///
    /// LogGroup: GatewayServicesLogs
    /// LogStream: GatewayService<INSTANCE_ID>
    ///
    /// CloudWatch Namespace: tls/s2n-tls
    /// CloudWatch Dimensions: "application" -> "test_server"
    ///
    #[tokio::test]
    async fn platform_metrics_with_per_resource_visibility() {
        // tracing_subscriber::fmt()
        //     .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
        //     .with_writer(std::io::stderr)
        //     .with_ansi(false)
        //     .init();

        let rsa_kx_policy = Policy::from_version("20150214").unwrap();
        let tls12_ecdhe_policy = Policy::from_version("20190214").unwrap();

        let mut kitten = TestEndpoint::initialize("kitten", &rsa_kx_policy).await;
        let mut puppy = TestEndpoint::initialize("puppy", &DEFAULT).await;
        let mut cub = TestEndpoint::initialize("cub", &DEFAULT_TLS13).await;

        {
            puppy.client_handshake(&DEFAULT);
            puppy.client_handshake(&DEFAULT_TLS13);
            puppy.client_handshake(&tls12_ecdhe_policy);

            puppy.subscriber.finish_record();
            let sent = puppy.exporter.try_write().await;
            assert!(sent);
        }

        {
            kitten.client_handshake(&rsa_kx_policy);
            kitten.client_handshake(&DEFAULT);
            kitten.client_handshake(&DEFAULT_TLS13);

            kitten.subscriber.finish_record();
            let sent = kitten.exporter.try_write().await;
            assert!(sent);
        }

        {
            cub.client_handshake(&tls12_ecdhe_policy);
            cub.client_handshake(&tls12_ecdhe_policy);
            cub.client_handshake(&DEFAULT);

            cub.subscriber.finish_record();
            let sent = cub.exporter.try_write().await;
            assert!(sent);
        }
    }
}
