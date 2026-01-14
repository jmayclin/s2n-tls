use std::sync::{
    atomic::{AtomicPtr, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
};

// consider a platform service, offering resources A, B, and C
// option 1: platform visibility -> aggregated across A, B, C
// option 2: platform visibility -> aggregated across A, B, C, but with per customer information in CloudWatch Logs.

mod cloudwatchlogs_exporter;
mod record;
mod static_lists;
mod emf_emitter;

use arc_swap::ArcSwap;
use brass_aphid_wire_messages::{
    codec::DecodeValue,
    protocol::{extensions::ClientHelloExtensionData, ClientHello},
};
use s2n_tls::events::EventSubscriber;

use crate::{
    record::{FrozenS2NMetricRecord, S2NMetricRecord},
    static_lists::TlsParam,
};

#[derive(Debug)]
struct ExportPipeline<E> {
    metric_receiver: Receiver<FrozenS2NMetricRecord>,
    exporter: E,
}

/// The AggregatedMetricSubscriber can be used to aggregate events over some period
/// of time, and then export them using some [`Exporter`].
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
pub struct AggregatedMetricsSubscriber<E: Send + Sync> {
    current_record: Arc<ArcSwap<S2NMetricRecord>>,
    /// This handle is not directly used, but is used when constructing new S2NMetricRecord
    /// items
    tx_handle: Arc<Sender<FrozenS2NMetricRecord>>,

    export_pipeline: Arc<Mutex<ExportPipeline<E>>>,
}

impl<E: Exporter + Send + Sync> AggregatedMetricsSubscriber<E> {
    pub fn new(exporter: E) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        let record = S2NMetricRecord::new(tx.clone());

        let export_pipe = ExportPipeline {
            metric_receiver: rx,
            exporter,
        };
        Self {
            current_record: Arc::new(ArcSwap::new(Arc::new(record))),
            tx_handle: Arc::new(tx),
            export_pipeline: Arc::new(Mutex::new(export_pipe)),
        }
    }

    /// Finish aggregation of the record and export it.
    /// 
    /// Note that this method will block until all other in-flight updates of the
    /// metric record are complete. This is generally very fast because updates
    /// only consist of atomic integer updates, but latency-sensitive applications
    /// should avoid calling this method in a tokio runtime, and using `spawn_blocking`
    /// instead.
    pub fn export(&self) {
        let mut export_lock = self.export_pipeline.lock().unwrap();

        let new_record = Arc::new(S2NMetricRecord::new(
            self.tx_handle.as_ref().clone(),
        ));

        let old_record = self.current_record.swap(new_record);
        // On drop, the record will be "frozen" and written to the channel
        // This might not happen immediately because other threads might also hold
        // a reference to the metric record
        drop(old_record);

        // This will block the thread until the record is received.
        let record = export_lock.metric_receiver.recv().unwrap();
        export_lock.exporter.export(record);
    }
}

impl<E: Send + Sync + 'static> EventSubscriber for AggregatedMetricsSubscriber<E> {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        // s2n-tls does not have convenient methods to extract the supported parameter,
        // so we just directly extract them from the client hello
        let client_hello = {
            let client_hello_bytes = connection.client_hello().unwrap().raw_message().unwrap();
            let buffer = &client_hello_bytes;
            ClientHello::decode_from_exact(buffer).unwrap()
        };

        let supported_ciphers = client_hello.offered_ciphers.list();
        let supported_groups = client_hello
            .extensions
            .as_ref()
            .map(|list| {
                list.list().iter().find_map(|ext| {
                    if let ClientHelloExtensionData::SupportedGroups(groups) = &ext.extension_data {
                        Some(groups.named_curve_list.list())
                    } else {
                        None
                    }
                })
            })
            .flatten();

        let current_record = self.current_record.load_full();

        supported_ciphers
            .iter()
            .filter_map(|c| TlsParam::Cipher.iana_name_to_metric_index(c.description))
            .for_each(|index| {
                current_record.supported_ciphers[index].fetch_add(1, Ordering::SeqCst);
            });
        if let Some(groups) = supported_groups {
            groups
                .iter()
                .filter_map(|group| TlsParam::Group.iana_name_to_metric_index(group.description))
                .for_each(|index| {
                    current_record.supported_groups[index].fetch_add(1, Ordering::SeqCst);
                });
        }
        current_record.update(event);

        tracing::debug!("handshake event invoked : {event:?}");
    }
}

pub trait Exporter {
    /// export a record to some sink.
    ///
    /// Most metrics API will have some synchronous call where drop appends it to
    /// some queue which is written in the background.
    ///
    /// E.g. this might call CloudWatch
    fn export(&self, metric_record: FrozenS2NMetricRecord);
}

impl Exporter for mpsc::Sender<FrozenS2NMetricRecord> {
    fn export(&self, metric_record: FrozenS2NMetricRecord) {
        self.send(metric_record).unwrap()
    }
}

struct CloudWatchPutMetricDataExporter {}

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
        subscriber_handle.export();
        let event = rx.recv().unwrap();
        println!("{event:?}");
    }

    /// do some handshake to get some events emitted.
    ///
    /// This function does _not_ call export
    fn fake_mixed_traffic(server_config: &s2n_tls::config::Config) {
        let policy = Policy::from_version("20190214").unwrap();
        for policy in [&DEFAULT_TLS13, &DEFAULT, &policy] {
            let client_config = build_config(policy).unwrap();
            let mut pair = TestPair::from_configs(&client_config, &server_config);
            pair.handshake().unwrap();
        }
    }

    /// do some handshake to get some events emitted.
    ///
    /// This function does _not_ call export
    fn fake_tls13_traffic(server_config: &s2n_tls::config::Config) {
        for policy in [&DEFAULT_TLS13, &DEFAULT] {
            let client_config = build_config(policy).unwrap();
            let mut pair = TestPair::from_configs(&client_config, &server_config);
            pair.handshake().unwrap();
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
        let (tx, rx) = mpsc::channel();
        let subscriber = AggregatedMetricsSubscriber::new(tx);
        let subscriber_handle = subscriber.clone();
        let mut cloudwatch_exporter = CloudWatchExporter::initialize(rx).await;

        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber).unwrap();
            config.build().unwrap()
        };

        // TLS 1.2 & TLS 1.3
        {
            cloudwatch_exporter.resource = Some("kitten_service".to_owned());
            fake_mixed_traffic(&server_config);

            // this sends it to the cloudwatch exporter
            subscriber_handle.export();
            let text = cloudwatch_exporter.to_text();
            std::fs::write("emf.json", text.unwrap()).unwrap();
        }

        {
            cloudwatch_exporter.resource = Some("puppy_service".to_owned());
            fake_mixed_traffic(&server_config);

            // this sends it to the cloudwatch exporter
            subscriber_handle.export();
            let sent = cloudwatch_exporter.try_write().await;
            assert!(sent);
        }

        {
            cloudwatch_exporter.resource = Some("cub_service".to_owned());
            fake_tls13_traffic(&server_config);

            // this sends it to the cloudwatch exporter
            subscriber_handle.export();
            let sent = cloudwatch_exporter.try_write().await;
            assert!(sent);
        }
    }
}
