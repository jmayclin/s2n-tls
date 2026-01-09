use std::sync::{
    atomic::{AtomicPtr, Ordering},
    mpsc::{self},
    Arc, Mutex,
};

// consider a platform service, offering resources A, B, and C
// option 1: platform visibility -> aggregated across A, B, C
// option 2: platform visibility -> aggregated across A, B, C, but with per customer information in CloudWatch Logs.

mod cloudwatchlogs_exporter;
mod record;
mod static_lists;

use brass_aphid_wire_messages::{
    codec::DecodeValue,
    protocol::{extensions::ClientHelloExtensionData, ClientHello},
};
use s2n_tls::events::EventSubscriber;

use crate::{
    record::{FrozenS2NMetricRecord, S2NMetricRecord},
    static_lists::TlsParam,
};

#[derive(Debug, Clone)]
pub struct AggregatedMetricsSubscriber<E: Send + Sync> {
    current_record: Arc<AtomicPtr<S2NMetricRecord>>,
    exporter: Arc<Mutex<E>>,
}

impl<E: Exporter + Send + Sync> AggregatedMetricsSubscriber<E> {
    const CHANNEL_CAPACITY: usize = 1024;

    fn new(exporter: E) -> Self {
        let heap_allocated_record = {
            let record = S2NMetricRecord::default();
            let record = Box::new(record);
            Box::into_raw(record)
        };

        Self {
            current_record: Arc::new(AtomicPtr::new(heap_allocated_record)),
            exporter: Arc::new(Mutex::new(exporter)),
        }
    }

    /// export the record to the channel, and reset all counters to zero.
    ///
    /// Todo -> it feels like this should return an optional future to be polled
    pub fn export(&self) {
        let mut export_lock = self.exporter.lock().unwrap();

        let heap_allocated_record = {
            let record = S2NMetricRecord::default();
            let record = Box::new(record);
            Box::into_raw(record)
        };
        let populated_record = self
            .current_record
            .swap(heap_allocated_record, Ordering::SeqCst);

        let populated_record = unsafe {
            // SAFETY: all records are created from Box::into_raw.
            Box::from_raw(populated_record)
        };

        let record = populated_record.freeze();
        export_lock.export(record)
    }
}

impl<E: Send + Sync + 'static> EventSubscriber for AggregatedMetricsSubscriber<E> {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        // s2n-tls does not have convenient methods to extra the supported parameter,
        // so we just directly extra them from the client hello
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

        let current_record = {
            let mut record_ptr;
            loop {
                record_ptr = self.current_record.load(Ordering::Relaxed);
                if let Ok(_) = (unsafe { &*record_ptr }).updates_in_flight.start_update() {
                    break;
                }
                // else err -> the flush has started, we should fetch the "fresh" record
                // which is not held in the pointer
            }
            unsafe { &*record_ptr }
        };

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
        current_record.updates_in_flight.finish_update();

        tracing::debug!("handshake event invoked : {event:?}");
    }
}

trait Exporter {
    /// export a record to some sink.
    ///
    /// Most metrics API will have some synchronous call where drop appends it to
    /// some queue which is written in the background.
    ///
    /// E.g. this might call CloudWatch
    fn export(&mut self, metric_record: FrozenS2NMetricRecord);
}

impl Exporter for mpsc::Sender<FrozenS2NMetricRecord> {
    fn export(&mut self, metric_record: FrozenS2NMetricRecord) {
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
