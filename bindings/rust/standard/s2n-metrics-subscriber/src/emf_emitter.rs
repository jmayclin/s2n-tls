// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::ErrorKind,
    sync::mpsc::{self, TryRecvError},
};

use metrique::writer::Entry;
use metrique_writer_format_emf::Emf;

use metrique_writer::{format::Format, FormatExt, IoStreamError};

use crate::record::MetricRecord;

/// The BufferedEmfEmitter is used to decouple aggregation logic and the actual
/// writing of records to an IO sink.
///
/// This might be useful for architectures where metric aggregation (report every
/// 5 minutes) is separate from the actual writing of the IO.
pub struct EmfEmitter {
    record_receiver: std::sync::mpsc::Receiver<MetricRecord>,
    resource: Option<String>,
    emf_formatter: metrique_writer::stream::MergeGlobals<Emf, EmfDimension>,
}

impl EmfEmitter {
    /// This is the namespace that will show up in the CloudWatch Metrics page.
    const NAMESPACE: &str = "tls/s2n-tls";

    /// * `service_name`: The application name, E.g. CuteKittenService. This will
    ///   be emitted under the "service_name" dimension in your metrics.
    /// * `resource`: The particular resource that metrics are being emitted for.
    ///   This will not be emitted as a dimension, but as a regular field in the
    ///   EMF records. E.g. "calico" or "tabby".
    pub fn new(
        service_name: String,
        resource: Option<String>,
    ) -> (Self, mpsc::Sender<MetricRecord>) {
        let (tx, rx) = mpsc::channel();
        let emf = Emf::builder(
            Self::NAMESPACE.to_string(),
            vec![vec![EmfDimension::NAME.to_owned()]],
        )
        .build()
        .merge_globals(EmfDimension { service_name });

        let emitter = EmfEmitter {
            record_receiver: rx,
            resource,
            emf_formatter: emf,
        };
        (emitter, tx)
    }
}

impl EmfEmitter {
    /// write a single record to the specified destination
    ///
    /// If there are no records to write, an error of type [`std::io::ErrorKind::WouldBlock`]
    /// will be returned.
    pub fn write(&mut self, destination: &mut impl std::io::Write) -> std::io::Result<()> {
        /// MetricWithAttribution is a simpler wrapper which can be used to add a
        /// "resource: <VALUE>" field to an EMF record.
        struct MetricWithAttribution<'a, E> {
            entry: &'a E,
            resource: &'a str,
        }
        impl<'b, E: metrique_writer::Entry> metrique_writer::Entry for MetricWithAttribution<'b, E> {
            fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
                self.entry.write(writer);
                writer.value("resource", &self.resource);
            }
        }

        match self.record_receiver.try_recv() {
            Ok(record) => {
                let write_result = if let Some(resource) = &self.resource {
                    let record_with_attribution = MetricWithAttribution {
                        entry: &record,
                        resource,
                    };
                    self.emf_formatter
                        .format(&record_with_attribution, destination)
                } else {
                    self.emf_formatter.format(&record, destination)
                };

                match write_result {
                    Ok(_) => Ok(()),
                    Err(IoStreamError::Validation(v)) => {
                        tracing::error!("failed to write metric: {v}");
                        Err(std::io::Error::new(ErrorKind::InvalidInput, v))
                    }
                    Err(IoStreamError::Io(io)) => Err(io),
                }
            }
            Err(TryRecvError::Disconnected) => Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                TryRecvError::Disconnected,
            )),
            Err(TryRecvError::Empty) => Err(std::io::Error::new(
                ErrorKind::WouldBlock,
                TryRecvError::Empty,
            )),
        }
    }
}

#[derive(Entry)]
struct EmfDimension {
    /// the service name, e.g. `CuteKittenService`
    service_name: String,
}
impl EmfDimension {
    // this must match the field name of EmfDimension, otherwise the EMF record
    // will fail validation.
    const NAME: &str = "service_name";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AggregatedMetricsSubscriber, test_utils::TestEndpointWithEmitter};
    use metrique_writer::FormatExt;
    use metrique_writer_format_emf::EmfBuilder;
    use s2n_tls::{
        security::{DEFAULT, DEFAULT_TLS13},
        testing::{build_config, config_builder, TestPair},
    };
    use std::sync::mpsc;

    /// Sanity check, we get a result
    #[test]
    fn emission() {
        let (mut emitter, tx) = EmfEmitter::new("cute-kitten".to_owned(), None);
        let subscriber = AggregatedMetricsSubscriber::new(tx);
        let subscriber_handle = subscriber.clone();

        // Configure and build the server with our subscriber
        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber).unwrap();
            config.build().unwrap()
        };

        let client_config = build_config(&DEFAULT_TLS13).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();

        subscriber_handle.finish_record();
        let mut record = Vec::new();
        emitter.write(&mut record).unwrap();

        assert!(!record.is_empty());
    }

    /// When no export is available, we get a "would block" error
    #[test]
    fn would_block() {
        // Create a channel with no records sent
        let (mut emitter, tx) = EmfEmitter::new("cute-kitten".to_owned(), None);

        let mut buffer = Vec::new();

        let err = emitter.write(&mut buffer).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn snapshot() {
        let snapshot = include_str!("../resources/emf_sample.json");
        // TODO: don't used defaults
        let mut endpoint = TestEndpointWithEmitter::new("cute-kitten", &DEFAULT_TLS13);
        endpoint.client_handshake(&DEFAULT);
        endpoint.client_handshake(&DEFAULT_TLS13);

        endpoint.subscriber.finish_record();
        let mut buffer = Vec::new();
        endpoint.exporter.write(&mut buffer).unwrap();

        let result = String::from_utf8(buffer).unwrap();
        // uncomment to update snapshot
        // {
        //     let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        //     let pretty = serde_json::to_string_pretty(&json).unwrap();
        //     std::fs::write("resources/emf_sample.json", pretty).unwrap();
        // }

        let mut result_json: serde_json::Value = serde_json::from_str(&result).unwrap();
        let mut snapshot_json: serde_json::Value = serde_json::from_str(snapshot).unwrap();

        // Remove the dynamic fields (timestamp + timers)
        result_json.as_object_mut().unwrap()["_aws"].as_object_mut().unwrap().remove("Timestamp");
        snapshot_json.as_object_mut().unwrap()["_aws"].as_object_mut().unwrap().remove("Timestamp");

        result_json.as_object_mut().unwrap().remove("handshake_compute");
        result_json.as_object_mut().unwrap().remove("handshake_duration");
        snapshot_json.as_object_mut().unwrap().remove("handshake_compute");
        snapshot_json.as_object_mut().unwrap().remove("handshake_duration");
        
        assert_eq!(result_json, snapshot_json);
    }

    #[test]
    fn record_contents() {
        // TODO: don't used defaults
        let mut endpoint = TestEndpointWithEmitter::new("cute-kitten", &DEFAULT_TLS13);
        endpoint.client_handshake(&DEFAULT);
        endpoint.client_handshake(&DEFAULT_TLS13);

        endpoint.subscriber.finish_record();
        let mut buffer = Vec::new();
        endpoint.exporter.write(&mut buffer).unwrap();

        let result = String::from_utf8(buffer).unwrap();

        // contains "resource": "cute-kitten"
    }

    #[test]
    fn buffer() {
        let mut endpoint = TestEndpointWithEmitter::new("cute-kitten", &DEFAULT_TLS13);
        endpoint.client_handshake(&DEFAULT);
        endpoint.client_handshake(&DEFAULT_TLS13);

        endpoint.exporter.write(&mut Vec::new()).unwrap_err();

        endpoint.subscriber.finish_record();

        endpoint.client_handshake(&DEFAULT);
        endpoint.client_handshake(&DEFAULT_TLS13);

        endpoint.subscriber.finish_record();

        endpoint.exporter.write(&mut Vec::new()).unwrap();
        endpoint.exporter.write(&mut Vec::new()).unwrap();
        endpoint.exporter.write(&mut Vec::new()).unwrap_err();
    }
}
