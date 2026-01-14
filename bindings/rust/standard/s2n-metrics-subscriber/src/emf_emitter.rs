use std::{
    io::ErrorKind,
    sync::mpsc::{self, TryRecvError},
};

use metrique::writer::Entry;
use metrique_writer_format_emf::Emf;

use crate::record::FrozenS2NMetricRecord;

use metrique_writer::{format::Format, FormatExt, IoStreamError};

/// The BufferedEmfEmitter is used to decouple aggregation logic and the actual
/// writing of records to an IO sink.
///
/// This might be useful for architectures where metric aggregation (report every
/// 5 minutes) is separate from the actual writing of the IO.
pub(crate) struct BufferedEmfEmitter {
    record_receiver: std::sync::mpsc::Receiver<FrozenS2NMetricRecord>,
    emf_formatter: metrique_writer::stream::MergeGlobals<Emf, EmfDimension>,
}

impl BufferedEmfEmitter {
    pub fn new(metric_config: EmfDimension) -> (Self, mpsc::Sender<FrozenS2NMetricRecord>) {
        let (tx, rx) = mpsc::channel();
        let emf = Emf::builder(
            "tls/s2n-tls".to_string(),
            vec![vec![
                "service_name".to_owned(),
                "marketplace".to_owned(),
                "stage".to_owned(),
            ]],
        )
        .build()
        .merge_globals(EmfDimension {
            service_name: "cute-kitten".to_owned(),
            marketplace: "us-east-1".to_owned(),
            stage: "local-dev".to_owned(),
        });

        let emitter = BufferedEmfEmitter {
            record_receiver: rx,
            emf_formatter: emf,
        };
        (emitter, tx)
    }
}
// F: metrique_writer::format::Format
impl BufferedEmfEmitter {
    /// write a single record to the specified destination
    fn write(&mut self, destination: &mut impl std::io::Write) -> std::io::Result<()> {
        match self.record_receiver.try_recv() {
            Ok(record) => match self.emf_formatter.format(&record, destination) {
                Ok(_) => Ok(()),
                Err(IoStreamError::Validation(v)) => {
                    tracing::error!("failed to write metric: {v}");
                    Err(std::io::Error::new(ErrorKind::InvalidInput, v))
                }
                Err(IoStreamError::Io(io)) => Err(io),
            },
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
    /// where the application is running, e.g. `us-east-1`
    marketplace: String,
    /// e.g. "alpha", "beta", "prod"
    stage: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AggregatedMetricsSubscriber;
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
        let (mut emitter, tx) = BufferedEmfEmitter::new(EmfDimension {
            service_name: "cute-kitten".to_owned(),
            marketplace: "us-east-1".to_owned(),
            stage: "local-dev".to_owned(),
        });
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

        subscriber_handle.export();
        let mut record = Vec::new();
        emitter.write(&mut record).unwrap();

        assert!(!record.is_empty());
    }

    /// When no export is available, we get a "would block" error
    #[test]
    fn would_block() {
        // Create a channel with no records sent
        let (mut emitter, tx) = BufferedEmfEmitter::new(EmfDimension {
            service_name: "cute-kitten".to_owned(),
            marketplace: "us-east-1".to_owned(),
            stage: "local-dev".to_owned(),
        });

        let mut buffer = Vec::new();

        let err = emitter.write(&mut buffer).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    // /// We assert that the EMF record matches the expected format
    // #[test]
    // fn snapshot() {
    //     // Create a channel and subscriber
    //     let (tx, rx) = mpsc::channel();
    //     let subscriber = AggregatedMetricsSubscriber::new(tx);
    //     let subscriber_handle = subscriber.clone();

    //     // Configure and build the server with our subscriber
    //     let server_config = {
    //         let mut config = config_builder(&DEFAULT_TLS13).unwrap();
    //         config.set_event_subscriber(subscriber).unwrap();
    //         config.build().unwrap()
    //     };

    //     // Build the client config and perform a handshake
    //     let client_config = build_config(&DEFAULT_TLS13).unwrap();
    //     let mut pair = TestPair::from_configs(&client_config, &server_config);
    //     pair.handshake().unwrap();

    //     // Export the metrics
    //     subscriber_handle.export();

    //     // Create our emitter to capture the formatted output
    //     let mut emitter = BufferedEmfEmitter {
    //         record_receiver: rx,
    //         emf_formatter: Emf::builder("tls/s2n-tls".to_string(), vec![vec![]]).build(),
    //     };

    //     let mut buffer = Vec::new();
    //     let result = emitter.write(&mut buffer);
    //     assert!(result.is_ok(), "Writing EMF data should succeed");

    //     // Convert buffer to string for easier examination
    //     let emf_json = String::from_utf8_lossy(&buffer);

    //     // Verify basic EMF structure (this is a simple check - you can expand this)
    //     assert!(
    //         emf_json.contains("\"_aws\""),
    //         "EMF JSON should contain _aws field"
    //     );
    //     assert!(
    //         emf_json.contains("\"CloudWatchMetrics\""),
    //         "EMF should contain CloudWatchMetrics"
    //     );
    //     assert!(
    //         emf_json.contains("\"tls/s2n-tls\""),
    //         "EMF should contain namespace"
    //     );

    //     // Verify some of the metric fields we expect
    //     assert!(
    //         emf_json.contains("\"sample_count\""),
    //         "EMF should contain sample_count metric"
    //     );
    //     assert!(
    //         emf_json.contains("\"handshake_duration\""),
    //         "EMF should contain handshake_duration metric"
    //     );
    //     assert!(
    //         emf_json.contains("\"handshake_compute\""),
    //         "EMF should contain handshake_compute metric"
    //     );

    //     // Verify at least one TLS cipher or protocol is present
    //     // We're looking for metrics like "TLS_AES_128_GCM_SHA256" which should be set in negotiated ciphers
    //     assert!(
    //         emf_json.contains("TLS_")
    //             || emf_json.contains("_tls1.3")
    //             || emf_json.contains("_cipher_"),
    //         "EMF should contain TLS-related metrics"
    //     );

    //     // Uncomment to write the snapshot for future reference
    //     // std::fs::write("emf_snapshot.json", emf_json).unwrap();
    // }

    // /// When export is called twice, we can then immediately export two EMF records
    // #[test]
    // fn buffering() {
    //     // Create a channel and subscriber
    //     let (tx, rx) = mpsc::channel();
    //     let subscriber = AggregatedMetricsSubscriber::new(tx);
    //     let subscriber_handle = subscriber.clone();

    //     // Configure and build the server
    //     let server_config = {
    //         let mut config = config_builder(&DEFAULT_TLS13).unwrap();
    //         config.set_event_subscriber(subscriber).unwrap();
    //         config.build().unwrap()
    //     };

    //     // Do first handshake
    //     let client_config = build_config(&DEFAULT_TLS13).unwrap();
    //     let mut pair = TestPair::from_configs(&client_config, &server_config);
    //     pair.handshake().unwrap();

    //     // Export first metrics
    //     subscriber_handle.export();

    //     // Do second handshake (with a different policy to get different metrics)
    //     let client_config2 = build_config(&DEFAULT).unwrap();
    //     let mut pair2 = TestPair::from_configs(&client_config2, &server_config);
    //     pair2.handshake().unwrap();

    //     // Export second metrics
    //     subscriber_handle.export();

    //     // Create emitter and buffer
    //     let mut emitter = BufferedEmfEmitter {
    //         record_receiver: rx,
    //         emf_formatter: Emf::builder("tls/s2n-tls".to_string(), vec![vec![]]).build(),
    //     };

    //     // First write should succeed
    //     let mut buffer1 = Vec::new();
    //     let result1 = emitter.write(&mut buffer1);
    //     assert!(result1.is_ok(), "First write should succeed");
    //     assert!(!buffer1.is_empty(), "First buffer should contain EMF data");

    //     // Second write should also succeed
    //     let mut buffer2 = Vec::new();
    //     let result2 = emitter.write(&mut buffer2);
    //     assert!(result2.is_ok(), "Second write should succeed");
    //     assert!(!buffer2.is_empty(), "Second buffer should contain EMF data");

    //     // Buffers should be different since they're from different handshakes
    //     assert_ne!(
    //         buffer1, buffer2,
    //         "EMF records should be different for different handshakes"
    //     );
    // }
}
