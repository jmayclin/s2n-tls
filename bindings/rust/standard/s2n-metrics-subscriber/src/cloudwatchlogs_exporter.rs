// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{ErrorKind, Write},
    sync::mpsc::{Receiver, Sender, TryRecvError},
    time::SystemTime,
};

use aws_sdk_cloudwatchlogs::{types::InputLogEvent, Client};
use metrique_writer_format_emf::Emf;

use crate::{
    emf_emitter::EmfEmitter, record::MetricRecord,
};

use metrique_writer::format::Format;

/// This is a very inefficient metric uploader for CloudWatch
///
/// You MUST poll [`CloudWatchExporter::try_write`] to actually write events to
/// cloudwatch. It does not happen in the background/automatically.
///
/// This is done to make sure that all events from short lived tests are getting
/// flushed.
pub struct CloudWatchExporter {
    /// The cloudwatch logs client, used to "put-metric-events"
    emf: EmfEmitter,
    cloudwatch_logs_client: Client,
}

impl CloudWatchExporter {
    pub async fn initialize(
        service_name: String,
        resource: Option<String>,
    ) -> (Self, Sender<MetricRecord>) {
        // load AWS credentials from the environments
        let config = aws_config::load_from_env().await;
        let client = aws_sdk_cloudwatchlogs::Client::new(&config);

        let (emitter, tx) = EmfEmitter::new(service_name, resource);

        let value = CloudWatchExporter {
            cloudwatch_logs_client: client,
            emf: emitter,
        };
        (value, tx)
    }

    fn current_timestamp() -> i64 {
        SystemTime::UNIX_EPOCH.elapsed().unwrap().as_millis() as i64
    }

    pub async fn try_write(&mut self) -> bool {
        let mut buffer: [u8; 5_000] = [0; 5_000];
        let mut buffer_slize = buffer.as_mut_slice();
        // let mut buffer = Vec::new();
        let written_length = match self.emf.write(&mut buffer_slize) {
            Ok(()) => {
                println!("remaining length?: {:?}", buffer_slize.len());
                let written_length = 5000 - buffer_slize.len();
                written_length
            }
            Err(e) => {
                tracing::error!("{e:?}");
                return false;
            }
        };

        let record = &buffer[0..written_length];

        println!("{}", String::from_utf8(record.to_owned()).unwrap());

        let event = InputLogEvent::builder()
            .message(String::from_utf8(record.to_owned()).unwrap())
            .timestamp(Self::current_timestamp())
            .build()
            .unwrap();
        let result = self
            .cloudwatch_logs_client
            .put_log_events()
            .log_group_name("s2n-tls-metric-development")
            .log_stream_name("stream1")
            .log_events(event)
            .send()
            .await
            .unwrap();
        println!("PUT THE EVENT: {result:?}");
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use s2n_tls::{
        security::{self, Policy},
        testing::{build_config, config_builder, TestPair},
    };

    // #[test]
    // fn event_emissions() {
    //     let subscriber = TestSubscriber::default();
    //     let invoked = subscriber.invoked.clone();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config.set_event_subscriber(subscriber).unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     assert_eq!(invoked.load(Ordering::Relaxed), 1);

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     assert_eq!(invoked.load(Ordering::Relaxed), 2);
    //     assert!(false);
    // }

    // #[test]
    // fn logging_events() {
    //     let subscriber = RollingFileExporter::service_metrics_init();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config.set_event_subscriber(subscriber).unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();

    //     assert!(false);
    // }

    // #[tokio::test]
    // async fn cloudwatch_events() {
    //     let subscriber = CloudWatchExporter::initialize().await;
    //     let subscriber_handle = subscriber.clone();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config
    //         .set_event_subscriber(subscriber_handle)
    //         .unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_configs = [
    //         build_config(&security::DEFAULT_TLS13).unwrap(),
    //         build_config(&security::DEFAULT_TLS13).unwrap(),
    //         build_config(&Policy::from_version("default_pq").unwrap()).unwrap(),
    //     ];

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     let tls12_client_config = build_config(&security::DEFAULT).unwrap();
    //     let mut test_pair = TestPair::from_configs(&tls12_client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     std::thread::sleep(Duration::from_secs(1));
    //     assert!(false);
    // }

    // #[tokio::test]
    // async fn cloudwatch_emission() {
    //     let config = aws_config::load_from_env().await;
    //     let client = aws_sdk_cloudwatchlogs::Client::new(&config);
    //     client.put_log_events().
    // }
}
