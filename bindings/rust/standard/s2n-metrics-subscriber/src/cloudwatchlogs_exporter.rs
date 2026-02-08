// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{sync::mpsc::Sender, time::SystemTime};

use aws_config::BehaviorVersion;
use aws_sdk_cloudwatchlogs::{types::InputLogEvent, Client};

use crate::{emf_emitter::EmfEmitter, record::MetricRecord};

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
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
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

                5000 - buffer_slize.len()
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
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use crate::AggregatedMetricsSubscriber;

    use super::*;
    use s2n_tls::{
        security::{self, Policy, DEFAULT, DEFAULT_TLS13},
        testing::{build_config, config_builder, TestPair},
    };

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
