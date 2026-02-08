// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::mpsc::{self, Receiver, Sender};

use s2n_tls::{
    security::{Policy, DEFAULT_TLS13},
    testing::{build_config, config_builder, TestPair},
};

use crate::{
    cloudwatchlogs_exporter::CloudWatchExporter, emf_emitter::EmfEmitter, record::MetricRecord,
    AggregatedMetricsSubscriber,
};

struct TestEndpointWithCloudwatch {
    config: s2n_tls::config::Config,
    subscriber: AggregatedMetricsSubscriber<Sender<MetricRecord>>,
    exporter: CloudWatchExporter,
}

impl TestEndpointWithCloudwatch {
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

pub struct TestEndpointWithEmitter {
    pub config: s2n_tls::config::Config,
    pub subscriber: AggregatedMetricsSubscriber<Sender<MetricRecord>>,
    pub exporter: EmfEmitter,
}

impl TestEndpointWithEmitter {
    pub fn new(resource: &str, policy: &Policy) -> Self {
        let (exporter, tx) = EmfEmitter::new("test_server".to_owned(), Some(resource.to_owned()));
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

    pub fn client_handshake(&self, client_policy: &Policy) {
        let client_config = build_config(client_policy).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &self.config);
        let _ = pair.handshake();
    }
}

pub struct TestEndpoint {
    pub server_config: s2n_tls::config::Config,
    pub subscriber: AggregatedMetricsSubscriber<Sender<MetricRecord>>,
    pub rx: Receiver<MetricRecord>,
}

impl TestEndpoint {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let subscriber = AggregatedMetricsSubscriber::new(tx);

        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };

        Self {
            server_config,
            subscriber,
            rx,
        }
    }

    pub fn client_handshake(&self) -> TestPair {
        let client_config = build_config(&DEFAULT_TLS13).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &self.server_config);
        pair.handshake().unwrap();
        pair
    }
}
