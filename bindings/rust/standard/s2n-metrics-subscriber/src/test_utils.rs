// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::mpsc::Sender;

use s2n_tls::{
    security::Policy,
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
        let (exporter, tx) =
            EmfEmitter::new("test_server".to_owned(), Some(resource.to_owned()));
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
        pair.handshake();
    }
}
