// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Demonstrates how to wire an `AggregatedMetricsSubscriber` into an s2n-tls
//! config, perform handshakes, and export the aggregated metrics as JSON.
//!
//! The subscriber is tagged with an `Attribution` so that the exported record
//! identifies which service and resource produced the metrics.

use std::{io, time::Duration};

use s2n_tls::{
    security::DEFAULT_TLS13,
    testing::{TestPair, build_config, config_builder},
};

use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, MetricRecord, TelemetrySink,
};

/// Example TelemetrySink that serializes each record as JSON to stdout.
/// Applications can implement TelemetrySink to route records to any
/// destination: a file, network socket, S3, Kinesis, etc.
struct StdoutJsonSink;

impl TelemetrySink for StdoutJsonSink {
    fn write_record(&self, record: &MetricRecord) -> io::Result<()> {
        let json = serde_json::to_string(record)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        println!("{json}");
        Ok(())
    }
}

fn main() {
    let attribution = Attribution {
        service: "my-service".to_owned(),
        resource: "test-resource".to_owned(),
    };
    let subscriber = AggregatedMetricsSubscriber::new(
        StdoutJsonSink,
        attribution,
        Duration::from_secs(3600),
    );

    // Wire the subscriber into a server config so handshake events flow into it.
    let server_config = {
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder.set_event_subscriber(subscriber.clone()).unwrap();
        builder.build().unwrap()
    };
    let client_config = build_config(&DEFAULT_TLS13).unwrap();

    // Perform a few handshakes so there is real data to export.
    for _ in 0..3 {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
    }

    // Flush the aggregated record. This prints one JSON line to stdout
    // containing attribution metadata and handshake metrics from the
    // three handshakes above.
    subscriber.finish_record();
}
