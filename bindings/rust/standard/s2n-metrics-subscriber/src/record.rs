// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use crate::static_lists::{
    self, Prefixer, State, TlsParam, ToStaticString, CIPHERS_AVAILABLE_IN_S2N,
    GROUPS_AVAILABLE_IN_S2N, SIGNATURE_SCHEMES_AVAILABLE_IN_S2N, VERSIONS_AVAILABLE_IN_S2N,
};

const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
const SIGNATURE_COUNT: usize = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N.len();
const PROTOCOL_COUNT: usize = VERSIONS_AVAILABLE_IN_S2N.len();

/// Metric Record is an opaque type which implements [`metrique_writer::Entry`].
///
/// This is the preferred type for public s2n-tls-metric-subscriber traits and
/// interfaces.
// This currently just holds a single struct. In the future we will
// likely rely on an enum to handle different record types, e.g. SessionResumptionFailure.
#[derive(Debug, Clone)]
pub struct MetricRecord {
    handshake: HandshakeRecord,
}

impl MetricRecord {
    pub(crate) fn new(handshake: HandshakeRecord) -> Self {
        Self { handshake }
    }
}

impl metrique_writer::Entry for MetricRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        self.handshake.write(writer)
    }
}

/// The S2NMetricRecord stores various metrics
#[derive(Debug)]
pub(crate) struct HandshakeRecordInProgress {
    /// This is used to send a frozen version back to the Aggregator, after which
    /// point it can be exported. This is only used in the drop impl.
    exporter: std::sync::mpsc::Sender<HandshakeRecord>,

    sample_count: AtomicU64,

    // negotiated
    pub protocols: [AtomicU64; PROTOCOL_COUNT],
    pub ciphers: [AtomicU64; CIPHER_COUNT],
    pub groups: [AtomicU64; GROUP_COUNT],
    pub signatures: [AtomicU64; SIGNATURE_COUNT],

    /// sum of handshake duration
    handshake_duration_us: AtomicU64,
    /// sum of handshake compute
    handshake_compute: AtomicU64,
}

fn relaxed_freeze<const T: usize>(array: &[AtomicU64; T]) -> [u64; T] {
    array
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed))
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<HandshakeRecord>) -> Self {
        // default is not implemented for arrays this large
        let ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        let supported_ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        Self {
            sample_count: Default::default(),

            groups: Default::default(),
            ciphers,
            protocols: Default::default(),
            signatures: Default::default(),

            handshake_duration_us: Default::default(),
            handshake_compute: Default::default(),
            exporter,
        }
    }

    pub fn update(
        &self,
        conn: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        ////////////////////////////////////////////////////////////////////////
        /////////////////////   fields from connection   ///////////////////////
        ////////////////////////////////////////////////////////////////////////

        if let Some(s) = conn.selected_signature_scheme() {
            let index = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
                .iter()
                .position(|s2n_sig| s2n_sig.description() == s);
            match index {
                Some(index) => {
                    self.signatures[index].fetch_add(1, Ordering::SeqCst);
                }
                None => {
                    // this should never happen, but we prefer to drop metrics
                    // rather than panic
                    tracing::error!("{s} was not a recognized s2n-tls signature");
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////
        //////////////////////   fields from event   ///////////////////////////
        ////////////////////////////////////////////////////////////////////////

        self.sample_count.fetch_add(1, Ordering::SeqCst);

        TlsParam::Version
            .name_to_metric_index(event.protocol_version().to_static_string())
            .and_then(|index| self.protocols.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::SeqCst));

        static_lists::cipher_ossl_name_to_index(event.cipher())
            .and_then(|index| self.ciphers.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::SeqCst));

        event
            .group()
            .and_then(|name| TlsParam::Group.name_to_metric_index(name))
            .and_then(|index| self.groups.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::SeqCst));

        // Assumption: durations are less than 500,000 years, otherwise this cast
        // will panic
        self.handshake_compute.fetch_add(
            event.synchronous_time().as_micros() as u64,
            Ordering::SeqCst,
        );
        self.handshake_duration_us
            .fetch_add(event.duration().as_micros() as u64, Ordering::SeqCst);
    }

    /// make a copy of this record to be exported.
    fn finish(&self) -> HandshakeRecord {
        HandshakeRecord {
            freeze_time: SystemTime::now(),
            sample_count: self.sample_count.load(Ordering::SeqCst),
            protocols: relaxed_freeze(&self.protocols),
            negotiated_ciphers: relaxed_freeze(&self.ciphers),
            negotiated_groups: relaxed_freeze(&self.groups),
            negotiated_signatures: relaxed_freeze(&self.signatures),
            handshake_duration: self.handshake_duration_us.load(Ordering::SeqCst),
            handshake_compute: self.handshake_compute.load(Ordering::SeqCst),
        }
    }
}

impl Drop for HandshakeRecordInProgress {
    fn drop(&mut self) {
        let frozen = self.finish();
        // no available way to report error
        let _ = self.exporter.send(frozen);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HandshakeRecord {
    pub freeze_time: SystemTime,

    sample_count: u64,

    // negotiated parameters
    pub protocols: [u64; PROTOCOL_COUNT],
    pub negotiated_ciphers: [u64; CIPHER_COUNT],
    pub negotiated_groups: [u64; GROUP_COUNT],
    pub negotiated_signatures: [u64; SIGNATURE_COUNT],

    pub handshake_duration: u64,
    pub handshake_compute: u64,
}

impl metrique_writer::Entry for HandshakeRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.timestamp(self.freeze_time);

        for (list, parameter, state) in [
            (
                self.protocols.as_slice(),
                TlsParam::Version,
                State::Negotiated,
            ),
            (
                self.negotiated_ciphers.as_slice(),
                TlsParam::Cipher,
                State::Negotiated,
            ),
            (
                self.negotiated_groups.as_slice(),
                TlsParam::Group,
                State::Negotiated,
            ),
            (
                self.negotiated_signatures.as_slice(),
                TlsParam::SignatureScheme,
                State::Negotiated,
            ),
        ] {
            list.iter()
                .enumerate()
                .filter(|(_index, count)| **count > 0)
                .filter_map(|(index, count)| match parameter.index_to_name(index) {
                    Some(name) => Some((name, count)),
                    None => {
                        debug_assert!(false, "failed to get name for {index} of {parameter:?}");
                        None
                    }
                })
                .for_each(|(name, count)| {
                    let prefixed_label = Prefixer::get_with_prefix(name, parameter, state);
                    writer.value(prefixed_label, count);
                });
        }

        writer.value("sample_count", &self.sample_count);
        writer.value("handshake_duration", &self.handshake_duration);
        writer.value("handshake_compute", &self.handshake_compute);
    }
}
