use std::{
    sync::{
        Arc, Mutex, atomic::{AtomicU16, AtomicU64, Ordering}, mpsc::{Receiver, SyncSender}
    },
    time::SystemTime,
};

use crate::static_lists::{
    self, CIPHERS_AVAILABLE_IN_S2N, CIPHER_PREFIXER, GROUPS_AVAILABLE_IN_S2N,
};

const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
const SIGNATURE_SCHEME_COUNT: usize = 5;
const SIG_HASH_COUNT: usize = 5;
const PROTOCOL_VERSION_COUNT: usize = 5;

/// https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_StatisticSet.html
#[derive(Debug, Default)]
pub struct StatisticSet {
    sum: AtomicU64,
    min: AtomicU64,
    max: AtomicU64,
    sample_count: AtomicU64,
}

impl StatisticSet {
    pub fn update(&self, new_measurement: u64) {
        self.sum.fetch_add(new_measurement, Ordering::Relaxed);
        self.min.fetch_min(new_measurement, Ordering::Relaxed);
        self.max.fetch_max(new_measurement, Ordering::Relaxed);
        self.sample_count.fetch_add(1, Ordering::Relaxed);
    }

    fn freeze(&self) -> FrozenStatisticSet {
        FrozenStatisticSet {
            sum: self.sum.load(Ordering::Relaxed),
            min: self.min.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
            sample_count: self.sample_count.load(Ordering::Relaxed),
        }
    }

    fn clear_statistics(&self) {
        self.sum.store(0, Ordering::Relaxed);
        self.min.store(0, Ordering::Relaxed);
        self.max.store(0, Ordering::Relaxed);
        self.sample_count.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Default)]
pub struct FrozenStatisticSet {
    sum: u64,
    min: u64,
    max: u64,
    sample_count: u64,
}

// TODO: "updaters" should refer to the people adding things
#[derive(Debug, Default)]
struct UpdatesInFlight(AtomicU64);

impl UpdatesInFlight {
    const FLUSHING_MASK: u64 = 1 << 63;
    const LOWER_63_MASK: u64 = Self::FLUSHING_MASK - 1;
    /// This is called to indicate that the record update is starting.
    /// 
    /// This will fail if a flusher has indicated that the record is about to be
    /// flushed.
    fn start_update(&self) -> Result<(),()> {
        loop {
            let current = self.0.load(Ordering::SeqCst);
            if current & Self::FLUSHING_MASK != 0 {
                // a flush is in progress, we should not modify the values
                return Err(());
            }
            assert!(current + 1 < Self::LOWER_63_MASK);
            if let Ok(_) = self.0.compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst) {
                return Ok(())
            }
            // else err -> this means that a different thread updated the in flight
            // we just need to retry
        }
    }

    /// This is called indicate that the record update is finished
    fn finish_update(&self) {
        loop {
            let current = self.0.load(Ordering::SeqCst);
            let minus_one = {
                if current & Self::FLUSHING_MASK != 0 {
                    // we need careful subtraction, bc we need to keep the flushing
                    // bit set
                    let mut lower_bits = current & Self::LOWER_63_MASK;
                    assert!(lower_bits != 0);
                    lower_bits - 1
                } else {
                    current - 1
                }
            };
            if let Ok(_) = self.0.compare_exchange(current, minus_one, Ordering::SeqCst, Ordering::SeqCst) {
                return;
            }
        }
    }

    /// This is called by the flusher.
    /// 
    /// It will continue to fail until 
    fn freeze(&self) {
        // set the flushing bit
        loop {
            let current = self.0.load(Ordering::SeqCst);
            if let Ok(_) = self.0.compare_exchange(current, current | Self::FLUSHING_MASK, Ordering::SeqCst, Ordering::SeqCst) {
                break;
            }
        }

        // wait for the remaining threads to finish
        loop {
            let current = self.0.load(Ordering::SeqCst);
            let in_progress = current & Self::LOWER_63_MASK;
            if in_progress == 0 {
                break;
            }
        }
    }

    /// Return true if the record is _frozen_. This means
    /// - the "FLUSHING" bit is set
    /// - there are not active writers
    fn is_frozen(&self) -> bool {
        self.0.load(Ordering::SeqCst) == Self::FLUSHING_MASK
    }
}

// TODO, this should have +1 for unrecognized things
#[derive(Debug)]
pub struct S2NMetricRecord {
    // writer_count -> are any updates in flight? We don't want to *freeze* the 
    // metrics until none are in flight.
    // we also use this 
    updates_in_flight: UpdatesInFlight,

    // negotiated
    protocols: [AtomicU64; PROTOCOL_VERSION_COUNT],
    ciphers: [AtomicU64; CIPHER_COUNT],
    groups: [AtomicU64; GROUP_COUNT],
    signature_scheme: [AtomicU64; SIGNATURE_SCHEME_COUNT],
    sig_hash: [AtomicU64; SIG_HASH_COUNT],

    // supported
    protocols: [AtomicU64; PROTOCOL_VERSION_COUNT],
    ciphers: [AtomicU64; CIPHER_COUNT],
    groups: [AtomicU64; GROUP_COUNT],
    signature_scheme: [AtomicU64; SIGNATURE_SCHEME_COUNT],
    sig_hash: [AtomicU64; SIG_HASH_COUNT],

    /// sum of handshake duration
    handshake_duration_us: StatisticSet,
    /// sum of handshake compute
    handshake_compute: StatisticSet,
}

impl Default for S2NMetricRecord {
    fn default() -> Self {
        let ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        Self {
            updates_in_flight: Default::default(),

            groups: Default::default(),
            ciphers,
            signature_scheme: Default::default(),
            sig_hash: Default::default(),
            protocols: Default::default(),
            
            handshake_duration_us: Default::default(),
            handshake_compute: Default::default(),
        }
    }
}

impl S2NMetricRecord {
    pub fn update(&self, event: &s2n_tls::events::HandshakeEvent) {
        dbg!(event);
        self.ciphers[static_lists::cipher_ossl_name_to_index(event.cipher()).unwrap()]
            .fetch_add(1, Ordering::Relaxed);
        self.handshake_compute
            .update(event.synchronous_time().as_micros() as u64);
        self.handshake_duration_us
            .update(event.duration().as_micros() as u64);
    }

    /// make a copy of this record to be exported, and zero all entries
    pub fn freeze(&self) -> FrozenS2NMetricRecord {
        self.updates_in_flight.freeze();

        let groups = self
            .groups
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let ciphers = self
            .ciphers
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let signature_scheme = self
            .signature_scheme
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let sig_hash = self
            .sig_hash
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let protocols = self
            .protocols
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));

        FrozenS2NMetricRecord {
            freeze_time: SystemTime::now(),
            groups,
            ciphers,
            signature_scheme,
            sig_hash,
            protocols,
            handshake_duration: self.handshake_duration_us.freeze(),
            handshake_compute: self.handshake_compute.freeze(),
        }
    }

    // /// Not that the metric record is _not_ locked during this action, so there
    // /// is not guarantee that all values will be zero upon the return of this function
    // fn adjust_for_export(&self, frozen: &FrozenS2NMetricRecord) {
    //     self.groups.iter().zip(frozen.groups.iter()).for_each(
    //         |(record_counter, frozen_counter)| {
    //             record_counter.fetch_sub(*frozen_counter, Ordering::Relaxed);
    //         },
    //     );

    //     let groups = self.groups.iter().zip(frozen.groups.iter());
    //     let cipher = self.ciphers.iter().zip(frozen.ciphers.iter());
    //     let signature_scheme = self
    //         .signature_scheme
    //         .iter()
    //         .zip(frozen.signature_scheme.iter());
    //     let sig_hash = self.sig_hash.iter().zip(frozen.sig_hash.iter());
    //     let protocols = self.protocols.iter().zip(frozen.protocols.iter());

    //     groups
    //         .chain(cipher)
    //         .chain(signature_scheme)
    //         .chain(sig_hash)
    //         .chain(protocols)
    //         .for_each(|(metric_counter, frozen_counter)| {
    //             metric_counter.fetch_sub(*frozen_counter, Ordering::Relaxed);
    //         });
    // }
}

#[derive(Debug)]
pub struct FrozenS2NMetricRecord {
    pub freeze_time: SystemTime,
    // groups
    pub groups: [u64; GROUP_COUNT],
    // ciphers
    pub ciphers: [u64; CIPHER_COUNT],
    // signature schemes
    pub signature_scheme: [u64; SIGNATURE_SCHEME_COUNT],
    // signatures
    pub sig_hash: [u64; SIG_HASH_COUNT],
    // protocol versions
    pub protocols: [u64; PROTOCOL_VERSION_COUNT],

    pub handshake_duration: FrozenStatisticSet,
    pub handshake_compute: FrozenStatisticSet,
}

// fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
//     //writer.timestamp(self.request_start);
//     writer.value("cipher", self.cipher);
//     let cipher_counter = CIPHER_PREFIXER.get_from_display(self.cipher);
//     writer.value(cipher_counter, &2_u64);

//     writer.value("protocol_version", &format!("{:?}", self.protocol_version));
//     let protocol_counter = PROTOCOL_VERSION_PREFIXER.get_from_debug(self.protocol_version);
//     writer.value(protocol_counter, &1_u64);

//     if let Some(group) = self.group {
//         writer.value("group", group);
//         let group_counter = GROUP_PREFIXER.get_from_display(group);
//         writer.value(group_counter, &1_u64);
//     }

//     // TODO need to maintain static str mapping for protocol version
//     writer.value("handshake_latency", &self.handshake_latency);
//     writer.value("handshake_duration", &self.handshake_duration);
// }

impl metrique_writer::Entry for FrozenS2NMetricRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.timestamp(self.freeze_time);

        // cipher
        let non_zero_ciphers = self
            .ciphers
            .iter()
            .enumerate()
            .filter(|(index, count)| **count > 0);
        for (index, count) in non_zero_ciphers {
            // e.g. TLS_AES_128_GCM_SHA256
            let cipher = static_lists::cipher_index_to_iana_name(index).unwrap();
            // e.g. cipher.TLS_AES_128_GCM_SHA256
            let prefixed_cipher_counter = CIPHER_PREFIXER.get_from_display(cipher);
            writer.value(prefixed_cipher_counter, count);
        }

        // timing information
        writer.value("handshake_duration", &self.handshake_duration.sum);
        writer.value(
            "handshake_duration_sample_count",
            &self.handshake_duration.sample_count,
        );

        writer.value("handshake_compute", &self.handshake_compute.sum);
        writer.value(
            "handshake_compute_sample_count",
            &self.handshake_compute.sample_count,
        );

        // tbd:
        // writer.value("resource", "foo_resource");
    }
}

pub struct MetricWithAttribution<E> {
    entry: E,
    resource: String,
}

impl<E> MetricWithAttribution<E> {
    pub fn new(entry: E, resource: String) -> Self {
        Self {
            entry,
            resource
        }
    }
}

impl<E: metrique_writer::Entry> metrique_writer::Entry for MetricWithAttribution<E> {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        self.entry.write(writer);
        writer.value("resource", &self.resource);
    }
}

