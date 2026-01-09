use std::{
    sync::{
        atomic::{AtomicU16, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender},
        Arc, Mutex,
    },
    time::SystemTime,
};

use crate::static_lists::{
    self, Prefixer, State, TlsParam, CIPHERS_AVAILABLE_IN_S2N, GROUPS_AVAILABLE_IN_S2N,
};

const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
const SIGNATURE_SCHEME_COUNT: usize = 5;
const SIG_HASH_COUNT: usize = 5;
/// SSLv3 -> TLS 1.3
const PROTOCOL_VERSION_COUNT: usize = 5;

// TODO: "updaters" should refer to the people adding things
#[derive(Debug, Default)]
pub struct UpdatesInFlight(AtomicU64);

impl UpdatesInFlight {
    const FLUSHING_MASK: u64 = 1 << 63;
    const LOWER_63_MASK: u64 = Self::FLUSHING_MASK - 1;
    /// This is called to indicate that the record update is starting.
    ///
    /// This will fail if a flusher has indicated that the record is about to be
    /// flushed.
    pub fn start_update(&self) -> Result<(), ()> {
        loop {
            let current = self.0.load(Ordering::SeqCst);
            if current & Self::FLUSHING_MASK != 0 {
                // a flush is in progress, we should not modify the values
                return Err(());
            }
            assert!(current + 1 < Self::LOWER_63_MASK);
            if let Ok(_) =
                self.0
                    .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                return Ok(());
            }
            // else err -> this means that a different thread updated the in flight
            // we just need to retry
        }
    }

    /// This is called indicate that the record update is finished
    pub fn finish_update(&self) {
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
            if let Ok(_) =
                self.0
                    .compare_exchange(current, minus_one, Ordering::SeqCst, Ordering::SeqCst)
            {
                return;
            }
        }
    }

    /// This is called by the flusher.
    ///
    /// It will continue to fail until
    pub fn freeze(&self) {
        // set the flushing bit
        loop {
            let current = self.0.load(Ordering::SeqCst);
            if let Ok(_) = self.0.compare_exchange(
                current,
                current | Self::FLUSHING_MASK,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
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
}

// TODO, this should have +1 for unrecognized things
#[derive(Debug)]
pub struct S2NMetricRecord {
    // writer_count -> are any updates in flight? We don't want to *freeze* the
    // metrics until none are in flight.
    // we also use this
    pub updates_in_flight: UpdatesInFlight,

    sample_count: AtomicU64,

    // negotiated
    protocols: [AtomicU64; PROTOCOL_VERSION_COUNT],
    ciphers: [AtomicU64; CIPHER_COUNT],
    groups: [AtomicU64; GROUP_COUNT],
    signature_scheme: [AtomicU64; SIGNATURE_SCHEME_COUNT],
    sig_hash: [AtomicU64; SIG_HASH_COUNT],

    // supported
    pub supported_protocols: [AtomicU64; PROTOCOL_VERSION_COUNT],
    pub supported_ciphers: [AtomicU64; CIPHER_COUNT],
    pub supported_groups: [AtomicU64; GROUP_COUNT],
    pub supported_signature_scheme: [AtomicU64; SIGNATURE_SCHEME_COUNT],
    pub supported_sig_hash: [AtomicU64; SIG_HASH_COUNT],

    /// sum of handshake duration
    handshake_duration_us: AtomicU64,
    /// sum of handshake compute
    handshake_compute: AtomicU64,
}

impl Default for S2NMetricRecord {
    fn default() -> Self {
        let ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        let supported_ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        Self {
            updates_in_flight: Default::default(),

            sample_count: Default::default(),

            groups: Default::default(),
            ciphers,
            signature_scheme: Default::default(),
            sig_hash: Default::default(),
            protocols: Default::default(),

            supported_protocols: Default::default(),
            supported_ciphers,
            supported_groups: Default::default(),
            supported_signature_scheme: Default::default(),
            supported_sig_hash: Default::default(),

            handshake_duration_us: Default::default(),
            handshake_compute: Default::default(),
        }
    }
}

fn relaxed_freeze<const T: usize>(array: &[AtomicU64; T]) -> [u64; T] {
    array
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed))
}

impl S2NMetricRecord {
    pub fn update(&self, event: &s2n_tls::events::HandshakeEvent) {
        dbg!(event);
        self.ciphers[static_lists::cipher_ossl_name_to_index(event.cipher()).unwrap()]
            .fetch_add(1, Ordering::Relaxed);
        // Assumption: durations are less than 500,000 years, otherwise this cast
        // will panic
        self.handshake_compute.fetch_add(
            event.synchronous_time().as_micros() as u64,
            Ordering::SeqCst,
        );
        self.handshake_duration_us
            .fetch_add(event.duration().as_micros() as u64, Ordering::SeqCst);
    }

    /// make a copy of this record to be exported, and zero all entries
    pub fn freeze(&self) -> FrozenS2NMetricRecord {
        self.updates_in_flight.freeze();

        FrozenS2NMetricRecord {
            freeze_time: SystemTime::now(),
            sample_count: self.sample_count.load(Ordering::SeqCst),
            protocols: relaxed_freeze(&self.protocols),
            ciphers: relaxed_freeze(&self.ciphers),
            groups: relaxed_freeze(&self.groups),
            signature_scheme: relaxed_freeze(&self.signature_scheme),
            sig_hash: relaxed_freeze(&self.sig_hash),
            supported_protocols: relaxed_freeze(&self.supported_protocols),
            supported_ciphers: relaxed_freeze(&self.supported_ciphers),
            supported_groups: relaxed_freeze(&self.supported_groups),
            supported_signature_scheme: relaxed_freeze(&self.supported_signature_scheme),
            supported_sig_hash: relaxed_freeze(&self.supported_sig_hash),
            handshake_duration: self.handshake_duration_us.load(Ordering::SeqCst),
            handshake_compute: self.handshake_compute.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug)]
pub struct FrozenS2NMetricRecord {
    pub freeze_time: SystemTime,

    sample_count: u64,

    // negotiated parameters
    pub protocols: [u64; PROTOCOL_VERSION_COUNT],
    pub ciphers: [u64; CIPHER_COUNT],
    pub groups: [u64; GROUP_COUNT],
    pub signature_scheme: [u64; SIGNATURE_SCHEME_COUNT],
    pub sig_hash: [u64; SIG_HASH_COUNT],

    pub supported_protocols: [u64; PROTOCOL_VERSION_COUNT],
    pub supported_ciphers: [u64; CIPHER_COUNT],
    pub supported_groups: [u64; GROUP_COUNT],
    pub supported_signature_scheme: [u64; SIGNATURE_SCHEME_COUNT],
    pub supported_sig_hash: [u64; SIG_HASH_COUNT],

    pub handshake_duration: u64,
    pub handshake_compute: u64,
}

impl metrique_writer::Entry for FrozenS2NMetricRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.timestamp(self.freeze_time);

        for (list, parameter, state) in [
            // ciphers
            (self.ciphers.as_slice(), TlsParam::Cipher, State::Negotiated),
            (self.supported_ciphers.as_slice(), TlsParam::Cipher, State::Supported),
            // groups
            (self.groups.as_slice(), TlsParam::Group, State::Negotiated),
            (self.supported_groups.as_slice(), TlsParam::Group, State::Supported),
        ] {
            list.iter()
                .enumerate()
                .filter(|(_index, count)| **count > 0)
                .for_each(|(index, count)| {
                    let iana_cipher_name = parameter.index_to_iana_name(index).unwrap();
                    let prefixed_label =
                        Prefixer::get_with_prefix(iana_cipher_name, parameter, state);
                    writer.value(prefixed_label, count);
                });
        }

        // timing information
        writer.value("handshake_duration", &self.handshake_duration);
        writer.value("handshake_compute", &self.handshake_compute);
    }
}

pub struct MetricWithAttribution<E> {
    entry: E,
    resource: String,
}

impl<E> MetricWithAttribution<E> {
    pub fn new(entry: E, resource: String) -> Self {
        Self { entry, resource }
    }
}

impl<E: metrique_writer::Entry> metrique_writer::Entry for MetricWithAttribution<E> {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        self.entry.write(writer);
        writer.value("resource", &self.resource);
    }
}
