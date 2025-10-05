use std::{
    collections::HashMap,
    ffi::CStr,
    fmt::Debug,
    hash::Hash,
    io,
    sync::{atomic::AtomicU64, mpsc::Sender, Arc, LazyLock, Mutex},
    time::{Duration, Instant, SystemTime},
};

use aws_sdk_cloudwatchlogs::{types::InputLogEvent, Client};
use metrique::{unit::Count, unit_of_work::metrics, ServiceMetrics};
use metrique_writer::{sink::AttachHandle, AttachGlobalEntrySinkExt, FormatExt, GlobalEntrySink};
use metrique_writer_format_emf::Emf;
use s2n_tls_sys::s2n_resumption_outcome;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::MakeWriter;

use crate::enums::Version;

#[derive(Debug, Default)]
pub struct TestSubscriber {
    invoked: Arc<AtomicU64>,
}

struct Prefixer<T> {
    /// e.g. cipher.
    prefix: &'static str,
    /// lookup from raw item to prefixed item
    prefixed_items: Mutex<HashMap<T, &'static str>>,
}

impl<T> Prefixer<T> {
    fn new(prefix: &'static str) -> Self {
        Prefixer {
            prefix,
            prefixed_items: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: std::cmp::Eq + Hash + std::fmt::Display + Clone> Prefixer<T> {
    fn get_from_display(&self, item: T) -> &'static str {
        // TODO: R/W Lock
        self.prefixed_items
            .lock()
            .unwrap()
            .entry(item.clone())
            .or_insert_with(|| format!("{}{}", &self.prefix, &item).leak())
    }
}

impl<T: std::cmp::Eq + Hash + std::fmt::Debug + Clone> Prefixer<T> {
    fn get_from_debug(&self, item: T) -> &'static str {
        // TODO: R/W Lock
        self.prefixed_items
            .lock()
            .unwrap()
            .entry(item.clone())
            .or_insert_with(|| format!("{}{:?}", &self.prefix, &item).leak())
    }
}

static CIPHER_PREFIXER: LazyLock<Prefixer<&'static str>> =
    LazyLock::new(|| Prefixer::new("cipher."));
static GROUP_PREFIXER: LazyLock<Prefixer<&'static str>> = LazyLock::new(|| Prefixer::new("group."));
static RESUMPTION_OUTCOME_PREFIXER: LazyLock<Prefixer<ResumptionOutcome>> =
    LazyLock::new(|| Prefixer::new("resumption_outcome."));
static PROTOCOL_VERSION_PREFIXER: LazyLock<Prefixer<crate::enums::Version>> =
    LazyLock::new(|| Prefixer::new("protocol_version."));

#[derive(Clone)]
pub struct CloudWatchExporter {
    cloudwatch_logs_client: Client,
    stream_receiver: Arc<Mutex<std::sync::mpsc::Receiver<Vec<u8>>>>,
    handle: Arc<AttachHandle>,
}

pub struct SenderWriter(Sender<Vec<u8>>);

pub struct ChannelMessage {
    buffer: Vec<u8>,
    channel: Sender<Vec<u8>>,
}

impl<'a> MakeWriter<'a> for SenderWriter {
    type Writer = ChannelMessage;

    fn make_writer(&'a self) -> Self::Writer {
        let channel = self.0.clone();
        ChannelMessage {
            buffer: Vec::new(),
            channel,
        }
    }
}

impl io::Write for ChannelMessage {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        println!("calling write: {}", buf.len());
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // this is a test-only reporter, so this is fine.
        unreachable!("metricque (currently) doesn't ever call flush");
    }
}

impl Drop for ChannelMessage {
    fn drop(&mut self) {
        println!("flushing through drop {}", self.buffer.len());
        self.channel.send(self.buffer.clone()).unwrap();
    }
}

impl CloudWatchExporter {
    async fn initialize() -> Self {
        let config = aws_config::load_from_env().await;
        println!("{config:?}");
        let client = aws_sdk_cloudwatchlogs::Client::new(&config);
        let (sender, receiver) = std::sync::mpsc::channel::<Vec<u8>>();
        let attach_handle = ServiceMetrics::attach_to_stream(
            Emf::builder("MyS2NTlsServer".to_string(), vec![vec![]])
                .build()
                .output_to_makewriter(SenderWriter(sender)),
        );

        CloudWatchExporter {
            cloudwatch_logs_client: client,
            stream_receiver: Arc::new(Mutex::new(receiver)),
            handle: Arc::new(attach_handle),
        }
    }

    fn current_timestamp() -> i64 {
        SystemTime::UNIX_EPOCH.elapsed().unwrap().as_millis() as i64
    }

    async fn try_write(&self) -> bool {
        let results = self
            .cloudwatch_logs_client
            .list_log_groups()
            .send()
            .await
            .unwrap();
        println!("{results:?}");
        if let Ok(data) = self.stream_receiver.lock().unwrap().try_recv() {
            let event = InputLogEvent::builder()
                .message(String::from_utf8(data).unwrap())
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
        } else {
            false
        }
    }
}

impl EventSubscriber for CloudWatchExporter {
    fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake) {
        let handshake = HandshakeMetrics::from_event(event);
        let resumption = ResumptionMetrics::from_event(&event.resumption_event);
        ServiceMetrics::append(handshake);
        resumption.map(|event| ServiceMetrics::append(event));
    }
}

pub struct RollingFileExporter(AttachHandle);

/// use metrique_writer::GlobalEntrySink;
/// use metrique_writer::{AttachGlobalEntrySinkExt, FormatExt, sink::AttachHandle};
/// use metrique_writer_format_emf::Emf;

impl RollingFileExporter {
    fn service_metrics_init() -> Self {
        let attach_handle = ServiceMetrics::attach_to_stream(
            Emf::builder("MyS2NTlsServer".to_string(), vec![vec![]])
                .build()
                .output_to_makewriter(RollingFileAppender::new(
                    Rotation::HOURLY,
                    "logs",
                    "s2n.log",
                )),
        );
        RollingFileExporter(attach_handle)
    }
}

impl EventSubscriber for RollingFileExporter {
    fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake) {
        let handshake = HandshakeMetrics::from_event(event);
        let resumption = ResumptionMetrics::from_event(&event.resumption_event);
        ServiceMetrics::append(handshake);
        resumption.map(|event| ServiceMetrics::append(event));
    }
}

struct ResumptionMetrics {
    outcome: ResumptionOutcome,
    ticket_age: Option<Duration>,
}

impl metrique_writer::Entry for ResumptionMetrics {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.value("resumption_outcome", &format!("{:?}", self.outcome));
        let resumption_label = RESUMPTION_OUTCOME_PREFIXER.get_from_debug(self.outcome);
        writer.value(resumption_label, &1_u64);

        if let Some(ticket_age) = self.ticket_age {
            writer.value("resumption_ticket_age", &ticket_age);
        }
    }
}

impl ResumptionMetrics {
    fn from_event(event: &s2n_tls_sys::s2n_event_resumption) -> Option<Self> {
        let event = ResumptionEvent(event);
        Some(ResumptionMetrics {
            outcome: event.outcome()?,
            ticket_age: event.ticket_age(),
        })
    }
}

struct HandshakeMetrics {
    /// The negotiated cipher, in IANA format.
    cipher: &'static str,
    /// The negotiated key exchange group, in IANA format.
    ///
    /// This is not emitted in the event of TLS 1.2 session resumption or RSA
    /// key exchange
    group: Option<&'static str>,
    protocol_version: Version,
    /// The time for the handshake to complete, including network trips
    handshake_latency: Duration,
    /// The time for the handshake to complete, only including compute
    handshake_duration: Duration,
}

impl metrique_writer::Entry for HandshakeMetrics {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        //writer.timestamp(self.request_start);
        writer.value("cipher", self.cipher);
        let cipher_counter = CIPHER_PREFIXER.get_from_display(self.cipher);
        writer.value(cipher_counter, &1_u64);

        writer.value("protocol_version", &format!("{:?}", self.protocol_version));
        let protocol_counter = PROTOCOL_VERSION_PREFIXER.get_from_debug(self.protocol_version);
        writer.value(protocol_counter, &1_u64);

        if let Some(group) = self.group {
            writer.value("group", group);
            let group_counter = GROUP_PREFIXER.get_from_display(group);
            writer.value(group_counter, &1_u64);
        }

        // TODO need to maintain static str mapping for protocol version
        writer.value("handshake_latency", &self.handshake_latency);
        writer.value("handshake_duration", &self.handshake_duration);
    }
}

impl HandshakeMetrics {
    fn from_event(event: &s2n_tls_sys::s2n_event_handshake) -> Self {
        let event = HandshakeEvent(event);
        HandshakeMetrics {
            cipher: event.cipher().unwrap(),
            group: event.group(),
            protocol_version: event.protocol_version(),
            handshake_latency: event.handshake_duration(),
            handshake_duration: event.handshake_cpu_duration(),
        }
    }
}

impl EventSubscriber for TestSubscriber {
    fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake) {
        let event = HandshakeEvent(event);
        println!("{event:#?}");
        self.invoked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[metrics(value(string))]
#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone, Eq, Hash)]
pub enum ResumptionOutcome {
    /// The client did not supply an SNI
    None,
    Success,
    FormatUnknown,
    StekUnknown,
    TicketExpired,
    OtherError,
}

impl TryFrom<s2n_resumption_outcome::Type> for ResumptionOutcome {
    type Error = ();
    fn try_from(input: s2n_resumption_outcome::Type) -> Result<Self, ()> {
        let error = match input {
            s2n_resumption_outcome::RESUMPTION_NONE => Self::None,
            s2n_resumption_outcome::RESUMPTION_SUCCESS => Self::Success,
            s2n_resumption_outcome::RESUMPTION_FORMAT_UNKNOWN => Self::FormatUnknown,
            s2n_resumption_outcome::RESUMPTION_STEK_UNKNOWN => Self::StekUnknown,
            s2n_resumption_outcome::RESUMPTION_TICKET_EXPIRED => Self::TicketExpired,
            s2n_resumption_outcome::RESUMPTION_OTHER_ERROR => Self::OtherError,
            _ => return Err(()),
        };
        Ok(error)
    }
}

// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct s2n_event_handshake {
//     pub protocol_version: u8,
//     pub cipher: *const ::libc::c_char,
//     pub group: *const ::libc::c_char,
//     pub signature: *const ::libc::c_char,
//     pub resumed: bool,
//     pub hello_retry: bool,
//     pub supports_resumption: bool,
//     pub attempted_resumption: bool,
// }

struct ResumptionEvent<'a>(&'a s2n_tls_sys::s2n_event_resumption);

impl<'a> ResumptionEvent<'a> {
    // TODO: return new, which forces Option field
    fn ticket_age(&self) -> Option<Duration> {
        if self.outcome() == Some(ResumptionOutcome::Success) {
            Some(Duration::from_millis(self.0.ticket_age_ms))
        } else {
            None
        }
    }

    fn outcome(&self) -> Option<ResumptionOutcome> {
        let outcome = ResumptionOutcome::try_from(self.0.outcome).unwrap();
        if outcome == ResumptionOutcome::None {
            None
        } else {
            Some(outcome)
        }
    }
}

impl<'a> Debug for ResumptionEvent<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("s2n_event_resumption")
            .field("outcome", &self.outcome())
            .field("ticket_age", &self.ticket_age())
            .finish()
    }
}

struct HandshakeEvent<'a>(&'a s2n_tls_sys::s2n_event_handshake);

impl<'a> HandshakeEvent<'a> {
    fn protocol_version(&self) -> crate::enums::Version {
        self.0.protocol_version.try_into().unwrap()
    }

    fn cipher(&self) -> Option<&'static str> {
        maybe_string(self.0.cipher)
    }

    fn group(&self) -> Option<&'static str> {
        maybe_string(self.0.group)
    }

    fn handshake_duration(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_duration_ns)
    }

    fn handshake_cpu_duration(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_negotiate_duration_ns)
    }

    fn resumption_event(&self) -> ResumptionEvent {
        ResumptionEvent(&self.0.resumption_event)
    }
}

impl Debug for HandshakeEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("s2n_event_handshake")
            .field("protocol_version", &self.protocol_version())
            .field("cipher", &self.cipher())
            .field("group", &self.group())
            .field("handshake_duration", &self.handshake_duration())
            .field("handshake_cpu_duration", &self.handshake_cpu_duration())
            .field("resumption_event", &self.resumption_event())
            .finish()
    }
}

fn maybe_string(string: *const libc::c_char) -> Option<&'static str> {
    if string.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(string).to_str().ok() }
    }
}

pub trait EventSubscriber: 'static + Send + Sync {
    fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::{
        security::{self, Policy},
        testing::{build_config, config_builder, TestPair},
    };

    #[test]
    fn event_emissions() {
        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();
        let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
        server_config.set_event_subscriber(subscriber).unwrap();
        let server_config = server_config.build().unwrap();

        let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
        let mut test_pair = TestPair::from_configs(&client_config, &server_config);
        test_pair.handshake().unwrap();
        assert_eq!(invoked.load(Ordering::Relaxed), 1);

        let mut test_pair = TestPair::from_configs(&client_config, &server_config);
        test_pair.handshake().unwrap();
        assert_eq!(invoked.load(Ordering::Relaxed), 2);
        assert!(false);
    }

    #[test]
    fn logging_events() {
        let subscriber = RollingFileExporter::service_metrics_init();
        let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
        server_config.set_event_subscriber(subscriber).unwrap();
        let server_config = server_config.build().unwrap();

        let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
        let mut test_pair = TestPair::from_configs(&client_config, &server_config);
        test_pair.handshake().unwrap();

        let mut test_pair = TestPair::from_configs(&client_config, &server_config);
        test_pair.handshake().unwrap();

        assert!(false);
    }

    #[tokio::test]
    async fn cloudwatch_events() {
        let subscriber = CloudWatchExporter::initialize().await;
        let subscriber_handle = subscriber.clone();
        let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
        server_config
            .set_event_subscriber(subscriber_handle)
            .unwrap();
        let server_config = server_config.build().unwrap();

        let client_configs = [
            build_config(&security::DEFAULT_TLS13).unwrap(),
            build_config(&security::DEFAULT_TLS13).unwrap(),
            build_config(&Policy::from_version("default_pq").unwrap()).unwrap(),
        ];

        let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
        let mut test_pair = TestPair::from_configs(&client_config, &server_config);
        test_pair.handshake().unwrap();
        subscriber.try_write().await;

        let mut test_pair = TestPair::from_configs(&client_config, &server_config);
        test_pair.handshake().unwrap();
        subscriber.try_write().await;

        let tls12_client_config = build_config(&security::DEFAULT).unwrap();
        let mut test_pair = TestPair::from_configs(&tls12_client_config, &server_config);
        test_pair.handshake().unwrap();
        subscriber.try_write().await;

        std::thread::sleep(Duration::from_secs(1));
        assert!(false);
    }

    // #[tokio::test]
    // async fn cloudwatch_emission() {
    //     let config = aws_config::load_from_env().await;
    //     let client = aws_sdk_cloudwatchlogs::Client::new(&config);
    //     client.put_log_events().
    // }
}
