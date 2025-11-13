use std::{
    collections::HashMap,
    ffi::CStr,
    fmt::Debug,
    hash::Hash,
    io,
    sync::{atomic::AtomicU64, mpsc::Sender, Arc, LazyLock, Mutex},
    time::{Duration, Instant, SystemTime},
};

use metrique_writer::{sink::AttachHandle, AttachGlobalEntrySinkExt, FormatExt, GlobalEntrySink};

use crate::enums::Version;

#[derive(Debug, Default)]
pub struct TestSubscriber {
    invoked: Arc<AtomicU64>,
}

pub struct TracingSubscriber;

impl EventSubscriber for TracingSubscriber {
    fn on_handshake_event(&self, event: &HandshakeEvent) {
        tracing::debug!("{event:?}");
    }
}


impl EventSubscriber for TestSubscriber {
    fn on_handshake_event(&self, event: &HandshakeEvent) {
        println!("{event:#?}");
        self.invoked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub struct HandshakeEvent<'a>(&'a s2n_tls_sys::s2n_event_handshake);

impl<'a> HandshakeEvent<'a> {
    pub(crate) fn new(event: &'a s2n_tls_sys::s2n_event_handshake) -> Self {
        Self(event)
    }
    fn protocol_version(&self) -> crate::enums::Version {
        self.0.protocol_version.try_into().unwrap()
    }

    /// The negotiated cipher, in IANA format.
    fn cipher(&self) -> Option<&'static str> {
        maybe_string(self.0.cipher)
    }

    /// The negotiated key exchange group, in IANA format.
    /// 
    /// None in the case of RSA key exchange or TLS 1.2 session resumption.
    fn group(&self) -> Option<&'static str> {
        maybe_string(self.0.group)
    }

    /// Handshake duration, which includes network latency and waiting for the peer.
    fn handshake_duration(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_end_epoch_ns - self.0.handshake_start_epoch_ns)
    }

    /// Handshake time, which just the amount of time synchronously spent in s2n_negotiate.
    /// 
    /// This is roughly the "cpu cost" of the handshake.
    fn handshake_time(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_time_ns)
    }
}

impl Debug for HandshakeEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("s2n_event_handshake")
            .field("protocol_version", &self.protocol_version())
            .field("cipher", &self.cipher())
            .field("group", &self.group())
            .field("handshake_duration", &self.handshake_duration())
            .field("handshake_cpu_duration", &self.handshake_time())
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

impl<A: EventSubscriber, B:EventSubscriber> EventSubscriber for (A, B) {
    fn on_handshake_event(&self, event: &HandshakeEvent) {
        self.0.on_handshake_event(event);
        self.1.on_handshake_event(event);
    }
}

pub trait EventSubscriber: 'static + Send + Sync {
    fn on_handshake_event(&self, event: &HandshakeEvent);
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
    // async fn native_rust_consumer() {
    //     // customer codebase
    //     // customer sets up their EMF format. 

    //     // unclear whether we have to care about format here?

    //     // goal: it would be nice to be format agnostic. But how does that react 
    //     // with dimensions?

    //     // I don't understand dimension sets
    //     // I don't understand how to specify the actual global dimenions?
    //     let formatter = Emf::builder("cute-kittens-cdn".into(), vec![vec!["region".into(), "stage".into()]]);
    // }

    // #[tokio::test]
    // async fn cloudwatch_emission() {
    //     let config = aws_config::load_from_env().await;
    //     let client = aws_sdk_cloudwatchlogs::Client::new(&config);
    //     client.put_log_events().
    // }
}
