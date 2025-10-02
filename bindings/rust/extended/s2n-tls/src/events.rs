use std::{ffi::CStr, fmt::Debug, sync::{atomic::AtomicU64, Arc}, time::Duration};

#[derive(Debug, Default)]
struct TestSubscriber {
    invoked: Arc<AtomicU64>,
}

impl EventSubscriber for TestSubscriber {
    fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake) {
        event.debug_stdout();
        self.invoked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

trait EventExtension {
    fn debug_stdout(&self);
}

impl EventExtension for s2n_tls_sys::s2n_event_handshake {
    fn debug_stdout(&self) {
        println!("{}", self.protocol_version);
        println!("{:?}", maybe_string(self.cipher));
        println!("{:?}", maybe_string(self.group));
        println!("{:?}", maybe_string(self.signature));
        println!("handshake duration: {:?}", Duration::from_nanos(self.handshake_duration_ns));
        println!("handshake negotiate duration: {:?}", Duration::from_nanos(self.handshake_negotiate_duration_ns));

    }
}

// impl Debug for TestSubscriber {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("TestSubscriber")
//             .field("invoked", &self.invoked)
//             .finish()
//     }
// }

fn maybe_string(string: *const libc::c_char) -> Option<&'static str> {
    let maybe_cstr = if string.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(string) })
    };

    maybe_cstr.and_then(|cstr| cstr.to_str().ok())
}

pub trait EventSubscriber: 'static + Send + Sync {
    fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake);
}


#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use crate::{security, testing::{build_config, config_builder, TestPair}};
    use super::*;

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
}