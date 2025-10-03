use std::{
    ffi::CStr,
    fmt::Debug,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use s2n_tls_sys::s2n_resumption_outcome;

#[derive(Debug, Default)]
pub struct TestSubscriber {
    invoked: Arc<AtomicU64>,
}

impl EventSubscriber for TestSubscriber {
    fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake) {
        let event =  HandshakeEvent(event);
        println!("{event:#?}");
        self.invoked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Copy, Clone)]
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
            _ => return Err(())
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

impl <'a> ResumptionEvent<'a> {

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
        security,
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
}
