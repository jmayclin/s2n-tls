use std::{
    collections::HashMap,
    fmt::Display,
    sync::{LazyLock, Mutex},
};

use crate::static_lists::TlsParam;

/// The state of the parameter, either `Negotiated` or `Supported`.
///
/// This enum makes it easy for us to generate the correct metrics labels. e.g.
/// `cipher.supported.TLS_AES_256_GCM_SHA384`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum State {
    Negotiated,
    // Supported,
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Negotiated => write!(f, "negotiated"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MetricLabel {
    /// e.g. "TLS_AES_256_GCM_SHA384" or "mlkem1024"
    item: &'static str,
    parameter: TlsParam,
    state: State,
}

impl MetricLabel {
    fn new(item: &'static str, parameter: TlsParam, state: State) -> Self {
        Self {
            item,
            parameter,
            state,
        }
    }

    fn value(&self) -> String {
        format!("{}.{}.{}", self.state, self.parameter, self.item)
    }
}

/// We want all of our counters to be prefixed, e.g. `group.secp256r1`
///
/// metrique needs the string to be static, so we deliberately "leak" the data.
///
/// This is acceptable because it's just a finite set of values.
pub(crate) struct MetricLabeller {
    /// lookup from raw item to prefixed item
    prefixes: Mutex<HashMap<MetricLabel, &'static str>>,
}

impl MetricLabeller {
    pub(crate) fn label(item: &'static str, parameter: TlsParam, state: State) -> &'static str {
        static PREFIXER: LazyLock<MetricLabeller> = LazyLock::new(|| MetricLabeller {
            prefixes: Mutex::new(HashMap::new()),
        });

        let key = MetricLabel::new(item, parameter, state);
        PREFIXER
            .prefixes
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_insert_with(|| key.value().leak())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_output() {
        assert_eq!(
            MetricLabeller::label(
                "TLS_AES_256_GCM_SHA384",
                TlsParam::Cipher,
                State::Negotiated
            ),
            "negotiated.cipher.TLS_AES_256_GCM_SHA384"
        );
    }
}
