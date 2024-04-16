use std::{env, fmt::Display, str::FromStr};

// `Common` provides a crate with functionality that other TLS implementors might find useful if they are implementing a
// rust shim.

pub const CLIENT_GREETING: &str = "i am the client. nice to meet you server.";
pub const SERVER_GREETING: &str = "i am the server. a pleasure to make your acquaintance.";

/// amount of data that will be downloaded by the large download test
pub const LARGE_DATA_DOWNLOAD_GB: u64 = 256;

/// If a server or client doesn't support a test case, then the process should
/// exit with this value.
pub const UNIMPLEMENTED_RETURN_VAL: i32 = 127;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub enum PemType {
    CaCert,
    ServerChain,
    ServerKey,
}

pub fn pem_file_path(file: PemType) -> &'static str {
    match file {
        PemType::CaCert => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/ca-cert.pem"
        ),
        PemType::ServerChain => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/server-chain.pem"
        ),
        PemType::ServerKey => concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/..",
            "/certificates/server-key.pem"
        ),
    }
}

/// This method is used to parse the server arguments from the environment (argv)
///
/// It will the return the [InteropTest] that is being run, as well as the expected
/// port for the server to run on.
pub fn parse_server_arguments() -> (InteropTest, u16) {
    let args: Vec<String> = env::args().skip(1).collect();
    let test: InteropTest = args
        .get(0)
        .expect("you must supply command line arguments")
        .parse()
        .unwrap();
    let port = args[1].parse().unwrap();
    (test, port)
}

/// This enum contains all of the defined Interop Test types. See the readme for more
/// details.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InteropTest {
    Handshake,
    Greeting,
    LargeDataDownload,
    LargeDataDownloadWithFrequentKeyUpdates,
}

// Fromt/Into should work here without two separate impls, but they are defeating me
impl<T: AsRef<str>> From<T> for InteropTest {
fn from(value: T) -> Self {
        let value = value.as_ref();
        match value {
            "handshake" => InteropTest::Handshake,
            "greeting" => InteropTest::Greeting,
            "large_data_download" => InteropTest::LargeDataDownload,
            _ => panic!("unrecognized test type: {}", value),
        }
    }
}

impl FromStr for InteropTest {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = match s {
            "handshake" => InteropTest::Handshake,
            "greeting" => InteropTest::Greeting,
            "large_data_download" => InteropTest::LargeDataDownload,
            "large_data_download_with_frequent_key_updates" => {
                InteropTest::LargeDataDownloadWithFrequentKeyUpdates
            }
            _ => return Err(format!("unrecognized test type: {}", s)),
        };
        Ok(name)
    }
}

impl Display for InteropTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            InteropTest::Handshake => "handshake",
            InteropTest::Greeting => "greeting",
            InteropTest::LargeDataDownload => "large_data_download",
            InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
                "large_data_download_with_frequent_key_updates"
            }
        };
        write!(f, "{}", name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_paths_valid() {
        std::fs::read(pem_file_path(PemType::CaCert)).unwrap();
        std::fs::read(pem_file_path(PemType::ServerChain)).unwrap();
        std::fs::read(pem_file_path(PemType::ServerKey)).unwrap();
    }
}
