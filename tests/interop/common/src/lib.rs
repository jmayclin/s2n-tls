use std::env;

// `Common` provides a crate with functionality that other TLS implementors might find useful if they are implementing a 
// rust shim.

pub const CLIENT_GREETING: &str = "i am the client. nice to meet you server.";
pub const SERVER_GREETING: &str = "i am the server. a pleasure to make your acquaintance.";

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
        PemType::CaCert => concat!(env!("CARGO_MANIFEST_DIR"), "/..", "/certificates/ca-cert.pem"),
        PemType::ServerChain => concat!(env!("CARGO_MANIFEST_DIR"), "/..", "/certificates/server-chain.pem"),
        PemType::ServerKey => concat!(env!("CARGO_MANIFEST_DIR"), "/..", "/certificates/server-key.pem"),
    }
}

/// This method is used to parse the server arguments from the environment (argv)
/// 
/// It will the return the [InteropTest] that is being run, as well as the expected
/// port for the server to run on.
pub fn parse_server_arguments() -> (InteropTest, u16) {
    let args: Vec<String> = env::args().skip(1).collect();
    let test = InteropTest::parse_test(&args.get(0).expect("you must supply command line arguments"));
    let port = args[1].parse().unwrap();
    (test, port)
}

/// This enum contains all of the defined Interop Test types. See the readme for more
/// details.
#[derive(Copy, Clone)]
pub enum InteropTest {
    Handshake,
    Greeting,
    LargeDataDownload,
    LargeDataDownloadWithFrequentKeyUpdates,
}

impl InteropTest {
    fn parse_test(argument: &str) -> Self {
        match argument {
            "handshake" => InteropTest::Handshake,
            "greeting" => InteropTest::Greeting,
            "large_data_download" => InteropTest::LargeDataDownload,
            _ => panic!("unrecognized test type: {}", argument),
        }
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
