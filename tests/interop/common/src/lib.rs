use std::env;

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
        PemType::ServerChain => concat!(env!("CARGO_MANIFEST_DIR"), "/..", "/certificates/ca-cert.pem"),
        PemType::ServerKey => concat!(env!("CARGO_MANIFEST_DIR"), "/..", "/certificates/ca-cert.pem"),
    }
}

pub fn parse_server_arguments() -> (InteropTest, u16) {
    let args: Vec<String> = env::args().skip(1).collect();
    let test = InteropTest::parse_test(&args[0]);
    let port = args[1].parse().unwrap();
    (test, port)
}

pub enum InteropTest {
    Handshake,
    LargeDataDownload,
}

impl InteropTest {
    fn parse_test(argument: &str) -> Self {
        match argument {
            "handshake" => InteropTest::Handshake,
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
