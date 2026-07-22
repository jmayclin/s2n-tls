use s2n_tls::{
    config,
    error::ErrorType,
    security::Policy,
    testing::{self, TestPair},
};
use std::{io::Write, sync::OnceLock, task::Poll, time::SystemTime};

extern "C" {
    #[link_name = "aws_lc_0_43_0_CRYPTO_get_thread_local"]
    fn CRYPTO_get_thread_local(index: u32) -> *mut core::ffi::c_void;
    #[link_name = "aws_lc_0_43_0_CTR_DRBG_init"]
    fn CTR_DRBG_init(drbg: *mut core::ffi::c_void, entropy: *const u8, personalization: *const u8, personalization_len: usize) -> i32;
    #[link_name = "aws_lc_0_43_0_RAND_bytes"]
    fn RAND_bytes(out: *mut u8, len: usize) -> i32;
    #[link_name = "aws_lc_0_43_0_RAND_public_bytes"]
    fn RAND_public_bytes(out: *mut u8, len: usize) -> i32;
}

unsafe fn fuzz_reset_rand() {
    let mut dummy = [0u8; 1];
    RAND_bytes(dummy.as_mut_ptr(), dummy.len());
    RAND_public_bytes(dummy.as_mut_ptr(), dummy.len());
    let zero_entropy = [0u8; 48];
    for key in [5u32, 6] {
        let state = CRYPTO_get_thread_local(key);
        if !state.is_null() {
            CTR_DRBG_init(state, zero_entropy.as_ptr(), core::ptr::null(), 0);
        }
    }
}

fn get_config() -> &'static config::Config {
    static CONFIG: OnceLock<config::Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        s2n_tls::init::init();
        let mut builder = testing::config_builder(&Policy::from_version("default_tls13").unwrap()).unwrap();
        builder.enable_quic().unwrap();
        builder.add_session_ticket_key(b"fuzz_key", &[0u8; 16], SystemTime::UNIX_EPOCH).unwrap();
        builder.build().unwrap()
    })
}

#[test]
fn find_stuffer_error_input() {
    let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join("server_handshake");
    for entry in std::fs::read_dir(&corpus_dir).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() { continue; }
        let data = std::fs::read(entry.path()).unwrap();
        let config = get_config();
        unsafe { fuzz_reset_rand(); }
        let mut pair = TestPair::from_config(config);
        pair.server.enable_quic().unwrap();
        pair.io.client_tx_stream.borrow_mut().write_all(&data).unwrap();
        loop {
            match pair.server.poll_negotiate() {
                Poll::Ready(Err(e)) if e.kind() == ErrorType::InternalError && format!("{:?}", e).contains("STUFFER") => {
                    println!("STUFFER error from file: {} ({} bytes)", entry.path().display(), data.len());
                    println!("  error: {:?}", e);
                    println!("  hex: {:?}", &data[..std::cmp::min(32, data.len())]);
                    return;
                }
                Poll::Ready(_) | Poll::Pending => break,
            }
        }
    }
    panic!("no stuffer error found");
}
