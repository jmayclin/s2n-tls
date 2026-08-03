// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module holds all of the "benchmark specific" configuration logic that is
//! used in the benchmark suites.
//!
//! Anything that is only relevant to the benchmarks should live in this module.
//! Similarly, anything that might be used outside of the benchmarks should _not_
//! live in this module.

use std::{debug_assert_eq, error::Error, fmt::Debug, task::Poll, todo};

mod setup;
#[cfg(test)]
mod test_utilities;

use tls_harness::{Mode, SigType, TlsConnPair, TlsConnection};

/// While ServerAuth and Resumption are not mutually exclusive, they are treated
/// as such for the purpose of benchmarking.
#[derive(Clone, Copy, Default, Eq, PartialEq, strum::EnumIter)]
pub enum HandshakeType {
    #[default]
    ServerAuth,
    MutualAuth,
    Resumption,
}

impl Debug for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeType::ServerAuth => write!(f, "server-auth"),
            HandshakeType::MutualAuth => write!(f, "mTLS"),
            HandshakeType::Resumption => write!(f, "resumption"),
        }
    }
}

// these parameters were the only ones readily usable for all three libaries:
// s2n-tls, rustls, and openssl
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, strum::EnumIter)]
pub enum CipherSuite {
    #[default]
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
}

#[derive(Clone, Copy, Default, strum::EnumIter)]
pub enum KXGroup {
    Secp256R1,
    #[default]
    X25519,
    X25519MLKEM768,
}

impl Debug for KXGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256R1 => write!(f, "secp256r1"),
            Self::X25519 => write!(f, "x25519"),
            Self::X25519MLKEM768 => write!(f, "X25519MLKEM768"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoConfig {
    pub cipher_suite: CipherSuite,
    pub kx_group: KXGroup,
    pub sig_type: SigType,
}

impl CryptoConfig {
    pub fn new(cipher_suite: CipherSuite, kx_group: KXGroup, sig_type: SigType) -> Self {
        Self {
            cipher_suite,
            kx_group,
            sig_type,
        }
    }
}

/// The TlsBenchConfig trait allows us to map benchmarking parameters to
/// a configuration object
pub trait TlsBenchConfig: Sized {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>>;
}

/// Initialize buffers, configs, and connections (pre-handshake)
pub fn new_bench_pair<C, S>(
    crypto_config: CryptoConfig,
    handshake_type: HandshakeType,
) -> Result<TlsConnPair<C, S>, Box<dyn Error>>
where
    C: TlsConnection,
    S: TlsConnection,
    C::Config: TlsBenchConfig,
    S::Config: TlsBenchConfig,
{
    // do an initial handshake to generate the session ticket
    if handshake_type == HandshakeType::Resumption {
        let server_config = S::Config::make_config(Mode::Server, crypto_config, handshake_type)?;
        let client_config = C::Config::make_config(Mode::Client, crypto_config, handshake_type)?;

        // handshake the client and server connections. This will result in
        // session ticket getting stored in client_config
        let mut pair = TlsConnPair::<C, S>::from_configs(&client_config, &server_config);
        pair.handshake()?;
        // NewSessionTicket messages are part of the application data and sent
        // after the handshake is complete, so we must trigger an additional
        // "read" on the client connection to ensure that the session ticket
        // gets received and stored in the config
        pair.round_trip_transfer(&mut [0]).unwrap();
        // OpenSSL doesn't allow resumption unless the session was cleanly shutdown
        pair.shutdown().unwrap();

        // new_from_config is called interally by the TlsConnPair::new
        // method and will check if a session ticket is available and set it
        // on the connection. This results in the session ticket in
        // client_config (from the previous handshake) getting set on the
        // client connection.
        return Ok(TlsConnPair::<C, S>::from_configs(
            &client_config,
            &server_config,
        ));
    }

    Ok(TlsConnPair::<C, S>::from_configs(
        &C::Config::make_config(Mode::Client, crypto_config, handshake_type).unwrap(),
        &S::Config::make_config(Mode::Server, crypto_config, handshake_type).unwrap(),
    ))
}

/// This should match the fragment behavior used by s2n-tls.
///
/// If it doesn't then there will be unnecessary write sys-calls
pub const DATA_COALESCER_BUFFER: usize = 8_000;

/// This struct can be used to coalesce a whole bunch of small buffers into a 
/// larger contiguous chunk.
/// 
/// In the case of a buffer larger than N, then a direct reference
/// to the buffer is returned.
/// 
/// In terms of s2n-tls behavior, there is still a degenerative case where using
/// this to write lots of RECORD_PAYLOAD + 1 sized buffers will result in 2 write 
/// syscalls for each buffer.
struct DataCoalescer<'a, const N: usize> {
    data: &'a [&'a [u8]],
    /// this point to the next slice to be sent.
    /// data_cursor == data.len() means that all data has been sent
    data_cursor: usize,

    coalesce_buffer: [u8; N],
    coalesce_cursor: usize,
}

impl<'a, const N: usize> DataCoalescer<'a, N> {
    fn new(data: &'a [&'a [u8]]) -> Self {
        Self {
            data,
            data_cursor: 0,
            coalesce_buffer: [0; N],
            coalesce_cursor: 0,
        }
    }

    // Note: the lifetime of the return value is tied to the reference to self
    fn slice_to_send(&mut self) -> Option<&[u8]> {
        while self.data_cursor < self.data.len() {
            let remaining = self.coalesce_buffer.len() - self.coalesce_cursor;
            let next_buffer = self.data[self.data_cursor];

            if next_buffer.len() > remaining {
                // we have filled the buffer all that we can
                break;
            }

            // the coalescing buffer can fit the next slice
            let remaining_range = &mut self.coalesce_buffer[self.coalesce_cursor..];
            let target_range = &mut remaining_range[0..next_buffer.len()];
            target_range.copy_from_slice(next_buffer);
            self.coalesce_cursor += next_buffer.len();
            self.data_cursor += 1;
        }

        let data_in_coalesce = self.coalesce_cursor != 0;
        let additional_slices = self.data_cursor != self.data.len();

        if data_in_coalesce {
            // there is data in the coalesce buffer, return that
            let next_slice = &self.coalesce_buffer[0..self.coalesce_cursor];
            self.coalesce_cursor = 0;
            Some(next_slice)
        } else if additional_slices {
            // no data in the coalescing buffer, but still data to be sent
            // this means that the next slice is a chonky boi
            let next_slice = self.data[self.data_cursor];
            self.data_cursor += 1;
            Some(next_slice)
        } else {
            None
        }
    }
}

pub trait PsuedoVectoredSend {
    fn poll_send_vector(&mut self, data: &[&[u8]]) -> Poll<Result<usize, s2n_tls::error::Error>>;

    fn poll_send_vector_with_buffer<const N: usize>(
        &mut self,
        data: &[&[u8]],
    ) -> Poll<Result<usize, s2n_tls::error::Error>>;
}

impl PsuedoVectoredSend for s2n_tls::connection::Connection {
    /// This exists to work around for a lack of granularity in s2n-tls IO.
    ///
    /// Ideally, there would be an API that lets us
    /// 1. append a slice to a record payload
    /// 2. finalize the record
    /// 3. send the record (syscall)
    /// But s2n-tls doesn't expose that level of granularity. The lack of control
    /// over the actual send syscall's is the largest problem, resulting in lots
    /// of useless context switching with tiny payloads.
    ///
    /// TODO: Figure out whether this return result is actually correct
    fn poll_send_vector(&mut self, data: &[&[u8]]) -> Poll<Result<usize, s2n_tls::error::Error>> {
        self.poll_send_vector_with_buffer::<DATA_COALESCER_BUFFER>(data)
    }

    fn poll_send_vector_with_buffer<const N: usize>(
        &mut self,
        data: &[&[u8]],
    ) -> Poll<Result<usize, s2n_tls::error::Error>> {
        let mut total_written = 0;
        let mut data_to_send = DataCoalescer::<N>::new(data);

        while let Some(data_chunk) = data_to_send.slice_to_send() {
            // loop to send all of data_chunk
            let mut data_chunk_written = 0;
            let total_data_chunk = data_chunk.len();
            while data_chunk_written < total_data_chunk {
                match self.poll_send(data_chunk) {
                    Poll::Ready(Ok(poll_written)) => {
                        data_chunk_written += poll_written;
                        total_written += poll_written;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        if total_written == 0 {
                            return Poll::Pending;
                        } else {
                            return Poll::Ready(Ok(total_written));
                        }
                    }
                };
            }
        }

        Poll::Ready(Ok(total_written))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tls_harness::{
        cohort::{OpenSslConnection, RustlsConnection, S2NConnection},
        harness::TlsInfo,
        TlsConnection,
    };

    #[test]
    fn rustls_handshakes() {
        test_utilities::all_handshakes::<RustlsConnection>();
    }

    #[test]
    fn openssl_handshakes() {
        test_utilities::all_handshakes::<OpenSslConnection>();
    }

    #[test]
    fn s2n_handshakes() {
        test_utilities::all_handshakes::<S2NConnection>();
    }

    #[test]
    fn rustls_transfer() {
        test_utilities::transfer::<RustlsConnection>();
    }

    #[test]
    fn openssl_transfer() {
        test_utilities::transfer::<OpenSslConnection>();
    }

    #[test]
    fn s2n_transfer() {
        test_utilities::transfer::<S2NConnection>();
    }

    fn session_resumption<C, S>()
    where
        S: TlsConnection + TlsInfo,
        C: TlsConnection + TlsInfo,
        C::Config: TlsBenchConfig,
        S::Config: TlsBenchConfig,
    {
        println!("testing with client:{} server:{}", C::name(), S::name());
        let mut conn_pair =
            new_bench_pair::<C, S>(CryptoConfig::default(), HandshakeType::Resumption).unwrap();
        conn_pair.handshake().unwrap();
        // read the session tickets which were sent
        let err = conn_pair.client_mut().recv(&mut [0]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        assert!(conn_pair.server().resumed_connection());
        conn_pair.shutdown().unwrap();
    }

    #[test]
    fn session_resumption_interop() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init()
            .unwrap();
        session_resumption::<S2NConnection, S2NConnection>();
        session_resumption::<S2NConnection, RustlsConnection>();
        session_resumption::<S2NConnection, OpenSslConnection>();

        session_resumption::<RustlsConnection, RustlsConnection>();
        session_resumption::<RustlsConnection, S2NConnection>();
        session_resumption::<RustlsConnection, OpenSslConnection>();

        session_resumption::<OpenSslConnection, OpenSslConnection>();
        session_resumption::<OpenSslConnection, S2NConnection>();
        session_resumption::<OpenSslConnection, RustlsConnection>();
    }
}

#[cfg(test)]
mod vector_send_tests {
    use super::{DataCoalescer, DATA_COALESCER_BUFFER};

    /// Helper to collect all slices from a DataCoalescer and return the
    /// concatenated bytes along with the number of slices vended.
    fn collect_all(data: &[&[u8]]) -> (Vec<u8>, usize) {
        let mut coalescer = DataCoalescer::<DATA_COALESCER_BUFFER>::new(data);
        let mut result = Vec::new();
        let mut slice_count = 0;
        while let Some(slice) = coalescer.slice_to_send() {
            result.extend_from_slice(slice);
            slice_count += 1;
        }
        (result, slice_count)
    }

    /// Concatenate all input slices into a single expected Vec for comparison.
    fn expected_bytes(data: &[&[u8]]) -> Vec<u8> {
        data.iter().flat_map(|s| s.iter().copied()).collect()
    }

    #[test]
    fn empty_input() {
        let data: &[&[u8]] = &[];
        let mut coalescer = DataCoalescer::<DATA_COALESCER_BUFFER>::new(data);
        assert!(coalescer.slice_to_send().is_none());
    }

    #[test]
    fn single_small_buffer() {
        let buf = b"hello world";
        let data: &[&[u8]] = &[buf];
        let (result, slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        // A single small buffer should be coalesced into one slice
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn multiple_small_buffers_coalesce() {
        // Many small buffers that together fit within DATA_COALESCER_BUFFER
        let buf_a = [1u8; 100];
        let buf_b = [2u8; 200];
        let buf_c = [3u8; 300];
        let data: &[&[u8]] = &[&buf_a, &buf_b, &buf_c];
        let (result, slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        // All fit in one coalesced chunk
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn single_large_buffer_not_coalesced() {
        // A buffer larger than DATA_COALESCER_BUFFER should be returned directly
        let large_buf = vec![42u8; DATA_COALESCER_BUFFER + 1];
        let data: &[&[u8]] = &[&large_buf];
        let (result, slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        // Should be vended as a direct slice (not coalesced)
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn small_then_large_buffer() {
        // A small buffer followed by a large one: small gets coalesced first,
        // then large is vended directly
        let small_buf = [1u8; 100];
        let large_buf = vec![2u8; DATA_COALESCER_BUFFER + 1];
        let data: &[&[u8]] = &[&small_buf, &large_buf];
        let (result, slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        assert_eq!(slice_count, 2);
    }

    #[test]
    fn large_then_small_buffer() {
        let large_buf = vec![1u8; DATA_COALESCER_BUFFER + 1];
        let small_buf = [2u8; 100];
        let data: &[&[u8]] = &[&large_buf, &small_buf];
        let (result, slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        assert_eq!(slice_count, 2);
    }

    #[test]
    fn buffers_that_exactly_fill_coalescer() {
        // Two buffers that together exactly fill DATA_COALESCER_BUFFER
        let half = DATA_COALESCER_BUFFER / 2;
        let buf_a = vec![1u8; half];
        let buf_b = vec![2u8; DATA_COALESCER_BUFFER - half];
        let data: &[&[u8]] = &[&buf_a, &buf_b];
        let (result, slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn buffers_that_overflow_coalescer() {
        // Several buffers that collectively exceed DATA_COALESCER_BUFFER,
        // forcing multiple coalesced slices
        let chunk_size = DATA_COALESCER_BUFFER / 3;
        let buf_a = vec![1u8; chunk_size];
        let buf_b = vec![2u8; chunk_size];
        let buf_c = vec![3u8; chunk_size];
        let buf_d = vec![4u8; chunk_size];
        let buf_e = vec![5u8; chunk_size];
        let data: &[&[u8]] = &[&buf_a, &buf_b, &buf_c, &buf_d, &buf_e];
        let (result, _slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        // Should require more than one vended slice
        assert!(_slice_count >= 2);
    }

    #[test]
    fn many_tiny_buffers() {
        // Lots of 1-byte buffers should all coalesce into a single slice
        let bufs: Vec<[u8; 1]> = (0..100).map(|i| [i as u8]).collect();
        let data: Vec<&[u8]> = bufs.iter().map(|b| b.as_slice()).collect();
        let (result, slice_count) = collect_all(&data);
        assert_eq!(result, expected_bytes(&data));
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn data_integrity_with_mixed_sizes() {
        // Mix of various sizes to ensure data ordering is preserved
        let buf_a = b"hello";
        let buf_b = vec![0xAB; DATA_COALESCER_BUFFER + 500];
        let buf_c = b"world";
        let buf_d = vec![0xCD; DATA_COALESCER_BUFFER / 2];
        let buf_e = vec![0xEF; DATA_COALESCER_BUFFER / 2];
        let buf_f = b"!";
        let data: &[&[u8]] = &[buf_a, &buf_b, buf_c, &buf_d, &buf_e, buf_f];
        let (result, _) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
    }

    #[test]
    fn exact_coalescer_size_buffer() {
        // A single buffer that is exactly DATA_COALESCER_BUFFER bytes
        let buf = vec![7u8; DATA_COALESCER_BUFFER];
        let data: &[&[u8]] = &[&buf];
        let (result, slice_count) = collect_all(data);
        assert_eq!(result, expected_bytes(data));
        assert_eq!(slice_count, 1);
    }
}