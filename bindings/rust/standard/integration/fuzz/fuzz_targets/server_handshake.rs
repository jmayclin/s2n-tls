// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use libfuzzer_sys::fuzz_target;
use s2n_tls::{
    config,
    error::ErrorType,
    security::Policy,
    testing::{self, TestPair},
};
use std::{io::Write, sync::OnceLock, task::Poll, time::SystemTime};

/// The maximum number of bytes the server is allowed to allocate during a
/// handshake attempt. Any fuzz input that causes the server to exceed this
/// threshold indicates a potential memory amplification vulnerability.
const MAX_ALLOCATION_BYTES: usize = 150 * 1024;

mod memory_callbacks {
    use std::alloc::Layout;

    /// A tagged allocator which prefixes each blob with the length of the
    /// allocation. This is necessary because aws-lc's `free` callback does not
    /// provide the allocation size, but [`std::alloc::dealloc`] requires it.
    struct TaggedAllocation {
        allocation: *mut u8,
        size: usize,
    }

    impl TaggedAllocation {
        const ALIGNMENT: usize = size_of::<usize>();
        const USIZE_WIDTH: usize = size_of::<usize>();

        pub fn public_allocation(&self) -> *mut u8 {
            unsafe { self.allocation.add(Self::USIZE_WIDTH) }
        }

        unsafe fn alloc(public_size: usize) -> Self {
            let needed_size = public_size + Self::USIZE_WIDTH;
            let layout = Layout::from_size_align(needed_size, Self::ALIGNMENT).unwrap();
            let allocation = std::alloc::alloc(layout);
            (allocation as *mut usize).write(needed_size);
            Self {
                allocation,
                size: needed_size,
            }
        }

        unsafe fn from_public_view(public_view: *mut u8) -> Self {
            let alloc_start = (public_view as *mut usize).sub(1);
            let size = (alloc_start as *mut usize).read();
            Self {
                allocation: alloc_start as *mut u8,
                size,
            }
        }

        unsafe fn realloc(&mut self, new_public_size: usize) {
            let new_size = new_public_size + Self::USIZE_WIDTH;
            let old_layout = Layout::from_size_align(self.size, Self::ALIGNMENT).unwrap();
            let allocation = std::alloc::realloc(self.allocation, old_layout, new_size);
            (allocation as *mut usize).write(new_size);
            self.allocation = allocation;
            self.size = new_size;
        }

        unsafe fn free(self) {
            let layout = Layout::from_size_align(self.size, Self::ALIGNMENT).unwrap();
            std::alloc::dealloc(self.allocation, layout);
        }
    }

    pub unsafe extern "C" fn malloc_cb(
        num: usize,
        _file: *const std::ffi::c_char,
        _line: i32,
    ) -> *mut std::ffi::c_void {
        let allocation = TaggedAllocation::alloc(num);
        allocation.public_allocation() as *mut _
    }

    pub unsafe extern "C" fn realloc_cb(
        addr: *mut std::ffi::c_void,
        num: usize,
        _file: *const std::ffi::c_char,
        _line: i32,
    ) -> *mut std::ffi::c_void {
        let mut allocation = TaggedAllocation::from_public_view(addr as *mut _);
        allocation.realloc(num);
        allocation.public_allocation() as *mut _
    }

    pub unsafe extern "C" fn free_cb(
        addr: *mut std::ffi::c_void,
        _file: *const std::ffi::c_char,
        _line: i32,
    ) {
        let allocation = TaggedAllocation::from_public_view(addr as *mut _);
        allocation.free();
    }
}

// Deterministic randomness for fuzzing. We reach into aws-lc internals to
// forcibly reinitialize the thread-local DRBGs with known entropy so that
// the server's behavior depends only on the fuzz input.
extern "C" {
    #[link_name = "aws_lc_0_43_0_CRYPTO_get_thread_local"]
    fn CRYPTO_get_thread_local(index: u32) -> *mut core::ffi::c_void;

    #[link_name = "aws_lc_0_43_0_CTR_DRBG_init"]
    fn CTR_DRBG_init(
        drbg: *mut core::ffi::c_void,
        entropy: *const u8,
        personalization: *const u8,
        personalization_len: usize,
    ) -> i32;

    #[link_name = "aws_lc_0_43_0_RAND_bytes"]
    fn RAND_bytes(out: *mut u8, len: usize) -> i32;

    #[link_name = "aws_lc_0_43_0_RAND_public_bytes"]
    fn RAND_public_bytes(out: *mut u8, len: usize) -> i32;
}

const OPENSSL_THREAD_LOCAL_PRIVATE_RAND: u32 = 5;
const OPENSSL_THREAD_LOCAL_PUBLIC_RAND: u32 = 6;
const CTR_DRBG_ENTROPY_LEN: usize = 48;

unsafe fn fuzz_reset_rand() {
    // Force both private and public DRBGs to initialize by pulling a single byte
    // from them.
    let mut dummy = [0u8; 1];
    RAND_bytes(dummy.as_mut_ptr(), dummy.len());
    RAND_public_bytes(dummy.as_mut_ptr(), dummy.len());

    let zero_entropy = [0u8; CTR_DRBG_ENTROPY_LEN];
    for key in [OPENSSL_THREAD_LOCAL_PRIVATE_RAND, OPENSSL_THREAD_LOCAL_PUBLIC_RAND] {
        let state = CRYPTO_get_thread_local(key);
        if !state.is_null() {
            CTR_DRBG_init(state, zero_entropy.as_ptr(), core::ptr::null(), 0);
        }
    }
}

fn get_config() -> &'static config::Config {
    static CONFIG: OnceLock<config::Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        unsafe {
            aws_lc_sys::CRYPTO_set_mem_functions(
                Some(memory_callbacks::malloc_cb),
                Some(memory_callbacks::realloc_cb),
                Some(memory_callbacks::free_cb),
            );
        }

        s2n_tls::init::init();

        let mut builder = testing::config_builder(&Policy::from_version("default_tls13").unwrap())
            .unwrap();
        builder.enable_quic().unwrap();
        builder
            .add_session_ticket_key(b"fuzz_key", &[0u8; 16], SystemTime::UNIX_EPOCH)
            .unwrap();
        builder.build().unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let config = get_config();

    unsafe { fuzz_reset_rand(); }
    
    let _profiler = dhat::Profiler::builder().testing().build();

    let mut pair = TestPair::from_config(config);
    pair.server.enable_quic().unwrap();

    // Feed the fuzz input directly into the buffer the server reads from,
    // simulating a client sending arbitrary bytes.
    pair.io.client_tx_stream.borrow_mut().write_all(data).unwrap();

    // Drive the server handshake until it blocks or errors.
    loop {
        match pair.server.poll_negotiate() {
            Poll::Ready(Ok(_)) => break,
            Poll::Ready(Err(e)) => {
                // assert_ne!(
                //     e.kind(),
                //     ErrorType::InternalError,
                //     "internal error during handshake: {e:?}"
                // );
                break;
            }
            Poll::Pending => break,
        }
    }

    // Explicitly drop the pair so dhat records the deallocations before we
    // check stats.
    drop(pair);

    let stats = dhat::HeapStats::get();
    if stats.max_bytes > MAX_ALLOCATION_BYTES {
        panic!(
            "server allocated {} bytes (limit: {} bytes) for {} bytes of input",
            stats.max_bytes,
            MAX_ALLOCATION_BYTES,
            data.len()
        );
    }
});
