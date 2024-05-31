// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// use s2n_tls_sys::*;

// fn main() {
//     unsafe {
//         s2n_init();
//         let conn = s2n_connection_new(s2n_mode::SERVER);

//         if !conn.is_null() {
//             s2n_connection_free(conn);
//         }
//     }
// }

// had to update the rust toolchain, c_char isn't available in 1.63
use crabgrind as cg;

// valgrind --tool=callgrind   --cache-sim=yes --branch-sim=yes ../target/release/integration
// callgrind_annotate --inclusive=yes callgrind.out.40657.3 > dump_annotation.txt

// can get an estimated cycle count based on https://stackoverflow.com/questions/38311201/kcachegrind-cycle-estimation




fn main() {
    cg::callgrind::zero_stats();

    s2n_tls::init::init();
    cg::callgrind::dump_stats("s2n_init");

    // we do default initialization here ? Maybe, or I was just passing in the wrong
    // arguments
    let polluted_config = s2n_tls::config::Config::new();
    cg::callgrind::dump_stats("s2n_config_with_default");
    cg::callgrind::zero_stats();

    // no more default initialization, just the cert loading
    let mut builder = s2n_tls::config::Config::builder();
    builder.with_system_certs(false).unwrap();
    builder.build().unwrap();
    cg::callgrind::dump_stats("s2n_config_new_minimal");
    cg::callgrind::zero_stats();

    println!("testing a println");
    cg::callgrind::dump_stats(None);
}
