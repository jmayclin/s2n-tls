// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// conditionally declare the module only if `feature` is enabled. If the
/// feature is enabled, import all symbols into the main namespace.
/// Disable rustfmt because it wants the `mod` and `pub use` statement to be on
/// different levels of indentation
#[rustfmt::skip]
macro_rules! conditional_module {
    ($mod_name:ident, $feature_name:literal) => {
        // bindgen will automatically rustfmt everything, but we use nightly rustfmt as
        // the authoritiative rustfmt so that doesn't work for us
        #[cfg(feature = $feature_name)]
        #[rustfmt::skip]
        mod $mod_name;

        #[cfg(feature = $feature_name)]
        pub use $mod_name::*;
    };
}

/// Same as conditional_module but also excludes the module on Windows.
/// Used for modules whose headers are not available on Windows (e.g. gated
/// behind #ifndef _WIN32).
#[rustfmt::skip]
macro_rules! conditional_module_not_windows {
    ($mod_name:ident, $feature_name:literal) => {
        #[cfg(all(feature = $feature_name, not(windows)))]
        #[rustfmt::skip]
        mod $mod_name;

        #[cfg(all(feature = $feature_name, not(windows)))]
        pub use $mod_name::*;
    };
}

conditional_module!(quic, "quic");
conditional_module!(internal, "internal");
conditional_module!(renegotiate, "unstable-renegotiate");
conditional_module!(custom_x509_extensions, "unstable-custom_x509_extensions");
conditional_module!(npn, "unstable-npn");
conditional_module_not_windows!(ktls, "unstable-ktls");
conditional_module!(async_offload, "unstable-async_offload");
conditional_module!(cert_authorities, "unstable-cert_authorities");
conditional_module!(crl, "unstable-crl");
conditional_module!(fingerprint, "unstable-fingerprint");
conditional_module!(cleanup, "unstable-cleanup");
conditional_module!(events, "unstable-events");
conditional_module!(allow_ip_in_cn, "unstable-allow_ip_in_cn");
// conditional_module!(foo, "unstable-foo");
