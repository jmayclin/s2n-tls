use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");
    
    // Get the s2n-tls-sys directory path
    let s2n_tls_sys_dir = PathBuf::from("../../extended/s2n-tls-sys");
    
    // The include path to the s2n-tls-sys C library headers
    let s2n_lib_include_path = s2n_tls_sys_dir.join("lib");
    
    // Generate the bindings
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for
        .header("wrapper.h")
        
        // Add include path for the s2n-tls C library headers
        .clang_arg(format!("-I{}", s2n_lib_include_path.display()))
        .clang_arg(format!("-I{}/api", s2n_lib_include_path.display()))

        .size_t_is_usize(true)
        .allowlist_type("s2n_security_policy_selection")
        .allowlist_type("s2n_security_policy")
        .allowlist_type("s2n_cipher_preferences")
        .allowlist_type("s2n_cipher_suite")
        .allowlist_type("s2n_ecc_preferences")
        .allowlist_type("s2n_ecc_named_curve")
        .allowlist_type("s2n_kem_preferences")
        .allowlist_type("s2n_kem_group")
        .allowlist_var("security_policy_selection")
        
        // Generate the bindings
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
