
//fn tracing_log(message: &[u8; 256], )

use core::ffi;
use std::{borrow::Cow, ffi::CStr};

use tracing::{Level, Metadata, field::{self, FieldSet}};

use crate::testing::s2n_tls;

    // unsafe extern "C" fn(
    //     message: *mut u8,
    //     module: *mut ::libc::c_char,
    //     line_number: ::libc::c_int,
    //     function: *mut ::libc::c_char,
    // ) -> ::libc::c_int,
unsafe extern "C" fn log_cb(
    message: *mut u8,
    module: *mut ffi::c_char,
    line_number: ffi::c_int,
    function: *mut ffi::c_char,
) -> i32 {
    let module = CStr::from_ptr(module).to_str().unwrap();
    let function = CStr::from_ptr(function).to_str().unwrap();
    let message = std::slice::from_raw_parts(message, s2n_tls_sys::PRINT_BUFFER_SIZE as usize);
    log(&String::from_utf8_lossy(message), module, line_number as u32, function);
    0
}

fn enable_tracing_log() {
    unsafe {s2n_tls_sys::s2n_set_global_log(Some(log_cb))};
}

pub(crate) fn log(message: &Cow<str>, location: &str, line_number: u32, function: &str) {
    let location = format!("{location:?}:{line_number}");
    tracing::debug!(message = "{message}", c_location = location, c_function = function);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_logs() {
        
    }
}