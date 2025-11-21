
//fn tracing_log(message: &[u8; 256], )

use core::ffi;
use std::{borrow::Cow, ffi::CStr};

use tracing::{Level, Metadata, field::{self, FieldSet}};

unsafe extern "C" fn log_cb(
    message: *const u8,
    module: *const ffi::c_char,
    line_number: ffi::c_int,
    function: *const ffi::c_char,
) {
    let module = CStr::from_ptr(module).to_str().unwrap();
    let function = CStr::from_ptr(function).to_str().unwrap();
    let message = std::slice::from_raw_parts(message, s2n_tls_sys::PRINT_BUFFER_SIZE as usize);
    log(&String::from_utf8_lossy(message), module, line_number as u32, function);
}

pub fn enable_logging() {
    unsafe {s2n_tls_sys::s2n_set_global_log(Some(log_cb))};
}

/// Log the message to stdout with a nicely formatted location.
/// 
/// Ideally we'd use something like `tracing` to have richer functionality, but 
/// tracing requires the emitting location to be available as a constant at compile
/// time. This doesn't work because the rust callback only leans about the log location
/// at runtime.
/// 
/// So instead we just use println. Note that this is still an improvement over 
/// just using printf on the rust side because it lets the rust test harness correctly
/// capture the output when using the standard rust test harness.
pub(crate) fn log(message: &Cow<str>, location: &str, line_number: u32, function: &str) {
    print!("[{location}:{line_number}-{function}] {message}");
}
#[cfg(test)]
mod tests {
    #[test]
    fn it_logs() {
        
    }
}