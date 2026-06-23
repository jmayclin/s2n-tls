////////////////////////////////////////////////////////////////////////////////
///////////////////// generic Read & Write C callbacks /////////////////////////
////////////////////////////////////////////////////////////////////////////////

use std::{
    any::type_name,
    ffi::{c_int, c_void},
};

// This callback can be used where ctx is `Box<T: Write>`
pub(crate) unsafe extern "C" fn generic_send_cb<T: std::io::Write>(
    context: *mut c_void,
    data: *const u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts(data, len as _);
    match context.write(data) {
        Ok(bytes_written) => bytes_written as i32,
        Err(err) => {
            match err.raw_os_error() {
                Some(os_err) => {
                    tracing::debug!("setting errno for {err}");
                    errno::set_errno(errno::Errno(os_err))
                }
                None => {
                    tracing::warn!("Err {err} doesn't have a corresponding os err 😬")
                }
            }
            -1
        }
    }
}

// This callback can be used where ctx is `Box<T: Read>`
pub(crate) unsafe extern "C" fn generic_recv_cb<T: std::io::Read>(
    raw_context: *mut c_void,
    data: *mut u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(raw_context as *mut T);
    let data = core::slice::from_raw_parts_mut(data, len as _);
    tracing::trace!(
        "generic recv cb {:?} into: buffer of size {}",
        type_name::<T>(),
        data.len()
    );
    let read_result = context.read(data);
    tracing::trace!("generic recv cb: read result: {read_result:?}");
    match read_result {
        Ok(len) => {
            if len == 0 {
                // returning a length of 0 indicates a channel close (e.g. a
                // TCP Close) which would not be correct here since this is used
                // with shared memory structs (e.g. VecDeque). To just communicate
                // that there is no more data, we instead set the errno to
                // WouldBlock and return -1.
                errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                -1
            } else {
                len as c_int
            }
        }
        Err(err) => {
            match err.raw_os_error() {
                Some(os_err) => {
                    tracing::debug!("setting errno for {err}");
                    errno::set_errno(errno::Errno(os_err))
                }
                None => {
                    tracing::warn!("Err {err} doesn't have a corresponding os err 😬")
                }
            }
            -1
        }
    }
}
