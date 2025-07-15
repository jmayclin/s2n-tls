use std::{
    ffi::{c_int, c_void},
    io::ErrorKind,
    net::TcpStream,
    ops::{Deref, DerefMut},
    pin::Pin,
};

pub(crate) unsafe extern "C" fn generic_send_cb<T: std::io::Write>(
    context: *mut c_void,
    data: *const u8,
    len: u32,
) -> c_int {
    // we need to double box because Box<dyn Write> is a fat pointer (16 bytes)
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts(data, len as _);
    let bytes_written = match context.write(data) {
        Ok(written) => written,
        // probably need to handle the "would block" error
        Err(e) => todo!("handle errors like {e:?}"),
    };
    bytes_written as c_int
}

pub(crate) unsafe extern "C" fn generic_recv_cb<T: std::io::Read>(
    context: *mut c_void,
    data: *mut u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts_mut(data, len as _);
    match context.read(data) {
        Ok(len) => len as c_int,
        Err(err) => {
            if err.kind() == ErrorKind::WouldBlock {
                -1
            } else {
                todo!("handle other errors like {err:?}");
                //panic!("unrecognized error {err:?}")
            }
        }
    }
}

struct S2NStream {
    // we need to pin the box because the send and recv contexts are stored as
    // raw pointers
    stream: Pin<Box<std::net::TcpStream>>,
    connection: s2n_tls::connection::Connection,
}

impl S2NStream {
    fn new(
        mut connection: s2n_tls::connection::Connection,
        stream: std::net::TcpStream,
    ) -> Result<Self, s2n_tls::error::Error> {
        let pinned_stream = Box::pin(stream);
        let stream_ptr = pinned_stream.as_ref().get_ref() as *const TcpStream as *mut c_void;
        connection.set_send_callback(Some(generic_send_cb::<std::net::TcpStream>))?;
        connection.set_receive_callback(Some(generic_recv_cb::<std::net::TcpStream>))?;
        unsafe { connection.set_send_context(stream_ptr) }?;
        unsafe { connection.set_receive_context(stream_ptr) }?;

        Ok(Self {
            stream: pinned_stream,
            connection,
        })
    }
}

impl Deref for S2NStream {
    type Target = s2n_tls::connection::Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for S2NStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}
