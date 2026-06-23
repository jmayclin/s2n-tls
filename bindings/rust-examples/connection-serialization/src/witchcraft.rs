use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Sleep;

pub struct MyTlsStream {
    connection: s2n_tls::connection::Connection,
    transport: tokio::net::TcpStream,
    blinding: Option<Pin<Box<Sleep>>>,
    shutdown_error: Option<s2n_tls::error::Error>,
}

pub fn to_tokio_connection(
    connection: s2n_tls::connection::Connection,
    transport: tokio::net::TcpStream,
) -> s2n_tls_tokio::TlsStream<tokio::net::TcpStream> {
    let my_stream = MyTlsStream {
        connection,
        transport,
        blinding: None,
        shutdown_error: None,
    };
    unsafe {
        // probably not safe :AHHHHHHHH
        std::mem::transmute(my_stream)
    }
}
