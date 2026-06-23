use connection_serialization::{HandshakeOffloadingConnection, PING_PONG_VOLLEYS, server_config};
use s2n_tls_tokio::TlsAcceptor;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::main]
async fn main() {
    let config = server_config().unwrap();
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    let server = TlsAcceptor::new(config);

    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        tokio::spawn({
            let server = server.clone();
            async move {
                let mut tls_stream = server.accept(stream).await.unwrap();

                tls_stream.write_all(b"ready").await.unwrap();

                for _ in 0..PING_PONG_VOLLEYS {
                    let mut pong_buffer = [0; 4];
                    tls_stream.read_exact(&mut pong_buffer).await.unwrap();
                    tls_stream.write_all(b"pong").await.unwrap();
                }
            }
        });
    }
}
