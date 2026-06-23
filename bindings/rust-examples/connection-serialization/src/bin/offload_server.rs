use connection_serialization::{HandshakeOffloadingConnection, PING_PONG_VOLLEYS, server_config};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::main]
async fn main() {
    let config = server_config().unwrap();
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        tokio::spawn({
            let config = config.clone();
            async {
                let offloaded_connection = HandshakeOffloadingConnection::new(stream, config);
                let mut tls_stream = offloaded_connection.handshake().await.unwrap();

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
