use std::{
    borrow::BorrowMut,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use bench::{
    harness::TlsBenchConfig, CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup, OpenSslConnection, RustlsConnection, S2NConnection, SigType, TlsConnPair, TlsConnection
};

fn large_data_server<C>(mut stream: TcpStream)
where
    C: TlsConnection,
    C::Config: TlsBenchConfig,
{
    const APP_REQUEST: &str = "gimme data";
    const APP_THANKS: &str = "thanks for the data";
    const SERVER_ACK: &str = "no problem, i gotchu";
    const MB: usize = 1_000_000;
    const GB: usize = 1_000_000_000;

    // the java client is set up to use the
    let crypto_config =
        CryptoConfig::new(CipherSuite::default(), KXGroup::default(), SigType::Rsa2048);

    let server_config = C::Config::make_config(
        bench::Mode::Server,
        crypto_config,
        HandshakeType::ServerAuth,
    )
    .unwrap();
    let server_buffer = ConnectedBuffer::default();
    let mut client_buffer = server_buffer.clone_inverse();

    let mut server = C::new_from_config(&server_config, server_buffer).unwrap();

    // handshake between the JVM client and the
    {
        // used to ferry information between the TCP stream and the connected buffer
        // we can't directly read to the copied buffer because it's a vecdequeue
        // (or maybe we can, but for now this is easiest)
        let mut buffer = vec![0; 1_000_000];

        while !server.handshake_completed() {
            println!("gonna read from client buffer");
            // if there is something to write to the client, write it to the stream
            if let Ok(length) = client_buffer.read(&mut buffer) {
                // write the server stuff into the stream
                println!("length of server hello: {}", length);
                stream.write_all(&buffer[0..length]).unwrap();
            }

            println!("gonna read from stream");
            // if the client wrote something, give it to the server
            if let Ok(length) = stream.read(&mut buffer) {
                println!("length of client stuff: {}", length);
                client_buffer.write_all(&buffer[0..length]).unwrap();
            }

            server.handshake().unwrap();
        }
    }
    println!("done with the server handshake");

    // read the "gimme data" message
    {
        let mut buffer = vec![0; 1_000_000];
        let length;

        length = stream.read(&mut buffer).unwrap();
        client_buffer.write_all(&buffer[0..length]).unwrap();
        // clear the buffer to make sure we are reading real things
        buffer[0] = 0;
        server.recv(&mut buffer[0..APP_REQUEST.len()]).unwrap();
        assert_eq!(APP_REQUEST.as_bytes(), &buffer[0..APP_REQUEST.len()]);
    }

    // send 200 Gb of data
    {
        let payload_buffer = vec![0x56; 1_000_000];
        // the encrypted payload buffer won't be exactly the same length because
        // of cipher/tag shenanigans
        let mut stream_buffer = vec![0; 2_000_000];
        for i in 0..(200 * 1_000) {
            println!("server sent {i} Mb");
            server.send(&payload_buffer).unwrap();
            // fill the stream buffer with the encrypted payload
            let length = client_buffer.read(&mut stream_buffer).unwrap();
            // write the encrypted payload to the tcp stream
            stream.write_all(&stream_buffer[0..length]).unwrap();
        }
    }
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9004")?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        large_data_server::<OpenSslConnection>(stream?);
    }
    Ok(())
}
