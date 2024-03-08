use std::{
    any::type_name, borrow::BorrowMut, io::{Read, Write}, net::{TcpListener, TcpStream}, time::Duration
};

use bench::{
    harness::TlsBenchConfig, s2n_tls::S2NConfig, CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup, OpenSslConnection, RustlsConnection, S2NConnection, SigType, TlsConnPair, TlsConnection
};

fn large_data_server(mut stream: TcpStream)
{
    const APP_REQUEST: &str = "gimme data";
    const APP_THANKS: &str = "thanks for the data";
    const SERVER_ACK: &str = "no problem, i gotchu";
    const MB: usize = 1_000_000;
    const GB: usize = 1_000_000_000;

    // the java client is set up to use the
    let crypto_config =
        CryptoConfig::new(CipherSuite::default(), KXGroup::default(), SigType::Rsa2048);

    let server_config = S2NConfig::make_config(
        bench::Mode::Server,
        crypto_config,
        HandshakeType::ServerAuth,
    )
    .unwrap();
    let server_buffer = ConnectedBuffer::default();
    let mut client_buffer = server_buffer.clone_inverse();

    let mut server = S2NConnection::new_from_config(&server_config, server_buffer).unwrap();

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

    stream
        .set_read_timeout(Some(Duration::from_micros(1)))
        .unwrap();
    // send 200 Gb of data
    {
        let mut payload_buffer = vec![0x56; MB];
        // the encrypted payload buffer won't be exactly the same length because
        // of cipher/tag shenanigans
        let mut stream_buffer = vec![0; 2 * MB];
        for i in 0..(200 * GB / MB) {
            println!("server sent {i} Mb");
            // prefix each megabyte with the Gb that it is on
            payload_buffer[0] = (i / (GB / MB)) as u8;
            server.send(&payload_buffer).unwrap();
            // fill the stream buffer with the encrypted payload
            let length = client_buffer.read(&mut stream_buffer).unwrap();
            // write the encrypted payload to the tcp stream
            // absolutely hideous code, but this is fine for now
            stream.write_all(&stream_buffer[0..length]).unwrap();

            if i > 136_000 {
                // the client might have send a key update request
                // my chopped up blocking timeout thing slows down the sending, so only start
                // this once we get close
                println!("trying to peek");
                if let Ok(length) = stream.read(&mut stream_buffer) {
                    println!("oh goody, I just love receiving letters");
                    client_buffer.write_all(&stream_buffer[0..length]).unwrap();
                    // there should be no application data, so an empty slice should
                    // be sufficient to "receive" enough data.

                    server.recv(&mut [0]).unwrap();

                    println!("after calling recv the updates are {:?}", server.connection().key_updates().unwrap());
                }
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9004")?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        large_data_server(stream?);    
    }
    Ok(())
}
