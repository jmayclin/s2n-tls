use common::InteropTest;
use s2n_tls::{
    callbacks::MonotonicClock,
    enums::Version,
    security::{Policy, DEFAULT_TLS13},
};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    time::Duration,
};
use tls_shim_interop::{rustls_shim::RustlsShim, s2n_tls_shim::ShimS2nTls, ClientTLS, ServerTLS};
use turmoil::net::*;


struct TurmoilClock {
    start: tokio::time::Instant,
}

impl TurmoilClock {
    fn new() -> Self {
        TurmoilClock {
            start: tokio::time::Instant::now(),
        }
    }
}

impl MonotonicClock for TurmoilClock {
    fn get_time(&self) -> Duration {
        self.start.elapsed()
    }
}

const PORT: u16 = 1738;

// fn server_config(animal: &str) -> s2n_tls::config::Config {
//     let cert_path = format!("{}/certs/{}-chain.pem", env!("CARGO_MANIFEST_DIR"), animal);
//     let key_path = format!("{}/certs/{}-key.pem", env!("CARGO_MANIFEST_DIR"), animal);
//     let cert = std::fs::read(cert_path).unwrap();
//     let key = std::fs::read(key_path).unwrap();
//     let mut config = s2n_tls::config::Builder::new();

//     // we can set different policies for different configs. "20190214" doesn't
//     // support TLS 1.3, so any customer requesting www.wombat.com won't be able
//     // to negoatiate TLS 1.3
//     let security_policy = match animal {
//         "wombat" => Policy::from_version("20190214").unwrap(),
//         _ => DEFAULT_TLS13,
//     };
//     config.set_security_policy(&security_policy).unwrap();
//     config.load_pem(&cert, &key).unwrap();
//     config.set_monotonic_clock(TurmoilClock::new()).unwrap();
//     config.build().unwrap()
// }

// pub fn client_config() -> s2n_tls::config::Config {
//     let mut config = s2n_tls::config::Config::builder();
//     let ca: Vec<u8> =
//         std::fs::read(env!("CARGO_MANIFEST_DIR").to_owned() + "/certs/ca-cert.pem").unwrap();
//     config.set_security_policy(&DEFAULT_TLS13).unwrap();
//     config.trust_pem(&ca).unwrap();
//     config.build().unwrap()
// }

#[test]
fn scenario() -> turmoil::Result {
    // turmoil is a network simulator, so we can simulate running a single and
    // two servers without having to spin up multiple processes or wait for
    // real time to elapse
    let mut sim = turmoil::Builder::new().build();

    // we can attach the server to all of the things

    sim.host("s2n-tls-server-greeting", || async {
        let cert_pem = fs::read(common::pem_file_path(common::PemType::ServerChain))?;
        let key_pem = fs::read(common::pem_file_path(common::PemType::ServerKey))?;
        let config = <ShimS2nTls as ServerTLS<turmoil::net::TcpStream>>::get_server_config(
            common::InteropTest::Greeting,
            &cert_pem,
            &key_pem,
        )?
        .unwrap();

        let server = <ShimS2nTls as ServerTLS<turmoil::net::TcpStream>>::acceptor(config);

        // Bind to an address and listen for connections.
        // ":0" can be used to automatically assign a port.
        println!("creating the server listener");
        let listener =
            turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

        println!("the server listener was created");
        // Wait for a client to connect.
        let (stream, peer_addr) = listener.accept().await?;
        println!("Connection from {:?}", peer_addr);

        // Spawn a new task to handle the connection.
        // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
        // because the TLS handshake can be slow.
        let server_clone = server.clone();
        let tls = ShimS2nTls::accept(&server_clone, stream).await.unwrap();
        ShimS2nTls::handle_server_connection(InteropTest::Greeting, tls)
            .await
            .unwrap();
        Ok(())
    });

    sim.client("rustls-client", async {
        //let mut stream = TcpStream::connect(("s2n-tls-server-greeting", PORT)).await?;
        let ca_pem = fs::read(common::pem_file_path(common::PemType::CaCert))?;
        let config = <RustlsShim as ClientTLS<TcpStream>>::get_client_config(InteropTest::Greeting, &ca_pem)?.unwrap();

        let client = <RustlsShim as ClientTLS<TcpStream>>::connector(config);

        // Bind to an address and listen for connections.
        // ":0" can be used to automatically assign a port.
        println!("trying to make the TCP stream");
        let transport_stream = turmoil::net::TcpStream::connect(("s2n-tls-server-greeting", PORT)).await?;
    
        println!("client trying to connect");
        let tls = RustlsShim::connect(&client, transport_stream).await.unwrap();
        println!("client connected");
        RustlsShim::handle_client_connection(InteropTest::Greeting, tls).await.unwrap();
        Ok(())
    });

    sim.run()
}
