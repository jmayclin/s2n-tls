use common::InteropTest;
use s2n_tls::{
    callbacks::MonotonicClock,
    enums::Version,
    security::{Policy, DEFAULT_TLS13},
};
use tracing::Level;
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

async fn server_loop(test: InteropTest) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = fs::read(common::pem_file_path(common::PemType::ServerChain))?;
    let key_pem = fs::read(common::pem_file_path(common::PemType::ServerKey))?;
    let config = <ShimS2nTls as ServerTLS<turmoil::net::TcpStream>>::get_server_config(
        test, &cert_pem, &key_pem,
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
    println!("accepting the TLS connection");
    let tls = ShimS2nTls::accept(&server_clone, stream).await.unwrap();
    println!("now handling the TLS connection");
    ShimS2nTls::handle_server_connection(test, tls)
        .await
        .unwrap();
    Ok(())
}

async fn client_loop(
    test: InteropTest,
    server_domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_pem = fs::read(common::pem_file_path(common::PemType::CaCert))?;
    let config = <RustlsShim as ClientTLS<TcpStream>>::get_client_config(test, &ca_pem)?.unwrap();

    let client = <RustlsShim as ClientTLS<TcpStream>>::connector(config);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    println!("trying to make the TCP stream");
    let transport_stream = turmoil::net::TcpStream::connect((server_domain, PORT)).await?;

    println!("client trying to connect");
    let tls = RustlsShim::connect(&client, transport_stream)
        .await
        .unwrap();
    println!("client connected");
    RustlsShim::handle_client_connection(test, tls)
        .await
        .unwrap();
    Ok(())
}

async fn s2n_client_loop(
    test: InteropTest,
    server_domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_pem = fs::read(common::pem_file_path(common::PemType::CaCert))?;
    let config = <ShimS2nTls as ClientTLS<TcpStream>>::get_client_config(test, &ca_pem)?.unwrap();

    let client = <ShimS2nTls as ClientTLS<TcpStream>>::connector(config);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    println!("trying to make the TCP stream");
    let transport_stream = turmoil::net::TcpStream::connect((server_domain, PORT)).await?;

    println!("client trying to connect");
    let tls = ShimS2nTls::connect(&client, transport_stream)
        .await
        .unwrap();
    println!("client connected");
    ShimS2nTls::handle_client_connection(test, tls)
        .await
        .unwrap();
    Ok(())
}

// note that there is a gap in this Turmoil testing setup. If a client uses the 
// Handshake scenario to call a Greeting server, we would naively expect a failure.
// However this test will actually succeed because
// 1. Handshake completes successfully, both assert on that
// 2. client immediately calls shutdown
// 3. 
#[test]
fn scenario() -> turmoil::Result {
    let subscriber = tracing_subscriber::fmt::fmt().with_max_level(Level::TRACE).init();
    // turmoil is a network simulator, so we can simulate running a single and
    // two servers without having to spin up multiple processes or wait for
    // real time to elapse
    let mut sim = turmoil::Builder::new().build();

    // we can attach the server to all of the things

    sim.host("s2n-tls-server-greeting", || {
        server_loop(InteropTest::Greeting)
    });
    // sim.host("s2n-tls-server-handshake", || {
    //     server_loop(InteropTest::Handshake)
    // });

    sim.client(
        "rustls-client-greeting",
        s2n_client_loop(InteropTest::Handshake, "s2n-tls-server-greeting"),
    );

    // sim.client("rustls-client-handshake", async {
    //     //let mut stream = TcpStream::connect(("s2n-tls-server-greeting", PORT)).await?;
    //     let ca_pem = fs::read(common::pem_file_path(common::PemType::CaCert))?;
    //     let config = <RustlsShim as ClientTLS<TcpStream>>::get_client_config(
    //         InteropTest::Handshake,
    //         &ca_pem,
    //     )?
    //     .unwrap();

    //     let client = <RustlsShim as ClientTLS<TcpStream>>::connector(config);

    //     // Bind to an address and listen for connections.
    //     // ":0" can be used to automatically assign a port.
    //     println!("trying to make the TCP stream");
    //     let transport_stream =
    //         turmoil::net::TcpStream::connect(("s2n-tls-server-handshake", PORT)).await?;

    //     println!("client trying to connect");
    //     let tls = RustlsShim::connect(&client, transport_stream)
    //         .await
    //         .unwrap();
    //     println!("client connected");
    //     RustlsShim::handle_client_connection(InteropTest::Handshake, tls)
    //         .await
    //         .unwrap();
    //     Ok(())
    // });

    sim.run()
}
