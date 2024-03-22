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
use tokio_rustls::client;
use tracing::Level;
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
    tracing::info!("creating the server listener");
    let listener =
        turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

    tracing::info!("the server listener was created");
    // Wait for a client to connect.
    let (stream, peer_addr) = listener.accept().await?;
    tracing::info!("Connection from {:?}", peer_addr);

    // Spawn a new task to handle the connection.
    // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
    // because the TLS handshake can be slow.
    let server_clone = server.clone();
    tracing::info!("accepting the TLS connection");
    let tls = ShimS2nTls::accept(&server_clone, stream).await.unwrap();
    tracing::info!("now handling the TLS connection");
    ShimS2nTls::handle_server_connection(test, tls)
        .await
        .unwrap();
    Ok(())
}

async fn client_loop<T>(
    test: InteropTest,
    server_domain: String,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: ClientTLS<TcpStream>,
{
    let ca_pem = fs::read(common::pem_file_path(common::PemType::CaCert))?;
    let config = T::get_client_config(test, &ca_pem)?.unwrap();

    let client = T::connector(config);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    tracing::info!("trying to make the TCP stream");
    let transport_stream = turmoil::net::TcpStream::connect((server_domain, PORT)).await?;

    tracing::info!("client trying to connect");
    let tls = T::connect(&client, transport_stream)
        .await
        .unwrap();
    tracing::info!("client connected");
    T::handle_client_connection(test, tls)
        .await
        .unwrap();
    Ok(())
}

// note that there is a gap in this Turmoil testing setup. If a client uses the
// Handshake scenario to call a Greeting server, we would naively expect a failure.
// However this test will actually succeed because
// 1. Handshake completes successfully, both assert on that
// 2. client immediately calls shutdown
// 3. this results in transmitting a TCP FIN to the server
// 4. at which point turmoil consider the client "done"
// 5. the simulation is then done
// 5. the server is never polled
// 6. so the server asserts are never triggered. We'd need to use poll_shutdown instead of
// 7. poll_shutdown_send in order to get the real close behavior
// We can probably add an assert on the read call returning 0, but I'm unwilling to make an s2n-tls
// specific event loop at the moment. The tests are still relatively useful
#[test]
fn s2n_tls_server_rustls_client() -> turmoil::Result {
    let subscriber = tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .try_init();
    // turmoil is a network simulator, so we can simulate running a single and
    // two servers without having to spin up multiple processes or wait for
    // real time to elapse
    let mut sim = turmoil::Builder::new().build();

    // we can attach the server to all of the things
    // turmoil's send function seems to be quadratic somewhere. Sending 1 Gb takes approximately 229 seconds
    // so don't enable the large data test
    let tests = vec![
        InteropTest::Greeting,
        InteropTest::Handshake, /*InteropTest::LargeDataDownload */
    ];
    for t in tests {
        let server_name = format!("s2n-tls-server-{}", t);
        let client_name = format!("rustls-client-{}", t);
        sim.host(server_name.as_str(), move || server_loop(t));
        sim.client(client_name.as_str(), client_loop::<RustlsShim>(t, server_name));
    }

    sim.run()
}

#[test]
fn s2n_tls_server_s2n_tls_client() -> turmoil::Result {
    let subscriber = tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .try_init();
    // turmoil is a network simulator, so we can simulate running a single and
    // two servers without having to spin up multiple processes or wait for
    // real time to elapse
    let mut sim = turmoil::Builder::new().build();

    // we can attach the server to all of the things
    // turmoil's send function seems to be quadriatic somewhere. Sending 1 Gb takes approximately 229 seconds
    // so don't enable the large data test
    let tests = vec![
        InteropTest::Greeting,
        InteropTest::Handshake, /*InteropTest::LargeDataDownload */
    ];
    for t in tests {
        let server_name = format!("s2n-tls-server-{}", t);
        let client_name = format!("rustls-client-{}", t);
        sim.host(server_name.as_str(), move || server_loop(t));
        sim.client(client_name.as_str(), client_loop::<ShimS2nTls>(t, server_name));
    }

    sim.run()
}
