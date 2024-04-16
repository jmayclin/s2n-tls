use common::InteropTest;
use s2n_tls::callbacks::MonotonicClock;
use std::{
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};
use tls_shim_interop::{rustls_shim::RustlsShim, s2n_tls_shim::ShimS2nTls, ClientTLS, ServerTLS};

use tracing::Level;
use turmoil::net::*;

const PORT: u16 = 1738;

async fn server_loop(test: InteropTest) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = fs::read(common::pem_file_path(common::PemType::ServerChain))?;
    let key_pem = fs::read(common::pem_file_path(common::PemType::ServerKey))?;
    let config = <ShimS2nTls as ServerTLS<turmoil::net::TcpStream>>::get_server_config(
        test, &cert_pem, &key_pem,
    )?
    .unwrap();

    let server = <ShimS2nTls as ServerTLS<turmoil::net::TcpStream>>::acceptor(config);

    let listener =
        turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

    // Wait for a client to connect.
    let (stream, _peer_addr) = listener.accept().await?;

    let server_clone = server.clone();
    let tls = ShimS2nTls::accept(&server_clone, stream).await.unwrap();
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
    let transport_stream = turmoil::net::TcpStream::connect((server_domain, PORT)).await?;

    let tls = T::connect(&client, transport_stream).await.unwrap();
    T::handle_client_connection(test, tls).await.unwrap();
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
// 6. so the server asserts are never triggered. 
// We'd need to use poll_shutdown instead of poll_shutdown_send so that the client
// would actually wait for the server response before exiting. Then the test would
// fail in this scenario as expected.
#[test]
fn s2n_tls_server_rustls_client() -> turmoil::Result {
    let _subscriber = tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .try_init();
    // turmoil is a network simulator, so we can simulate running a single and
    // two servers without having to spin up multiple processes or wait for
    // real time to elapse
    let mut sim = turmoil::Builder::new().build();

    // turmoil's send function seems to be quadratic somewhere. Sending 1 Gb takes approximately 229 seconds
    // so don't enable the large data tests.
    let tests = vec![
        InteropTest::Greeting,
        InteropTest::Handshake, 
        // InteropTest::LargeDataDownload,
        // InteropTest::LargeDataDownloadWithFrequentKeyUpdates,

    ];
    for t in tests {
        let server_name = format!("s2n-tls-server-{}", t);
        let client_name = format!("rustls-client-{}", t);
        sim.host(server_name.as_str(), move || server_loop(t));
        sim.client(
            client_name.as_str(),
            client_loop::<RustlsShim>(t, server_name),
        );
    }

    sim.run()
}

#[test]
fn s2n_tls_server_s2n_tls_client() -> turmoil::Result {
    let _subscriber = tracing_subscriber::fmt::fmt()
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
        sim.client(
            client_name.as_str(),
            client_loop::<ShimS2nTls>(t, server_name),
        );
    }

    sim.run()
}
