// PORT_START: u16 = 9_000;
// PORT_END: u16 = 9_100;

use common::{InteropTest, UNIMPLEMENTED_RETURN_VAL};
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::{
    process::Command,
    sync::mpsc::unbounded_channel,
    time::{sleep, timeout},
};
use tracing::Level;

const CONCURRENT_TESTS: usize = 6;
const TEST_TIMEOUT: Duration = Duration::from_secs(60 * 5);

#[derive(Debug, Copy, Clone)]
enum Client {
    S2nTls,
    Rustls,
    Java,
}

impl Client {
    fn executable_path(&self) -> &'static str {
        match self {
            Client::S2nTls => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/tls-shim-interop/target/release/s2n_tls_client"
            ),
            Client::Rustls => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/tls-shim-interop/target/release/rustls_client"
            ),
            Client::Java => "java",
        }
    }

    // lifetimes are used to indicate that the returned `&mut Command` has the same
    // lifetime as the input `&mut Command`
    fn configure<'a, 'b>(&'a self, command: &'b mut Command) -> &'b mut Command {
        match self {
            Client::Java => command
                // configure the class path (-cp) 
                .arg("-cp")
                // to point to the folder that contains the SSLSocketClient
                .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/..", "/java"))
                // and use the SSLSocketClient as the entry point
                .arg("SSLSocketClient"),
            _ => command,
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum Server {
    S2nTls,
}

impl Server {
    fn executable_path(&self) -> &'static str {
        match self {
            Server::S2nTls => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/tls-shim-interop/target/release/s2n_tls_server"
            ),
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum TestResult {
    Success,
    Failure,
    Unimplemented,
}

#[derive(Debug)]
struct TestScenario {
    client: Client,
    server: Server,
    test_case: InteropTest,
}

impl TestScenario {
    async fn execute(&mut self, port: u16) -> TestResult {
        let test_case_name = format!("{}", self.test_case);

        let server_log = format!(
            "interop_logs/{}_s:{:?}_c:{:?}_server.log",
            self.test_case, self.server, self.client
        );
        let client_log = format!(
            "interop_logs/{}_s:{:?}_c:{:?}_client.log",
            self.test_case, self.server, self.client
        );
        let mut server_log = tokio::fs::File::create(server_log).await.unwrap();
        let mut client_log = tokio::fs::File::create(client_log).await.unwrap();

        let mut server = tokio::process::Command::new(self.server.executable_path())
            .args([&test_case_name, &port.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut server_stdout = server.stdout.take().unwrap();

        // let the server start up and start listening
        sleep(Duration::from_secs(1)).await;

        let mut client_command = tokio::process::Command::new(self.client.executable_path());
        let mut client = self
            .client
            .configure(&mut client_command)
            .args([&test_case_name, &port.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut client_stdout = client.stdout.take().unwrap();

        // wrap everything in a timeout since the "try_join" macro needs everything
        // to have the same error type
        let res = tokio::try_join!(
            timeout(TEST_TIMEOUT, client.wait()),
            timeout(TEST_TIMEOUT, server.wait()),
            timeout(
                TEST_TIMEOUT,
                tokio::io::copy(&mut client_stdout, &mut client_log)
            ),
            timeout(
                TEST_TIMEOUT,
                tokio::io::copy(&mut server_stdout, &mut server_log)
            ),
        );

        let (c_status, s_status) = match res {
            // this branch indicates a timeout
            Ok((Ok(s), Ok(c), Ok(_), Ok(_))) => (c, s),
            // if there was a timeout "Err(_)" or any other kind of error, we
            // return a "failure"
            Err(_) => {
                tracing::error!("{:?} timed out", self);
                server.kill().await.unwrap();
                client.kill().await.unwrap();
                return TestResult::Failure;
            }
            _ => return TestResult::Failure,
        };
        let c_status = c_status.code().unwrap();
        let s_status = s_status.code().unwrap();

        if c_status == UNIMPLEMENTED_RETURN_VAL || s_status == UNIMPLEMENTED_RETURN_VAL {
            TestResult::Unimplemented
        } else if c_status == 0 && s_status == 0 {
            TestResult::Success
        } else {
            TestResult::Failure
        }
    }
}

fn print_results_table(results: Vec<(TestScenario, TestResult)>) {
    for (t, r) in results {
        println!(
            "{} | {:?} | {:?} -> {:?}",
            t.test_case, t.server, t.client, r
        );
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .init();

    // make sure that the logs directory is created
    tokio::fs::create_dir_all("interop_logs").await.unwrap();

    let clients = vec![/*Client::S2nTls, Client::Rustls,*/ Client::Java];
    let servers = vec![Server::S2nTls];
    let tests = vec![
        InteropTest::Handshake,
        InteropTest::Greeting,
        InteropTest::LargeDataDownload,
        InteropTest::LargeDataDownloadWithFrequentKeyUpdates,
    ];

    let mut scenarios = Vec::new();

    for t in tests {
        for s in servers.iter() {
            for c in clients.iter() {
                let scenario = TestScenario {
                    client: *c,
                    server: *s,
                    test_case: t,
                };
                scenarios.push(scenario)
            }
        }
    }

    let (results_tx, mut results_rx) = unbounded_channel();

    let concurrent_tests = Arc::new(tokio::sync::Semaphore::new(CONCURRENT_TESTS));
    let min_port = 9010;
    for (i, mut scenario) in scenarios.into_iter().enumerate() {
        let results_tx_handle = results_tx.clone();
        let test_limiter_handle = Arc::clone(&concurrent_tests);
        tokio::spawn(async move {
            let ticket = test_limiter_handle.acquire().await.unwrap();
            let result = scenario.execute(min_port + (i as u16)).await;
            drop(ticket);
            // something has gone drastically wrong if this panics, so use unwrap
            results_tx_handle.send((scenario, result)).unwrap();
        });
    }
    // we manually drop results_tx, because the channel will never return "None"
    // on a read if there is a sender still open
    drop(results_tx);

    let mut results = Vec::new();
    while let Some((scenario, result)) = results_rx.recv().await {
        results.push((scenario, result));
    }

    print_results_table(results);
}
