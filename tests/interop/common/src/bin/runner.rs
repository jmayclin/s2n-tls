// PORT_START: u16 = 9_000;
// PORT_END: u16 = 9_100;

use std::{fs::File, io, process::Stdio, result, thread::sleep};
use tracing::Level;
use common::InteropTest;

#[derive(Debug, Copy, Clone)]
enum Client {
    S2nTls,
    Rustls,
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

struct TestScenario {
    client: Client,
    server: Server,
    test_case: InteropTest,
}

impl TestScenario {
    async fn execute(&mut self, port: u16) -> TestResult {
        let test_case_name = format!("{}", self.test_case);

        let server_log = format!(
            "{}_s:{:?}_c:{:?}_server.log",
            self.test_case, self.server, self.client
        );
        let client_log = format!(
            "{}_s:{:?}_c:{:?}_client.log",
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
        sleep(std::time::Duration::from_secs(1));

        let mut client = tokio::process::Command::new(self.client.executable_path())
            .args([&test_case_name, &port.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut client_stdout = client.stdout.take().unwrap();

        let (c_status, s_status, _, _) = tokio::join!(
            client.wait(),
            server.wait(),
            tokio::io::copy(&mut client_stdout, &mut client_log),
            tokio::io::copy(&mut server_stdout, &mut server_log),
        );
        let c_status = c_status.unwrap().code().unwrap();
        let s_status = s_status.unwrap().code().unwrap();

        if c_status == 127 || s_status == 127 {
            TestResult::Unimplemented
        } else if c_status == 0 && s_status == 0 {
            TestResult::Success
        } else {
            TestResult::Failure
        }
    }
}

fn print_results_table(results: Vec<(InteropTest, Server, Client, TestResult)>) {
    for (t, s, c, r) in results {
        println!("{} | {:?} | {:?} -> {:?}", t, s, c, r);
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .init();

    let clients = vec![Client::S2nTls, Client::Rustls];
    let servers = vec![Server::S2nTls];
    let tests = vec![
        //InteropTest::Handshake,
        //InteropTest::Greeting,
        //InteropTest::LargeDataDownload,
        InteropTest::LargeDataDownloadWithFrequentKeyUpdates,
    ];

    let mut results = Vec::new();

    let mut port = 9010;
    for t in tests {
        let test_arg = format!("{}", t);
        for s in servers.iter() {
            for c in clients.iter() {
                let mut scenario = TestScenario {
                    client: *c,
                    server: *s,
                    test_case: t,
                };
                let result = scenario.execute(port).await;
                println!("the result was {:?}", result);
                port += 1;
                results.push((t, s.clone(), c.clone(), result.clone()));
            }
        }
    }

    print_results_table(results);

    // println!("hello world");
    // let mut server = std::process::Command::new(Server::S2nTls.executable_path())
    //     .args(["handshake", "9001"])
    //     .spawn()
    //     .unwrap();
    // sleep(std::time::Duration::from_secs(1));
    // let mut client = std::process::Command::new(Client::S2nTls.executable_path())
    //     .args(["handshake", "9001"])
    //     .spawn()
    //     .unwrap();
    // client.wait().unwrap();
    // println!("successfully waited the child");
    // server.wait().unwrap();
    // println!("successfully waited the server");
}
