// PORT_START: u16 = 9_000;
// PORT_END: u16 = 9_100;

use std::{result, thread::sleep};

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

fn print_results_table(results: Vec<(InteropTest, Server, Client, TestResult)>) {
    for (t, s, c, r) in results {
        println!("{} | {:?} | {:?} -> {:?}", t, s, c, r);
    }
}

fn main() {
    let clients = vec![Client::S2nTls, Client::Rustls];
    let servers = vec![Server::S2nTls];
    let tests = vec![
        InteropTest::Handshake,
        InteropTest::Greeting,
        InteropTest::LargeDataDownload,
        InteropTest::LargeDataDownloadWithFrequentKeyUpdates,
    ];

    let mut results = Vec::new();

    let mut port = 9010;
    for t in tests {
        let test_arg = format!("{}", t);
        for s in servers.iter() {
            for c in clients.iter() {
                let mut server = std::process::Command::new(s.executable_path());
                let mut client = std::process::Command::new(c.executable_path());
                server.args([&test_arg, &port.to_string()]);
                client.args([&test_arg, &port.to_string()]);
                port += 1;

                println!("for {}, {:?}, {:?}", t, s, c);

                let mut server_handle = server.spawn().unwrap();
                sleep(std::time::Duration::from_secs(1));
                let mut client_handle = client.spawn().unwrap();

                let client_exit = client_handle.wait().unwrap().code().unwrap();
                let server_exit = server_handle.wait().unwrap().code().unwrap();
                let result = if client_exit == 127 || server_exit == 127 {
                    TestResult::Unimplemented
                } else if client_exit == 0 && server_exit == 0 {
                    TestResult::Success
                } else {
                    TestResult::Failure
                };
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
