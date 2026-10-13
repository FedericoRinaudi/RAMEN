use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown};
use std::time::{Duration, Instant};
use std::fs::OpenOptions;
use std::env;
use std::sync::Arc;
use tokio::task;

use rustls::pki_types::ServerName;

mod common;
use common::*;

const DEFAULT_SERVER_ADDRESS: &str = "192.0.2.10:8081";
const N_PARALLEL_PACKETS: usize = 20;

// In TLS mode: tls_config and server_name are Some; the timer starts after the handshake.
// In plain TCP mode: both are None; the payload is enlarged to keep the same wire size.
fn send_and_receive_packet(
    server_address: &str,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    server_name: Option<ServerName<'static>>,
) -> Result<Duration, std::io::Error> {
    let tcp = TcpStream::connect(server_address)?;
    tcp.set_nodelay(true).ok();
    set_tcp_quickack(&tcp, true);

    match (tls_config, server_name) {
        (Some(config), Some(name)) => {
            let conn = rustls::ClientConnection::new(config, name)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            let mut tls = rustls::StreamOwned::new(conn, tcp);

            loop {
                tls.conn.complete_io(&mut tls.sock)?;
                if !tls.conn.is_handshaking() { break; }
            }

            let data = vec![0u8; BYTES_TO_SEND_TLS];
            let start = Instant::now();
            tls.write_all(&data)?;
            let mut response = vec![0u8; BYTES_TO_RECEIVE_TLS];
            tls.read_exact(&mut response)?;
            let duration = start.elapsed();

            tls.conn.send_close_notify();
            let _ = tls.flush();
            let _ = tls.sock.shutdown(Shutdown::Write);
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf);

            Ok(duration)
        }
        _ => {
            let mut stream = tcp;
            let data = vec![0u8; BYTES_TO_SEND_PLAIN];
            let start = Instant::now();
            stream.write_all(&data)?;
            let mut response = vec![0u8; BYTES_TO_RECEIVE_PLAIN];
            stream.read_exact(&mut response)?;
            let duration = start.elapsed();

            let _ = stream.shutdown(Shutdown::Write);
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);

            Ok(duration)
        }
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();

    // Usage: <output_file> [server_address] [n_requests] [--http]
    let args: Vec<String> = env::args().collect();
    let output_file = if args.len() > 1 {
        args[1].clone()
    } else {
        eprintln!("Usage: {} <output_file> [server_address] [n_requests] [--http]", args[0]);
        std::process::exit(1);
    };

    let server_address = if args.len() > 2 {
        args[2].clone()
    } else {
        DEFAULT_SERVER_ADDRESS.to_string()
    };

    let use_tls = !args.iter().any(|a| a == "--http");

    if use_tls {
        println!("TLS connection to {}", server_address);
        println!("Configuration:");
        println!("  - Bytes to send: {} (+ 22 TLS + 54 net = 144 wire)", BYTES_TO_SEND_TLS);
        println!("  - Bytes to receive: {} (+ 22 TLS + 54 net = 265 wire)", BYTES_TO_RECEIVE_TLS);
    } else {
        println!("TCP (plain) connection to {}", server_address);
        println!("Configuration:");
        println!("  - Bytes to send: {} (+ 54 net = 144 wire, same size as TLS)", BYTES_TO_SEND_PLAIN);
        println!("  - Bytes to receive: {} (+ 54 net = 265 wire, same size as TLS)", BYTES_TO_RECEIVE_PLAIN);
    }

    let n_requests = if args.len() > 3 {
        args[3].parse::<usize>().unwrap_or(N_REQUESTS)
    } else if let Ok(value) = env::var("N_REQUESTS") {
        value.parse::<usize>().unwrap_or(N_REQUESTS)
    } else {
        N_REQUESTS
    };

    println!("  - Total requests: {}", n_requests);
    println!("  - New connection for each request");
    println!("  - Output file: {}", output_file);
    println!();

    let tls_config: Option<Arc<rustls::ClientConfig>> = if use_tls {
        Some(Arc::new(make_client_config()))
    } else {
        None
    };
    let server_name: Option<ServerName<'static>> = if use_tls {
        Some(ServerName::try_from("experiment.server").expect("Invalid server name").to_owned())
    } else {
        None
    };

    let mut rtts = Vec::with_capacity(n_requests);

    for i in 0..n_requests {
        let mut tasks = Vec::new();

        for _j in 0..N_PARALLEL_PACKETS {
            let addr = server_address.clone();
            let config = tls_config.clone();
            let name = server_name.clone();
            let task = task::spawn_blocking(move || {
                send_and_receive_packet(&addr, config, name)
            });
            tasks.push(task);
        }

        let mut all_ok = true;
        let mut durations = Vec::new();

        for task in tasks {
            match task.await {
                Ok(Ok(duration)) => {
                    durations.push(duration);
                }
                Ok(Err(e)) => {
                    eprintln!("Error in a packet: {}", e);
                    all_ok = false;
                }
                Err(e) => {
                    eprintln!("Task error: {}", e);
                    all_ok = false;
                }
            }
        }

        if all_ok && !durations.is_empty() {
            let max_duration = durations.iter().max().unwrap();
            rtts.push(max_duration.as_micros());
            println!("Request {}/{}: {} parallel packets completed, max data transfer time: {:.3} ms",
                     i + 1, n_requests, N_PARALLEL_PACKETS, max_duration.as_secs_f64() * 1000.0);
        } else {
            eprintln!("Request {}/{}: some packets failed", i + 1, N_REQUESTS);
        }

        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    println!("\nCompleted all {} requests", n_requests);

    if !rtts.is_empty() {
        let sum: u128 = rtts.iter().sum();
        let avg = sum / rtts.len() as u128;
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();

        println!("\nData transfer time statistics:");
        println!("  - Mean: {:.3} ms", avg as f64 / 1000.0);
        println!("  - Min: {:.3} ms", min as f64 / 1000.0);
        println!("  - Max: {:.3} ms", max as f64 / 1000.0);

        match OpenOptions::new().create(true).append(true).open(&output_file) {
            Ok(mut file) => {
                use std::io::Write as _;
                let is_empty = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
                if is_empty {
                    writeln!(file, "data_transfer_time_us").ok();
                }
                for rtt in rtts.iter() {
                    writeln!(file, "{}", rtt).ok();
                }
                println!("\nResults saved to: {}", output_file);
            }
            Err(e) => {
                eprintln!("Error writing the file: {}", e);
            }
        }
    }
}
