use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown};
use std::time::{Duration, Instant};
use std::fs::OpenOptions;
use std::env;
use std::thread;
use std::sync::Arc;

use rustls::pki_types::ServerName;

mod common;
use common::*;

const DEFAULT_SERVER_ADDRESS: &str = "192.0.2.10:8080";

fn main() {
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

    let tls_config = if use_tls { Some(Arc::new(make_client_config())) } else { None };
    let server_name: Option<ServerName<'static>> = if use_tls {
        Some(ServerName::try_from("experiment.server").expect("Invalid server name").to_owned())
    } else {
        None
    };

    let mut rtts = Vec::with_capacity(n_requests);

    for i in 0..n_requests {
        if use_tls {
            let tcp = match TcpStream::connect(&server_address) {
                Ok(s) => s,
                Err(e) => { eprintln!("TCP connection error: {}", e); continue; }
            };
            tcp.set_nodelay(true).ok();
            set_tcp_quickack(&tcp, true);

            let conn = match rustls::ClientConnection::new(
                Arc::clone(tls_config.as_ref().unwrap()),
                server_name.as_ref().unwrap().clone(),
            ) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error creating TLS connection: {}", e); continue; }
            };
            let mut tls = rustls::StreamOwned::new(conn, tcp);

            loop {
                match tls.conn.complete_io(&mut tls.sock) {
                    Ok(_) => {}
                    Err(e) => { eprintln!("TLS handshake error: {}", e); break; }
                }
                if !tls.conn.is_handshaking() { break; }
            }

            let data = vec![0u8; BYTES_TO_SEND_TLS];
            let start = Instant::now();

            if let Err(e) = tls.write_all(&data) {
                eprintln!("Send error: {}", e); continue;
            }
            let mut response = vec![0u8; BYTES_TO_RECEIVE_TLS];
            if let Err(e) = tls.read_exact(&mut response) {
                eprintln!("Receive error: {}", e); continue;
            }

            let rtt = start.elapsed();
            rtts.push(rtt.as_micros());
            println!("Request {}/{}: sent {} bytes, received {} bytes, RTT: {:.3} ms",
                     i + 1, n_requests, BYTES_TO_SEND_TLS, BYTES_TO_RECEIVE_TLS, rtt.as_secs_f64() * 1000.0);

            tls.conn.send_close_notify();
            let _ = tls.flush();
            let _ = tls.sock.shutdown(Shutdown::Write);
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf);
        } else {
            let mut stream = match TcpStream::connect(&server_address) {
                Ok(s) => s,
                Err(e) => { eprintln!("TCP connection error: {}", e); continue; }
            };
            stream.set_nodelay(true).ok();
            set_tcp_quickack(&stream, true);

            let data = vec![0u8; BYTES_TO_SEND_PLAIN];
            let start = Instant::now();

            if let Err(e) = stream.write_all(&data) {
                eprintln!("Send error: {}", e); continue;
            }
            let mut response = vec![0u8; BYTES_TO_RECEIVE_PLAIN];
            if let Err(e) = stream.read_exact(&mut response) {
                eprintln!("Receive error: {}", e); continue;
            }

            let rtt = start.elapsed();
            rtts.push(rtt.as_micros());
            println!("Request {}/{}: sent {} bytes, received {} bytes, RTT: {:.3} ms",
                     i + 1, n_requests, BYTES_TO_SEND_PLAIN, BYTES_TO_RECEIVE_PLAIN, rtt.as_secs_f64() * 1000.0);

            let _ = stream.shutdown(Shutdown::Write);
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        }

        thread::sleep(Duration::from_millis(2));
    }

    println!("\nCompleted all {} requests", n_requests);

    if !rtts.is_empty() {
        let sum: u128 = rtts.iter().sum();
        let avg = sum / rtts.len() as u128;
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();

        println!("\nRTT statistics:");
        println!("  - Mean: {:.3} ms", avg as f64 / 1000.0);
        println!("  - Min: {:.3} ms", min as f64 / 1000.0);
        println!("  - Max: {:.3} ms", max as f64 / 1000.0);

        match OpenOptions::new().create(true).append(true).open(&output_file) {
            Ok(mut file) => {
                use std::io::Write as _;
                let is_empty = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
                if is_empty {
                    writeln!(file, "rtt_us").ok();
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
