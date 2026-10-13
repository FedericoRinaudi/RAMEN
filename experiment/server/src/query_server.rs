use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::thread;
use std::sync::Arc;

mod common;
use common::*;

const DEFAULT_PORT: &str = "8080";

fn handle_client_tls(stream: TcpStream, tls_config: Arc<rustls::ServerConfig>) {
    println!("New connection (TLS) from: {}", stream.peer_addr().unwrap());

    stream.set_nodelay(true).ok();
    set_tcp_quickack(&stream, true);

    let conn = match rustls::ServerConnection::new(tls_config) {
        Ok(c) => c,
        Err(e) => { eprintln!("Error creating TLS server connection: {}", e); return; }
    };
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let mut buffer = vec![0u8; 65536];
    match tls.read_exact(&mut buffer[..BYTES_TO_RECEIVE_TLS]) {
        Ok(_) => {}
        Err(e) => { eprintln!("Read error: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND_TLS];
    match tls.write_all(&response) {
        Ok(_) => {}
        Err(e) => { eprintln!("Send error: {}", e); return; }
    }
    let _ = tls.flush();

    let mut buf = [0u8; 1];
    let _ = tls.read(&mut buf);

    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(Shutdown::Write);
}

fn handle_client_plain(mut stream: TcpStream) {
    println!("New connection (plain) from: {}", stream.peer_addr().unwrap());

    stream.set_nodelay(true).ok();
    set_tcp_quickack(&stream, true);

    let mut buffer = vec![0u8; 65536];
    match stream.read_exact(&mut buffer[..BYTES_TO_RECEIVE_PLAIN]) {
        Ok(_) => {}
        Err(e) => { eprintln!("Read error: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND_PLAIN];
    match stream.write_all(&response) {
        Ok(_) => {}
        Err(e) => { eprintln!("Send error: {}", e); return; }
    }
    let _ = stream.flush();

    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);
    let _ = stream.shutdown(Shutdown::Write);
}

fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();

    // Usage: [port] [--http]
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_PORT);
    let use_tls = !args.iter().any(|a| a == "--http");
    let bind_address = format!("0.0.0.0:{}", port);

    let listener = TcpListener::bind(&bind_address).unwrap();

    if use_tls {
        let tls_config = Arc::new(make_server_config());
        println!("TLS server listening on {}", bind_address);
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let config = Arc::clone(&tls_config);
                    thread::spawn(move || handle_client_tls(stream, config));
                }
                Err(e) => eprintln!("Connection error: {}", e),
            }
        }
    } else {
        println!("TCP (plain) server listening on {}", bind_address);
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => { thread::spawn(move || handle_client_plain(stream)); }
                Err(e) => eprintln!("Connection error: {}", e),
            }
        }
    }
}
