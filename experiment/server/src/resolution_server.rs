use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

mod common;
use common::*;

const DEFAULT_PORT: &str = "8081";

async fn handle_client_tls(tcp_stream: TcpStream, acceptor: TlsAcceptor) {
    let peer_addr = tcp_stream.peer_addr().unwrap();
    println!("New connection (TLS) from: {}", peer_addr);

    tcp_stream.set_nodelay(true).ok();
    set_tcp_quickack(&tcp_stream, true);

    let mut tls_stream = match acceptor.accept(tcp_stream).await {
        Ok(s) => s,
        Err(e) => { eprintln!("TLS accept error: {}", e); return; }
    };

    let mut buffer = vec![0u8; 65536];
    match tls_stream.read_exact(&mut buffer[..BYTES_TO_RECEIVE_TLS]).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Read error: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND_TLS];
    match tls_stream.write_all(&response).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Send error: {}", e); return; }
    }

    let mut buf = [0u8; 1];
    let _ = tls_stream.read(&mut buf).await;
    let _ = tls_stream.shutdown().await;
}

async fn handle_client_plain(mut tcp_stream: TcpStream) {
    let peer_addr = tcp_stream.peer_addr().unwrap();
    println!("New connection (plain) from: {}", peer_addr);

    tcp_stream.set_nodelay(true).ok();
    set_tcp_quickack(&tcp_stream, true);

    let mut buffer = vec![0u8; 65536];
    match tcp_stream.read_exact(&mut buffer[..BYTES_TO_RECEIVE_PLAIN]).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Read error: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND_PLAIN];
    match tcp_stream.write_all(&response).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Send error: {}", e); return; }
    }

    let mut buf = [0u8; 1];
    let _ = tcp_stream.read(&mut buf).await;
    let _ = tcp_stream.shutdown().await;
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();

    // Usage: [port] [--http]
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_PORT);
    let use_tls = !args.iter().any(|a| a == "--http");
    let bind_address = format!("0.0.0.0:{}", port);

    let listener = TcpListener::bind(&bind_address).await.unwrap();

    if use_tls {
        let server_config = Arc::new(make_server_config());
        let acceptor = TlsAcceptor::from(Arc::clone(&server_config));
        println!("TLS server listening on {}", bind_address);
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let acc = acceptor.clone();
                    tokio::spawn(async move { handle_client_tls(stream, acc).await; });
                }
                Err(e) => eprintln!("Connection error: {}", e),
            }
        }
    } else {
        println!("TCP (plain) server listening on {}", bind_address);
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tokio::spawn(async move { handle_client_plain(stream).await; });
                }
                Err(e) => eprintln!("Connection error: {}", e),
            }
        }
    }
}
