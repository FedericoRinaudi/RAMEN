use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::thread;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const DEFAULT_PORT: &str = "8080";
// Payload sizes (without TLS/network overhead):
//   TLS  - client sends: 68 bytes  → wire: 68  + 22 TLS + 54 net = 144 bytes
//   TLS  - server sends: 189 bytes → wire: 189 + 22 TLS + 54 net = 265 bytes
//   plain - client sends: 90 bytes  → wire: 90  + 54 net = 144 bytes (same wire size)
//   plain - server sends: 211 bytes → wire: 211 + 54 net = 265 bytes (same wire size)
const BYTES_TO_RECEIVE_TLS: usize = 68;
const BYTES_TO_SEND_TLS: usize = 189;
const BYTES_TO_RECEIVE_PLAIN: usize = 90;
const BYTES_TO_SEND_PLAIN: usize = 211;

fn set_tcp_quickack(stream: &TcpStream, enable: bool) {
    unsafe {
        let optval: libc::c_int = if enable { 1 } else { 0 };
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        );
    }
}

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

fn make_server_config() -> rustls::ServerConfig {
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(
        vec!["experiment.server".to_string()]
    ).expect("Failed to generate the self-signed certificate");

    let cert_der = CertificateDer::from(cert.der().as_ref().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("Failed to build the TLS server configuration")
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
