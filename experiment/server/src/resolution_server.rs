use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const DEFAULT_PORT: &str = "8081";
// Dimensioni payload (senza overhead TLS/rete):
//   TLS  - client invia: 68 bytes  → wire: 68  + 22 TLS + 54 net = 144 bytes
//   TLS  - server invia: 189 bytes → wire: 189 + 22 TLS + 54 net = 265 bytes
//   plain - client invia: 90 bytes  → wire: 90  + 54 net = 144 bytes (stessa dimensione wire)
//   plain - server invia: 211 bytes → wire: 211 + 54 net = 265 bytes (stessa dimensione wire)
const BYTES_TO_RECEIVE_TLS: usize = 68;
const BYTES_TO_SEND_TLS: usize = 189;
const BYTES_TO_RECEIVE_PLAIN: usize = 90;  // 68 + 22 TLS overhead
const BYTES_TO_SEND_PLAIN: usize = 211;    // 189 + 22 TLS overhead

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

async fn handle_client_tls(tcp_stream: TcpStream, acceptor: TlsAcceptor) {
    let peer_addr = tcp_stream.peer_addr().unwrap();
    println!("Nuova connessione (TLS) da: {}", peer_addr);

    tcp_stream.set_nodelay(true).ok();
    set_tcp_quickack(&tcp_stream, true);

    let mut tls_stream = match acceptor.accept(tcp_stream).await {
        Ok(s) => s,
        Err(e) => { eprintln!("Errore TLS accept: {}", e); return; }
    };

    let mut buffer = vec![0u8; 65536];
    match tls_stream.read_exact(&mut buffer[..BYTES_TO_RECEIVE_TLS]).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nella lettura: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND_TLS];
    match tls_stream.write_all(&response).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nell'invio: {}", e); return; }
    }

    let mut buf = [0u8; 1];
    let _ = tls_stream.read(&mut buf).await;
    let _ = tls_stream.shutdown().await;
}

async fn handle_client_plain(mut tcp_stream: TcpStream) {
    let peer_addr = tcp_stream.peer_addr().unwrap();
    println!("Nuova connessione (plain) da: {}", peer_addr);

    tcp_stream.set_nodelay(true).ok();
    set_tcp_quickack(&tcp_stream, true);

    let mut buffer = vec![0u8; 65536];
    match tcp_stream.read_exact(&mut buffer[..BYTES_TO_RECEIVE_PLAIN]).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nella lettura: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND_PLAIN];
    match tcp_stream.write_all(&response).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nell'invio: {}", e); return; }
    }

    let mut buf = [0u8; 1];
    let _ = tcp_stream.read(&mut buf).await;
    let _ = tcp_stream.shutdown().await;
}

fn make_server_config() -> rustls::ServerConfig {
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(
        vec!["experiment.server".to_string()]
    ).expect("Errore nella generazione del certificato autofirmato");

    let cert_der = CertificateDer::from(cert.der().as_ref().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("Errore nella configurazione TLS server")
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();

    // Uso: [porta] [--http]
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_PORT);
    let use_tls = !args.iter().any(|a| a == "--http");
    let bind_address = format!("0.0.0.0:{}", port);

    let listener = TcpListener::bind(&bind_address).await.unwrap();

    if use_tls {
        let server_config = Arc::new(make_server_config());
        let acceptor = TlsAcceptor::from(Arc::clone(&server_config));
        println!("Server TLS in ascolto su {}", bind_address);
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let acc = acceptor.clone();
                    tokio::spawn(async move { handle_client_tls(stream, acc).await; });
                }
                Err(e) => eprintln!("Errore nella connessione: {}", e),
            }
        }
    } else {
        println!("Server TCP (plain) in ascolto su {}", bind_address);
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tokio::spawn(async move { handle_client_plain(stream).await; });
                }
                Err(e) => eprintln!("Errore nella connessione: {}", e),
            }
        }
    }
}
