use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const BIND_ADDRESS: &str = "0.0.0.0:8081";
// Dimensioni payload (senza overhead TLS/rete):
//   client invia: 68 bytes → wire: 68 + 22 TLS + 54 net = 144 bytes
//   server invia: 189 bytes → wire: 189 + 22 TLS + 54 net = 265 bytes
const BYTES_TO_RECEIVE: usize = 68;
const BYTES_TO_SEND: usize = 189;

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

async fn handle_client(tcp_stream: TcpStream, acceptor: TlsAcceptor) {
    let peer_addr = tcp_stream.peer_addr().unwrap();
    println!("Nuova connessione da: {}", peer_addr);

    // Opzioni socket sul raw TcpStream prima del wrapping TLS
    tcp_stream.set_nodelay(true).ok();
    set_tcp_quickack(&tcp_stream, false);

    let mut tls_stream = match acceptor.accept(tcp_stream).await {
        Ok(s) => s,
        Err(e) => { eprintln!("Errore TLS accept: {}", e); return; }
    };

    let mut buffer = vec![0u8; 65536];

    match tls_stream.read_exact(&mut buffer[..BYTES_TO_RECEIVE]).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nella lettura: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND];
    match tls_stream.write_all(&response).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nell'invio: {}", e); return; }
    }

    // Aspetta il FIN dal client + shutdown TLS
    let mut buf = [0u8; 1];
    let _ = tls_stream.read(&mut buf).await;
    let _ = tls_stream.shutdown().await;
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

    let server_config = Arc::new(make_server_config());
    let acceptor = TlsAcceptor::from(Arc::clone(&server_config));

    let listener = TcpListener::bind(BIND_ADDRESS).await.unwrap();
    println!("Server TLS in ascolto su {}", BIND_ADDRESS);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    handle_client(stream, acc).await;
                });
            }
            Err(e) => {
                eprintln!("Errore nella connessione: {}", e);
            }
        }
    }
}
