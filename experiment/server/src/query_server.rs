use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::thread;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const DEFAULT_PORT: &str = "8080";
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

fn handle_client(stream: TcpStream, tls_config: Arc<rustls::ServerConfig>) {
    println!("Nuova connessione da: {}", stream.peer_addr().unwrap());

    // Opzioni socket sul raw TcpStream prima del wrapping TLS
    stream.set_nodelay(true).ok();
    set_tcp_quickack(&stream, true);

    let conn = match rustls::ServerConnection::new(tls_config) {
        Ok(c) => c,
        Err(e) => { eprintln!("Errore creazione connessione TLS server: {}", e); return; }
    };
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let mut buffer = vec![0u8; 65536];

    match tls.read_exact(&mut buffer[..BYTES_TO_RECEIVE]) {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nella lettura: {}", e); return; }
    }

    let response = vec![0u8; BYTES_TO_SEND];
    match tls.write_all(&response) {
        Ok(_) => {}
        Err(e) => { eprintln!("Errore nell'invio: {}", e); return; }
    }
    let _ = tls.flush();

    // Aspetta il FIN dal client
    let mut buf = [0u8; 1];
    let _ = tls.read(&mut buf);

    // TLS close_notify + TCP FIN
    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(Shutdown::Write);
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

fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();

    // Uso: [porta]  (default: 8080)
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).map(|s| s.as_str()).unwrap_or(DEFAULT_PORT);
    let bind_address = format!("0.0.0.0:{}", port);

    let tls_config = Arc::new(make_server_config());
    let listener = TcpListener::bind(&bind_address).unwrap();
    println!("Server TLS in ascolto su {}", bind_address);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = Arc::clone(&tls_config);
                thread::spawn(move || {
                    handle_client(stream, config);
                });
            }
            Err(e) => {
                eprintln!("Errore nella connessione: {}", e);
            }
        }
    }
}
