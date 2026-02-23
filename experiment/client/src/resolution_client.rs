use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};
use std::fs::OpenOptions;
use std::env;
use std::sync::Arc;
use tokio::task;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

const DEFAULT_SERVER_ADDRESS: &str = "10.10.0.2:8081";
// TLS 1.3 overhead per record: 5 (header) + 1 (inner content type) + 16 (AEAD tag) = 22 bytes
// Wire invariant:
//   send:    68 payload + 22 TLS + 54 net headers = 144 bytes  (was: 90 + 54)
//   receive: 189 payload + 22 TLS + 54 net headers = 265 bytes (was: 211 + 54)
const BYTES_TO_SEND: usize = 68;
const BYTES_TO_RECEIVE: usize = 189;
const N_REQUESTS: usize = 100;
const N_PARALLEL_PACKETS: usize = 20;

// Accetta qualsiasi certificato (autofirmato) senza verifica
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn make_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

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

// Funzione che invia un singolo pacchetto e riceve la risposta via TLS
// Restituisce il tempo impiegato per il data transfer (senza handshake TCP+TLS)
fn send_and_receive_packet(
    server_address: &str,
    tls_config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
) -> Result<Duration, std::io::Error> {
    // Connessione TCP
    let tcp = TcpStream::connect(server_address)?;
    tcp.set_nodelay(true).ok();
    set_tcp_quickack(&tcp, true);

    // Wrap TLS
    let conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    // Completa handshake TLS prima di iniziare la misurazione
    loop {
        tls.conn.complete_io(&mut tls.sock)?;
        if !tls.conn.is_handshaking() { break; }
    }

    let data = vec![0u8; BYTES_TO_SEND];

    // Inizia misurazione dopo TCP + TLS handshake
    let start = Instant::now();

    tls.write_all(&data)?;

    let mut response = vec![0u8; BYTES_TO_RECEIVE];
    tls.read_exact(&mut response)?;

    let duration = start.elapsed();

    // Chiusura: TLS close_notify + TCP FIN
    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(Shutdown::Write);
    let mut buf = [0u8; 1];
    let _ = tls.read(&mut buf);

    Ok(duration)
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();

    // Uso: <output_file> [server_address] [n_requests]
    let args: Vec<String> = env::args().collect();
    let output_file = if args.len() > 1 {
        args[1].clone()
    } else {
        eprintln!("Uso: {} <output_file> [server_address] [n_requests]", args[0]);
        std::process::exit(1);
    };

    let server_address = if args.len() > 2 {
        args[2].clone()
    } else {
        DEFAULT_SERVER_ADDRESS.to_string()
    };

    println!("Connessione TLS a {}", server_address);
    println!("Configurazione:");
    println!("  - Bytes da inviare: {} (+ 22 TLS + 54 net = 144 wire)", BYTES_TO_SEND);
    println!("  - Bytes da ricevere: {} (+ 22 TLS + 54 net = 265 wire)", BYTES_TO_RECEIVE);

    let n_requests = if args.len() > 3 {
        args[3].parse::<usize>().unwrap_or(N_REQUESTS)
    } else if let Ok(value) = env::var("N_REQUESTS") {
        value.parse::<usize>().unwrap_or(N_REQUESTS)
    } else {
        N_REQUESTS
    };

    println!("  - Numero totale richieste: {}", n_requests);
    println!("  - Nuova connessione TLS per ogni richiesta");
    println!("  - Output file: {}", output_file);
    println!();

    let tls_config = Arc::new(make_client_config());
    let server_name = ServerName::try_from("experiment.server")
        .expect("Invalid server name")
        .to_owned();

    let mut rtts = Vec::with_capacity(n_requests);

    for i in 0..n_requests {
        // Crea N_PARALLEL_PACKETS task paralleli
        let mut tasks = Vec::new();

        for _j in 0..N_PARALLEL_PACKETS {
            let addr = server_address.clone();
            let config = Arc::clone(&tls_config);
            let name = server_name.clone();
            let task = task::spawn_blocking(move || {
                send_and_receive_packet(&addr, config, name)
            });
            tasks.push(task);
        }

        // Aspetta che tutti i task completino e raccogli i tempi
        let mut all_ok = true;
        let mut durations = Vec::new();

        for task in tasks {
            match task.await {
                Ok(Ok(duration)) => {
                    durations.push(duration);
                }
                Ok(Err(e)) => {
                    eprintln!("Errore in un pacchetto: {}", e);
                    all_ok = false;
                }
                Err(e) => {
                    eprintln!("Errore nel task: {}", e);
                    all_ok = false;
                }
            }
        }

        if all_ok && !durations.is_empty() {
            let max_duration = durations.iter().max().unwrap();
            rtts.push(max_duration.as_micros());
            println!("Richiesta {}/{}: {} pacchetti paralleli completati, tempo massimo data transfer: {:.3} ms",
                     i + 1, n_requests, N_PARALLEL_PACKETS, max_duration.as_secs_f64() * 1000.0);
        } else {
            eprintln!("Richiesta {}/{}: alcuni pacchetti hanno fallito", i + 1, N_REQUESTS);
        }

        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    println!("\nCompletate tutte le {} richieste", n_requests);

    if !rtts.is_empty() {
        let sum: u128 = rtts.iter().sum();
        let avg = sum / rtts.len() as u128;
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();

        println!("\nStatistiche tempo data transfer:");
        println!("  - Media: {:.3} ms", avg as f64 / 1000.0);
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
                println!("\n✓ Risultati salvati in: {}", output_file);
            }
            Err(e) => {
                eprintln!("✗ Errore nella scrittura del file: {}", e);
            }
        }
    }
}
