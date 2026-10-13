use std::os::unix::io::AsRawFd;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// Payload sizes (without TLS/network overhead):
//   TLS  - client sends: 68 bytes  → wire: 68  + 22 TLS + 54 net = 144 bytes
//   TLS  - server sends: 189 bytes → wire: 189 + 22 TLS + 54 net = 265 bytes
//   plain - client sends: 90 bytes  → wire: 90  + 54 net = 144 bytes (same wire size)
//   plain - server sends: 211 bytes → wire: 211 + 54 net = 265 bytes (same wire size)
pub const BYTES_TO_RECEIVE_TLS: usize = 68;
pub const BYTES_TO_SEND_TLS: usize = 189;
pub const BYTES_TO_RECEIVE_PLAIN: usize = 90;
pub const BYTES_TO_SEND_PLAIN: usize = 211;

pub fn set_tcp_quickack(stream: &impl AsRawFd, enable: bool) {
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

pub fn make_server_config() -> rustls::ServerConfig {
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
