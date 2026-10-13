use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

// TLS 1.3 overhead per record: 5 (header) + 1 (inner content type) + 16 (AEAD tag) = 22 bytes
// Wire invariant (TLS):
//   send:    68 payload + 22 TLS + 54 net headers = 144 bytes wire
//   receive: 189 payload + 22 TLS + 54 net headers = 265 bytes wire
// Wire invariant (plain TCP, same wire size):
//   send:    90 payload + 54 net headers = 144 bytes wire  (90 = 68 + 22)
//   receive: 211 payload + 54 net headers = 265 bytes wire (211 = 189 + 22)
pub const BYTES_TO_SEND_TLS: usize = 68;
pub const BYTES_TO_RECEIVE_TLS: usize = 189;
pub const BYTES_TO_SEND_PLAIN: usize = 90;
pub const BYTES_TO_RECEIVE_PLAIN: usize = 211;
pub const N_REQUESTS: usize = 100;

// Accepts any (self-signed) certificate without verification
#[derive(Debug)]
pub struct NoVerifier;

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

pub fn make_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

pub fn set_tcp_quickack(stream: &TcpStream, enable: bool) {
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
