//! rustls setup for the server (STARTTLS on the submission ports) and the
//! client (SMTPS/STARTTLS to the smarthost). Certificates, keys and CA
//! bundles are read via our own PEM parser.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName, UnixTime,
};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SignatureScheme};
use std::sync::Arc;

pub fn load_server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    let cert_text = std::fs::read_to_string(cert_path)
        .map_err(|e| format!("cannot read {}: {}", cert_path, e))?;
    let key_text =
        std::fs::read_to_string(key_path).map_err(|e| format!("cannot read {}: {}", key_path, e))?;

    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    for (label, der) in crate::pem::blocks(&cert_text) {
        if label.ends_with("CERTIFICATE") {
            certs.push(CertificateDer::from(der));
        }
    }
    if certs.is_empty() {
        return Err(format!("no certificate found in {}", cert_path));
    }

    let mut key: Option<(String, Vec<u8>)> = None;
    for (label, der) in crate::pem::blocks(&key_text) {
        if label.contains("PRIVATE KEY") {
            key = Some((label, der));
            break;
        }
    }
    let Some((label, der)) = key else {
        return Err(format!("no private key found in {}", key_path));
    };
    let key = match label.as_str() {
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
        _ => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
    };

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid TLS certificate/key: {}", e))?;
    Ok(Arc::new(cfg))
}

/// Load CA certificates for verifying the smarthost's certificate.
pub fn load_client_config(ca_path: &str) -> Result<Arc<ClientConfig>, String> {
    let text = std::fs::read_to_string(ca_path)
        .map_err(|e| format!("cannot read {}: {}", ca_path, e))?;
    let mut roots = RootCertStore::empty();
    let mut n = 0;
    for (label, der) in crate::pem::blocks(&text) {
        if label.ends_with("CERTIFICATE") {
            if roots.add(CertificateDer::from(der)).is_ok() {
                n += 1;
            }
        }
    }
    if n == 0 {
        return Err(format!("no usable CA certificates in {}", ca_path));
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Client config that accepts any certificate (smarthost_verify = false).
/// Explicitly insecure; for self-signed smarthosts only.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn load_client_config_insecure() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth(),
    )
}

/// ServerName for the smarthost host (IP literal or DNS name).
pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<std::net::Ipv4Addr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(h.to_string()).map_err(|e| format!("invalid smarthost name: {}", e))
}
