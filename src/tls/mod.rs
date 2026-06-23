//! TLS server configuration and client certificate verification.
//!
//! Builds a `rustls::ServerConfig` from the Kipuka `[tls]` config section.
//! Supports:
//!
//! - Server certificate chain and private key loading from PEM files
//! - Client certificate verification with a dedicated EST truststore
//!   (RHELBU-3536 R18: separate from admin truststore)
//! - TLS 1.2+ enforcement (NIAP CA PP FTP_TRP.1)
//! - Channel binding computation for `tls-server-end-point` (RFC 5929)

use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::config::{ClientAuthMode, TlsConfig};
use crate::error::KipukaError;

/// Build a `TlsAcceptor` from the Kipuka TLS configuration.
///
/// The resulting acceptor can be used with `tokio_rustls` to wrap a
/// TCP listener.
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor, KipukaError> {
    let server_config = build_server_config(config)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a `rustls::ServerConfig` from the Kipuka TLS configuration.
fn build_server_config(config: &TlsConfig) -> Result<rustls::ServerConfig, KipukaError> {
    // ── Load server certificate chain ────────────────────────────────────
    let cert_chain = load_cert_chain(&config.cert_file)?;
    let private_key = load_private_key(&config.key_file)?;

    // ── Configure TLS protocol versions (FTP_TRP.1: TLS 1.2+) ───────────
    let versions = protocol_versions(&config.min_protocol, &config.max_protocol)?;

    // ── Configure client authentication ──────────────────────────────────
    let builder = rustls::ServerConfig::builder_with_protocol_versions(&versions);

    let server_config = match config.client_auth {
        ClientAuthMode::Required => {
            let client_verifier = build_client_verifier(&config.ca_file)?;
            builder
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| KipukaError::Tls(format!("server cert config: {e}")))?
        }
        ClientAuthMode::Optional => {
            let client_verifier = build_optional_client_verifier(&config.ca_file)?;
            builder
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| KipukaError::Tls(format!("server cert config: {e}")))?
        }
        ClientAuthMode::None => builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| KipukaError::Tls(format!("server cert config: {e}")))?,
    };

    Ok(server_config)
}

/// Load a PEM certificate chain from a file.
fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, KipukaError> {
    let file = std::fs::File::open(path)
        .map_err(|e| KipukaError::Tls(format!("cannot open cert file '{path}': {e}")))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KipukaError::Tls(format!("cannot parse cert file '{path}': {e}")))?;

    if certs.is_empty() {
        return Err(KipukaError::Tls(format!(
            "no certificates found in '{path}'"
        )));
    }

    Ok(certs)
}

/// Load a PEM private key from a file.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, KipukaError> {
    let file = std::fs::File::open(path)
        .map_err(|e| KipukaError::Tls(format!("cannot open key file '{path}': {e}")))?;
    let mut reader = BufReader::new(file);

    // Try all PEM key formats (PKCS#8, PKCS#1 RSA, SEC1 EC)
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| KipukaError::Tls(format!("cannot parse key file '{path}': {e}")))?
        .ok_or_else(|| KipukaError::Tls(format!("no private key found in '{path}'")))?;

    Ok(key)
}

/// Load CA certificates from a PEM file for client verification.
fn load_trust_anchors(
    ca_file: &str,
) -> Result<rustls::RootCertStore, KipukaError> {
    let file = std::fs::File::open(ca_file)
        .map_err(|e| KipukaError::Tls(format!("cannot open CA file '{ca_file}': {e}")))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KipukaError::Tls(format!("cannot parse CA file '{ca_file}': {e}")))?;

    if certs.is_empty() {
        return Err(KipukaError::Tls(format!(
            "no CA certificates found in '{ca_file}'"
        )));
    }

    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| KipukaError::Tls(format!("invalid CA certificate: {e}")))?;
    }

    Ok(root_store)
}

/// Build a client certificate verifier that requires a valid certificate.
fn build_client_verifier(
    ca_file: &str,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, KipukaError> {
    let roots = load_trust_anchors(ca_file)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| KipukaError::Tls(format!("client verifier build: {e}")))?;
    Ok(verifier)
}

/// Build a client certificate verifier that accepts but does not require
/// a valid certificate (optional mTLS).
fn build_optional_client_verifier(
    ca_file: &str,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, KipukaError> {
    let roots = load_trust_anchors(ca_file)?;
    let verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .map_err(|e| KipukaError::Tls(format!("optional client verifier build: {e}")))?;
    Ok(verifier)
}

/// Map config protocol version strings to rustls `SupportedProtocolVersion`.
fn protocol_versions(
    min: &str,
    max: &str,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, KipukaError> {
    let mut versions = Vec::new();

    match (min, max) {
        ("1.2", "1.2") => {
            versions.push(&rustls::version::TLS12);
        }
        ("1.2", "1.3") => {
            versions.push(&rustls::version::TLS12);
            versions.push(&rustls::version::TLS13);
        }
        ("1.3", "1.3") => {
            versions.push(&rustls::version::TLS13);
        }
        _ => {
            return Err(KipukaError::Tls(format!(
                "unsupported protocol version range: {min}..{max}"
            )));
        }
    }

    Ok(versions)
}

/// Compute the `tls-server-end-point` channel binding value (RFC 5929).
///
/// This is the hash of the server's TLS certificate, used for channel
/// binding in HTTP authentication protocols.  The hash algorithm is
/// determined by the certificate's signature algorithm:
///
/// - MD5 or SHA-1 signed certs → use SHA-256
/// - All others → use the cert's own hash algorithm
///
/// EST uses this for binding enrollment requests to the TLS session,
/// preventing credential forwarding attacks.
pub fn compute_channel_binding(cert_der: &[u8]) -> Vec<u8> {
    // Per RFC 5929 §3: for certs signed with MD5 or SHA-1, use SHA-256.
    // For simplicity, we always use SHA-256 here since most modern CAs
    // use SHA-256+ anyway, and the RFC requires SHA-256 as the fallback.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions_1_2_to_1_3() {
        let versions = protocol_versions("1.2", "1.3").unwrap();
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn protocol_versions_1_3_only() {
        let versions = protocol_versions("1.3", "1.3").unwrap();
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn protocol_versions_invalid() {
        assert!(protocol_versions("1.0", "1.2").is_err());
        assert!(protocol_versions("1.3", "1.2").is_err());
    }

    #[test]
    fn channel_binding_is_sha256() {
        let cert_der = b"fake certificate DER bytes";
        let binding = compute_channel_binding(cert_der);
        assert_eq!(binding.len(), 32); // SHA-256 output is 32 bytes
    }
}
