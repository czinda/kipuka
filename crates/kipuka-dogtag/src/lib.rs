//! Dogtag PKI CA REST API client for kipuka EST server.
//!
//! Provides a Rust client for the Dogtag Certificate Authority REST API,
//! enabling kipuka to use RHCS/Dogtag PKI as its CA backend for certificate
//! enrollment, revocation, and management.
//!
//! # Architecture
//!
//! The client communicates with Dogtag CA over HTTPS using mutual TLS (mTLS)
//! with an agent certificate. All operations are async and use `hyper` +
//! `hyper-openssl` for HTTP transport with full PKCS#11 support.
//!
//! # Supported Operations
//!
//! - **Enrollment**: PKCS#10 profile-based certificate issuance via `/ca/rest/certrequests`
//! - **Certificate management**: Retrieval, listing, and revocation via `/ca/rest/certs`
//! - **Profiles**: Profile enumeration and constraint extraction via `/ca/rest/profiles`
//! - **Full CMC**: CMC request passthrough via `/ca/ee/ca/profileSubmitCMCFull`
//! - **KRA**: Server-side key generation and archival via `/kra/rest/agent/keys`
//! - **HA**: Multi-CA connection pooling with health-based routing

pub mod certs;
pub mod client;
pub mod cmc;
pub mod config;
pub mod enroll;
pub mod kem;
pub mod kra;
pub mod pool;
pub mod profiles;

pub use certs::{CertFilter, CertInfo, RevocationReason};
pub use client::DogtagClient;
pub use cmc::CmcClient;
pub use config::DogtagConfig;
pub use enroll::{EnrollResult, EnrollStatus, ServerKeygenResult};
pub use kra::{KeySearchEntry, KraClient};
pub use pool::DogtagPool;
pub use profiles::{ProfileConstraints, ProfileDetail, ProfileInfo};

use thiserror::Error;

/// Errors from Dogtag PKI REST API operations.
#[derive(Debug, Error)]
pub enum DogtagError {
    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    /// Dogtag returned a non-success HTTP status.
    #[error("Dogtag returned HTTP {status}: {body}")]
    ApiError {
        /// HTTP status code.
        status: u16,
        /// Response body text.
        body: String,
    },

    /// Failed to parse Dogtag response JSON.
    #[error("Failed to parse response: {0}")]
    ParseError(String),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    /// TLS or certificate error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// I/O error reading certificate or key files.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// No healthy CA backend available.
    #[error("No healthy CA backend available")]
    NoHealthyBackend,

    /// Enrollment request was rejected by the CA.
    #[error("Enrollment rejected: {reason}")]
    EnrollmentRejected {
        /// Rejection reason from the CA.
        reason: String,
    },

    /// Enrollment request is pending approval.
    #[error("Enrollment pending: request_id={request_id}")]
    EnrollmentPending {
        /// The request ID to poll for status.
        request_id: String,
    },

    /// KRA operation failed.
    #[error("KRA error: {0}")]
    KraError(String),
}

/// Result type alias for Dogtag operations.
pub type DogtagResult<T> = Result<T, DogtagError>;

pub(crate) fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Cumulative limit applies even to chunked or misleading Content-Length bodies.
pub(crate) async fn bounded_bytes(mut response: reqwest::Response) -> DogtagResult<Vec<u8>> {
    const LIMIT: usize = 4 * 1024 * 1024;
    if response.content_length().is_some_and(|n| n > LIMIT as u64) {
        return Err(DogtagError::ParseError(
            "backend response exceeds 4 MiB".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DogtagError::HttpError(e.to_string()))?
    {
        if chunk.len() > LIMIT.saturating_sub(bytes.len()) {
            return Err(DogtagError::ParseError(
                "backend response exceeds 4 MiB".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub(crate) async fn bounded_text(response: reqwest::Response) -> DogtagResult<String> {
    Ok(String::from_utf8_lossy(&bounded_bytes(response).await?).into_owned())
}

#[cfg(test)]
mod review_regressions {
    use super::*;
    #[test]
    fn tls_verification_is_the_default() {
        let config: DogtagConfig = serde_json::from_value(serde_json::json!({
            "ca_url":"https://ca.example.test", "agent_cert_file":"cert", "agent_key_file":"key", "ca_cert_file":"ca", "profile_id":"profile"
        })).unwrap();
        assert!(!config.accept_invalid_certs);
    }

    #[tokio::test]
    async fn chunked_backend_response_is_bounded() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let block = vec![b'x'; 65536];
            for _ in 0..65 {
                if socket
                    .write_all(b"10000\r\n")
                    .and_then(|_| socket.write_all(&block))
                    .and_then(|_| socket.write_all(b"\r\n"))
                    .is_err()
                {
                    return;
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n");
        });
        let response = reqwest::get(format!("http://{address}")).await.unwrap();
        assert!(
            bounded_bytes(response)
                .await
                .unwrap_err()
                .to_string()
                .contains("exceeds 4 MiB")
        );
        writer.join().unwrap();
    }
}
