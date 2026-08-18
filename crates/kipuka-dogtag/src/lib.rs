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
