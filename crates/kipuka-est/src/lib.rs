//! EST (RFC 7030) protocol types with ML-DSA (FIPS 204) and ML-KEM (FIPS 203) support.
//!
//! This crate implements the wire protocol types for Enrollment over Secure Transport,
//! with comprehensive support for NIST FIPS 204 (ML-DSA) digital signatures and
//! FIPS 203 (ML-KEM) key encapsulation mechanisms.
//!
//! # Supported Operations
//!
//! - `/cacerts` - Retrieve CA certificate chain
//! - `/simpleenroll` - Certificate enrollment with PKCS#10 CSR
//! - `/simplereenroll` - Certificate re-enrollment with mTLS
//! - `/fullcmc` - Full CMC protocol support
//! - `/serverkeygen` - Server-side key generation with ML-KEM KRA support
//! - `/csrattrs` - CSR attribute hints including PQC algorithm OIDs
//!
//! # Post-Quantum Cryptography
//!
//! All enrollment operations support:
//! - ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204 digital signatures)
//! - ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203 key encapsulation)
//! - Composite algorithms (ML-DSA + traditional) per OID arc 2.16.840.1.114027.80.5.2

pub mod cacerts;
pub mod content_type;
pub mod csrattrs;
pub mod enroll;
pub mod fullcmc;
pub mod reenroll;
pub mod serverkeygen;

use thiserror::Error;

/// EST protocol errors.
#[derive(Debug, Error, Clone)]
pub enum EstError {
    /// Invalid base64 encoding.
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Invalid DER encoding.
    #[error("Invalid DER encoding: {0}")]
    InvalidDer(String),

    /// Invalid PKCS#7 structure.
    #[error("Invalid PKCS#7 structure: {0}")]
    InvalidPkcs7(String),

    /// Invalid PKCS#10 CSR.
    #[error("Invalid PKCS#10 CSR: {0}")]
    InvalidPkcs10(String),

    /// Invalid PKCS#8 private key.
    #[error("Invalid PKCS#8 private key: {0}")]
    InvalidPkcs8(String),

    /// Invalid CMC request.
    #[error("Invalid CMC request: {0}")]
    InvalidCmc(String),

    /// Missing required field.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Unsupported algorithm.
    #[error("Unsupported algorithm: OID {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid multipart MIME structure.
    #[error("Invalid multipart MIME: {0}")]
    InvalidMultipart(String),

    /// Subject mismatch in re-enrollment.
    #[error("Subject mismatch: expected {expected}, got {actual}")]
    SubjectMismatch { expected: String, actual: String },

    /// Invalid proof of possession.
    #[error("Invalid proof of possession: {0}")]
    InvalidPop(String),

    /// Invalid EKU for CMC RA.
    #[error("Invalid EKU: expected id-kp-cmcRA")]
    InvalidEku,

    /// ML-KEM level mismatch.
    #[error("ML-KEM level mismatch: requested {requested}, server only supports {supported}")]
    MlKemLevelMismatch { requested: u16, supported: u16 },

    /// Generic protocol error.
    #[error("EST protocol error: {0}")]
    Protocol(String),
}

/// Result type for EST operations.
pub type EstResult<T> = Result<T, EstError>;

/// EST protocol operations per RFC 7030.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EstOperation {
    /// Retrieve CA certificates (§4.1).
    CaCerts,

    /// Simple enrollment (§4.2).
    SimpleEnroll,

    /// Simple re-enrollment (§4.2.2).
    SimpleReenroll,

    /// Full CMC (§4.3).
    FullCmc,

    /// Server-side key generation (§4.4) with ML-KEM KRA support.
    ServerKeygen,

    /// CSR attributes (§4.5).
    CsrAttrs,
}

impl EstOperation {
    /// Returns the URL path segment for this operation.
    pub fn path(&self) -> &'static str {
        match self {
            Self::CaCerts => "cacerts",
            Self::SimpleEnroll => "simpleenroll",
            Self::SimpleReenroll => "simplereenroll",
            Self::FullCmc => "fullcmc",
            Self::ServerKeygen => "serverkeygen",
            Self::CsrAttrs => "csrattrs",
        }
    }

    /// Returns whether this operation requires mTLS client authentication.
    pub fn requires_mtls(&self) -> bool {
        match self {
            Self::CaCerts | Self::CsrAttrs => false,
            Self::SimpleEnroll | Self::SimpleReenroll | Self::FullCmc | Self::ServerKeygen => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_paths() {
        assert_eq!(EstOperation::CaCerts.path(), "cacerts");
        assert_eq!(EstOperation::SimpleEnroll.path(), "simpleenroll");
        assert_eq!(EstOperation::SimpleReenroll.path(), "simplereenroll");
        assert_eq!(EstOperation::FullCmc.path(), "fullcmc");
        assert_eq!(EstOperation::ServerKeygen.path(), "serverkeygen");
        assert_eq!(EstOperation::CsrAttrs.path(), "csrattrs");
    }

    #[test]
    fn test_mtls_requirements() {
        assert!(!EstOperation::CaCerts.requires_mtls());
        assert!(!EstOperation::CsrAttrs.requires_mtls());
        assert!(EstOperation::SimpleEnroll.requires_mtls());
        assert!(EstOperation::SimpleReenroll.requires_mtls());
        assert!(EstOperation::FullCmc.requires_mtls());
        assert!(EstOperation::ServerKeygen.requires_mtls());
    }
}
