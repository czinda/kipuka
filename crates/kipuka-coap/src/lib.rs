//! EST over CoAP (RFC 9483) transport for constrained devices.
//!
//! This crate implements the CoAP transport binding for Enrollment over Secure
//! Transport, enabling EST operations on constrained IoT devices that cannot
//! use HTTP/TLS.
//!
//! # Protocol Mapping
//!
//! RFC 9483 maps EST operations to CoAP as follows:
//! - HTTPS transport is replaced by CoAP over DTLS ("coaps")
//! - EST URI paths use abbreviated names (e.g., `/sen` for `/simpleenroll`)
//! - HTTP Content-Type headers map to CoAP Content-Format option IDs
//! - Large payloads (PQC certificates can exceed 7KB) use RFC 7959 block-wise transfer
//!
//! # Modules
//!
//! - [`server`]: CoAP message parsing, encoding, and EST-coaps URI routing
//! - [`dtls`]: DTLS session management abstraction for CoAP security
//! - [`block`]: RFC 7959 block-wise transfer for large EST payloads
//! - [`content_format`]: CoAP content-format IDs for EST media types (RFC 9483 §5.4)

pub mod block;
pub mod content_format;
pub mod dtls;
pub mod server;

pub use server::{AuditInfo, CoapDtlsServer, EstHandler, EstResponse};

use thiserror::Error;

/// Errors arising from CoAP/EST-coaps protocol handling.
#[derive(Debug, Error, Clone)]
pub enum CoapError {
    /// Malformed CoAP message (header, token, or option encoding).
    #[error("Invalid CoAP message: {0}")]
    InvalidMessage(String),

    /// Unrecognized or unsupported CoAP method code.
    #[error("Unsupported CoAP method: {0}")]
    UnsupportedMethod(String),

    /// Unrecognized CoAP Content-Format option value.
    ///
    /// RFC 9483 §5.4 defines the content-format IDs that EST-coaps supports.
    #[error("Unsupported Content-Format: {0}")]
    UnsupportedContentFormat(u16),

    /// Block-wise transfer failure per RFC 7959.
    #[error("Block transfer error: {0}")]
    BlockTransferError(String),

    /// DTLS session establishment or resumption failure.
    ///
    /// RFC 9483 §5 requires DTLS to secure all EST-coaps exchanges.
    #[error("DTLS error: {0}")]
    DtlsError(String),

    /// Payload exceeds the configured maximum size.
    ///
    /// Even with block-wise transfer, reassembled payloads are bounded to
    /// prevent resource exhaustion on constrained devices.
    #[error("Payload too large: {size} bytes exceeds maximum {max} bytes")]
    PayloadTooLarge {
        /// Actual payload size in bytes.
        size: usize,
        /// Configured maximum payload size in bytes.
        max: usize,
    },

    /// No CoAP resource matches the requested URI path.
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    /// Client authentication required but not provided (4.01).
    ///
    /// Returned when an EST operation requires mTLS client certificate
    /// authentication but no certificate was presented during the DTLS
    /// handshake.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Internal server error (catch-all).
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for CoAP operations.
pub type CoapResult<T> = Result<T, CoapError>;
