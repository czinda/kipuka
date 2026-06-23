//! One-Time Password generation, validation, and lifecycle for EST enrollment.
//!
//! Provides OTP creation, cryptographic storage, and consumption for EST
//! enrollment authentication per RHELBU-3536 R7-R12:
//! - R7: Minimum 128-bit entropy for generated tokens
//! - R8: Timing-safe comparison during validation
//! - R9: Single-use and multi-use token support
//! - R10: Configurable expiration and max-use limits
//! - R11: Tokens stored as SHA-256 hashes (never plaintext)
//! - R12: Periodic cleanup of expired tokens

pub mod generate;
pub mod store;
pub mod validate;

pub use generate::{OtpGenerator, OtpGeneratorConfig, OtpMetadata};
pub use store::{DbOtpStore, InMemoryOtpStore, OtpRecord, OtpStore as OtpStoreTrait};
pub use validate::{OtpValidator, ValidationResult};

use std::sync::Arc;

/// Errors produced by OTP operations.
#[derive(Debug, thiserror::Error)]
pub enum OtpError {
    /// The supplied OTP token was not found in the store.
    #[error("OTP token not found")]
    NotFound,

    /// The OTP has expired.
    #[error("OTP has expired (expired at {expired_at})")]
    Expired {
        /// ISO-8601 expiration timestamp.
        expired_at: String,
    },

    /// The OTP has exceeded its maximum usage count.
    #[error("OTP usage limit exceeded ({max_uses} uses allowed)")]
    UsageLimitExceeded {
        /// Configured maximum uses.
        max_uses: u32,
    },

    /// The OTP has been explicitly revoked by an administrator.
    #[error("OTP has been revoked")]
    Revoked,

    /// Cryptographic or RNG error during token generation.
    #[error("token generation failed: {0}")]
    GenerationError(String),

    /// Storage backend error.
    #[error("storage error: {0}")]
    StorageError(String),
}

/// Convenience alias for OTP operation results.
pub type OtpResult<T> = Result<T, OtpError>;

/// Placeholder OTP storage and validation engine.
///
/// Preserves backward compatibility with the main binary's initialization
/// until the full OTP subsystem is wired in.
pub struct OtpStore {
    _private: (),
}

impl OtpStore {
    /// Create a placeholder OTP store (backend integration pending).
    pub fn placeholder() -> Arc<Self> {
        Arc::new(Self { _private: () })
    }
}
