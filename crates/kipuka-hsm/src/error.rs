//! Error types for HSM operations.

use thiserror::Error;

/// Result type for HSM operations.
pub type HsmResult<T> = Result<T, HsmError>;

/// HSM operation errors.
#[derive(Debug, Error)]
pub enum HsmError {
    /// Failed to load PKCS#11 library.
    #[error("Failed to load PKCS#11 library: {0}")]
    LibraryLoad(String),

    /// Slot access error.
    #[error("Slot access error: {0}")]
    SlotAccess(String),

    /// Session creation failed.
    #[error("Session creation failed: {0}")]
    SessionCreate(String),

    /// Login failed.
    #[error("Login failed: {0}")]
    Login(String),

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Signing operation failed.
    #[error("Signing operation failed: {0}")]
    SigningFailure(String),

    /// Key not found.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Unsupported mechanism.
    #[error("Unsupported mechanism: {0}")]
    UnsupportedMechanism(String),

    /// Post-quantum cryptography not supported by HSM.
    #[error("PQC not supported: {0}")]
    PqcNotSupported(String),

    /// Key wrapping failed.
    #[error("Key wrapping failed: {0}")]
    KeyWrap(String),

    /// URI parsing error.
    #[error("PKCS#11 URI parse error: {0}")]
    UriParse(String),

    /// Cryptoki library error.
    #[error("Cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// UTF-8 conversion error.
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// URL parsing error.
    #[error("URL error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Hex decoding error.
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
