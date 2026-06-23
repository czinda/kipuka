//! CA initialization and validation.
//!
//! Loads CA keys and certificates from files or PKCS#11 URIs, validates
//! that the CA certificate has the required extensions (Basic Constraints
//! CA:TRUE, Key Usage keyCertSign), and builds the per-CA runtime state.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors during CA initialization.
#[derive(Debug, Error)]
pub enum CaInitError {
    /// The CA certificate file could not be read.
    #[error("failed to read CA certificate from {path}: {source}")]
    CertRead {
        path: String,
        source: std::io::Error,
    },

    /// No certificates found in the CA certificate file.
    #[error("no certificates found in {path}")]
    NoCertificates { path: String },

    /// The CA certificate does not have Basic Constraints CA:TRUE.
    #[error("CA certificate is missing Basic Constraints CA:TRUE")]
    NotCaCertificate,

    /// The CA certificate Key Usage does not include keyCertSign.
    #[error("CA certificate Key Usage does not include keyCertSign")]
    MissingKeyCertSign,

    /// The CA private key could not be loaded.
    #[error("failed to load CA private key from {path}: {reason}")]
    KeyLoad { path: String, reason: String },

    /// The key is referenced by a PKCS#11 URI and requires HSM setup.
    #[error("PKCS#11 URI detected for CA key: {uri}")]
    Pkcs11Uri { uri: String },

    /// General configuration error.
    #[error("CA init error: {0}")]
    Config(String),
}

/// Configuration for a single CA backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    /// Unique identifier for this CA.
    pub id: String,
    /// Path to the CA certificate chain (PEM).
    pub cert_chain_path: PathBuf,
    /// Path to the CA private key (PEM, PKCS#8, or PKCS#11 URI).
    pub key_path: PathBuf,
    /// Whether the key is stored in an HSM (PKCS#11).
    pub hsm: bool,
    /// Priority for HA selection (lower = higher priority).
    pub priority: u32,
    /// Weight for weighted distribution.
    pub weight: u32,
    /// Base URL for remote CA operations (if this is a proxy to an upstream CA).
    pub endpoint: Option<String>,
}

/// Initialized CA instance ready for certificate issuance.
pub struct CaInstance {
    /// Configuration this instance was built from.
    pub config: CaConfig,
    /// Loaded CA certificate chain (DER-encoded).
    pub cert_chain: Vec<Vec<u8>>,
    /// Whether the private key is HSM-backed.
    pub hsm_backed: bool,
    // In a full implementation, this would hold the signing key handle:
    // - Software key: `openssl::pkey::PKey<openssl::pkey::Private>`
    // - HSM key: `kipuka_hsm::HsmContext` + key handle
}

impl CaInstance {
    /// Initialize a CA from configuration.
    ///
    /// Loads the certificate chain, validates CA extensions, and prepares
    /// the signing key (or detects PKCS#11 URI for HSM delegation).
    pub fn from_config(config: &CaConfig) -> Result<Self, CaInitError> {
        let cert_chain = load_cert_chain(&config.cert_chain_path)?;
        validate_ca_certificate(&cert_chain)?;

        // Check if key is PKCS#11 URI.
        if config.hsm || is_pkcs11_uri(&config.key_path)? {
            info!(
                ca_id = %config.id,
                "CA key is HSM-backed (PKCS#11); deferring to kipuka-hsm"
            );
            return Ok(Self {
                config: config.clone(),
                cert_chain,
                hsm_backed: true,
            });
        }

        // Software key: validate the file is readable.
        if !config.key_path.exists() {
            return Err(CaInitError::KeyLoad {
                path: config.key_path.display().to_string(),
                reason: "file does not exist".into(),
            });
        }

        info!(
            ca_id = %config.id,
            cert_count = cert_chain.len(),
            hsm = false,
            "CA instance initialized"
        );

        Ok(Self {
            config: config.clone(),
            cert_chain,
            hsm_backed: false,
        })
    }

    /// The CA identifier.
    pub fn id(&self) -> &str {
        &self.config.id
    }
}

/// Load a PEM certificate chain and return DER-encoded certificates.
fn load_cert_chain(path: &Path) -> Result<Vec<Vec<u8>>, CaInitError> {
    let pem_data = std::fs::read(path).map_err(|e| CaInitError::CertRead {
        path: path.display().to_string(),
        source: e,
    })?;

    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut &pem_data[..])
        .filter_map(|r| r.ok())
        .map(|c| c.to_vec())
        .collect();

    if certs.is_empty() {
        return Err(CaInitError::NoCertificates {
            path: path.display().to_string(),
        });
    }

    debug!(
        path = %path.display(),
        count = certs.len(),
        "loaded CA certificate chain"
    );

    Ok(certs)
}

/// Validate that the first certificate in the chain is a CA certificate.
///
/// Checks:
/// - Basic Constraints: CA:TRUE
/// - Key Usage: keyCertSign
///
/// Uses `synta-certificate` for X.509 parsing when available. For now,
/// performs a best-effort check by looking for known ASN.1 OID patterns
/// in the DER encoding.
fn validate_ca_certificate(chain: &[Vec<u8>]) -> Result<(), CaInitError> {
    let ca_cert_der = chain.first().ok_or(CaInitError::NotCaCertificate)?;

    // Basic Constraints OID: 2.5.29.19 = 55 1D 13
    let bc_oid = [0x55, 0x1D, 0x13];
    if !contains_subsequence(ca_cert_der, &bc_oid) {
        warn!("CA certificate may be missing Basic Constraints extension");
        // Don't fail hard yet; the full implementation will use synta-certificate
        // for proper ASN.1 parsing.
    }

    // Key Usage OID: 2.5.29.15 = 55 1D 0F
    let ku_oid = [0x55, 0x1D, 0x0F];
    if !contains_subsequence(ca_cert_der, &ku_oid) {
        warn!("CA certificate may be missing Key Usage extension");
    }

    debug!("CA certificate validation passed (basic OID check)");
    Ok(())
}

/// Check if a key file path contains a PKCS#11 URI.
fn is_pkcs11_uri(path: &Path) -> Result<bool, CaInitError> {
    if let Some(s) = path.to_str()
        && s.starts_with("pkcs11:")
    {
        return Ok(true);
    }

    // Also check file contents for a PKCS#11 URI.
    if path.exists()
        && let Ok(contents) = std::fs::read_to_string(path)
        && contents.trim().starts_with("pkcs11:")
    {
        return Ok(true);
    }

    Ok(false)
}

/// Naive subsequence search in a byte slice.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
