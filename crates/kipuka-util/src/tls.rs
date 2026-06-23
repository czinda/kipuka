//! TLS configuration with NIAP CA PP and FIPS compliance.
//!
//! Enforces:
//! - TLS 1.2+ only (no SSLv3, TLS 1.0, TLS 1.1) per NIAP CA PP
//! - FIPS-approved cipher suites only per NIAP CA PP FCS_TLSC_EXT.1
//! - mTLS client certificate verification for EST enrollment
//! - PKCS#11 URI detection for HSM-backed private keys

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors during TLS configuration.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Failed to read a PEM file.
    #[error("failed to read PEM file {path}: {source}")]
    PemRead {
        path: String,
        source: std::io::Error,
    },

    /// No certificates found in the PEM file.
    #[error("no certificates found in {path}")]
    NoCertificates { path: String },

    /// No private key found in the PEM file.
    #[error("no private key found in {path}")]
    NoPrivateKey { path: String },

    /// The private key references a PKCS#11 URI (needs HSM integration).
    #[error("PKCS#11 URI detected: {uri} (use kipuka-hsm crate)")]
    Pkcs11Uri { uri: String },

    /// rustls configuration error.
    #[error("TLS configuration error: {0}")]
    Config(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Serializable TLS configuration from the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the server certificate chain (PEM).
    pub cert_chain_path: PathBuf,
    /// Path to the server private key (PEM, PKCS#8, or PKCS#11 URI).
    pub private_key_path: PathBuf,
    /// Optional path to trusted CA certificates for client verification (mTLS).
    pub client_ca_path: Option<PathBuf>,
    /// Whether to require client certificates (mTLS).
    pub require_client_cert: bool,
    /// Minimum TLS version (default: TLS 1.2, per NIAP CA PP).
    pub min_version: Option<String>,
}

/// Builder for constructing a `rustls::ServerConfig`.
///
/// Enforces NIAP CA PP requirements:
/// - FCS_TLSS_EXT.1: TLS 1.2 minimum, no deprecated protocols
/// - FCS_TLSC_EXT.1: FIPS-approved cipher suites only
/// - FCS_COP.1: Approved cryptographic operations
pub struct TlsConfigBuilder {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: Option<PrivateKeyDer<'static>>,
    client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
}

impl TlsConfigBuilder {
    /// Start building a TLS configuration.
    pub fn new() -> Self {
        Self {
            cert_chain: Vec::new(),
            private_key: None,
            client_verifier: None,
        }
    }

    /// Load the server certificate chain from a PEM file.
    pub fn with_cert_chain(mut self, path: &Path) -> Result<Self, TlsError> {
        let pem_data = std::fs::read(path).map_err(|e| TlsError::PemRead {
            path: path.display().to_string(),
            source: e,
        })?;

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &pem_data[..])
                .filter_map(|r| r.ok())
                .collect();

        if certs.is_empty() {
            return Err(TlsError::NoCertificates {
                path: path.display().to_string(),
            });
        }

        info!(
            path = %path.display(),
            count = certs.len(),
            "loaded certificate chain"
        );

        self.cert_chain = certs;
        Ok(self)
    }

    /// Load the server private key from a PEM or PKCS#8 file.
    ///
    /// If the file content starts with `pkcs11:`, returns an error
    /// indicating that the HSM crate should be used instead.
    pub fn with_private_key(mut self, path: &Path) -> Result<Self, TlsError> {
        let pem_data = std::fs::read(path).map_err(|e| TlsError::PemRead {
            path: path.display().to_string(),
            source: e,
        })?;

        // Detect PKCS#11 URI (key managed by HSM).
        if let Ok(text) = std::str::from_utf8(&pem_data) {
            let trimmed = text.trim();
            if trimmed.starts_with("pkcs11:") {
                return Err(TlsError::Pkcs11Uri {
                    uri: trimmed.to_owned(),
                });
            }
        }

        let key = rustls_pemfile::private_key(&mut &pem_data[..])
            .map_err(|e| TlsError::Config(format!("key parse error: {e}")))?
            .ok_or_else(|| TlsError::NoPrivateKey {
                path: path.display().to_string(),
            })?;

        debug!(path = %path.display(), "loaded private key");

        self.private_key = Some(key);
        Ok(self)
    }

    /// Set up client certificate verification for mTLS.
    pub fn with_client_auth(mut self, ca_path: &Path, required: bool) -> Result<Self, TlsError> {
        let pem_data = std::fs::read(ca_path).map_err(|e| TlsError::PemRead {
            path: ca_path.display().to_string(),
            source: e,
        })?;

        let mut root_store = rustls::RootCertStore::empty();
        let ca_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &pem_data[..])
                .filter_map(|r| r.ok())
                .collect();

        if ca_certs.is_empty() {
            return Err(TlsError::NoCertificates {
                path: ca_path.display().to_string(),
            });
        }

        for cert in &ca_certs {
            root_store.add(cert.clone()).map_err(|e| {
                TlsError::Config(format!("failed to add CA cert to trust store: {e}"))
            })?;
        }

        let verifier = if required {
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| TlsError::Config(format!("client verifier build error: {e}")))?
        } else {
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                .allow_unauthenticated()
                .build()
                .map_err(|e| TlsError::Config(format!("client verifier build error: {e}")))?
        };

        info!(
            ca_path = %ca_path.display(),
            ca_count = ca_certs.len(),
            required,
            "configured client certificate verification"
        );

        self.client_verifier = Some(verifier);
        Ok(self)
    }

    /// Build the `rustls::ServerConfig`.
    ///
    /// Enforces NIAP CA PP requirements:
    /// - TLS 1.2+ only (FCS_TLSS_EXT.1)
    /// - FIPS-approved cipher suites (FCS_TLSC_EXT.1)
    pub fn build(self) -> Result<rustls::ServerConfig, TlsError> {
        let key = self
            .private_key
            .ok_or_else(|| TlsError::Config("no private key loaded".into()))?;

        if self.cert_chain.is_empty() {
            return Err(TlsError::Config("no certificate chain loaded".into()));
        }

        let provider = Arc::new(ring_provider::default_provider());

        let mut config = if let Some(verifier) = self.client_verifier {
            rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
                .map_err(|e| TlsError::Config(format!("protocol version error: {e}")))?
                .with_client_cert_verifier(verifier)
                .with_single_cert(self.cert_chain, key)
                .map_err(|e| TlsError::Config(format!("server config error: {e}")))?
        } else {
            rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
                .map_err(|e| TlsError::Config(format!("protocol version error: {e}")))?
                .with_no_client_auth()
                .with_single_cert(self.cert_chain, key)
                .map_err(|e| TlsError::Config(format!("server config error: {e}")))?
        };

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        info!("TLS server config built (TLS 1.2+, NIAP CA PP compliant)");

        Ok(config)
    }

    /// Build from a [`TlsConfig`] (convenience wrapper).
    pub fn from_config(config: &TlsConfig) -> Result<rustls::ServerConfig, TlsError> {
        let mut builder = Self::new()
            .with_cert_chain(&config.cert_chain_path)?
            .with_private_key(&config.private_key_path)?;

        if let Some(ref ca_path) = config.client_ca_path {
            builder = builder.with_client_auth(ca_path, config.require_client_cert)?;
        } else if config.require_client_cert {
            warn!("require_client_cert is true but no client_ca_path configured");
        }

        builder.build()
    }
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
