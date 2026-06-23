//! TLS configuration for EST and admin listeners.
//!
//! EST requires TLS 1.2+ (RFC 7030 §3.3.1).  The NIAP CA PP FTP_TRP.1
//! further constrains the cipher suite selection to AEAD-only suites
//! with forward secrecy (ECDHE or DHE key exchange).
//!
//! Two separate truststores are supported (RHELBU-3536 R18):
//!
//! - **EST truststore** (`ca_file`) — validates EST client certificates
//!   for `/simpleenroll`, `/simplereenroll`, and `/serverkeygen`.
//! - **Admin truststore** — configured in `[admin]` — validates admin
//!   operator mTLS certificates independently.

use serde::Deserialize;

/// Client certificate authentication mode.
///
/// RFC 7030 §3.3.2: EST servers SHOULD support certificate-based client
/// authentication.  The mode determines whether the TLS handshake
/// requests and/or requires a client certificate.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuthMode {
    /// TLS handshake requires a valid client certificate.
    Required,
    /// TLS handshake requests but does not require a client certificate.
    /// Authentication falls through to HTTP-layer methods (OTP, etc.).
    Optional,
    /// No client certificate is requested.
    None,
}

impl Default for ClientAuthMode {
    fn default() -> Self {
        ClientAuthMode::Optional
    }
}

/// `[tls]` section — TLS configuration for the EST listener.
///
/// # NIAP CA PP FTP_TRP.1 compliance
///
/// - TLS 1.2 is the minimum supported version; TLS 1.0 and 1.1 are rejected.
/// - Only AEAD cipher suites with forward secrecy (ECDHE/DHE key exchange)
///   are permitted.
/// - The default cipher suite list excludes CBC-mode suites and static
///   RSA key exchange.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Enable TLS on the EST listener.  Default: `false`.
    ///
    /// When `false`, the server listens in plain HTTP mode (intended only
    /// for development behind a TLS-terminating reverse proxy).
    #[serde(default)]
    pub enabled: bool,

    /// Path to the server certificate chain in PEM format.
    ///
    /// The file MUST contain the server's end-entity certificate first,
    /// followed by any intermediate CA certificates.
    #[serde(default)]
    pub cert_file: String,

    /// Path to the server private key in PEM format.
    #[serde(default)]
    pub key_file: String,

    /// Client certificate authentication mode.
    ///
    /// - `required` — mTLS is mandatory; unauthenticated clients are rejected
    ///   at the TLS layer.
    /// - `optional` (default) — the server requests a client certificate but
    ///   accepts connections without one.  EST enrollment can fall back to
    ///   HTTP-layer authentication (OTP, HTTP Basic, etc.).
    /// - `none` — no client certificate is requested.
    #[serde(default)]
    pub client_auth: ClientAuthMode,

    /// Path to the CA certificate bundle (PEM) for validating EST client
    /// certificates.
    ///
    /// RHELBU-3536 R18: this truststore is dedicated to the EST listener.
    /// Admin operator mTLS uses a separate truststore configured in `[admin]`.
    #[serde(default)]
    pub ca_file: String,

    /// Minimum TLS protocol version.
    ///
    /// NIAP CA PP FTP_TRP.1: must be `"1.2"` or `"1.3"`.
    /// Default: `"1.2"`.
    #[serde(default = "default_min_protocol")]
    pub min_protocol: String,

    /// Maximum TLS protocol version.
    ///
    /// Default: `"1.3"`.
    #[serde(default = "default_max_protocol")]
    pub max_protocol: String,

    /// Allowed cipher suites (IANA names).
    ///
    /// When empty, the server uses the rustls default selection which
    /// already satisfies FTP_TRP.1 (AEAD + forward secrecy only).
    ///
    /// Example:
    /// ```toml
    /// ciphersuites = [
    ///     "TLS_AES_256_GCM_SHA384",
    ///     "TLS_AES_128_GCM_SHA256",
    ///     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ///     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    /// ]
    /// ```
    #[serde(default)]
    pub ciphersuites: Vec<String>,
}

fn default_min_protocol() -> String {
    "1.2".to_string()
}

fn default_max_protocol() -> String {
    "1.3".to_string()
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: String::new(),
            key_file: String::new(),
            client_auth: ClientAuthMode::default(),
            ca_file: String::new(),
            min_protocol: default_min_protocol(),
            max_protocol: default_max_protocol(),
            ciphersuites: Vec::new(),
        }
    }
}

impl TlsConfig {
    /// Validate TLS configuration constraints.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.cert_file.is_empty() {
            return Err("[tls].cert_file must not be empty when TLS is enabled".into());
        }
        if self.key_file.is_empty() {
            return Err("[tls].key_file must not be empty when TLS is enabled".into());
        }

        // NIAP CA PP FTP_TRP.1: TLS 1.2 minimum
        match self.min_protocol.as_str() {
            "1.2" | "1.3" => {}
            other => {
                return Err(format!(
                    "[tls].min_protocol must be \"1.2\" or \"1.3\", got {other:?}"
                ));
            }
        }
        match self.max_protocol.as_str() {
            "1.2" | "1.3" => {}
            other => {
                return Err(format!(
                    "[tls].max_protocol must be \"1.2\" or \"1.3\", got {other:?}"
                ));
            }
        }
        if self.min_protocol == "1.3" && self.max_protocol == "1.2" {
            return Err("[tls].min_protocol (1.3) cannot exceed max_protocol (1.2)".into());
        }

        // Client auth modes that need a CA file
        if self.client_auth != ClientAuthMode::None && self.ca_file.is_empty() {
            return Err(
                "[tls].ca_file must be set when client_auth is \"required\" or \"optional\"".into(),
            );
        }

        Ok(())
    }
}
