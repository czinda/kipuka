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
#[derive(Default)]
pub enum ClientAuthMode {
    /// TLS handshake requires a valid client certificate.
    Required,
    /// TLS handshake requests but does not require a client certificate.
    /// Authentication falls through to HTTP-layer methods (OTP, etc.).
    #[default]
    Optional,
    /// No client certificate is requested.
    None,
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

    /// OCSP stapling configuration (RFC 7633 / RFC 6066 Section 8).
    ///
    /// When the server's TLS certificate contains the TLS Feature Extension
    /// (must-staple, OID 1.3.6.1.5.5.7.1.24), OCSP stapling MUST be
    /// enabled to satisfy RFC 7633 Section 4 requirements.  Clients that
    /// understand must-staple will abort the handshake if no stapled OCSP
    /// response is provided.
    ///
    /// Even without must-staple, enabling OCSP stapling improves TLS
    /// handshake performance by eliminating the client-side OCSP lookup.
    #[serde(default)]
    pub ocsp_stapling: OcspStaplingConfig,
}

/// OCSP stapling configuration for the TLS listener.
///
/// RFC 6066 Section 8: the `status_request` TLS extension allows the
/// server to provide a stapled OCSP response during the TLS handshake,
/// eliminating the client's need to contact the OCSP responder directly.
///
/// RFC 7633 Section 4: when the server certificate contains the TLS
/// Feature Extension (must-staple), the server MUST provide a stapled
/// response; failure to do so causes compliant clients to abort.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OcspStaplingConfig {
    /// Enable OCSP stapling.
    ///
    /// When `true`, the server fetches an OCSP response for its own
    /// certificate at startup and refreshes it periodically.
    ///
    /// Default: `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Override the OCSP responder URL.
    ///
    /// When `None`, the responder URL is extracted from the server
    /// certificate's Authority Information Access (AIA) extension
    /// (OID 1.3.6.1.5.5.7.48.1).
    ///
    /// Set this when the AIA URL is not reachable from the server
    /// (e.g., behind a firewall) and a local OCSP responder proxy
    /// is available.
    #[serde(default)]
    pub responder_url: Option<String>,

    /// Interval in seconds between OCSP response refreshes.
    ///
    /// The server fetches a fresh OCSP response from the responder
    /// at this interval, replacing the cached stapled response.
    ///
    /// Default: `14400` (4 hours).  OCSP responses typically have a
    /// `nextUpdate` validity of 24-48 hours, so refreshing every 4
    /// hours provides adequate margin.
    #[serde(default = "default_ocsp_refresh_interval")]
    pub refresh_interval_secs: u64,

    /// Allow serving TLS without a stapled OCSP response when the
    /// OCSP responder is unreachable.
    ///
    /// When `true` (soft-fail mode), the server continues to accept
    /// TLS connections without a stapled response if the OCSP
    /// responder cannot be reached.  A stale cached response is
    /// served if still within its `nextUpdate` window.  A warning
    /// is logged on each failed refresh attempt.
    ///
    /// When `false` (hard-fail mode), the server refuses to start
    /// if the initial OCSP fetch fails, and transitions to
    /// unhealthy status if subsequent refreshes fail with no valid
    /// cached response.
    ///
    /// Default: `true`.
    #[serde(default = "default_soft_fail")]
    pub soft_fail: bool,
}

fn default_min_protocol() -> String {
    "1.2".to_string()
}

fn default_max_protocol() -> String {
    "1.3".to_string()
}

fn default_ocsp_refresh_interval() -> u64 {
    14400 // 4 hours
}

fn default_soft_fail() -> bool {
    true
}

impl Default for OcspStaplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            responder_url: None,
            refresh_interval_secs: default_ocsp_refresh_interval(),
            soft_fail: default_soft_fail(),
        }
    }
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
            ocsp_stapling: OcspStaplingConfig::default(),
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
