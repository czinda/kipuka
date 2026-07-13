//! Configuration types for Dogtag PKI client.
//!
//! Provides strongly-typed configuration for connecting to Dogtag CA and KRA
//! subsystems, including mTLS agent credentials and retry policy.

use serde::Deserialize;
use url::Url;

/// Configuration for connecting to a Dogtag PKI instance.
///
/// Supports deserialization from TOML configuration files. The agent certificate
/// and key are used for mTLS authentication to the Dogtag REST API, which requires
/// an agent-level certificate for enrollment and revocation operations.
///
/// # Example TOML
///
/// ```toml
/// [dogtag]
/// ca_url = "https://ca.example.com:8443"
/// kra_url = "https://kra.example.com:8443"
/// agent_cert_file = "/etc/kipuka/agent.pem"
/// agent_key_file = "/etc/kipuka/agent.key"
/// ca_cert_file = "/etc/pki/tls/certs/ca-bundle.crt"
/// profile_id = "caServerCert"
/// timeout_secs = 30
/// retry_max = 3
/// retry_delay_ms = 1000
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct DogtagConfig {
    /// Base URL of the Dogtag CA subsystem.
    ///
    /// Typically `https://<hostname>:8443` for the secure admin/agent port.
    /// The REST API endpoints are relative to this URL (e.g., `/ca/rest/certs`).
    pub ca_url: Url,

    /// Base URL of the Dogtag KRA subsystem (optional).
    ///
    /// Required only for `/serverkeygen` operations that need server-side key
    /// generation and archival. Typically on the same host as the CA but may
    /// be a separate instance.
    pub kra_url: Option<Url>,

    /// Path to the PEM-encoded agent certificate file.
    ///
    /// This certificate authenticates the client to the Dogtag REST API.
    /// Must be issued by a CA trusted by the Dogtag instance and have
    /// the appropriate agent privileges.
    pub agent_cert_file: String,

    /// Path to the PEM-encoded agent private key file.
    pub agent_key_file: String,

    /// Path to the PEM-encoded CA certificate file for TLS verification.
    ///
    /// Used to verify the Dogtag server's TLS certificate. This is typically
    /// the root CA certificate that issued the Dogtag instance's server cert.
    pub ca_cert_file: String,

    /// Default enrollment profile ID.
    ///
    /// Common profiles include:
    /// - `caServerCert` — TLS server certificates
    /// - `caUserCert` — User/client certificates
    /// - `caIPAserviceCert` — FreeIPA service certificates
    /// - `caDualCert` — Dual-key (signing + encryption) certificates
    pub profile_id: String,

    /// HTTP request timeout in seconds.
    ///
    /// Applied to each individual HTTP request to the Dogtag REST API.
    /// Enrollment operations may take longer if the CA profile requires
    /// approval workflows.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Maximum number of retry attempts for transient failures.
    ///
    /// Retries are attempted for HTTP 5xx errors and connection failures.
    /// Client errors (4xx) are not retried.
    #[serde(default = "default_retry_max")]
    pub retry_max: u32,

    /// Delay between retry attempts in milliseconds.
    #[serde(default = "default_retry_delay")]
    pub retry_delay_ms: u64,

    /// Username for HTTP basic auth (used when ca_url is HTTP).
    ///
    /// NSS cannot validate ML-DSA-87 client certs in the TLS handshake
    /// (Bug 2025246). When ca_url uses HTTP, basic auth with username/password
    /// is used instead of mTLS agent cert authentication.
    #[serde(default)]
    pub username: Option<String>,

    /// Password for HTTP basic auth.
    #[serde(default)]
    pub password: Option<String>,

    /// Username for KRA basic auth. Defaults to `username` if not set.
    /// Dogtag creates `kraadmin` as the KRA admin (separate from `caadmin`).
    #[serde(default)]
    pub kra_username: Option<String>,

    /// Password for KRA basic auth. Defaults to `password` if not set.
    #[serde(default)]
    pub kra_password: Option<String>,

    /// Skip mTLS client certificate presentation on HTTPS connections.
    ///
    /// When true, the client connects to HTTPS endpoints using basic auth
    /// only, without presenting the agent certificate during the TLS
    /// handshake. Required for PQ (ML-DSA-87) CAs where the Dogtag
    /// server's NSS cannot validate ML-DSA-signed agent cert chains
    /// during TLS client authentication (NSS lacks ML-DSA TLS
    /// SignatureScheme support).
    #[serde(default)]
    pub skip_mtls: bool,
}

fn default_timeout() -> u64 {
    30
}

fn default_retry_max() -> u32 {
    3
}

fn default_retry_delay() -> u64 {
    1000
}
