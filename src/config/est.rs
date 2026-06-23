//! EST protocol configuration.
//!
//! The `[est]` section controls which EST operations are enabled globally,
//! and `[[est.label]]` entries define per-label enrollment profiles with
//! CA routing and authentication policies.
//!
//! # EST labels (RFC 7030 §3.2.2)
//!
//! EST labels provide a namespace mechanism for multiple enrollment profiles
//! under the same server.  Each label maps to a URL path segment:
//!
//! ```text
//! https://est.example.com/.well-known/est/{label}/simpleenroll
//! ```
//!
//! When no label is specified in the URL, the default label configuration
//! applies.

use serde::Deserialize;

/// Authentication method for EST enrollment requests.
///
/// RFC 7030 §3.2.3 defines several client authentication mechanisms.
/// Each EST label can require a specific method or accept multiple.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EstAuthMethod {
    /// mTLS client certificate authentication (RFC 7030 §3.3.2).
    Mtls,
    /// HTTP Basic authentication with OTP (RHELBU-3536 R7).
    Otp,
    /// HTTP Basic authentication with static credentials.
    Basic,
    /// Certificate-based re-enrollment (existing certificate proves identity).
    Certificate,
}

/// `[est]` section — global EST protocol settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstConfig {
    /// Enable the `/simpleenroll` endpoint (RFC 7030 §4.2).
    #[serde(default = "bool_true")]
    pub simpleenroll: bool,

    /// Enable the `/simplereenroll` endpoint (RFC 7030 §4.2.2).
    #[serde(default = "bool_true")]
    pub simplereenroll: bool,

    /// Enable the `/fullcmc` endpoint (RFC 7030 §4.3).
    ///
    /// Full CMC is rarely needed; disabled by default.
    #[serde(default)]
    pub fullcmc: bool,

    /// Enable the `/serverkeygen` endpoint (RFC 7030 §4.4).
    ///
    /// Server-side key generation requires HSM integration.
    /// Disabled by default.
    #[serde(default)]
    pub serverkeygen: bool,

    /// Enable the `/csrattrs` endpoint (RFC 7030 §4.5).
    #[serde(default = "bool_true")]
    pub csrattrs: bool,

    /// Default enrollment profile applied when no label is specified.
    ///
    /// When absent, enrollment requests without a label use the default
    /// CA and authentication policy.
    #[serde(default)]
    pub default_profile: Option<String>,

    /// CSR attribute hints returned by `/csrattrs`.
    ///
    /// Each entry is an OID string (e.g., `"1.2.840.113549.1.9.14"` for
    /// the Certificate Extensions Request attribute).
    #[serde(default)]
    pub csr_attributes: Vec<String>,

    /// Per-label enrollment configurations.
    #[serde(default, rename = "label")]
    pub labels: Vec<EstLabelConfig>,

    /// Disconnected mode: accept enrollment requests without upstream
    /// CA connectivity (RHELBU-3536 R7-Disconnected).
    ///
    /// When `true`, the server queues CSRs for deferred signing and
    /// returns `202 Accepted` with a `Retry-After` header instead of
    /// the signed certificate.
    #[serde(default)]
    pub disconnected: bool,

    /// Retry-After value (seconds) returned in disconnected mode.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_retry_after_secs")]
    pub disconnected_retry_after_secs: u64,
}

/// `[[est.label]]` — per-label enrollment profile.
///
/// Each label provides an independent enrollment namespace with its own
/// CA routing, authentication requirements, and CSR attribute set.
///
/// ```toml
/// [[est.label]]
/// name = "devices"
/// ca_id = "device-ca"
/// auth_methods = ["mtls", "otp"]
/// require_cn_match = true
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstLabelConfig {
    /// Label name used in the URL path.
    ///
    /// Must be a non-empty string matching `^[a-z0-9][a-z0-9_-]*$`.
    pub name: String,

    /// CA identifier to use for enrollments under this label.
    ///
    /// Must reference a `[[ca]]` entry by its `id` field.
    /// When absent, the default CA is used.
    pub ca_id: Option<String>,

    /// Allowed authentication methods for this label.
    ///
    /// When empty, all globally-enabled auth methods are accepted.
    #[serde(default)]
    pub auth_methods: Vec<EstAuthMethod>,

    /// Per-label CSR attribute hints (overrides global `csr_attributes`
    /// for this label).
    #[serde(default)]
    pub csr_attributes: Vec<String>,

    /// Require that the CSR Common Name matches the authenticated identity.
    ///
    /// When `true`, the server rejects CSRs where the CN does not match
    /// the client's authenticated principal name.
    #[serde(default)]
    pub require_cn_match: bool,

    /// Maximum validity period (days) for certificates issued under this label.
    ///
    /// Overrides the CA's default `validity_days` for this label.
    pub max_validity_days: Option<u32>,

    /// Enable disconnected mode for this specific label.
    /// Overrides the global `[est].disconnected` setting.
    pub disconnected: Option<bool>,
}

fn bool_true() -> bool {
    true
}

fn default_retry_after_secs() -> u64 {
    300
}

impl Default for EstConfig {
    fn default() -> Self {
        Self {
            simpleenroll: true,
            simplereenroll: true,
            fullcmc: false,
            serverkeygen: false,
            csrattrs: true,
            default_profile: None,
            csr_attributes: Vec::new(),
            labels: Vec::new(),
            disconnected: false,
            disconnected_retry_after_secs: default_retry_after_secs(),
        }
    }
}
