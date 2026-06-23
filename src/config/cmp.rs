//! CMP v3 configuration (RFC 9810).
//!
//! The `[cmp]` section enables the Certificate Management Protocol
//! endpoint at `/.well-known/cmp`.  CMP provides a comprehensive
//! certificate lifecycle protocol with its own ASN.1 message format.

use serde::Deserialize;

/// `[cmp]` section — CMP v3 certificate management endpoint.
///
/// ```toml
/// [cmp]
/// enabled = true
/// allow_ir = true
/// allow_cr = true
/// allow_kur = true
/// allow_rr = false
/// allow_mac_protection = true
/// mac_algorithm = "hmac-sha256"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CmpConfig {
    /// Enable the CMP endpoint.
    #[serde(default)]
    pub enabled: bool,

    /// Allow initialization requests (new enrollment).
    #[serde(default = "default_true")]
    pub allow_ir: bool,

    /// Allow certification requests.
    #[serde(default = "default_true")]
    pub allow_cr: bool,

    /// Allow key update requests.
    #[serde(default = "default_true")]
    pub allow_kur: bool,

    /// Allow revocation requests via CMP.
    #[serde(default)]
    pub allow_rr: bool,

    /// Allow MAC-based protection for initial enrollment.
    #[serde(default = "default_true")]
    pub allow_mac_protection: bool,

    /// MAC algorithm for shared-secret protection.
    #[serde(default = "default_mac_algorithm")]
    pub mac_algorithm: String,

    /// Certificate profile for cross-certification requests.
    #[serde(default)]
    pub reference_cert_profile: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_mac_algorithm() -> String {
    "hmac-sha256".to_string()
}

impl Default for CmpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_ir: true,
            allow_cr: true,
            allow_kur: true,
            allow_rr: false,
            allow_mac_protection: true,
            mac_algorithm: default_mac_algorithm(),
            reference_cert_profile: None,
        }
    }
}
