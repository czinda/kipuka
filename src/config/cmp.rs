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
///
/// [[cmp.mac_secrets]]
/// reference = "client-ref-01"
/// secret_hex = "deadbeef01020304"
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

    /// Shared secrets for CMP MAC-based protection (RFC 4210 §5.1.3.1).
    /// Each entry maps a reference number to a shared secret.
    #[serde(default)]
    pub mac_secrets: Vec<CmpMacSecret>,
}

/// A shared secret entry for CMP MAC-based protection.
///
/// The reference number identifies the secret and is matched against the
/// CMP sender field.  The secret is hex-encoded for safe storage in TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct CmpMacSecret {
    /// Reference number identifying this secret (matched against CMP sender field).
    pub reference: String,
    /// Hex-encoded shared secret bytes.
    pub secret_hex: String,
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
            mac_secrets: Vec::new(),
        }
    }
}
