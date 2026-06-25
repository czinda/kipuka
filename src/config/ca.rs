//! Multi-CA configuration.
//!
//! Each `[[ca]]` entry in the TOML config defines one Certificate Authority
//! with its own key material, validity policy, and certificate profile.
//!
//! EST labels (see `EstLabelConfig`) reference CAs by their `id` field,
//! enabling per-label CA routing (e.g., different CAs for different device
//! classes or enrollment profiles).

use serde::Deserialize;

/// `[[ca]]` section — per-CA key material and issuance policy.
///
/// Multiple CAs are supported via the TOML array-of-tables syntax:
///
/// ```toml
/// [[ca]]
/// id = "production"
/// is_default = true
/// key_file = "/etc/kipuka/ca-prod.key"
/// cert_file = "/etc/kipuka/ca-prod.crt"
///
/// [[ca]]
/// id = "dev"
/// key_file = "/etc/kipuka/ca-dev.key"
/// cert_file = "/etc/kipuka/ca-dev.crt"
/// validity_days = 30
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// Unique identifier for this CA.
    ///
    /// Used in EST label configurations to route enrollment requests to
    /// the appropriate CA.  Must match `^[a-z0-9][a-z0-9_-]*$` and be
    /// at most 64 characters.
    #[serde(default)]
    pub id: String,

    /// Whether this CA is the default for EST labels that do not specify
    /// a `ca_id`.  Exactly one CA must be marked as default when multiple
    /// CAs are configured.
    #[serde(default)]
    pub is_default: bool,

    /// Path to the CA private key in PEM format.
    ///
    /// Mutually exclusive with `pkcs11_uri`: when `pkcs11_uri` is set,
    /// the key is accessed via the HSM and this field is ignored.
    pub key_file: String,

    /// Path to the CA certificate (or chain) in PEM format.
    ///
    /// The file should contain the CA's end-entity certificate first,
    /// followed by any intermediates up to (but not including) the root.
    pub cert_file: String,

    /// Key type for CA key generation (used only when `key_file` does
    /// not exist and auto-generation is requested).
    ///
    /// Supported values:
    ///
    /// Classical:
    /// - `"rsa:2048"`, `"rsa:3072"`, `"rsa:4096"`
    /// - `"ec:P-256"`, `"ec:P-384"`, `"ec:P-521"`
    /// - `"ed25519"`
    ///
    /// Post-Quantum (FIPS 204 — ML-DSA standalone):
    /// - `"ml-dsa-44"` (NIST Security Level 2, ~2.5 KB sig)
    /// - `"ml-dsa-65"` (NIST Security Level 3, ~3.3 KB sig)
    /// - `"ml-dsa-87"` (NIST Security Level 5, ~4.6 KB sig)
    ///
    /// Composite (draft-ietf-lamps-pq-composite-sigs-19):
    /// - `"ml-dsa-44-with-rsa-2048"`, `"ml-dsa-44-with-rsa-3072"`
    /// - `"ml-dsa-44-with-ec-P-256"`
    /// - `"ml-dsa-65-with-ec-P-384"`
    /// - `"ml-dsa-65-with-rsa-3072"`, `"ml-dsa-65-with-rsa-4096"`
    /// - `"ml-dsa-87-with-ec-P-384"`
    /// - `"ml-dsa-87-with-ed448"`
    ///
    /// Default: `"ec:P-256"`.
    #[serde(default = "default_key_type")]
    pub key_type: String,

    /// PKCS#11 URI for HSM-backed CA key.
    ///
    /// When set, the CA private key is accessed via the configured HSM
    /// (`[hsm]` section) instead of reading `key_file` from disk.
    ///
    /// Example: `"pkcs11:token=kipuka;object=ca-key;type=private"`
    pub pkcs11_uri: Option<String>,

    /// Default validity period for issued end-entity certificates (days).
    ///
    /// CA/B Forum BR §6.3.2 limits publicly-trusted certificates to
    /// 398 days (roughly 13 months).  Private CAs may use longer periods.
    ///
    /// Default: 365 days.
    #[serde(default = "default_validity_days")]
    pub validity_days: u32,

    /// Hash algorithm for certificate and CRL signing.
    ///
    /// Supported: `"sha256"`, `"sha384"`, `"sha512"`.
    /// For ML-DSA CAs, set to `"none"` — the hash is built into the
    /// algorithm per FIPS 204. Auto-detected when `key_type` starts
    /// with `"ml-dsa"`.
    /// Default: `"sha256"`.
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,

    /// CRL distribution point URL embedded in issued certificates.
    pub crl_url: Option<String>,

    /// OCSP responder URL embedded in issued certificates.
    pub ocsp_url: Option<String>,

    /// Subject Common Name for auto-generated CA certificates.
    #[serde(default = "default_common_name")]
    pub common_name: String,

    /// Subject Organization for auto-generated CA certificates.
    #[serde(default = "default_organization")]
    pub organization: String,

    /// CRL validity period in seconds.
    ///
    /// Determines the `nextUpdate` field in generated CRLs.
    /// Default: 86400 (24 hours).
    #[serde(default = "default_crl_lifetime_secs")]
    pub crl_lifetime_secs: u64,

    /// CA/B Forum compliance mode.
    ///
    /// When `true`, the server enforces:
    /// - Maximum 398-day end-entity certificate validity
    /// - Required key usage and extended key usage extensions
    /// - Minimum RSA 2048-bit key size in CSRs
    #[serde(default)]
    pub cab_forum_compliant: bool,
}

fn default_key_type() -> String {
    "ec:P-256".to_string()
}

fn default_validity_days() -> u32 {
    365
}

fn default_hash_algorithm() -> String {
    "sha256".to_string()
}

fn default_common_name() -> String {
    "Kipuka EST CA".to_string()
}

fn default_organization() -> String {
    "Kipuka EST Server".to_string()
}

fn default_crl_lifetime_secs() -> u64 {
    86400
}

impl CaConfig {
    /// Returns `true` when this CA uses an HSM-backed key via PKCS#11.
    pub fn is_hsm_backed(&self) -> bool {
        self.pkcs11_uri.is_some()
    }
}
