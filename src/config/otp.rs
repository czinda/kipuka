//! One-Time Password (OTP) configuration for EST enrollment.
//!
//! OTP authentication provides an alternative to mTLS for initial device
//! enrollment (RHELBU-3536 R7).  An administrator generates an OTP via
//! the admin API, which the client presents in an HTTP Basic Authorization
//! header alongside its CSR.
//!
//! OTP storage backends:
//!
//! - **db** — OTPs are stored in the Kipuka database.
//! - **ldap** — OTPs are stored as attributes on LDAP entries, enabling
//!   integration with FreeIPA or Active Directory enrollment workflows.

use serde::Deserialize;

/// OTP storage backend.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OtpStorageBackend {
    /// Store OTPs in the Kipuka database.
    Db,
    /// Store OTPs in an LDAP directory.
    Ldap,
}

impl Default for OtpStorageBackend {
    fn default() -> Self {
        OtpStorageBackend::Db
    }
}

/// `[otp]` section — OTP enrollment authentication configuration.
///
/// ```toml
/// [otp]
/// enabled = true
/// entropy_bits = 128
/// ttl_seconds = 3600
/// max_usage = 1
/// storage_backend = "db"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtpConfig {
    /// Enable OTP-based enrollment authentication.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum entropy bits for generated OTPs.
    ///
    /// NIST SP 800-63B requires at least 112 bits for authenticator
    /// secrets; the Kipuka default is 128 bits for a comfortable margin.
    /// Values below 128 are rejected during validation.
    #[serde(default = "default_entropy_bits")]
    pub entropy_bits: u32,

    /// Time-to-live for OTPs in seconds.
    ///
    /// After this duration, unused OTPs are automatically invalidated.
    /// Default: 3600 (1 hour).
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,

    /// Maximum number of times an OTP can be used before it is consumed.
    ///
    /// `1` (the default) enforces single-use semantics.  Values greater
    /// than 1 allow re-enrollment within the TTL window (e.g., for
    /// retry after transient failure).
    #[serde(default = "default_max_usage")]
    pub max_usage: u32,

    /// Storage backend for OTP records.
    #[serde(default)]
    pub storage_backend: OtpStorageBackend,

    /// LDAP connection configuration (required when `storage_backend = "ldap"`).
    #[serde(default)]
    pub ldap: Option<OtpLdapConfig>,
}

/// LDAP backend configuration for OTP storage (RHELBU-3536 R7).
///
/// ```toml
/// [otp.ldap]
/// url = "ldaps://ipa.example.com"
/// bind_dn = "uid=kipuka,cn=sysaccounts,cn=etc,dc=example,dc=com"
/// bind_password = "env:KIPUKA_LDAP_BIND_PW"
/// base_dn = "cn=otp,cn=kipuka,dc=example,dc=com"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtpLdapConfig {
    /// LDAP server URL (`ldap://` or `ldaps://`).
    pub url: String,

    /// Bind DN for LDAP authentication.
    pub bind_dn: String,

    /// Bind password.  Supports `"env:VAR_NAME"` for env-var expansion.
    #[serde(default)]
    pub bind_password: String,

    /// Base DN under which OTP entries are stored.
    pub base_dn: String,

    /// LDAP attribute name for the OTP value.
    /// Default: `"kipukaOtp"`.
    #[serde(default = "default_otp_attribute")]
    pub otp_attribute: String,

    /// Connection timeout in seconds.
    #[serde(default = "default_ldap_timeout_secs")]
    pub timeout_secs: u64,

    /// Use STARTTLS over a plain LDAP connection.
    #[serde(default)]
    pub starttls: bool,
}

fn default_entropy_bits() -> u32 {
    128
}

fn default_ttl_seconds() -> u64 {
    3600
}

fn default_max_usage() -> u32 {
    1
}

fn default_otp_attribute() -> String {
    "kipukaOtp".to_string()
}

fn default_ldap_timeout_secs() -> u64 {
    10
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entropy_bits: default_entropy_bits(),
            ttl_seconds: default_ttl_seconds(),
            max_usage: default_max_usage(),
            storage_backend: OtpStorageBackend::default(),
            ldap: None,
        }
    }
}

impl OtpConfig {
    /// Validate OTP configuration constraints.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.entropy_bits < 128 {
            return Err(format!(
                "[otp].entropy_bits must be at least 128, got {}",
                self.entropy_bits
            ));
        }

        if self.ttl_seconds == 0 {
            return Err("[otp].ttl_seconds must be at least 1".into());
        }

        if self.max_usage == 0 {
            return Err("[otp].max_usage must be at least 1".into());
        }

        if self.storage_backend == OtpStorageBackend::Ldap && self.ldap.is_none() {
            return Err("[otp].ldap section is required when storage_backend = \"ldap\"".into());
        }

        if let Some(ref ldap) = self.ldap {
            if ldap.url.is_empty() {
                return Err("[otp.ldap].url must not be empty".into());
            }
            if ldap.bind_dn.is_empty() {
                return Err("[otp.ldap].bind_dn must not be empty".into());
            }
            if ldap.base_dn.is_empty() {
                return Err("[otp.ldap].base_dn must not be empty".into());
            }
        }

        Ok(())
    }
}
