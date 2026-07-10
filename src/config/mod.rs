//! Configuration loading and validation.
//!
//! The Kipuka EST server is configured via a single TOML file.  The
//! top-level [`Config`] struct owns all sub-configurations and provides
//! [`Config::from_file`] for loading with semantic validation.
//!
//! # Example configuration
//!
//! ```toml
//! [server]
//! listen_addr = "0.0.0.0:8443"
//!
//! [tls]
//! enabled = true
//! cert_file = "/etc/kipuka/server.crt"
//! key_file  = "/etc/kipuka/server.key"
//! ca_file   = "/etc/kipuka/est-ca.pem"
//!
//! [database]
//! url = "sqlite:///var/lib/kipuka/kipuka.db"
//!
//! [[ca]]
//! id = "default"
//! is_default = true
//! key_file  = "/etc/kipuka/ca.key"
//! cert_file = "/etc/kipuka/ca.crt"
//!
//! [est]
//! simpleenroll = true
//! simplereenroll = true
//!
//! [audit]
//! enabled = true
//! ```

mod admin;
pub mod audit;
mod ca;
mod cmp;
mod cms_est;
mod coap;
mod db;
mod est;
mod hsm;
mod otp;
pub mod secret;
mod server;
mod star;
mod tls;

pub use self::admin::*;
pub use self::audit::*;
pub use self::secret::{ResolvedSecrets, SecretRef, SecretResolver};
pub use self::ca::*;
pub use self::cmp::*;
pub use self::cms_est::*;
pub use self::coap::*;
pub use self::db::*;
pub use self::est::*;
pub use self::hsm::*;
pub use self::otp::*;
pub use self::server::*;
pub use self::star::*;
pub use self::tls::*;

// Re-export OcspConfig from the ocsp module for config-level access.
pub use crate::ocsp::OcspConfig;

use serde::Deserialize;

/// Root configuration for the Kipuka EST server.
///
/// Loaded from a TOML file via [`Config::from_file`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Server listener configuration.
    #[serde(default)]
    pub server: ServerConfig,

    /// TLS configuration for the EST listener.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Database connection configuration.
    #[serde(default)]
    pub database: DbConfig,

    /// Certificate Authority configurations.
    ///
    /// Supports `[ca]` (single-CA backward compat) or `[[ca]]` (multi-CA).
    #[serde(rename = "ca", deserialize_with = "deserialize_ca_array")]
    pub cas: Vec<CaConfig>,

    /// EST protocol configuration.
    #[serde(default)]
    pub est: EstConfig,

    /// HSM / PKCS#11 configuration.  Absent → software-only key storage.
    #[serde(default)]
    pub hsm: Option<HsmConfig>,

    /// OTP enrollment authentication.
    #[serde(default)]
    pub otp: OtpConfig,

    /// Admin API configuration.  Absent → admin endpoints disabled.
    #[serde(default)]
    pub admin: Option<AdminConfig>,

    /// Audit trail configuration.
    #[serde(default)]
    pub audit: AuditConfig,

    /// CoAP transport configuration (RFC 9483).  Absent → CoAP disabled.
    #[serde(default)]
    pub coap: Option<CoapConfig>,

    /// CMS-wrapped EST configuration (RFC 8295).  Absent → CMS-EST disabled.
    #[serde(default)]
    pub cms_est: Option<CmsEstConfig>,

    /// CMP v3 configuration (RFC 9810).  Absent → CMP disabled.
    #[serde(default)]
    pub cmp: Option<CmpConfig>,

    /// Dogtag PKI backend configuration (CA + KRA).
    ///
    /// When present, enrollment and CMC requests are forwarded to a
    /// Dogtag PKI CA via its REST API instead of using direct signing.
    /// Absent → direct signing only (no Dogtag integration).
    #[serde(default)]
    pub dogtag: Option<kipuka_dogtag::DogtagConfig>,

    /// STAR certificate configuration (RFC 8739).  Absent → STAR disabled.
    #[serde(default)]
    pub star: Option<StarConfig>,

    /// OCSP configuration for certificate revocation checking (RFC 6960).
    /// Absent → OCSP checking disabled (RHELBU-3536 R21).
    #[serde(default)]
    pub ocsp: OcspConfig,

    /// Interval in seconds between CRL regeneration cycles.
    ///
    /// Default: 3600 (1 hour).
    #[serde(default = "default_crl_refresh_interval_secs")]
    pub crl_refresh_interval_secs: u64,
}

fn default_crl_refresh_interval_secs() -> u64 {
    3600
}

impl Config {
    /// Load and validate configuration from a TOML file.
    ///
    /// Returns the parsed config or a human-readable error string
    /// suitable for startup diagnostics.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file '{path}': {e}"))?;
        let config: Self =
            toml::from_str(&content).map_err(|e| format!("config parse error: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate semantic constraints that cannot be expressed in serde alone.
    ///
    /// Called automatically by [`Self::from_file`].
    pub fn validate(&self) -> Result<(), String> {
        // ── CAs ──────────────────────────────────────────────────────────────
        if self.cas.is_empty() {
            return Err("at least one [ca] or [[ca]] entry is required".into());
        }

        // Validate each CA entry
        for ca in &self.cas {
            if ca.id.is_empty() {
                return Err("each [[ca]] entry must have a non-empty `id` field".into());
            }
            if !is_valid_ca_id(&ca.id) {
                return Err(format!(
                    "CA id {:?} must match ^[a-z0-9][a-z0-9_-]*$ (max 64 chars)",
                    ca.id
                ));
            }
        }

        // Check for duplicate CA IDs
        let mut seen_ids = std::collections::HashSet::new();
        for ca in &self.cas {
            if !seen_ids.insert(ca.id.as_str()) {
                return Err(format!("duplicate CA id {:?}", ca.id));
            }
        }

        // Multi-CA: exactly one default
        if self.cas.len() > 1 {
            let default_count = self.cas.iter().filter(|c| c.is_default).count();
            if default_count == 0 {
                return Err(
                    "with multiple [[ca]] entries, exactly one must have `is_default = true`"
                        .into(),
                );
            }
            if default_count > 1 {
                return Err("at most one [[ca]] entry may have `is_default = true`".into());
            }
        }

        // ── TLS ──────────────────────────────────────────────────────────────
        self.tls.validate()?;

        // TLS + Unix socket conflict
        if self.tls.enabled && self.server.is_unix_socket() {
            return Err("TLS cannot be used with a Unix domain socket listener".into());
        }

        // ── EST labels reference valid CAs ───────────────────────────────────
        let known_ca_ids: std::collections::HashSet<&str> =
            self.cas.iter().map(|c| c.id.as_str()).collect();

        for label in &self.est.labels {
            if let Some(ref ca_id) = label.ca_id
                && !known_ca_ids.contains(ca_id.as_str())
            {
                return Err(format!(
                    "EST label {:?} references unknown CA id {ca_id:?}",
                    label.name
                ));
            }
        }

        // ── OTP ──────────────────────────────────────────────────────────────
        self.otp.validate()?;

        // ── Admin ────────────────────────────────────────────────────────────
        if let Some(ref admin) = self.admin {
            admin.validate()?;
        }

        // ── Audit ────────────────────────────────────────────────────────────
        self.audit.validate()?;

        // ── CoAP ────────────────────────────────────────────────────────────
        if let Some(ref coap) = self.coap {
            coap.validate()?;
        }

        // ── CMS-EST ─────────────────────────────────────────────────────────
        if let Some(ref cms_est) = self.cms_est {
            cms_est.validate()?;
        }

        // ── CMP ─────────────────────────────────────────────────────────────
        if let Some(ref cmp) = self.cmp {
            let _ = cmp; // No validation needed yet beyond serde
        }

        // ── Dogtag ───────────────────────────────────────────────────────
        if let Some(ref dogtag) = self.dogtag {
            if dogtag.ca_url.scheme() != "https" && dogtag.ca_url.scheme() != "http" {
                return Err("dogtag.ca_url must use HTTPS or HTTP".into());
            }
            if dogtag.ca_url.scheme() == "http" {
                tracing::warn!(
                    url = %dogtag.ca_url,
                    "dogtag.ca_url uses HTTP — agent credentials sent in cleartext"
                );
            }
            if dogtag.agent_cert_file.is_empty() {
                return Err("dogtag.agent_cert_file must not be empty".into());
            }
            if dogtag.agent_key_file.is_empty() {
                return Err("dogtag.agent_key_file must not be empty".into());
            }
            if dogtag.ca_cert_file.is_empty() {
                return Err("dogtag.ca_cert_file must not be empty".into());
            }
            if dogtag.profile_id.is_empty() {
                return Err("dogtag.profile_id must not be empty".into());
            }
        }

        // ── STAR ────────────────────────────────────────────────────────────
        if let Some(ref star) = self.star {
            star.validate()?;
        }

        // ── CRL refresh interval ─────────────────────────────────────────────
        if self.crl_refresh_interval_secs == 0 {
            return Err("crl_refresh_interval_secs must be at least 1".into());
        }

        // ── File path existence checks ───────────────────────────────────────
        // These are warnings rather than hard failures to allow config
        // validation before all files are deployed (--check-config).
        // At startup, missing files will produce clear errors anyway.
        if self.tls.enabled {
            check_file_exists("[tls].cert_file", &self.tls.cert_file)?;
            check_file_exists("[tls].key_file", &self.tls.key_file)?;
            if !self.tls.ca_file.is_empty() {
                check_file_exists("[tls].ca_file", &self.tls.ca_file)?;
            }
        }

        Ok(())
    }

    /// Returns the default CA config: the one with `is_default = true`, or the
    /// only CA when there is exactly one `[[ca]]` entry.
    ///
    /// # Panics
    ///
    /// Panics if `cas` is empty or no CA is marked default in a multi-CA
    /// config.  [`Self::validate`] prevents both situations.
    pub fn default_ca(&self) -> &CaConfig {
        if self.cas.len() == 1 {
            return &self.cas[0];
        }
        self.cas
            .iter()
            .find(|c| c.is_default)
            .expect("validate() ensures exactly one default CA")
    }
}

/// Validate that a CA identifier conforms to naming rules.
///
/// CA IDs must:
/// - Be 1–64 characters
/// - Start with a lowercase ASCII letter or digit
/// - Contain only lowercase ASCII letters, digits, `_`, and `-`
fn is_valid_ca_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    let mut chars = id.chars();
    match chars.next() {
        None => return false,
        Some(c) if !c.is_ascii_lowercase() && !c.is_ascii_digit() => return false,
        _ => {}
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Check that a file path exists (for config validation).
fn check_file_exists(field: &str, path: &str) -> Result<(), String> {
    if path.is_empty() || path.starts_with("pkcs11:") {
        return Ok(());
    }
    if !std::path::Path::new(path).exists() {
        return Err(format!("{field} path {path:?} does not exist"));
    }
    Ok(())
}

/// Deserialize either a `[ca]` single-table or a `[[ca]]` array-of-tables
/// into `Vec<CaConfig>`.
///
/// When the TOML source uses the old `[ca]` form the resulting single entry
/// gets `id = "default"` and `is_default = true` injected automatically.
fn deserialize_ca_array<'de, D>(deserializer: D) -> Result<Vec<CaConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct CaArrayVisitor;

    impl<'de> Visitor<'de> for CaArrayVisitor {
        type Value = Vec<CaConfig>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a [ca] table or [[ca]] array of tables")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<CaConfig>, A::Error> {
            let mut cas = Vec::new();
            while let Some(ca) = seq.next_element::<CaConfig>()? {
                cas.push(ca);
            }
            Ok(cas)
        }

        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Vec<CaConfig>, M::Error> {
            let mut ca = CaConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
            if ca.id.is_empty() {
                ca.id = "default".to_owned();
            }
            ca.is_default = true;
            Ok(vec![ca])
        }
    }

    deserializer.deserialize_any(CaArrayVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml() -> &'static str {
        r#"
[database]
url = "sqlite::memory:"

[ca]
key_file = "/tmp/ca.key"
cert_file = "/tmp/ca.crt"
"#
    }

    #[test]
    fn parse_minimal_config() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(cfg.database.url, "sqlite::memory:");
        assert_eq!(cfg.cas.len(), 1);
        assert_eq!(cfg.cas[0].id, "default");
        assert!(cfg.cas[0].is_default);
    }

    #[test]
    fn default_ca_returns_single_entry() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(cfg.default_ca().id, "default");
    }

    #[test]
    fn multi_ca_requires_default() {
        let toml = r#"
[database]
url = "sqlite::memory:"
[[ca]]
id = "a"
key_file = "/tmp/a.key"
cert_file = "/tmp/a.crt"
[[ca]]
id = "b"
key_file = "/tmp/b.key"
cert_file = "/tmp/b.crt"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("is_default"), "err: {err}");
    }

    #[test]
    fn multi_ca_rejects_duplicate_id() {
        let toml = r#"
[database]
url = "sqlite::memory:"
[[ca]]
id = "a"
is_default = true
key_file = "/tmp/a.key"
cert_file = "/tmp/a.crt"
[[ca]]
id = "a"
key_file = "/tmp/a2.key"
cert_file = "/tmp/a2.crt"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("duplicate"), "err: {err}");
    }

    #[test]
    fn est_label_rejects_unknown_ca_id() {
        let toml = r#"
[database]
url = "sqlite::memory:"
[ca]
key_file = "/tmp/ca.key"
cert_file = "/tmp/ca.crt"
[[est.label]]
name = "devices"
ca_id = "nonexistent"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("nonexistent"), "err: {err}");
    }

    #[test]
    fn invalid_ca_id_rejected() {
        assert!(!is_valid_ca_id(""));
        assert!(!is_valid_ca_id("Bad Id!"));
        assert!(!is_valid_ca_id("_starts_with_underscore"));
        assert!(is_valid_ca_id("good-id"));
        assert!(is_valid_ca_id("a123_test-ca"));
    }

    #[test]
    fn server_defaults_applied() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(cfg.server.listen_addr, "0.0.0.0:8443");
        assert_eq!(cfg.server.max_body_size, 65536);
    }

    #[test]
    fn est_defaults_applied() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert!(cfg.est.simpleenroll);
        assert!(cfg.est.simplereenroll);
        assert!(!cfg.est.fullcmc);
        assert!(!cfg.est.serverkeygen);
        assert!(cfg.est.csrattrs);
    }
}
