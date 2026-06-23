//! Admin API configuration.
//!
//! The `[admin]` section controls the administrative REST API used for
//! operator management, OTP provisioning, CA health monitoring, and
//! audit log queries.

use serde::Deserialize;

/// Admin authentication method.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdminAuthMethod {
    /// mTLS client certificate authentication.
    Mtls,
    /// HTTP Basic authentication.
    Basic,
    /// GSSAPI/SPNEGO (Kerberos) authentication.
    Gssapi,
}

impl Default for AdminAuthMethod {
    fn default() -> Self {
        AdminAuthMethod::Mtls
    }
}

/// `[admin]` section — administrative API configuration.
///
/// When this section is absent, admin endpoints return 404.
///
/// ```toml
/// [admin]
/// enabled = true
/// listen_addr = "127.0.0.1:8444"
/// auth_method = "mtls"
/// allowed_operators = ["admin@example.com"]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Enable the admin API.
    #[serde(default)]
    pub enabled: bool,

    /// Listen address for the admin API.
    ///
    /// When absent, admin endpoints are served on the main EST listener.
    /// Setting a separate address allows binding the admin API to a
    /// management network interface.
    pub listen_addr: Option<String>,

    /// Authentication method for admin API access.
    #[serde(default)]
    pub auth_method: AdminAuthMethod,

    /// List of allowed operator identities.
    ///
    /// The format depends on `auth_method`:
    /// - `mtls` — Subject DN or SAN email of the client certificate.
    /// - `basic` — Username (passwords stored in the database).
    /// - `gssapi` — Kerberos principal name.
    #[serde(default)]
    pub allowed_operators: Vec<String>,

    /// Path to the CA certificate bundle (PEM) for admin mTLS.
    ///
    /// RHELBU-3536 R18: separate truststore from the EST client truststore.
    /// Required when `auth_method = "mtls"`.
    pub admin_ca_file: Option<String>,

    /// Session TTL in seconds.
    ///
    /// Admin sessions expire after this duration of inactivity.
    /// Default: 3600 (1 hour).
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,

    /// Maximum concurrent admin sessions.
    /// Default: 16.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// GSSAPI configuration (required when `auth_method = "gssapi"`).
    pub gssapi: Option<AdminGssapiConfig>,
}

/// GSSAPI/SPNEGO configuration for admin authentication.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminGssapiConfig {
    /// Path to the Kerberos keytab file.
    pub keytab_file: Option<String>,

    /// Service principal name.
    /// Default: `"HTTP"` (the hostname is appended automatically).
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Use gssproxy for credential management instead of a keytab.
    #[serde(default)]
    pub gssproxy: bool,
}

fn default_session_ttl_secs() -> u64 {
    3600
}

fn default_max_sessions() -> usize {
    16
}

fn default_service_name() -> String {
    "HTTP".to_string()
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: None,
            auth_method: AdminAuthMethod::default(),
            allowed_operators: Vec::new(),
            admin_ca_file: None,
            session_ttl_secs: default_session_ttl_secs(),
            max_sessions: default_max_sessions(),
            gssapi: None,
        }
    }
}

impl AdminConfig {
    /// Validate admin configuration constraints.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.auth_method == AdminAuthMethod::Mtls && self.admin_ca_file.is_none() {
            return Err(
                "[admin].admin_ca_file is required when auth_method = \"mtls\"".into(),
            );
        }

        if self.auth_method == AdminAuthMethod::Gssapi {
            match &self.gssapi {
                None => {
                    return Err(
                        "[admin].gssapi section is required when auth_method = \"gssapi\"".into(),
                    );
                }
                Some(g) => {
                    if !g.gssproxy && g.keytab_file.is_none() {
                        return Err(
                            "[admin.gssapi]: set `keytab_file` or enable `gssproxy = true`".into(),
                        );
                    }
                    if g.gssproxy && g.keytab_file.is_some() {
                        return Err(
                            "[admin.gssapi]: `keytab_file` and `gssproxy = true` are mutually exclusive".into(),
                        );
                    }
                }
            }
        }

        if self.session_ttl_secs == 0 {
            return Err("[admin].session_ttl_secs must be at least 1".into());
        }

        Ok(())
    }
}
