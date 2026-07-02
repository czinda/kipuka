//! Unified secret management — no plaintext credentials in deployed config.
//!
//! All config fields that hold secrets use [`SecretRef`], a serde-transparent
//! newtype that encodes the resolution backend via a URI-like prefix:
//!
//! | Prefix | Backend |
//! |--------|---------|
//! | `env:VAR` | Environment variable |
//! | `file:/path` | File contents (trimmed) |
//! | `prompt:Label` | Interactive terminal input |
//! | `keyring:name` | Linux kernel keyring |
//! | `systemd-creds:name` | systemd `LoadCredential=` |
//! | (none) | Literal — logs a warning |

use std::collections::HashMap;
use std::io::IsTerminal;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

/// A reference to a secret in a config file.
///
/// Deserializes transparently from a TOML string. The prefix selects the
/// resolution backend; prefix-free values are treated as literals with a
/// startup warning.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(String);

impl From<&str> for SecretRef {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl PartialEq<&str> for SecretRef {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl SecretRef {
    pub fn backend(&self) -> SecretBackend {
        let s = &self.0;
        if let Some(var) = s.strip_prefix("env:") {
            SecretBackend::Env(var.to_string())
        } else if let Some(path) = s.strip_prefix("file:") {
            SecretBackend::File(path.to_string())
        } else if let Some(label) = s.strip_prefix("prompt:") {
            SecretBackend::Prompt(label.to_string())
        } else if let Some(key) = s.strip_prefix("keyring:") {
            SecretBackend::Keyring(key.to_string())
        } else if let Some(name) = s.strip_prefix("systemd-creds:") {
            SecretBackend::SystemdCreds(name.to_string())
        } else {
            SecretBackend::Literal(s.to_string())
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn raw(&self) -> &str {
        &self.0
    }
}

/// Resolution backend for a single secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretBackend {
    Env(String),
    File(String),
    Prompt(String),
    Keyring(String),
    SystemdCreds(String),
    Literal(String),
}

/// Errors during secret resolution.
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("{field}: environment variable {var:?} is not set")]
    EnvNotSet { field: String, var: String },

    #[error("{field}: secret file {path:?} not found")]
    FileNotFound { field: String, path: String },

    #[error("{field}: secret file {path:?} read error: {source}")]
    FileRead {
        field: String,
        path: String,
        source: std::io::Error,
    },

    #[error("{field}: no TTY available for interactive prompt; use env: or file: instead")]
    NoTty { field: String },

    #[error("{field}: interactive prompt failed: {reason}")]
    PromptFailed { field: String, reason: String },

    #[error("{field}: kernel keyring lookup failed for {key:?}: {reason}")]
    KeyringFailed {
        field: String,
        key: String,
        reason: String,
    },

    #[error("{field}: systemd credential {name:?} not found at {path}")]
    SystemdCredNotFound {
        field: String,
        name: String,
        path: String,
    },
}

/// Resolves [`SecretRef`] values at startup and caches results in memory.
///
/// Never writes secrets to disk. Detects whether stdin is a TTY to gate
/// the `prompt:` backend.
pub struct SecretResolver {
    cache: Arc<RwLock<HashMap<String, String>>>,
    interactive: bool,
}

impl Default for SecretResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretResolver {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            interactive: std::io::stdin().is_terminal(),
        }
    }

    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Resolve a single secret by config field name.
    pub fn resolve(&self, field: &str, secret_ref: &SecretRef) -> Result<String, SecretError> {
        if secret_ref.is_empty() {
            return Ok(String::new());
        }

        // Check cache
        {
            let cache = self.cache.read();
            if let Some(val) = cache.get(field) {
                return Ok(val.clone());
            }
        }

        let value = match secret_ref.backend() {
            SecretBackend::Env(var) => {
                debug!(field = field, var = %var, "resolving secret from environment");
                std::env::var(&var).map_err(|_| SecretError::EnvNotSet {
                    field: field.to_string(),
                    var,
                })?
            }
            SecretBackend::File(path) => {
                debug!(field = field, path = %path, "resolving secret from file");
                std::fs::read_to_string(&path)
                    .map_err(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            SecretError::FileNotFound {
                                field: field.to_string(),
                                path: path.clone(),
                            }
                        } else {
                            SecretError::FileRead {
                                field: field.to_string(),
                                path: path.clone(),
                                source: e,
                            }
                        }
                    })?
                    .trim_end()
                    .to_string()
            }
            SecretBackend::Prompt(label) => {
                if !self.interactive {
                    return Err(SecretError::NoTty {
                        field: field.to_string(),
                    });
                }
                rpassword::prompt_password(format!("Enter {label}: ")).map_err(|e| {
                    SecretError::PromptFailed {
                        field: field.to_string(),
                        reason: e.to_string(),
                    }
                })?
            }
            SecretBackend::Keyring(key) => {
                debug!(field = field, key = %key, "resolving secret from kernel keyring");
                Self::read_keyring(field, &key)?
            }
            SecretBackend::SystemdCreds(name) => {
                let creds_dir = std::env::var("CREDENTIALS_DIRECTORY")
                    .unwrap_or_else(|_| "/run/credentials/kipuka.service".to_string());
                let path = format!("{creds_dir}/{name}");
                debug!(field = field, path = %path, "resolving secret from systemd credentials");
                std::fs::read_to_string(&path)
                    .map_err(|_| SecretError::SystemdCredNotFound {
                        field: field.to_string(),
                        name,
                        path,
                    })?
                    .trim_end()
                    .to_string()
            }
            SecretBackend::Literal(val) => {
                if !val.is_empty() {
                    warn!(
                        field = field,
                        "secret stored as plaintext in config; use env:, file:, or prompt: prefix in production"
                    );
                }
                val
            }
        };

        // Cache
        {
            let mut cache = self.cache.write();
            cache.insert(field.to_string(), value.clone());
        }

        Ok(value)
    }

    /// Store a secret in the Linux kernel keyring for restart persistence.
    #[cfg(target_os = "linux")]
    pub fn store_keyring(key: &str, value: &str) -> Result<(), SecretError> {
        use std::process::Command;

        let status = Command::new("keyctl")
            .args(["padd", "user", key, "@s"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(value.as_bytes())?;
                }
                child.wait()
            });

        match status {
            Ok(s) if s.success() => {
                debug!(key = key, "stored secret in kernel keyring");
                Ok(())
            }
            Ok(s) => Err(SecretError::KeyringFailed {
                field: key.to_string(),
                key: key.to_string(),
                reason: format!("keyctl exited with {s}"),
            }),
            Err(e) => Err(SecretError::KeyringFailed {
                field: key.to_string(),
                key: key.to_string(),
                reason: format!("failed to run keyctl: {e}"),
            }),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn store_keyring(key: &str, _value: &str) -> Result<(), SecretError> {
        Err(SecretError::KeyringFailed {
            field: key.to_string(),
            key: key.to_string(),
            reason: "kernel keyring is only available on Linux".to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    fn read_keyring(field: &str, key: &str) -> Result<String, SecretError> {
        use std::process::Command;

        let output = Command::new("keyctl")
            .args(["pipe", &format!("%user:{key}")])
            .output()
            .map_err(|e| SecretError::KeyringFailed {
                field: field.to_string(),
                key: key.to_string(),
                reason: format!("failed to run keyctl: {e}"),
            })?;

        if !output.status.success() {
            return Err(SecretError::KeyringFailed {
                field: field.to_string(),
                key: key.to_string(),
                reason: "key not found in session keyring".to_string(),
            });
        }

        String::from_utf8(output.stdout).map_err(|e| SecretError::KeyringFailed {
            field: field.to_string(),
            key: key.to_string(),
            reason: format!("keyring value is not valid UTF-8: {e}"),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn read_keyring(field: &str, key: &str) -> Result<String, SecretError> {
        Err(SecretError::KeyringFailed {
            field: field.to_string(),
            key: key.to_string(),
            reason: "kernel keyring is only available on Linux".to_string(),
        })
    }

    /// Resolve all configured secrets and return a bundle.
    pub fn resolve_config(
        &self,
        config: &super::Config,
    ) -> Result<ResolvedSecrets, SecretError> {
        let db_url = self.resolve("database.url", &config.database.url)?;

        let hsm_pin = if let Some(ref hsm) = config.hsm {
            if hsm.pin.is_empty() {
                None
            } else {
                Some(self.resolve("hsm.pin", &hsm.pin)?)
            }
        } else {
            None
        };

        let admin_bearer_token = if let Some(ref admin) = config.admin {
            if let Some(ref token_ref) = admin.bearer_token {
                Some(self.resolve("admin.bearer_token", token_ref)?)
            } else {
                None
            }
        } else {
            None
        };

        let ldap_bind_password = if config.otp.enabled {
            if let Some(ref ldap) = config.otp.ldap {
                if ldap.bind_password.is_empty() {
                    None
                } else {
                    Some(self.resolve("otp.ldap.bind_password", &ldap.bind_password)?)
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut cmp_mac_secrets = HashMap::new();
        if let Some(ref cmp) = config.cmp {
            for secret in &cmp.mac_secrets {
                let resolved =
                    self.resolve(&format!("cmp.mac_secrets.{}", secret.reference), &secret.secret_hex)?;
                cmp_mac_secrets.insert(secret.reference.clone(), resolved);
            }
        }

        Ok(ResolvedSecrets {
            db_url,
            hsm_pin,
            admin_bearer_token,
            ldap_bind_password,
            cmp_mac_secrets,
        })
    }

    /// Persist all prompted secrets to the kernel keyring.
    pub fn persist_to_keyring(&self, _secrets: &ResolvedSecrets) {
        let cache = self.cache.read();
        for (field, _value) in cache.iter() {
            if let Some(val) = cache.get(field) {
                let key = format!("kipuka/{}", field.replace('.', "/"));
                if let Err(e) = Self::store_keyring(&key, val) {
                    warn!(field = field, error = %e, "failed to persist secret to keyring");
                }
            }
        }
    }
}

/// All resolved secrets for the running instance. Never serialized to disk.
#[derive(Debug, Clone)]
pub struct ResolvedSecrets {
    pub db_url: String,
    pub hsm_pin: Option<String>,
    pub admin_bearer_token: Option<String>,
    pub ldap_bind_password: Option<String>,
    pub cmp_mac_secrets: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_env_prefix() {
        let r = SecretRef("env:MY_VAR".into());
        assert_eq!(r.backend(), SecretBackend::Env("MY_VAR".into()));
    }

    #[test]
    fn parse_file_prefix() {
        let r = SecretRef("file:/run/secrets/db-pass".into());
        assert_eq!(r.backend(), SecretBackend::File("/run/secrets/db-pass".into()));
    }

    #[test]
    fn parse_prompt_prefix() {
        let r = SecretRef("prompt:HSM PIN".into());
        assert_eq!(r.backend(), SecretBackend::Prompt("HSM PIN".into()));
    }

    #[test]
    fn parse_keyring_prefix() {
        let r = SecretRef("keyring:kipuka/hsm-pin".into());
        assert_eq!(r.backend(), SecretBackend::Keyring("kipuka/hsm-pin".into()));
    }

    #[test]
    fn parse_systemd_creds_prefix() {
        let r = SecretRef("systemd-creds:hsm-pin".into());
        assert_eq!(r.backend(), SecretBackend::SystemdCreds("hsm-pin".into()));
    }

    #[test]
    fn parse_literal_no_prefix() {
        let r = SecretRef("plaintext-value".into());
        assert_eq!(r.backend(), SecretBackend::Literal("plaintext-value".into()));
    }

    #[test]
    fn resolve_env_backend() {
        // SAFETY: test-only, single-threaded by #[test] default.
        unsafe { std::env::set_var("KIPUKA_TEST_SECRET", "test-value-42") };
        let resolver = SecretResolver::new();
        let r = SecretRef("env:KIPUKA_TEST_SECRET".into());
        let val = resolver.resolve("test.field", &r).unwrap();
        assert_eq!(val, "test-value-42");
        unsafe { std::env::remove_var("KIPUKA_TEST_SECRET") };
    }

    #[test]
    fn resolve_env_missing() {
        let resolver = SecretResolver::new();
        let r = SecretRef("env:KIPUKA_NONEXISTENT_VAR_XYZ".into());
        let err = resolver.resolve("test.field", &r).unwrap_err();
        assert!(err.to_string().contains("is not set"));
    }

    #[test]
    fn resolve_file_backend() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-secret");
        std::fs::write(&path, "file-secret-value\n").unwrap();

        let resolver = SecretResolver::new();
        let r = SecretRef(format!("file:{}", path.display()));
        let val = resolver.resolve("test.field", &r).unwrap();
        assert_eq!(val, "file-secret-value");
    }

    #[test]
    fn resolve_caches_value() {
        // SAFETY: test-only, single-threaded by #[test] default.
        unsafe { std::env::set_var("KIPUKA_CACHE_TEST", "cached") };
        let resolver = SecretResolver::new();
        let r = SecretRef("env:KIPUKA_CACHE_TEST".into());

        let val1 = resolver.resolve("cache.test", &r).unwrap();
        unsafe { std::env::remove_var("KIPUKA_CACHE_TEST") };
        let val2 = resolver.resolve("cache.test", &r).unwrap();

        assert_eq!(val1, "cached");
        assert_eq!(val2, "cached");
    }
}
