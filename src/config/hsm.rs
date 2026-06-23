//! HSM / PKCS#11 configuration.
//!
//! The `[hsm]` section configures hardware security module access via
//! the PKCS#11 API.  When present, CA private keys referenced by
//! `pkcs11_uri` in `[[ca]]` entries are accessed through this HSM.
//!
//! Supported HSM providers:
//!
//! | Provider | Description |
//! |----------|-------------|
//! | `entrust` | Entrust nShield (nCipher) |
//! | `utimaco` | Utimaco SecurityServer |
//! | `kryoptic` | Kryoptic software PKCS#11 (dev/test) |
//! | `thales_csp` | Thales CipherTrust Platform (Luna CSP) |
//! | `thales_tct` | Thales Luna Network HSM (TCT) |

use serde::Deserialize;

/// HSM provider identifier.
///
/// Each provider corresponds to a specific PKCS#11 middleware library
/// and may require provider-specific initialization parameters.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HsmProvider {
    Entrust,
    Utimaco,
    Kryoptic,
    #[serde(rename = "thales_csp")]
    ThalesCsp,
    #[serde(rename = "thales_tct")]
    ThalesTct,
}

/// `[hsm]` section — PKCS#11 HSM configuration.
///
/// ```toml
/// [hsm]
/// provider = "entrust"
/// library_path = "/opt/nfast/toolkits/pkcs11/libcknfast.so"
/// pin = "env:KIPUKA_HSM_PIN"
/// slot_id = 0
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HsmConfig {
    /// HSM middleware provider.
    pub provider: HsmProvider,

    /// Absolute path to the PKCS#11 shared library (`.so` / `.dylib` / `.dll`).
    pub library_path: String,

    /// PKCS#11 user PIN for session login.
    ///
    /// Supports `"env:VAR_NAME"` syntax to read the PIN from an
    /// environment variable at startup, avoiding plaintext storage
    /// in the config file.
    #[serde(default)]
    pub pin: String,

    /// PKCS#11 slot ID to use.
    ///
    /// When absent, the first available slot is used.
    pub slot_id: Option<u64>,

    /// PKCS#11 token label (alternative to `slot_id`).
    ///
    /// When both `slot_id` and `token_label` are set, `slot_id` takes
    /// precedence.
    pub token_label: Option<String>,

    /// PKCS#11 URI for advanced key identification.
    ///
    /// Example: `"pkcs11:token=kipuka;object=ca-key;type=private"`
    ///
    /// This is a template for CA keys; per-CA `pkcs11_uri` in `[[ca]]`
    /// overrides this when present.
    pub pkcs11_uri: Option<String>,

    /// Maximum concurrent PKCS#11 sessions.
    ///
    /// Limits the number of simultaneous signing operations to avoid
    /// exhausting HSM session resources.  Default: 8.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

fn default_max_sessions() -> usize {
    8
}

impl HsmConfig {
    /// Resolve the HSM PIN, expanding `"env:VAR_NAME"` references.
    pub fn resolve_pin(&self) -> std::result::Result<String, String> {
        if let Some(var_name) = self.pin.strip_prefix("env:") {
            std::env::var(var_name).map_err(|_| {
                format!("[hsm].pin references env var {var_name:?} which is not set")
            })
        } else {
            Ok(self.pin.clone())
        }
    }
}
