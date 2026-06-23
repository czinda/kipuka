//! CMS-wrapped EST configuration (RFC 8295).
//!
//! The `[cms_est]` section enables EST endpoints that use CMS
//! message-level security instead of TLS for authentication and
//! confidentiality.  This supports disconnected/air-gapped
//! deployments where a TLS-terminating proxy handles transport.

use serde::Deserialize;

/// `[cms_est]` section — CMS message-level security for EST.
///
/// ```toml
/// [cms_est]
/// enabled = true
/// require_signed_requests = true
/// encrypt_responses = true
/// allowed_content_encryption = ["AES-256-GCM", "AES-128-GCM"]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CmsEstConfig {
    /// Enable CMS-wrapped EST endpoints.
    #[serde(default)]
    pub enabled: bool,

    /// Require CMS SignedData wrapping on all requests.
    #[serde(default = "default_true")]
    pub require_signed_requests: bool,

    /// Encrypt responses using CMS EnvelopedData.
    #[serde(default = "default_true")]
    pub encrypt_responses: bool,

    /// Allowed content-encryption algorithms for CMS EnvelopedData.
    #[serde(default = "default_allowed_content_encryption")]
    pub allowed_content_encryption: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_allowed_content_encryption() -> Vec<String> {
    vec!["AES-256-GCM".to_string(), "AES-128-GCM".to_string()]
}

impl Default for CmsEstConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_signed_requests: true,
            encrypt_responses: true,
            allowed_content_encryption: default_allowed_content_encryption(),
        }
    }
}

impl CmsEstConfig {
    /// Validate CMS-EST configuration constraints.
    pub fn validate(&self) -> Result<(), String> {
        if self.encrypt_responses && self.allowed_content_encryption.is_empty() {
            return Err(
                "[cms_est].allowed_content_encryption must not be empty when encrypt_responses is true"
                    .into(),
            );
        }

        Ok(())
    }
}
