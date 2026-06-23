//! CoAP transport configuration (RFC 9483).
//!
//! The `[coap]` section enables EST over CoAP with DTLS for
//! constrained device enrollment.  When enabled, the server
//! listens on a UDP port (default 5684 for DTLS) in addition
//! to the primary HTTP/TLS listener.

use serde::Deserialize;

/// `[coap]` section — CoAP transport for constrained devices.
///
/// ```toml
/// [coap]
/// enabled = true
/// listen_addr = "0.0.0.0:5684"
/// dtls_enabled = true
/// block_size = 512
/// max_payload = 65536
/// session_timeout_secs = 300
/// max_sessions = 1024
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoapConfig {
    /// Enable the CoAP transport listener.
    #[serde(default)]
    pub enabled: bool,

    /// UDP listen address for CoAP/DTLS.
    #[serde(default = "default_coap_listen_addr")]
    pub listen_addr: String,

    /// Enable DTLS for the CoAP listener.
    #[serde(default = "default_true")]
    pub dtls_enabled: bool,

    /// CoAP block-wise transfer size in bytes (64, 128, 256, 512, 1024).
    #[serde(default = "default_block_size")]
    pub block_size: u16,

    /// Maximum reassembled payload size in bytes.
    #[serde(default = "default_max_payload")]
    pub max_payload: usize,

    /// DTLS session timeout for constrained device resumption.
    #[serde(default = "default_session_timeout_secs")]
    pub session_timeout_secs: u64,

    /// Maximum number of concurrent DTLS sessions.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

fn default_coap_listen_addr() -> String {
    "0.0.0.0:5684".to_string()
}

fn default_true() -> bool {
    true
}

fn default_block_size() -> u16 {
    512
}

fn default_max_payload() -> usize {
    65536
}

fn default_session_timeout_secs() -> u64 {
    300
}

fn default_max_sessions() -> usize {
    1024
}

impl Default for CoapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_coap_listen_addr(),
            dtls_enabled: true,
            block_size: default_block_size(),
            max_payload: default_max_payload(),
            session_timeout_secs: default_session_timeout_secs(),
            max_sessions: default_max_sessions(),
        }
    }
}

impl CoapConfig {
    /// Validate CoAP configuration constraints.
    pub fn validate(&self) -> Result<(), String> {
        const VALID_BLOCK_SIZES: &[u16] = &[16, 32, 64, 128, 256, 512, 1024];
        if !VALID_BLOCK_SIZES.contains(&self.block_size) {
            return Err(format!(
                "[coap].block_size must be one of {:?}, got {}",
                VALID_BLOCK_SIZES, self.block_size
            ));
        }

        if self.max_payload == 0 {
            return Err("[coap].max_payload must be greater than 0".into());
        }

        Ok(())
    }
}
