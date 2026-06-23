//! CA backend pool for HA enrollment routing.
//!
//! Routes EST enrollment requests to healthy CA backends using the
//! HA subsystem's failover strategy. Provides retry logic and
//! connection management.

use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{debug, info, warn};

use crate::ha::pool::{CaId, CaPool};

/// Errors during CA backend operations.
#[derive(Debug, Error)]
pub enum CaBackendError {
    /// No healthy CA backend is available.
    #[error("no healthy CA backend available")]
    NoHealthyBackend,

    /// The request timed out.
    #[error("request to CA {ca_id} timed out after {elapsed_ms}ms")]
    Timeout { ca_id: String, elapsed_ms: u64 },

    /// All retry attempts exhausted.
    #[error("all {attempts} retry attempts exhausted")]
    RetriesExhausted { attempts: u32 },

    /// Backend request failed.
    #[error("CA backend error from {ca_id}: {message}")]
    BackendError { ca_id: String, message: String },
}

/// Configuration for the CA backend pool.
#[derive(Debug, Clone)]
pub struct CaBackendPoolConfig {
    /// Request timeout per CA backend attempt.
    pub request_timeout: Duration,
    /// Maximum number of retry attempts with different CAs.
    pub max_retries: u32,
    /// Whether to keep connections alive for reuse.
    pub keep_alive: bool,
}

impl Default for CaBackendPoolConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            max_retries: 2,
            keep_alive: true,
        }
    }
}

/// Routes enrollment requests to healthy CA backends via the HA pool.
///
/// Wraps the HA [`CaPool`] with retry logic and timeout management
/// for enrollment operations (simpleenroll, simplereenroll, serverkeygen).
pub struct CaBackendPool {
    /// The underlying HA pool for CA selection.
    ha_pool: Arc<CaPool>,
    /// Pool configuration.
    config: CaBackendPoolConfig,
}

impl CaBackendPool {
    /// Create a new backend pool wrapping the HA pool.
    pub fn new(ha_pool: Arc<CaPool>, config: CaBackendPoolConfig) -> Self {
        Self { ha_pool, config }
    }

    /// Route a certificate issuance request to a healthy CA.
    ///
    /// Selects a CA via the HA strategy, sends the request, and retries
    /// with the next available CA on failure (up to `max_retries`).
    ///
    /// # Arguments
    ///
    /// * `csr_der` - DER-encoded CSR to submit
    /// * `profile` - Enrollment profile name
    ///
    /// # Returns
    ///
    /// DER-encoded issued certificate on success.
    pub async fn route_enrollment(
        &self,
        csr_der: &[u8],
        profile: &str,
    ) -> Result<Vec<u8>, CaBackendError> {
        let mut attempts = 0u32;
        let mut last_error = None;

        while attempts <= self.config.max_retries {
            let ca = self
                .ha_pool
                .select()
                .ok_or(CaBackendError::NoHealthyBackend)?;

            debug!(
                ca_id = %ca.id,
                attempt = attempts + 1,
                profile = %profile,
                "routing enrollment to CA"
            );

            let start = Instant::now();
            match self
                .send_to_ca(&ca.id, &ca.endpoint, csr_der, profile)
                .await
            {
                Ok(cert_der) => {
                    let elapsed = start.elapsed();
                    self.ha_pool.record_success(&ca.id, elapsed);
                    info!(
                        ca_id = %ca.id,
                        elapsed_ms = elapsed.as_millis(),
                        "enrollment succeeded"
                    );
                    return Ok(cert_der);
                }
                Err(e) => {
                    let elapsed = start.elapsed();
                    warn!(
                        ca_id = %ca.id,
                        attempt = attempts + 1,
                        elapsed_ms = elapsed.as_millis(),
                        error = %e,
                        "enrollment attempt failed"
                    );
                    self.ha_pool.record_failure(&ca.id);
                    last_error = Some(e);
                }
            }

            attempts += 1;
        }

        Err(last_error.unwrap_or(CaBackendError::RetriesExhausted {
            attempts: self.config.max_retries + 1,
        }))
    }

    /// Send a CSR to a specific CA backend.
    ///
    /// TODO: implement actual HTTP/CMP request to the CA endpoint.
    /// For local CAs, this calls `ca::issue::issue_certificate` directly.
    async fn send_to_ca(
        &self,
        ca_id: &CaId,
        endpoint: &str,
        _csr_der: &[u8],
        _profile: &str,
    ) -> Result<Vec<u8>, CaBackendError> {
        // Apply request timeout.
        let result = tokio::time::timeout(self.config.request_timeout, async {
            // TODO: for remote CAs, issue an HTTP request to `endpoint`.
            // For local CAs, call the issuance pipeline directly.
            debug!(
                ca_id = %ca_id,
                endpoint = %endpoint,
                "sending enrollment request (integration pending)"
            );

            // Placeholder: simulate successful issuance.
            Ok::<Vec<u8>, CaBackendError>(vec![0x30, 0x00])
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(CaBackendError::Timeout {
                ca_id: ca_id.to_string(),
                elapsed_ms: self.config.request_timeout.as_millis() as u64,
            }),
        }
    }

    /// Reference to the underlying HA pool.
    pub fn ha_pool(&self) -> &Arc<CaPool> {
        &self.ha_pool
    }
}
