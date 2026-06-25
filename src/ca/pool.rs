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
    /// Reusable HTTP client for remote CA requests.
    http_client: reqwest::Client,
}

impl CaBackendPool {
    /// Create a new backend pool wrapping the HA pool.
    pub fn new(ha_pool: Arc<CaPool>, config: CaBackendPoolConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .danger_accept_invalid_certs(false)
            .pool_max_idle_per_host(4)
            .build()
            .expect("failed to build reqwest::Client for CA backend pool");
        Self {
            ha_pool,
            config,
            http_client,
        }
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

    /// Send a CSR to a specific CA backend via EST simple enrollment.
    ///
    /// For remote CAs, issues an HTTP POST to the CA's EST endpoint
    /// (`/.well-known/est/simpleenroll`) per RFC 7030 §4.2.
    /// The CSR is base64-encoded (DER) and the response is a base64-encoded
    /// PKCS#7 (`application/pkcs7-mime`) containing the issued certificate.
    async fn send_to_ca(
        &self,
        ca_id: &CaId,
        endpoint: &str,
        csr_der: &[u8],
        profile: &str,
    ) -> Result<Vec<u8>, CaBackendError> {
        use base64::Engine as _;

        // Apply request timeout.
        let result = tokio::time::timeout(self.config.request_timeout, async {
            debug!(
                ca_id = %ca_id,
                endpoint = %endpoint,
                profile = %profile,
                csr_len = csr_der.len(),
                "sending EST simpleenroll request to remote CA"
            );

            // 1. Base64-encode the DER CSR (RFC 7030 §4.2: base64 of DER PKCS#10).
            let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr_der);

            // 2. Build the EST enrollment URL.
            let url = format!(
                "{}/.well-known/est/simpleenroll",
                endpoint.trim_end_matches('/')
            );

            // 3. POST to the remote CA's EST endpoint (reusing pooled client).
            let response = self.http_client
                .post(&url)
                .header("Content-Type", "application/pkcs10")
                .header("Content-Transfer-Encoding", "base64")
                .body(csr_b64)
                .send()
                .await
                .map_err(|e| CaBackendError::BackendError {
                    ca_id: ca_id.to_string(),
                    message: format!("HTTP request to {url} failed: {e}"),
                })?;

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(CaBackendError::BackendError {
                    ca_id: ca_id.to_string(),
                    message: format!("EST enrollment failed: HTTP {status} from {url}: {body}"),
                });
            }

            // 4. Read the response body (base64-encoded PKCS#7 / CMS).
            let body_bytes = response.bytes().await.map_err(|e| {
                CaBackendError::BackendError {
                    ca_id: ca_id.to_string(),
                    message: format!("failed to read EST response body: {e}"),
                }
            })?;

            // 5. Decode the base64 PKCS#7 response to DER.
            let cert_der = base64::engine::general_purpose::STANDARD
                .decode(body_bytes.as_ref())
                .map_err(|e| CaBackendError::BackendError {
                    ca_id: ca_id.to_string(),
                    message: format!("failed to decode base64 PKCS#7 response: {e}"),
                })?;

            info!(
                ca_id = %ca_id,
                cert_len = cert_der.len(),
                "EST simpleenroll succeeded"
            );

            Ok(cert_der)
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
