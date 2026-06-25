//! HTTP client for the Dogtag CA REST API.
//!
//! Provides [`DogtagClient`], the core HTTP client that handles mTLS
//! authentication, request retry, and JSON response parsing for all
//! Dogtag REST API interactions.

use std::time::Duration;

use reqwest::{Certificate, Client, Identity};
use tracing::{debug, warn};

use crate::config::DogtagConfig;
use crate::{DogtagError, DogtagResult};

/// HTTP client for Dogtag CA REST API operations.
///
/// Wraps a `reqwest::Client` configured with mTLS agent credentials for
/// authenticating to the Dogtag PKI REST API. All methods perform automatic
/// retry on transient failures (HTTP 5xx and connection errors).
///
/// # Construction
///
/// Use [`DogtagClient::new`] with a [`DogtagConfig`] to build a client.
/// The agent certificate and key files are read during construction and
/// the TLS identity is established once for the lifetime of the client.
///
/// # Thread Safety
///
/// `DogtagClient` is `Send + Sync` and can be shared across async tasks
/// via `Arc<DogtagClient>`.
pub struct DogtagClient {
    http: Client,
    base_url: String,
    retry_max: u32,
    retry_delay: Duration,
}

impl DogtagClient {
    /// Create a new Dogtag client from configuration.
    ///
    /// Reads the agent certificate, key, and CA certificate files to
    /// configure mTLS. Returns an error if any file cannot be read or
    /// if the TLS identity cannot be constructed.
    pub fn new(config: &DogtagConfig) -> DogtagResult<Self> {
        let cert_pem = std::fs::read(&config.agent_cert_file)?;
        let key_pem = std::fs::read(&config.agent_key_file)?;
        let ca_pem = std::fs::read(&config.ca_cert_file)?;

        // reqwest Identity expects concatenated cert + key PEM.
        let mut identity_pem = cert_pem;
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&key_pem);

        let identity = Identity::from_pem(&identity_pem)
            .map_err(|e| DogtagError::TlsError(format!("Failed to load agent identity: {e}")))?;

        let ca_cert = Certificate::from_pem(&ca_pem)
            .map_err(|e| DogtagError::TlsError(format!("Failed to load CA certificate: {e}")))?;

        let http = Client::builder()
            .identity(identity)
            .add_root_certificate(ca_cert)
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| DogtagError::TlsError(format!("HTTP client build failed: {e}")))?;

        // Normalize base URL: strip trailing slash.
        let base_url = config.ca_url.as_str().trim_end_matches('/').to_owned();

        Ok(Self {
            http,
            base_url,
            retry_max: config.retry_max,
            retry_delay: Duration::from_millis(config.retry_delay_ms),
        })
    }

    /// Check Dogtag CA health by querying the info endpoint.
    ///
    /// Sends `GET /ca/rest/info` and returns `true` if the CA responds
    /// with HTTP 200.
    pub async fn health_check(&self) -> DogtagResult<bool> {
        let url = format!("{}/ca/rest/info", self.base_url);
        debug!(url = %url, "Dogtag health check");

        match self.http.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!(error = %e, "Dogtag health check failed");
                Ok(false)
            }
        }
    }

    /// Send a GET request with retry.
    pub(crate) async fn get(&self, path: &str) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.request_with_retry(|| self.http.get(&url).send()).await
    }

    /// Send a POST request with a JSON body and retry.
    pub(crate) async fn post_json<T: serde::Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.request_with_retry(|| self.http.post(&url).json(body).send())
            .await
    }

    /// Send a POST request with raw bytes and a specific content type.
    pub(crate) async fn post_bytes(
        &self,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let ct = content_type.to_owned();
        self.request_with_retry(|| {
            self.http
                .post(&url)
                .header("Content-Type", &ct)
                .body(body.clone())
                .send()
        })
        .await
    }

    /// Execute a request with retry on transient failures.
    ///
    /// Retries on HTTP 5xx responses and connection errors, up to
    /// `retry_max` attempts with a fixed delay between attempts.
    async fn request_with_retry<F, Fut>(&self, make_request: F) -> DogtagResult<reqwest::Response>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = reqwest::Result<reqwest::Response>>,
    {
        let mut last_error = None;

        for attempt in 0..=self.retry_max {
            if attempt > 0 {
                debug!(attempt, max = self.retry_max, "Retrying request");
                tokio::time::sleep(self.retry_delay).await;
            }

            match make_request().await {
                Ok(resp) if resp.status().is_server_error() => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    warn!(
                        attempt,
                        status = status.as_u16(),
                        "Server error, will retry"
                    );
                    last_error = Some(DogtagError::ApiError {
                        status: status.as_u16(),
                        body,
                    });
                }
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    warn!(attempt, error = %e, "Request failed, will retry");
                    last_error = Some(DogtagError::Http(e));
                }
            }
        }

        Err(last_error.unwrap_or(DogtagError::ApiError {
            status: 0,
            body: "All retry attempts exhausted".into(),
        }))
    }

    /// Return the base URL (for pool routing).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Extract a successful JSON response or return an API error.
    pub(crate) async fn json_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> DogtagResult<T> {
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DogtagError::ApiError {
                status: status.as_u16(),
                body,
            });
        }
        resp.json::<T>()
            .await
            .map_err(|e| DogtagError::ParseError(e.to_string()))
    }
}
