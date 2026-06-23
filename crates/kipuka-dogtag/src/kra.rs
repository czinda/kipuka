//! KRA (Key Recovery Authority) operations for server-side key generation.
//!
//! Supports kipuka's `/serverkeygen` EST endpoint (RFC 7030 S4.4) by
//! generating key pairs on the Dogtag KRA subsystem and archiving the
//! private key for optional recovery.
//!
//! The KRA communicates over a separate base URL from the CA and requires
//! its own agent-level authentication.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;

use reqwest::{Certificate, Client, Identity};

use crate::config::DogtagConfig;
use crate::{DogtagError, DogtagResult};

/// Client for Dogtag KRA REST API operations.
///
/// Manages a separate HTTP client configured for the KRA subsystem.
/// The KRA may run on the same host as the CA but uses a different
/// subsystem path (`/kra/rest/...`).
pub struct KraClient {
    http: Client,
    base_url: String,
    retry_max: u32,
    retry_delay: Duration,
}

/// Result of a server-side key generation request.
#[derive(Debug, Clone)]
pub struct KeyGenResult {
    /// KRA key identifier for the archived key.
    pub key_id: String,
    /// DER-encoded public key.
    pub public_key_der: Vec<u8>,
    /// Wrapped (encrypted) private key bytes, if returned.
    ///
    /// The wrapping key is typically the transport certificate of the
    /// requesting agent. The EST client must unwrap this using the
    /// corresponding private key.
    pub wrapped_private_key: Option<Vec<u8>>,
}

/// Key generation request body.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct KeyGenRequest {
    /// Key algorithm (e.g., "RSA", "EC", "ML-KEM-768").
    key_algorithm: String,
    /// Key size in bits (for RSA) or named curve/parameter set.
    key_size: u32,
    /// Client key ID for tracking.
    client_key_id: String,
}

/// Key archival request body.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ArchiveRequest {
    /// Client key ID.
    client_key_id: String,
    /// Base64-encoded wrapped key data.
    wrapped_private_data: String,
    /// Algorithm OID of the wrapped key.
    algorithm_oid: Option<String>,
}

/// Key recovery request body.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RecoverRequest {
    /// Key ID to recover.
    key_id: String,
}

/// Response from key generation.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeyGenResponse {
    /// Key request info containing the generated key data.
    #[serde(default)]
    request_info: Option<KeyRequestInfo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeyRequestInfo {
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    wrapped_private_data: Option<String>,
}

/// Response from key recovery.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RecoverResponse {
    /// Base64-encoded recovered key data.
    #[serde(default)]
    data: Option<String>,
}

/// Response from key archival.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ArchiveResponse {
    /// Archived key ID.
    #[serde(default)]
    key_id: Option<String>,
}

impl KraClient {
    /// Create a new KRA client from the Dogtag configuration.
    ///
    /// Uses the same agent credentials as the CA client but connects
    /// to the KRA subsystem URL. Returns an error if `kra_url` is not
    /// configured.
    pub fn new(config: &DogtagConfig) -> DogtagResult<Self> {
        let kra_url = config
            .kra_url
            .as_ref()
            .ok_or_else(|| DogtagError::ConfigError("kra_url is required for KRA operations".into()))?;

        let cert_pem = std::fs::read(&config.agent_cert_file)?;
        let key_pem = std::fs::read(&config.agent_key_file)?;
        let ca_pem = std::fs::read(&config.ca_cert_file)?;

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
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        let base_url = kra_url.as_str().trim_end_matches('/').to_owned();

        Ok(Self {
            http,
            base_url,
            retry_max: config.retry_max,
            retry_delay: Duration::from_millis(config.retry_delay_ms),
        })
    }

    /// Generate a key pair on the KRA.
    ///
    /// Sends `POST /kra/rest/agent/keys/generate` to create a new key pair.
    /// The private key is archived in the KRA and the public key is returned
    /// for inclusion in the certificate request.
    ///
    /// # Supported Algorithms
    ///
    /// - RSA: `key_type = "RSA"`, `key_size = 2048 | 3072 | 4096`
    /// - ECDSA: `key_type = "EC"`, `key_size = 256 | 384 | 521`
    /// - ML-KEM: `key_type = "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024"`, `key_size = 0`
    pub async fn generate_key(
        &self,
        key_type: &str,
        key_size: u32,
    ) -> DogtagResult<KeyGenResult> {
        debug!(key_type, key_size, "Generating key on KRA");

        let request = KeyGenRequest {
            key_algorithm: key_type.to_owned(),
            key_size,
            client_key_id: uuid_v4(),
        };

        let resp = self
            .post_json("/kra/rest/agent/keys/generate", &request)
            .await?;

        let keygen_resp: KeyGenResponse = json_response(resp).await?;

        let info = keygen_resp
            .request_info
            .ok_or_else(|| DogtagError::KraError("Missing request_info in response".into()))?;

        let key_id = info
            .key_id
            .ok_or_else(|| DogtagError::KraError("Missing key_id in response".into()))?;

        let public_key_b64 = info
            .public_key
            .ok_or_else(|| DogtagError::KraError("Missing public_key in response".into()))?;

        use base64::Engine;
        let public_key_der = base64::engine::general_purpose::STANDARD
            .decode(&public_key_b64)
            .map_err(|e| DogtagError::KraError(format!("Invalid base64 in public key: {e}")))?;

        let wrapped_private_key = if let Some(ref wrapped) = info.wrapped_private_data {
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(wrapped)
                    .map_err(|e| {
                        DogtagError::KraError(format!("Invalid base64 in wrapped key: {e}"))
                    })?,
            )
        } else {
            None
        };

        Ok(KeyGenResult {
            key_id,
            public_key_der,
            wrapped_private_key,
        })
    }

    /// Archive a private key in the KRA.
    ///
    /// Sends `POST /kra/rest/agent/keys/archive` to store a wrapped
    /// private key for later recovery. Returns the KRA key identifier.
    pub async fn archive_key(
        &self,
        key_id: &str,
        wrapped_key: &[u8],
    ) -> DogtagResult<String> {
        debug!(key_id, size = wrapped_key.len(), "Archiving key in KRA");

        use base64::Engine;
        let wrapped_b64 = base64::engine::general_purpose::STANDARD.encode(wrapped_key);

        let request = ArchiveRequest {
            client_key_id: key_id.to_owned(),
            wrapped_private_data: wrapped_b64,
            algorithm_oid: None,
        };

        let resp = self
            .post_json("/kra/rest/agent/keys/archive", &request)
            .await?;

        let archive: ArchiveResponse = json_response(resp).await?;

        archive
            .key_id
            .ok_or_else(|| DogtagError::KraError("Missing key_id in archive response".into()))
    }

    /// Recover an archived private key from the KRA.
    ///
    /// Sends `POST /kra/rest/agent/keys/{key_id}/recover` to retrieve
    /// a previously archived key. The key is returned in its wrapped form.
    pub async fn recover_key(&self, key_id: &str) -> DogtagResult<Vec<u8>> {
        debug!(key_id, "Recovering key from KRA");

        let request = RecoverRequest {
            key_id: key_id.to_owned(),
        };

        let resp = self
            .post_json(
                &format!("/kra/rest/agent/keys/{key_id}/recover"),
                &request,
            )
            .await?;

        let recover: RecoverResponse = json_response(resp).await?;

        let data_b64 = recover
            .data
            .ok_or_else(|| DogtagError::KraError("Missing data in recovery response".into()))?;

        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&data_b64)
            .map_err(|e| DogtagError::KraError(format!("Invalid base64 in recovered key: {e}")))
    }

    /// Send a POST request with a JSON body and retry.
    async fn post_json<T: serde::Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut last_error = None;

        for attempt in 0..=self.retry_max {
            if attempt > 0 {
                debug!(attempt, max = self.retry_max, "Retrying KRA request");
                tokio::time::sleep(self.retry_delay).await;
            }

            match self.http.post(&url).json(body).send().await {
                Ok(resp) if resp.status().is_server_error() => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::warn!(attempt, status = status.as_u16(), "KRA server error");
                    last_error = Some(DogtagError::ApiError {
                        status: status.as_u16(),
                        body,
                    });
                }
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "KRA request failed");
                    last_error = Some(DogtagError::Http(e));
                }
            }
        }

        Err(last_error.unwrap_or(DogtagError::KraError(
            "All retry attempts exhausted".into(),
        )))
    }
}

/// Extract a successful JSON response or return an API error.
async fn json_response<T: serde::de::DeserializeOwned>(
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

/// Generate a simple UUID v4 for client key IDs.
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("kipuka-{nanos:x}")
}
