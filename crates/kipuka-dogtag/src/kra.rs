//! KRA (Key Recovery Authority) operations for server-side key generation.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;

use reqwest::{Certificate, Client, Identity};

use crate::config::DogtagConfig;
use crate::{DogtagError, DogtagResult};

pub struct KraClient {
    http: Client,
    base_url: String,
    basic_auth: Option<(String, String)>,
    retry_max: u32,
    retry_delay: Duration,
}

/// Result of a key generation operation.
pub struct KeyGenResult {
    pub key_id: String,
    pub request_id: String,
    pub public_key: Option<String>,
    pub wrapped_private_key: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct KeyGenRequest {
    #[serde(rename = "keyAlgorithm")]
    key_algorithm: String,
    #[serde(rename = "keySize")]
    key_size: u32,
    #[serde(rename = "clientKeyID")]
    client_key_id: String,
}

#[derive(Deserialize)]
struct KeyGenResponse {
    #[serde(rename = "requestInfo")]
    request_info: Option<RequestInfo>,
}

#[derive(Deserialize)]
struct RequestInfo {
    #[serde(rename = "requestID")]
    request_id: Option<String>,
    #[serde(rename = "keyURL")]
    key_url: Option<String>,
}

#[derive(Deserialize)]
struct RecoverResponse {
    #[serde(rename = "wrappedPrivateData")]
    data: Option<String>,
}

#[derive(Deserialize)]
struct ArchiveResponse {
    #[serde(rename = "requestInfo")]
    request_info: Option<RequestInfo>,
}

impl KraClient {
    pub fn new(config: &DogtagConfig) -> DogtagResult<Self> {
        let kra_url = config.kra_url.as_ref().ok_or_else(|| {
            DogtagError::ConfigError("kra_url is required for KRA operations".into())
        })?;

        let is_http = kra_url.scheme() == "http";

        let mut builder = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(config.timeout_secs));

        if !is_http && !config.skip_mtls {
            let cert_pem = std::fs::read(&config.agent_cert_file)?;
            let key_pem = std::fs::read(&config.agent_key_file)?;
            let identity = Identity::from_pkcs8_pem(&cert_pem, &key_pem)
                .map_err(|e| DogtagError::TlsError(format!("Failed to load agent identity: {e}")))?;
            builder = builder.identity(identity);
        }

        let ca_pem = std::fs::read(&config.ca_cert_file)?;
        let ca_cert = Certificate::from_pem(&ca_pem)
            .map_err(|e| DogtagError::TlsError(format!("Failed to load CA certificate: {e}")))?;
        builder = builder.add_root_certificate(ca_cert);

        let http = builder.build()
            .map_err(|e| DogtagError::TlsError(format!("KRA client build failed: {e:?}")))?;

        let base_url = kra_url.as_str().trim_end_matches('/').to_owned();

        let basic_auth = match (&config.username, &config.password) {
            (Some(user), Some(pass)) => Some((user.clone(), pass.clone())),
            _ if is_http => Some(("caadmin".into(), "RedHat123".into())),
            _ => None,
        };

        Ok(Self {
            http,
            base_url,
            basic_auth,
            retry_max: config.retry_max,
            retry_delay: Duration::from_millis(config.retry_delay_ms),
        })
    }

    pub async fn generate_key(&self, key_type: &str, key_size: u32) -> DogtagResult<KeyGenResult> {
        debug!(key_type, key_size, "Generating key on KRA");

        let request = KeyGenRequest {
            key_algorithm: key_type.to_owned(),
            key_size,
            client_key_id: format!("kipuka-{:x}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()),
        };

        let resp = self.post_json("/kra/rest/agent/keys/generate", &request).await?;
        let keygen_resp: KeyGenResponse = Self::json_response(resp).await?;

        let info = keygen_resp
            .request_info
            .ok_or_else(|| DogtagError::KraError("Missing request_info in response".into()))?;

        let key_id = info
            .key_url
            .as_ref()
            .and_then(|url| url.rsplit('/').next())
            .unwrap_or("")
            .to_owned();

        Ok(KeyGenResult {
            key_id,
            request_id: info.request_id.unwrap_or_default(),
            public_key: None,
            wrapped_private_key: None,
        })
    }

    pub async fn archive_key(&self, key_data: &[u8], algorithm: &str) -> DogtagResult<String> {
        use base64::Engine;
        let wrapped = base64::engine::general_purpose::STANDARD.encode(key_data);

        let body = serde_json::json!({
            "clientKeyID": format!("kipuka-archive-{:x}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()),
            "dataType": "symmetricKey",
            "keyAlgorithm": algorithm,
            "wrappedPrivateData": wrapped,
        });

        let resp = self.post_json("/kra/rest/agent/keys/archive", &body).await?;
        let archive: ArchiveResponse = Self::json_response(resp).await?;

        archive
            .request_info
            .and_then(|i| i.request_id)
            .ok_or_else(|| DogtagError::KraError("No request_id in archive response".into()))
    }

    pub async fn recover_key(&self, key_id: &str) -> DogtagResult<Vec<u8>> {
        let body = serde_json::json!({});
        let resp = self
            .post_json(&format!("/kra/rest/agent/keys/{key_id}/recover"), &body)
            .await?;
        let recover: RecoverResponse = Self::json_response(resp).await?;

        let data_b64 = recover
            .data
            .ok_or_else(|| DogtagError::KraError("Missing data in recovery response".into()))?;

        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&data_b64)
            .map_err(|e| DogtagError::KraError(format!("Invalid base64 in recovered key: {e}")))
    }

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

            let mut req = self.http.post(&url)
                .header("Accept", "application/json")
                .json(body);
            if let Some((ref user, ref pass)) = self.basic_auth {
                req = req.basic_auth(user, Some(pass));
            }
            match req.send().await {
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
                    last_error = Some(DogtagError::HttpError(e.to_string()));
                }
            }
        }

        Err(last_error.unwrap_or(DogtagError::KraError("All retry attempts exhausted".into())))
    }

    async fn json_response<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> DogtagResult<T> {
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
