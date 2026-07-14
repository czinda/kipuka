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

/// Dogtag RESTMessage attribute entry.
#[derive(Serialize)]
struct RestAttribute {
    name: String,
    value: String,
}

/// Dogtag RESTMessage-format request for KRA key generation.
///
/// Dogtag's KRA REST API uses the RESTMessage wire format where parameters
/// are carried in `Attributes.Attribute[]`, not as flat JSON fields.
/// `ClassName` selects the Java handler class via reflection.
#[derive(Serialize)]
struct KeyGenRequest {
    #[serde(rename = "ClassName")]
    class_name: String,
    #[serde(rename = "Attributes")]
    attributes: RestAttributes,
}

#[derive(Serialize)]
struct RestAttributes {
    #[serde(rename = "Attribute")]
    attribute: Vec<RestAttribute>,
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
struct P12RecoverResponse {
    #[serde(flatten)]
    fields: serde_json::Value,
}

impl P12RecoverResponse {
    fn p12_data(&self) -> Option<&str> {
        self.fields.get("p12Data").and_then(|v| v.as_str())
    }
    fn request_id(&self) -> Option<&str> {
        self.fields.get("requestID")
            .or_else(|| self.fields.get("requestId"))
            .and_then(|v| v.as_str())
    }
    fn request_status(&self) -> Option<&str> {
        self.fields.get("requestInfo")
            .and_then(|ri| ri.get("requestStatus"))
            .and_then(|v| v.as_str())
    }
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

        let basic_auth = match (
            config.kra_username.as_ref().or(config.username.as_ref()),
            config.kra_password.as_ref().or(config.password.as_ref()),
        ) {
            (Some(user), Some(pass)) => Some((user.clone(), pass.clone())),
            _ if is_http => Some(("kraadmin".into(), "RedHat123".into())),
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

    pub async fn login(&self) {
        let login_resp = self.post_json("/kra/rest/account/login", &serde_json::json!({})).await;
        match login_resp {
            Ok(r) if r.status().is_success() => {
                tracing::info!("KRA session login succeeded");
            }
            Ok(r) => {
                tracing::warn!(status = r.status().as_u16(), "KRA session login returned non-200 (continuing)");
            }
            Err(e) => {
                tracing::warn!(error = %e, "KRA session login failed (continuing without session)");
            }
        }
    }

    pub async fn generate_key(&self, key_type: &str, key_size: u32) -> DogtagResult<KeyGenResult> {
        self.login().await;
        debug!(key_type, key_size, "Generating key on KRA");

        let class_name = if key_type.eq_ignore_ascii_case("AES")
            || key_type.eq_ignore_ascii_case("DESede")
        {
            "com.netscape.certsrv.key.SymKeyGenerationRequest"
        } else {
            "com.netscape.certsrv.key.AsymKeyGenerationRequest"
        };

        let client_key_id = format!("kipuka-{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos());

        let request = KeyGenRequest {
            class_name: class_name.to_owned(),
            attributes: RestAttributes {
                attribute: vec![
                    RestAttribute { name: "clientKeyID".into(), value: client_key_id },
                    RestAttribute { name: "keyAlgorithm".into(), value: key_type.to_owned() },
                    RestAttribute { name: "keySize".into(), value: key_size.to_string() },
                    RestAttribute { name: "keyUsage".into(), value: "wrap,unwrap".into() },
                ],
            },
        };

        let resp = self.post_json("/kra/v2/agent/keyrequests", &request).await?;
        let keygen_resp: KeyGenResponse = Self::json_response(resp).await?;

        let info = keygen_resp
            .request_info
            .ok_or_else(|| DogtagError::KraError("Missing request_info in response".into()))?;

        let key_id = info
            .key_url
            .as_ref()
            .and_then(|url| url.rsplit('/').next())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DogtagError::KraError("KRA response missing keyURL or key ID".into()))?
            .to_owned();

        // Fetch the public key via GET /kra/v2/agent/keys/{key_id}.
        // The keygen response doesn't include the public key directly,
        // but the key info endpoint returns it as base64 SPKI DER.
        let public_key = self.get_public_key(&key_id).await?;

        Ok(KeyGenResult {
            key_id,
            request_id: info.request_id.unwrap_or_default(),
            public_key: Some(public_key),
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

        let resp = self.post_json("/kra/v2/agent/keys/archive", &body).await?;
        let archive: ArchiveResponse = Self::json_response(resp).await?;

        archive
            .request_info
            .and_then(|i| i.request_id)
            .ok_or_else(|| DogtagError::KraError("No request_id in archive response".into()))
    }

    pub async fn recover_key(&self, key_id: &str) -> DogtagResult<Vec<u8>> {
        let body = serde_json::json!({});
        let resp = self
            .post_json(&format!("/kra/v2/agent/keys/{key_id}/recover"), &body)
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

    /// Recover a private key via PKCS#12 passphrase path (no ML-KEM encapsulation needed).
    ///
    /// Three-call flow per Dogtag master `KeyClient.retrieveKeyByPKCS12()`:
    /// 1. Submit recovery request (keyId + certificate, no passphrase)
    /// 2. Approve the recovery (mandatory, even with single agent)
    /// 3. Retrieve PKCS#12 (keyId + requestId + passphrase)
    ///
    /// Returns the DER-encoded private key extracted from the PKCS#12.
    pub async fn recover_key_p12(
        &self,
        key_id: &str,
        cert_der: &[u8],
    ) -> DogtagResult<Vec<u8>> {
        use base64::Engine;
        let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);

        // Call 1: submit recovery (no passphrase — just keyId + certificate)
        tracing::info!(key_id, "submitting PKCS#12 recovery request");
        let submit_req = KeyGenRequest {
            class_name: "com.netscape.certsrv.key.KeyRecoveryRequest".to_owned(),
            attributes: RestAttributes {
                attribute: vec![
                    RestAttribute { name: "keyId".into(), value: key_id.to_owned() },
                    RestAttribute { name: "certificate".into(), value: cert_b64 },
                ],
            },
        };
        let resp = self.post_json("/kra/v2/agent/keyrequests", &submit_req).await?;
        let submit_body: serde_json::Value = Self::json_response(resp).await?;
        let request_id = submit_body.get("requestInfo")
            .and_then(|ri| ri.get("requestID").or_else(|| ri.get("requestId")))
            .and_then(|v| v.as_str())
            .ok_or_else(|| DogtagError::KraError("No requestID in recovery submit response".into()))?
            .to_owned();
        tracing::info!(request_id = %request_id, "recovery request submitted");

        // Call 2: approve (mandatory — empty body, treat 2xx as success)
        let approve_url = format!("/kra/v2/agent/keyrequests/{request_id}/approve");
        tracing::info!(request_id = %request_id, url = %approve_url, base = %self.base_url, "approving recovery request");
        let approve_resp = self
            .post_json(&approve_url, &serde_json::json!({}))
            .await?;
        let approve_status = approve_resp.status();
        let approve_body = approve_resp.text().await.unwrap_or_default();
        tracing::info!(status = approve_status.as_u16(), body_len = approve_body.len(), "approve response");
        if !approve_status.is_success() {
            return Err(DogtagError::KraError(
                format!("Recovery approve failed (HTTP {}): {}", approve_status.as_u16(), &approve_body[..approve_body.len().min(200)])
            ));
        }
        tracing::info!("recovery approved");

        // Call 3: retrieve PKCS#12 (fixed path: /kra/v2/agent/keys/retrieve, NOT /keys/{id}/retrieve)
        let mut rand_bytes = [0u8; 16];
        openssl::rand::rand_bytes(&mut rand_bytes)
            .map_err(|e| DogtagError::KraError(format!("Failed to generate random passphrase: {e}")))?;
        let passphrase: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();

        let retrieve_req = KeyGenRequest {
            class_name: "com.netscape.certsrv.key.KeyRecoveryRequest".to_owned(),
            attributes: RestAttributes {
                attribute: vec![
                    RestAttribute { name: "keyId".into(), value: key_id.to_owned() },
                    RestAttribute { name: "requestId".into(), value: request_id.clone() },
                    RestAttribute { name: "passphrase".into(), value: passphrase.clone() },
                ],
            },
        };
        tracing::info!(key_id = %key_id, request_id = %request_id, "retrieving PKCS#12 from /kra/v2/agent/keys/retrieve");
        let resp = self.post_json("/kra/v2/agent/keys/retrieve", &retrieve_req).await?;
        let resp_status = resp.status();
        if resp_status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DogtagError::KraError(
                "Recovery retrieve returned 401 — approve may not have completed".into()
            ));
        }
        let retrieve: P12RecoverResponse = Self::json_response(resp).await?;

        let p12_b64 = retrieve.p12_data()
            .ok_or_else(|| DogtagError::KraError(
                "No p12Data in recovery response (field name mismatch or key not found)".into()
            ))?;

        let p12_der = base64::engine::general_purpose::STANDARD
            .decode(p12_b64)
            .map_err(|e| DogtagError::KraError(format!("Invalid base64 in p12Data: {e}")))?;

        // Extract private key from PKCS#12 using OpenSSL
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&p12_der)
            .map_err(|e| DogtagError::KraError(format!("Failed to parse PKCS#12: {e}")))?;
        let parsed = pkcs12.parse2(&passphrase)
            .map_err(|e| DogtagError::KraError(format!("Failed to decrypt PKCS#12: {e}")))?;
        let pkey = parsed.pkey
            .ok_or_else(|| DogtagError::KraError("No private key in PKCS#12".into()))?;

        let der = pkey.private_key_to_der()
            .map_err(|e| DogtagError::KraError(format!("Failed to serialize private key: {e}")))?;

        tracing::info!(key_len = der.len(), "private key recovered from PKCS#12");
        Ok(der)
    }

    /// Recover a private key via PKCS#12 without requiring a certificate.
    ///
    /// Variant of [`recover_key_p12`] for freshly KRA-generated keys that
    /// have no associated certificate yet (SSKG flow: generate → recover →
    /// build CSR → enroll).  The submit step sends only `keyId`; the
    /// `certificate` attribute is omitted.
    ///
    /// Returns the DER-encoded private key.
    pub async fn recover_key_no_cert(
        &self,
        key_id: &str,
    ) -> DogtagResult<Vec<u8>> {
        use base64::Engine;

        // Call 1: submit recovery (keyId only — no certificate for freshly generated keys)
        tracing::info!(key_id, "submitting PKCS#12 recovery request (no cert)");
        let submit_req = KeyGenRequest {
            class_name: "com.netscape.certsrv.key.KeyRecoveryRequest".to_owned(),
            attributes: RestAttributes {
                attribute: vec![
                    RestAttribute { name: "keyId".into(), value: key_id.to_owned() },
                ],
            },
        };
        let resp = self.post_json("/kra/v2/agent/keyrequests", &submit_req).await?;
        let submit_body: serde_json::Value = Self::json_response(resp).await?;
        let request_id = submit_body.get("requestInfo")
            .and_then(|ri| ri.get("requestID").or_else(|| ri.get("requestId")))
            .and_then(|v| v.as_str())
            .ok_or_else(|| DogtagError::KraError("No requestID in recovery submit response".into()))?
            .to_owned();
        tracing::info!(request_id = %request_id, "recovery request submitted (no cert)");

        // Call 2: approve (mandatory — even for single-agent KRA)
        let approve_url = format!("/kra/v2/agent/keyrequests/{request_id}/approve");
        tracing::info!(request_id = %request_id, "approving recovery request");
        let approve_resp = self
            .post_json(&approve_url, &serde_json::json!({}))
            .await?;
        let approve_status = approve_resp.status();
        let approve_body = approve_resp.text().await.unwrap_or_default();
        tracing::info!(status = approve_status.as_u16(), body_len = approve_body.len(), "approve response");
        if !approve_status.is_success() {
            return Err(DogtagError::KraError(
                format!("Recovery approve failed (HTTP {}): {}", approve_status.as_u16(), &approve_body[..approve_body.len().min(200)])
            ));
        }

        // Call 3: retrieve PKCS#12
        let mut rand_bytes = [0u8; 16];
        openssl::rand::rand_bytes(&mut rand_bytes)
            .map_err(|e| DogtagError::KraError(format!("Failed to generate random passphrase: {e}")))?;
        let passphrase: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();

        let retrieve_req = KeyGenRequest {
            class_name: "com.netscape.certsrv.key.KeyRecoveryRequest".to_owned(),
            attributes: RestAttributes {
                attribute: vec![
                    RestAttribute { name: "keyId".into(), value: key_id.to_owned() },
                    RestAttribute { name: "requestId".into(), value: request_id.clone() },
                    RestAttribute { name: "passphrase".into(), value: passphrase.clone() },
                ],
            },
        };
        tracing::info!(key_id = %key_id, request_id = %request_id, "retrieving PKCS#12");
        let resp = self.post_json("/kra/v2/agent/keys/retrieve", &retrieve_req).await?;
        let resp_status = resp.status();
        if resp_status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DogtagError::KraError(
                "Recovery retrieve returned 401 — approve may not have completed".into()
            ));
        }
        let retrieve: P12RecoverResponse = Self::json_response(resp).await?;

        let p12_b64 = retrieve.p12_data()
            .ok_or_else(|| DogtagError::KraError(
                "No p12Data in recovery response".into()
            ))?;

        let p12_der = base64::engine::general_purpose::STANDARD
            .decode(p12_b64)
            .map_err(|e| DogtagError::KraError(format!("Invalid base64 in p12Data: {e}")))?;

        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&p12_der)
            .map_err(|e| DogtagError::KraError(format!("Failed to parse PKCS#12: {e}")))?;
        let parsed = pkcs12.parse2(&passphrase)
            .map_err(|e| DogtagError::KraError(format!("Failed to decrypt PKCS#12: {e}")))?;
        let pkey = parsed.pkey
            .ok_or_else(|| DogtagError::KraError("No private key in PKCS#12".into()))?;

        let der = pkey.private_key_to_der()
            .map_err(|e| DogtagError::KraError(format!("Failed to serialize private key: {e}")))?;

        tracing::info!(key_len = der.len(), "private key recovered from PKCS#12 (no cert path)");
        Ok(der)
    }

    /// Fetch the KRA transport certificate as DER.
    ///
    /// The transport cert's ML-KEM-1024 public key is used by clients to
    /// encapsulate the shared secret for key archival.
    pub async fn get_transport_cert(&self) -> DogtagResult<Vec<u8>> {
        let resp = self.get_json("/kra/v2/config/cert/transport").await?;
        let body: serde_json::Value = Self::json_response(resp).await?;
        let pem = body.get("Encoded")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DogtagError::KraError(
                "No Encoded field in transport cert response".into(),
            ))?;

        // Strip PEM headers and decode
        let b64: String = pem.lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| DogtagError::KraError(format!("Transport cert base64 decode failed: {e}")))
    }

    /// Fetch the public key (base64 SPKI DER) for a KRA-generated key.
    async fn get_public_key(&self, key_id: &str) -> DogtagResult<String> {
        let path = format!("/kra/v2/agent/keys/{key_id}");
        let resp = self.get_json(&path).await?;
        let body: serde_json::Value = Self::json_response(resp).await?;
        body.get("publicKey")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| DogtagError::KraError(
                "No publicKey in key info response".into(),
            ))
    }

    async fn get_json(&self, path: &str) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.get(&url)
            .header("Accept", "application/json");
        if let Some((ref user, ref pass)) = self.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }
        req.send()
            .await
            .map_err(|e| DogtagError::HttpError(e.to_string()))
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
