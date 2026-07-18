//! KRA (Key Recovery Authority) operations for server-side key generation.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;
use zeroize::Zeroizing;

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

#[derive(Debug, Clone)]
pub struct KeySearchEntry {
    pub key_id: String,
    pub client_key_id: String,
    pub algorithm: String,
    pub size: u32,
    pub status: String,
}

/// Dogtag RESTMessage attribute entry.
/// KRA REST API uses lowercase name/value (unlike CA ProfileAttribute).
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
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .timeout(Duration::from_secs(config.timeout_secs));

        if config.accept_invalid_certs {
            tracing::warn!("KRA client: TLS certificate validation disabled (accept_invalid_certs=true)");
        }

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
            _ if is_http => {
                tracing::warn!("KRA: no credentials configured for HTTP — using defaults (set kra_username/kra_password in config)");
                Some(("kraadmin".into(), String::new()))
            }
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
        // Dogtag v2 uses GET for session login (v1 uses POST).
        // Try GET first, fall back to POST for older KRAs.
        let login_resp = self.get_json("/kra/v2/account/login").await;
        match login_resp {
            Ok(r) if r.status().is_success() => {
                tracing::info!("KRA session login succeeded (v2 GET)");
                return;
            }
            Ok(r) => {
                tracing::debug!(status = r.status().as_u16(), "KRA v2 GET login returned non-200, trying v1 POST");
            }
            Err(e) => {
                tracing::debug!(error = %e, "KRA v2 GET login failed, trying v1 POST");
            }
        }
        let login_resp = self.post_json("/kra/rest/account/login", &serde_json::json!({})).await;
        match login_resp {
            Ok(r) if r.status().is_success() => {
                tracing::info!("KRA session login succeeded (v1 POST)");
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

    /// Recover a private key via PKCS#12 passphrase path.
    ///
    /// Three-call flow per Dogtag `KeyClient.retrieveKeyByPKCS12()`:
    /// 1. Submit recovery request (keyId + certificate)
    /// 2. Approve the recovery (mandatory, even with single agent)
    /// 3. Retrieve PKCS#12 (keyId + requestId + passphrase)
    ///
    /// Returns the PKCS#8 DER-encoded private key.
    pub async fn recover_key_p12(
        &self,
        key_id: &str,
        cert_der: &[u8],
    ) -> DogtagResult<Vec<u8>> {
        self.recover_key_inner(key_id, Some(cert_der)).await
    }

    /// Recover a private key via PKCS#12 without requiring a certificate.
    ///
    /// Variant for freshly KRA-generated keys (SSKG flow: generate →
    /// recover → build CSR → enroll). Returns PKCS#8 DER.
    pub async fn recover_key_no_cert(
        &self,
        key_id: &str,
    ) -> DogtagResult<Vec<u8>> {
        self.recover_key_inner(key_id, None).await
    }

    /// Session-key-based key recovery for escrow recovery and PQ paths.
    ///
    /// NOT for routine EST serverkeygen — use the CA's SSKG profile for that.
    /// This path is for explicit escrow recovery of archived keys and the
    /// PQ path where the SSKG profile machinery doesn't exist yet.
    async fn recover_key_inner(
        &self,
        key_id: &str,
        cert_der: Option<&[u8]>,
    ) -> DogtagResult<Vec<u8>> {
        use base64::Engine;

        self.login().await;

        // 128-bit session key matches KRA default sessionKeyLength
        let mut session_key = Zeroizing::new(vec![0u8; 16]);
        openssl::rand::rand_bytes(&mut session_key)
            .map_err(|e| DogtagError::KraError(format!("Failed to generate session key: {e}")))?;

        let transport_der = self.get_transport_cert().await?;
        // Default: RSA PKCS#1 v1.5. Only use OAEP if KRA has keyWrap.useOAEP=true.
        let trans_wrapped_b64 = wrap_session_key(&transport_der, &session_key, false)?;

        // Call 1: submit recovery request
        let mut attrs = vec![
            RestAttribute { name: "keyId".into(), value: key_id.to_owned() },
        ];
        if let Some(cert) = cert_der {
            let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert);
            attrs.push(RestAttribute { name: "certificate".into(), value: cert_b64 });
        }

        tracing::info!(key_id, has_cert = cert_der.is_some(), "submitting recovery request");
        let submit_req = KeyGenRequest {
            class_name: "com.netscape.certsrv.key.KeyRecoveryRequest".to_owned(),
            attributes: RestAttributes { attribute: attrs },
        };
        let resp = self.post_json("/kra/v2/agent/keyrequests", &submit_req).await?;
        let submit_body: serde_json::Value = Self::json_response(resp).await?;
        let request_id = submit_body.get("requestInfo")
            .and_then(|ri| ri.get("requestID").or_else(|| ri.get("requestId")))
            .and_then(|v| v.as_str())
            .ok_or_else(|| DogtagError::KraError("No requestID in recovery submit response".into()))?
            .to_owned();
        tracing::info!(request_id = %request_id, "recovery request submitted");

        // Call 2: approve
        let approve_url = format!("/kra/v2/agent/keyrequests/{request_id}/approve");
        tracing::info!(request_id = %request_id, "approving recovery request");
        let approve_resp = self.post_json(&approve_url, &serde_json::json!({})).await?;
        let approve_status = approve_resp.status();
        if !approve_status.is_success() {
            let approve_body = approve_resp.text().await.unwrap_or_default();
            return Err(DogtagError::KraError(
                format!("Recovery approve failed (HTTP {}): {}",
                    approve_status.as_u16(), crate::truncate_str(&approve_body, 200))
            ));
        }
        // Verify the request actually reached APPROVED state.
        // The approve REST call can return 2xx without the request reaching
        // APPROVED — asymmetric-key recovery routes through async agent
        // bookkeeping that may leave the request pending.
        let req_info: serde_json::Value = Self::json_response(
            self.get_json(&format!("/kra/v2/agent/keyrequests/{request_id}")).await?
        ).await?;
        let req_status = req_info.get("requestStatus")
            .and_then(|v| v.as_str()).unwrap_or("unknown");
        if !req_status.eq_ignore_ascii_case("approved")
            && !req_status.eq_ignore_ascii_case("complete") {
            return Err(DogtagError::KraError(format!(
                "recovery request {request_id} is '{req_status}' after approve — \
                 check kra.noOfRequiredRecoveryAgents in CS.cfg"
            )));
        }
        tracing::info!(request_id = %request_id, status = %req_status, "recovery approval verified");

        // Call 3: retrieve with session-key wrapping
        let retrieve_req = KeyGenRequest {
            class_name: "com.netscape.certsrv.key.KeyRecoveryRequest".to_owned(),
            attributes: RestAttributes {
                attribute: vec![
                    RestAttribute { name: "keyId".into(), value: key_id.to_owned() },
                    RestAttribute { name: "requestId".into(), value: request_id.clone() },
                    RestAttribute { name: "transWrappedSessionKey".into(), value: trans_wrapped_b64 },
                    RestAttribute { name: "payloadWrappingName".into(), value: "AES KeyWrap/Padding".into() },
                ],
            },
        };
        tracing::info!(key_id = %key_id, request_id = %request_id, "retrieving key via session-key wrapping");
        let resp = self.post_json("/kra/v2/agent/keys/retrieve", &retrieve_req).await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DogtagError::KraError(
                "Recovery retrieve returned 401 — session may have expired".into()
            ));
        }

        let body: serde_json::Value = Self::json_response(resp).await?;

        let wrapped_b64 = body.get("wrappedPrivateData")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DogtagError::KraError(
                format!("No wrappedPrivateData in retrieve response: {}", crate::truncate_str(
                    &body.to_string(), 300))
            ))?;
        let wrapped = base64::engine::general_purpose::STANDARD
            .decode(wrapped_b64)
            .map_err(|e| DogtagError::KraError(format!("Invalid base64 in wrappedPrivateData: {e}")))?;

        // Branch on wrap mode: nonceData present → AES-CBC, absent → AES-KWP
        let der = match body.get("nonceData").and_then(|v| v.as_str()) {
            Some(nonce_b64) => {
                let iv = base64::engine::general_purpose::STANDARD
                    .decode(nonce_b64)
                    .map_err(|e| DogtagError::KraError(format!("Invalid nonceData: {e}")))?;
                let cipher = match session_key.len() {
                    16 => openssl::symm::Cipher::aes_128_cbc(),
                    32 => openssl::symm::Cipher::aes_256_cbc(),
                    n => return Err(DogtagError::KraError(format!("Unsupported session key length {n} for AES-CBC"))),
                };
                Zeroizing::new(openssl::symm::decrypt(
                    cipher,
                    &session_key, Some(&iv), &wrapped,
                ).map_err(|e| DogtagError::KraError(format!("AES-CBC unwrap failed: {e}")))?)
            }
            None => {
                aes_kwp_unwrap(&session_key, &wrapped)?
            }
        };

        tracing::info!(key_len = der.len(), "private key recovered (PKCS#8 DER)");
        let out = der.to_vec();
        // der (Zeroizing) scrubs on drop; out is the caller's responsibility
        Ok(out)
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

    /// Search for archived keys on the KRA.
    ///
    /// Returns the most recent key matching the query. The KRA stores keys
    /// with a `clientKeyID` that typically contains the cert subject DN.
    /// If no query is given, returns the most recently archived key.
    pub async fn search_keys(&self, client_key_id: Option<&str>, max_results: u32) -> DogtagResult<Vec<KeySearchEntry>> {
        self.login().await;

        let mut path = format!("/kra/rest/agent/keys?maxResults={max_results}&status=active");
        if let Some(ckid) = client_key_id {
            use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
            let encoded = utf8_percent_encode(ckid, NON_ALPHANUMERIC);
            path.push_str(&format!("&clientKeyID={encoded}"));
        }

        let resp = self.get_json(&path).await?;
        let body: serde_json::Value = Self::json_response(resp).await?;

        let entries = body.get("entries")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|e| {
                    let key_url = e.get("keyURL").and_then(|v| v.as_str()).unwrap_or("");
                    let key_id = key_url.rsplit('/').next().unwrap_or("").to_owned();
                    if key_id.is_empty() { return None; }
                    Some(KeySearchEntry {
                        key_id,
                        client_key_id: e.get("clientKeyID").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                        algorithm: e.get("algorithm").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                        size: e.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                        status: e.get("status").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
                    })
                }).collect()
            })
            .unwrap_or_default();

        Ok(entries)
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
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_owned();

        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(DogtagError::ApiError {
                status: status.as_u16(),
                body,
            });
        }

        tracing::debug!(
            body_len = body.len(),
            content_type = %content_type,
            "parsing KRA response"
        );

        serde_json::from_str(&body).map_err(|e| {
            let preview = crate::truncate_str(&body, 500);
            DogtagError::ParseError(format!(
                "JSON parse failed (content-type: {content_type}): {e}; body: {preview}"
            ))
        })
    }
}

/// RSA-wrap a session key with the KRA transport cert's public key.
///
/// `use_oaep`: false = PKCS#1 v1.5 (Dogtag default), true = RSA-OAEP
/// (only when KRA has `keyWrap.useOAEP=true` in CS.cfg).
fn wrap_session_key(
    transport_cert_der: &[u8],
    session_key: &[u8],
    use_oaep: bool,
) -> DogtagResult<String> {
    use base64::Engine;

    let transport_cert = openssl::x509::X509::from_der(transport_cert_der)
        .map_err(|e| DogtagError::KraError(format!("Failed to parse transport cert: {e}")))?;
    let rsa = transport_cert.public_key()
        .map_err(|e| DogtagError::KraError(format!("Failed to extract transport public key: {e}")))?
        .rsa()
        .map_err(|e| DogtagError::KraError(format!("Transport cert is not RSA: {e}")))?;

    let padding = if use_oaep {
        openssl::rsa::Padding::PKCS1_OAEP
    } else {
        openssl::rsa::Padding::PKCS1
    };

    let mut out = vec![0u8; rsa.size() as usize];
    let n = rsa.public_encrypt(session_key, &mut out, padding)
        .map_err(|e| DogtagError::KraError(format!("RSA session key wrap failed: {e}")))?;
    out.truncate(n);

    Ok(base64::engine::general_purpose::STANDARD.encode(&out))
}

/// AES Key Wrap with Padding (RFC 5649) unwrap.
///
/// Used when the KRA returns `wrappedPrivateData` without `nonceData` —
/// the default config (`kra.allowEncDecrypt.recovery=false`).
fn aes_kwp_unwrap(key: &[u8], wrapped: &[u8]) -> DogtagResult<Zeroizing<Vec<u8>>> {
    unsafe {
        let cipher_name = match key.len() {
            16 => c"AES-128-WRAP-PAD",
            24 => c"AES-192-WRAP-PAD",
            32 => c"AES-256-WRAP-PAD",
            _ => return Err(DogtagError::KraError(format!("Invalid KEK length {}", key.len()))),
        };

        let cipher = openssl_sys::EVP_CIPHER_fetch(
            std::ptr::null_mut(), cipher_name.as_ptr(), std::ptr::null(),
        );
        if cipher.is_null() {
            return Err(DogtagError::KraError("AES-KWP cipher not available".into()));
        }

        let ctx = openssl_sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            openssl_sys::EVP_CIPHER_free(cipher as *mut _);
            return Err(DogtagError::KraError("EVP_CIPHER_CTX_new failed".into()));
        }

        openssl_sys::EVP_CIPHER_CTX_set_flags(ctx, openssl_sys::EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

        let rc = openssl_sys::EVP_DecryptInit_ex(
            ctx, cipher, std::ptr::null_mut(), key.as_ptr(), std::ptr::null(),
        );
        openssl_sys::EVP_CIPHER_free(cipher as *mut _);
        if rc != 1 {
            openssl_sys::EVP_CIPHER_CTX_free(ctx);
            return Err(DogtagError::KraError("EVP_DecryptInit_ex failed for AES-KWP".into()));
        }

        let max_out = wrapped.len() + 32;
        let mut output = Zeroizing::new(vec![0u8; max_out]);
        let mut out_len: i32 = 0;

        let rc = openssl_sys::EVP_DecryptUpdate(
            ctx, output.as_mut_ptr(), &mut out_len,
            wrapped.as_ptr(), wrapped.len() as i32,
        );
        if rc != 1 {
            openssl_sys::EVP_CIPHER_CTX_free(ctx);
            return Err(DogtagError::KraError("AES-KWP unwrap failed (DecryptUpdate)".into()));
        }

        let mut final_len: i32 = 0;
        let rc = openssl_sys::EVP_DecryptFinal_ex(
            ctx, output.as_mut_ptr().add(out_len as usize), &mut final_len,
        );
        openssl_sys::EVP_CIPHER_CTX_free(ctx);

        if rc != 1 {
            return Err(DogtagError::KraError("AES-KWP unwrap failed (DecryptFinal)".into()));
        }

        let total = (out_len + final_len) as usize;
        output.truncate(total);
        Ok(output)
    }
}
