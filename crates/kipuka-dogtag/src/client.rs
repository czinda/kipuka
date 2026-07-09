//! HTTP client for the Dogtag CA REST API.
//!
//! Uses `hyper` + `hyper-openssl` for HTTPS connections, giving full
//! control over the OpenSSL `SslConnector`.  When the agent key is a
//! `pkcs11:` URI, the private key is loaded via OpenSSL's PKCS#11
//! engine — the key never leaves the HSM.

use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_openssl::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod};
use openssl::x509::X509;
use tracing::{debug, warn};

use crate::config::DogtagConfig;
use crate::{DogtagError, DogtagResult};

/// HTTP response wrapper with an API matching reqwest::Response.
pub struct HttpResponse {
    status: StatusCode,
    body: Bytes,
}

impl HttpResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }

    pub async fn text(self) -> Result<String, DogtagError> {
        Ok(String::from_utf8_lossy(&self.body).into_owned())
    }

    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, DogtagError> {
        serde_json::from_slice(&self.body).map_err(|e| DogtagError::ParseError(e.to_string()))
    }

    pub async fn bytes(self) -> Result<Bytes, DogtagError> {
        Ok(self.body)
    }
}

type HyperClient = Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>;

/// HTTP client for Dogtag CA REST API operations.
///
/// Uses `hyper` + `hyper-openssl` for mTLS with PKCS#11 support.
/// When the agent key file is a `pkcs11:` URI, the private key is
/// loaded via OpenSSL's engine mechanism and never leaves the HSM.
pub struct DogtagClient {
    http: HyperClient,
    base_url: String,
    retry_max: u32,
    retry_delay: Duration,
}

impl DogtagClient {
    pub fn new(config: &DogtagConfig) -> DogtagResult<Self> {
        let mut ssl_builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| DogtagError::TlsError(format!("SslConnector init: {e}")))?;

        // Load agent certificate
        let cert_pem = std::fs::read(&config.agent_cert_file)?;
        let cert = X509::from_pem(&cert_pem)
            .map_err(|e| DogtagError::TlsError(format!("agent cert parse: {e}")))?;
        ssl_builder
            .set_certificate(&cert)
            .map_err(|e| DogtagError::TlsError(format!("set agent cert: {e}")))?;

        // Load agent private key — PKCS#11 or PEM file
        if config.agent_key_file.starts_with("pkcs11:") {
            tracing::info!(
                uri = %config.agent_key_file,
                "loading Dogtag agent key from PKCS#11 HSM"
            );
            let engine = openssl::engine::Engine::by_id("pkcs11")
                .map_err(|e| DogtagError::TlsError(format!("PKCS#11 engine load: {e}")))?;
            engine
                .init()
                .map_err(|e| DogtagError::TlsError(format!("PKCS#11 engine init: {e}")))?;
            let pkey = engine
                .load_private_key(&config.agent_key_file)
                .map_err(|e| DogtagError::TlsError(format!("PKCS#11 key load: {e}")))?;
            ssl_builder
                .set_private_key(&pkey)
                .map_err(|e| DogtagError::TlsError(format!("set PKCS#11 key: {e}")))?;
        } else {
            let key_pem = std::fs::read(&config.agent_key_file)?;
            let pkey = PKey::private_key_from_pem(&key_pem)
                .map_err(|e| DogtagError::TlsError(format!("agent key parse: {e}")))?;
            ssl_builder
                .set_private_key(&pkey)
                .map_err(|e| DogtagError::TlsError(format!("set agent key: {e}")))?;
        }

        // Load CA trust anchors
        let ca_pem = std::fs::read(&config.ca_cert_file)?;
        let ca_certs = X509::stack_from_pem(&ca_pem)
            .map_err(|e| DogtagError::TlsError(format!("CA cert parse: {e}")))?;
        let store = ssl_builder.cert_store_mut();
        for ca in ca_certs {
            store
                .add_cert(ca)
                .map_err(|e| DogtagError::TlsError(format!("add CA cert: {e}")))?;
        }

        // Accept self-signed or internal CA certs
        ssl_builder.set_verify(openssl::ssl::SslVerifyMode::NONE);

        let ssl_connector = ssl_builder.build();
        let mut https_connector =
            HttpsConnector::with_connector(hyper_util::client::legacy::connect::HttpConnector::new(), ssl_connector)
                .map_err(|e| DogtagError::TlsError(format!("HTTPS connector: {e}")))?;
        https_connector.set_callback(|ssl, _uri| {
            // Allow connecting to any hostname (lab environment)
            ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);
            Ok(())
        });

        let http = Client::builder(TokioExecutor::new()).build(https_connector);

        let base_url = config.ca_url.as_str().trim_end_matches('/').to_owned();

        Ok(Self {
            http,
            base_url,
            retry_max: config.retry_max,
            retry_delay: Duration::from_millis(config.retry_delay_ms),
        })
    }

    pub async fn health_check(&self) -> DogtagResult<bool> {
        let url = format!("{}/ca/rest/info", self.base_url);
        debug!(url = %url, "Dogtag health check");

        match self.get("/ca/rest/info").await {
            Ok(resp) => Ok(resp.is_success()),
            Err(e) => {
                warn!(error = %e, "Dogtag health check failed");
                Ok(false)
            }
        }
    }

    pub(crate) async fn get(&self, path: &str) -> DogtagResult<HttpResponse> {
        let url = format!("{}{}", self.base_url, path);
        self.request(Method::GET, &url, None, None).await
    }

    pub(crate) async fn post_json<T: serde::Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> DogtagResult<HttpResponse> {
        let url = format!("{}{}", self.base_url, path);
        let json = serde_json::to_vec(body)
            .map_err(|e| DogtagError::ParseError(format!("JSON serialize: {e}")))?;
        self.request(
            Method::POST,
            &url,
            Some(Bytes::from(json)),
            Some("application/json"),
        )
        .await
    }

    pub(crate) async fn post_bytes(
        &self,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> DogtagResult<HttpResponse> {
        let url = format!("{}{}", self.base_url, path);
        self.request(
            Method::POST,
            &url,
            Some(Bytes::from(body)),
            Some(content_type),
        )
        .await
    }

    async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<Bytes>,
        content_type: Option<&str>,
    ) -> DogtagResult<HttpResponse> {
        let mut last_error = None;

        for attempt in 0..=self.retry_max {
            if attempt > 0 {
                debug!(attempt, max = self.retry_max, "retrying request");
                tokio::time::sleep(self.retry_delay).await;
            }

            let mut req_builder = Request::builder().method(method.clone()).uri(url);

            if let Some(ct) = content_type {
                req_builder = req_builder.header("Content-Type", ct);
            }

            let req = req_builder
                .body(Full::new(body.clone().unwrap_or_default()))
                .map_err(|e| DogtagError::TlsError(format!("request build: {e}")))?;

            match self.http.request(req).await {
                Ok(resp) => {
                    let status = resp.status();
                    let body_bytes = resp
                        .into_body()
                        .collect()
                        .await
                        .map_err(|e| DogtagError::TlsError(format!("body read: {e}")))?
                        .to_bytes();

                    if status.is_server_error() {
                        let body_str = String::from_utf8_lossy(&body_bytes).into_owned();
                        warn!(attempt, status = status.as_u16(), "server error, will retry");
                        last_error = Some(DogtagError::ApiError {
                            status: status.as_u16(),
                            body: body_str,
                        });
                        continue;
                    }

                    return Ok(HttpResponse {
                        status,
                        body: body_bytes,
                    });
                }
                Err(e) => {
                    warn!(attempt, error = %e, "request failed, will retry");
                    last_error = Some(DogtagError::TlsError(format!("HTTP error: {e}")));
                }
            }
        }

        Err(last_error.unwrap_or(DogtagError::ApiError {
            status: 0,
            body: "All retry attempts exhausted".into(),
        }))
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) async fn json_response<T: serde::de::DeserializeOwned>(
        resp: HttpResponse,
    ) -> DogtagResult<T> {
        if !resp.is_success() {
            let body = String::from_utf8_lossy(&resp.body).into_owned();
            return Err(DogtagError::ApiError {
                status: resp.status.as_u16(),
                body,
            });
        }
        serde_json::from_slice(&resp.body)
            .map_err(|e| DogtagError::ParseError(e.to_string()))
    }
}
