//! HTTP client for the Dogtag CA REST API.
//!
//! Uses `reqwest` with `native-tls` (OpenSSL 3.5+) for mTLS agent
//! authentication on HTTPS. OpenSSL 3.5 supports ML-DSA-87 TLS
//! SignatureSchemes, enabling mTLS with PQ agent certs. Falls back
//! to HTTP basic auth when ca_url uses the http scheme.

use std::time::Duration;

use reqwest::{Certificate, Client, Identity};
use tracing::{debug, info, warn};

use crate::config::DogtagConfig;
use crate::{DogtagError, DogtagResult};

pub struct DogtagClient {
    http: Client,
    base_url: String,
    basic_auth: Option<(String, String)>,
    retry_max: u32,
    retry_delay: Duration,
}

impl DogtagClient {
    pub fn new(config: &DogtagConfig) -> DogtagResult<Self> {
        let is_http = config.ca_url.scheme() == "http";

        let mut builder = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(config.timeout_secs));

        // HTTPS: use mTLS with agent cert (reqwest Identity)
        // HTTP: skip Identity (no TLS), use basic auth instead
        if !is_http {
            let cert_pem = std::fs::read(&config.agent_cert_file)?;
            let key_pem = std::fs::read(&config.agent_key_file)?;
            let identity = Identity::from_pkcs8_pem(&cert_pem, &key_pem)
                .map_err(|e| DogtagError::TlsError(format!("Failed to load agent identity: {e}")))?;
            builder = builder.identity(identity);
            info!("Dogtag client: HTTPS with mTLS agent cert");
        } else {
            info!("Dogtag client: HTTP with basic auth (no mTLS)");
        }

        let ca_pem = std::fs::read(&config.ca_cert_file)?;
        let ca_cert = Certificate::from_pem(&ca_pem)
            .map_err(|e| DogtagError::TlsError(format!("Failed to load CA certificate: {e}")))?;
        builder = builder.add_root_certificate(ca_cert);

        let http = builder
            .build()
            .map_err(|e| DogtagError::TlsError(format!("HTTP client build failed: {e:?}")))?;

        let base_url = config.ca_url.as_str().trim_end_matches('/').to_owned();

        let basic_auth = if is_http {
            let user = config.username.clone().unwrap_or_else(|| "caadmin".into());
            let pass = config.password.clone().unwrap_or_else(|| "RedHat123".into());
            Some((user, pass))
        } else {
            None
        };

        Ok(Self {
            http,
            base_url,
            basic_auth,
            retry_max: config.retry_max,
            retry_delay: Duration::from_millis(config.retry_delay_ms),
        })
    }

    pub async fn health_check(&self) -> DogtagResult<bool> {
        let url = format!("{}/ca/rest/info", self.base_url);
        debug!(url = %url, "Dogtag health check");

        match self.do_get(&url).await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!(error = %e, "Dogtag health check failed");
                Ok(false)
            }
        }
    }

    pub(crate) async fn get(&self, path: &str) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.request_with_retry(|| self.do_get(&url)).await
    }

    pub(crate) async fn post_json<T: serde::Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.request_with_retry(|| self.do_post_json(&url, body))
            .await
    }

    pub(crate) async fn post_bytes(
        &self,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> DogtagResult<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let ct = content_type.to_owned();
        self.request_with_retry(|| {
            let mut req = self.http.post(&url)
                .header("Content-Type", &ct)
                .body(body.clone());
            if let Some((ref user, ref pass)) = self.basic_auth {
                req = req.basic_auth(user, Some(pass));
            }
            req.send()
        })
        .await
    }

    fn do_get(&self, url: &str) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + '_ {
        let mut req = self.http.get(url);
        if let Some((ref user, ref pass)) = self.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }
        req.send()
    }

    fn do_post_json<'a, T: serde::Serialize + ?Sized>(&'a self, url: &'a str, body: &'a T) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + 'a {
        let mut req = self.http.post(url).json(body);
        if let Some((ref user, ref pass)) = self.basic_auth {
            req = req.basic_auth(user, Some(pass));
        }
        req.send()
    }

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
                    last_error = Some(DogtagError::HttpError(e.to_string()));
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
