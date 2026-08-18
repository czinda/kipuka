use std::path::PathBuf;
use std::time::Duration;

use reqwest::Certificate;
use reqwest::Identity;
use tracing::{debug, warn};

use crate::cacerts::CaCertsResult;
use crate::error::{CliError, CliResult};
use kipuka_est::cacerts::CaCertsResponse;
use kipuka_est::content_type;

/// TLS configuration for the EST client.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// CA certificate PEM file for server verification.
    pub cacert: Option<PathBuf>,
    /// Client certificate PEM file for mTLS.
    pub client_cert: Option<PathBuf>,
    /// Client private key PEM file for mTLS.
    pub client_key: Option<PathBuf>,
    /// Skip TLS certificate verification.
    pub insecure: bool,
}

/// EST protocol client.
///
/// Wraps a [`reqwest::Client`] configured for EST operations over HTTPS
/// with optional mTLS client authentication and custom CA trust.
pub struct EstClient {
    http: reqwest::Client,
    base_url: String,
}

impl EstClient {
    /// Creates a new EST client for the given server URL.
    ///
    /// The URL should include the scheme and port (e.g., `https://est.example.com:8443`).
    /// Trailing slashes are stripped.
    pub fn new(server_url: &str, tls: &TlsConfig) -> CliResult<Self> {
        let base_url = server_url.trim_end_matches('/').to_string();

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .no_proxy();

        if tls.insecure {
            warn!("TLS certificate verification disabled — connections are NOT secure");
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref cacert_path) = tls.cacert {
            let pem = std::fs::read(cacert_path).map_err(|e| {
                CliError::Tls(format!(
                    "Failed to read CA cert {}: {e}",
                    cacert_path.display()
                ))
            })?;
            let cert = Certificate::from_pem(&pem).map_err(|e| {
                CliError::Tls(format!("Invalid CA cert {}: {e}", cacert_path.display()))
            })?;
            builder = builder.add_root_certificate(cert);
            debug!(path = %cacert_path.display(), "Added CA certificate for server verification");
        }

        if let (Some(cert_path), Some(key_path)) = (&tls.client_cert, &tls.client_key) {
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                CliError::Tls(format!(
                    "Failed to read client cert {}: {e}",
                    cert_path.display()
                ))
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| {
                CliError::Tls(format!(
                    "Failed to read client key {}: {e}",
                    key_path.display()
                ))
            })?;
            let identity = Identity::from_pkcs8_pem(&cert_pem, &key_pem)
                .map_err(|e| CliError::Tls(format!("Invalid client identity: {e}")))?;
            builder = builder.identity(identity);
            debug!(
                cert = %cert_path.display(),
                key = %key_path.display(),
                "Configured mTLS client identity"
            );
        }

        let http = builder
            .build()
            .map_err(|e| CliError::Tls(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self { http, base_url })
    }

    /// Retrieves CA certificates from the EST server (RFC 7030 §4.1).
    ///
    /// This is an unauthenticated GET request that returns the CA certificate
    /// chain as a PKCS#7 certs-only structure.
    pub async fn cacerts(&self, label: Option<&str>) -> CliResult<CaCertsResult> {
        let url = match label {
            Some(l) => format!("{}/.well-known/est/{}/cacerts", self.base_url, l),
            None => format!("{}/.well-known/est/cacerts", self.base_url),
        };

        debug!(%url, "Requesting CA certificates");

        let response = self.http.get(&url).send().await?;
        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(CliError::Server {
                status: status.as_u16(),
                body,
            });
        }

        if let Some(ct) = response.headers().get(reqwest::header::CONTENT_TYPE) {
            let ct_str = ct.to_str().unwrap_or("");
            if !content_type::validate_content_type(ct_str, content_type::PKCS7_MIME) {
                warn!(
                    content_type = ct_str,
                    "Unexpected Content-Type (expected application/pkcs7-mime)"
                );
            }
        }

        let body = response.text().await?;
        let cacerts_response = CaCertsResponse::from_base64(body.trim())?;
        cacerts_response
            .validate()
            .map_err(|e| CliError::Protocol(format!("Invalid cacerts response: {e}")))?;

        Ok(CaCertsResult::new(cacerts_response))
    }
}
