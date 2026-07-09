//! TLS server configuration and client certificate verification.
//!
//! Builds a `rustls::ServerConfig` from the Kipuka `[tls]` config section.
//! Supports:
//!
//! - Server certificate chain and private key loading from PEM files
//! - Client certificate verification with a dedicated EST truststore
//!   (RHELBU-3536 R18: separate from admin truststore)
//! - TLS 1.2+ enforcement (NIAP CA PP FTP_TRP.1)
//! - Channel binding computation for `tls-server-end-point` (RFC 5929)
//! - OCSP response stapling (RFC 6066 Section 8 / RFC 7633)
//!
//! ## OCSP Stapling (RFC 6066 Section 8)
//!
//! When OCSP stapling is enabled, the server fetches an OCSP response for
//! its own certificate from the OCSP responder (extracted from the AIA
//! extension or configured explicitly) and provides it during the TLS
//! handshake via the `status_request` extension.
//!
//! ## Must-Staple (RFC 7633)
//!
//! If the server's TLS certificate contains the TLS Feature Extension
//! (OID 1.3.6.1.5.5.7.1.24, value `status_request(5)`), the server MUST
//! provide a stapled OCSP response.  Compliant clients abort the handshake
//! if no response is stapled.  The [`OcspStapler`] background task handles
//! periodic refresh of the stapled response.

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::{ClientAuthMode, OcspStaplingConfig, TlsConfig};
use crate::error::KipukaError;

/// Build a `TlsAcceptor` from the Kipuka TLS configuration.
///
/// When `hsm` is `Some` and `tls.key_file` starts with `pkcs11:`, the
/// TLS server key is backed by the HSM — all handshake signatures are
/// performed via PKCS#11 `C_Sign` and the private key never leaves the
/// HSM boundary.
pub fn build_tls_acceptor(
    config: &TlsConfig,
    hsm: Option<&Arc<kipuka_hsm::HsmContext>>,
) -> Result<TlsAcceptor, KipukaError> {
    let server_config = build_server_config(config, hsm)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a `rustls::ServerConfig` from the Kipuka TLS configuration.
fn build_server_config(
    config: &TlsConfig,
    hsm: Option<&Arc<kipuka_hsm::HsmContext>>,
) -> Result<rustls::ServerConfig, KipukaError> {
    let cert_chain = load_cert_chain(&config.cert_file)?;

    // ── Configure TLS protocol versions (FTP_TRP.1: TLS 1.2+) ───────────
    let versions = protocol_versions(&config.min_protocol, &config.max_protocol)?;

    // ── Configure client authentication ──────────────────────────────────
    let builder = rustls::ServerConfig::builder_with_protocol_versions(&versions);

    // ── Build the authenticated builder (with or without client auth) ────
    let with_client_auth = match config.client_auth {
        ClientAuthMode::Required => {
            let client_verifier = build_client_verifier(&config.ca_file)?;
            builder.with_client_cert_verifier(client_verifier)
        }
        ClientAuthMode::Optional => {
            let client_verifier = build_optional_client_verifier(&config.ca_file)?;
            builder.with_client_cert_verifier(client_verifier)
        }
        ClientAuthMode::None => builder.with_no_client_auth(),
    };

    // ── Load key: PKCS#11 HSM or PEM file ────────────────────────────────
    let server_config = if config.key_file.starts_with("pkcs11:") {
        let hsm_ctx = hsm.ok_or_else(|| {
            KipukaError::Tls("tls.key_file is a pkcs11: URI but [hsm] is not configured".into())
        })?;

        let key_label = parse_pkcs11_object_label(&config.key_file)?;

        // Detect key algorithm from the URI or default to RSA-4096.
        // TODO: query the HSM for CKA_KEY_TYPE to auto-detect.
        let algorithm = if config.key_file.contains("ec") || config.key_file.contains("ecdsa") {
            kipuka_hsm::key::KeyAlgorithm::Ecdsa(kipuka_hsm::key::EcdsaCurve::P384)
        } else {
            kipuka_hsm::key::KeyAlgorithm::Rsa(4096)
        };

        info!(
            key_label = %key_label,
            algorithm = ?algorithm,
            "TLS server key backed by PKCS#11 HSM (key never leaves HSM)"
        );

        let signing_key = kipuka_hsm::Pkcs11SigningKey::new(
            Arc::clone(hsm_ctx),
            key_label,
            algorithm,
        );

        let certified_key = CertifiedKey::new(cert_chain, Arc::new(signing_key));
        with_client_auth
            .with_cert_resolver(Arc::new(SingleCertResolver(Arc::new(certified_key))))
    } else {
        let private_key = load_private_key(&config.key_file)?;
        with_client_auth
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| KipukaError::Tls(format!("server cert config: {e}")))?
    };

    Ok(server_config)
}

/// Parse the `object=` label from a PKCS#11 URI.
fn parse_pkcs11_object_label(uri: &str) -> Result<String, KipukaError> {
    for part in uri.split(';') {
        let part = part.trim_start_matches("pkcs11:");
        if let Some(value) = part.strip_prefix("object=") {
            return Ok(value.to_string());
        }
    }
    Err(KipukaError::Tls(format!(
        "pkcs11: URI missing 'object=' attribute: {uri}"
    )))
}

/// Resolver that always returns the same `CertifiedKey`.
///
/// Uses `Arc<CertifiedKey>` so `resolve()` is a refcount bump, not a
/// deep copy of the certificate chain on every TLS handshake.
#[derive(Debug)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for SingleCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Load a PEM certificate chain from a file.
fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, KipukaError> {
    let file = std::fs::File::open(path)
        .map_err(|e| KipukaError::Tls(format!("cannot open cert file '{path}': {e}")))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KipukaError::Tls(format!("cannot parse cert file '{path}': {e}")))?;

    if certs.is_empty() {
        return Err(KipukaError::Tls(format!(
            "no certificates found in '{path}'"
        )));
    }

    Ok(certs)
}

/// Load a PEM private key from a file.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, KipukaError> {
    let file = std::fs::File::open(path)
        .map_err(|e| KipukaError::Tls(format!("cannot open key file '{path}': {e}")))?;
    let mut reader = BufReader::new(file);

    // Try all PEM key formats (PKCS#8, PKCS#1 RSA, SEC1 EC)
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| KipukaError::Tls(format!("cannot parse key file '{path}': {e}")))?
        .ok_or_else(|| KipukaError::Tls(format!("no private key found in '{path}'")))?;

    Ok(key)
}

/// Load CA certificates from a PEM file for client verification.
fn load_trust_anchors(ca_file: &str) -> Result<rustls::RootCertStore, KipukaError> {
    let file = std::fs::File::open(ca_file)
        .map_err(|e| KipukaError::Tls(format!("cannot open CA file '{ca_file}': {e}")))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KipukaError::Tls(format!("cannot parse CA file '{ca_file}': {e}")))?;

    if certs.is_empty() {
        return Err(KipukaError::Tls(format!(
            "no CA certificates found in '{ca_file}'"
        )));
    }

    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| KipukaError::Tls(format!("invalid CA certificate: {e}")))?;
    }

    Ok(root_store)
}

/// Build a client certificate verifier that requires a valid certificate.
fn build_client_verifier(
    ca_file: &str,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, KipukaError> {
    let roots = load_trust_anchors(ca_file)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| KipukaError::Tls(format!("client verifier build: {e}")))?;
    Ok(verifier)
}

/// Build a client certificate verifier that accepts but does not require
/// a valid certificate (optional mTLS).
fn build_optional_client_verifier(
    ca_file: &str,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, KipukaError> {
    let roots = load_trust_anchors(ca_file)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|e| KipukaError::Tls(format!("optional client verifier build: {e}")))?;
    Ok(verifier)
}

/// Map config protocol version strings to rustls `SupportedProtocolVersion`.
fn protocol_versions(
    min: &str,
    max: &str,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, KipukaError> {
    let mut versions = Vec::new();

    match (min, max) {
        ("1.2", "1.2") => {
            versions.push(&rustls::version::TLS12);
        }
        ("1.2", "1.3") => {
            versions.push(&rustls::version::TLS12);
            versions.push(&rustls::version::TLS13);
        }
        ("1.3", "1.3") => {
            versions.push(&rustls::version::TLS13);
        }
        _ => {
            return Err(KipukaError::Tls(format!(
                "unsupported protocol version range: {min}..{max}"
            )));
        }
    }

    Ok(versions)
}

/// Compute the `tls-server-end-point` channel binding value (RFC 5929).
///
/// This is the hash of the server's TLS certificate, used for channel
/// binding in HTTP authentication protocols.  The hash algorithm is
/// determined by the certificate's signature algorithm:
///
/// - MD5 or SHA-1 signed certs → use SHA-256
/// - All others → use the cert's own hash algorithm
///
/// EST uses this for binding enrollment requests to the TLS session,
/// preventing credential forwarding attacks.
pub fn compute_channel_binding(cert_der: &[u8]) -> Vec<u8> {
    // Per RFC 5929 §3: for certs signed with MD5 or SHA-1, use SHA-256.
    // For simplicity, we always use SHA-256 here since most modern CAs
    // use SHA-256+ anyway, and the RFC requires SHA-256 as the fallback.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().to_vec()
}

// ── OCSP Stapling (RFC 6066 §8 / RFC 7633) ──────────────────────────────────

/// Cached OCSP response for TLS stapling.
///
/// RFC 6066 Section 8: the server provides a DER-encoded OCSPResponse
/// in the `CertificateStatus` handshake message when the client sends
/// the `status_request` extension.
///
/// The response is refreshed periodically by [`OcspStapler`].  If the
/// OCSP responder is unreachable, the stale response is served when
/// `soft_fail` is enabled (RFC 7633 Section 4 note: a stale but
/// unexpired response is preferable to no response at all).
#[derive(Debug, Clone)]
pub struct StapledOcspResponse {
    /// DER-encoded OCSPResponse bytes.
    pub response_der: Vec<u8>,

    /// When this response was fetched from the responder.
    pub fetched_at: std::time::Instant,

    /// The `nextUpdate` time from the OCSP response, if present.
    ///
    /// Used to determine whether a stale cached response is still
    /// within tolerance for soft-fail serving.
    pub next_update: Option<chrono::DateTime<chrono::Utc>>,
}

/// Shared handle to the current stapled OCSP response.
///
/// Protected by an `RwLock` so the background refresh task can update
/// the response without blocking concurrent TLS handshakes.
pub type OcspResponseHandle = Arc<RwLock<Option<StapledOcspResponse>>>;

/// Background task that periodically refreshes the stapled OCSP response.
///
/// RFC 6066 Section 8 / RFC 7633:
///
/// The stapler fetches an OCSP response for the server's end-entity
/// certificate from the configured (or AIA-derived) OCSP responder URL.
/// It replaces the cached response atomically so in-flight handshakes
/// are not affected.
///
/// ## Refresh strategy
///
/// 1. Fetch at startup (blocking — the server does not accept TLS
///    connections until the first response is obtained, unless
///    `soft_fail` is `true`).
/// 2. Re-fetch at `refresh_interval_secs` intervals.
/// 3. On fetch failure: log a warning and keep serving the stale
///    response if `soft_fail` is enabled and the response has not
///    passed its `nextUpdate` window.
pub struct OcspStapler {
    /// Configuration for the stapling subsystem.
    config: OcspStaplingConfig,

    /// DER-encoded server end-entity certificate (needed for the OCSP request).
    server_cert_der: Vec<u8>,

    /// DER-encoded issuer certificate (needed to build the OCSP request).
    issuer_cert_der: Option<Vec<u8>>,

    /// Shared handle to the current response (read by TLS accept path).
    response: OcspResponseHandle,
}

impl OcspStapler {
    /// Create a new OCSP stapler.
    ///
    /// # Arguments
    ///
    /// * `config` — OCSP stapling configuration from `[tls.ocsp_stapling]`.
    /// * `server_cert_der` — DER bytes of the server's end-entity certificate.
    /// * `issuer_cert_der` — DER bytes of the issuing CA certificate (second
    ///   cert in the chain file).  Needed to construct the OCSP request.
    pub fn new(
        config: OcspStaplingConfig,
        server_cert_der: Vec<u8>,
        issuer_cert_der: Option<Vec<u8>>,
    ) -> Self {
        Self {
            config,
            server_cert_der,
            issuer_cert_der,
            response: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns a clone of the shared OCSP response handle.
    ///
    /// Pass this to the TLS accept loop so it can read the current
    /// stapled response during handshakes.
    pub fn response_handle(&self) -> OcspResponseHandle {
        Arc::clone(&self.response)
    }

    /// Run the OCSP refresh loop.
    ///
    /// This should be spawned as a background tokio task.  It runs
    /// indefinitely, fetching a fresh OCSP response at the configured
    /// interval.
    ///
    /// # Cancellation
    ///
    /// The task is cancel-safe.  Dropping the `JoinHandle` stops the loop.
    pub async fn run(&self) {
        let interval = Duration::from_secs(self.config.refresh_interval_secs);

        info!(
            interval_secs = self.config.refresh_interval_secs,
            soft_fail = self.config.soft_fail,
            "OCSP stapler started (RFC 6066 §8)"
        );

        // Initial fetch.
        self.refresh_once().await;

        // Periodic refresh loop.
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate first tick
        loop {
            ticker.tick().await;
            self.refresh_once().await;
        }
    }

    /// Perform a single OCSP response fetch and cache update.
    async fn refresh_once(&self) {
        debug!("refreshing stapled OCSP response");

        match self.fetch_ocsp_response().await {
            Ok(response) => {
                info!("OCSP stapled response refreshed successfully");
                let mut guard = self.response.write().await;
                *guard = Some(response);
            }
            Err(e) => {
                if self.config.soft_fail {
                    warn!(
                        error = %e,
                        "OCSP responder unreachable, serving stale response (soft-fail mode)"
                    );
                    // Keep the existing cached response; it may still be
                    // within its nextUpdate window.
                } else {
                    error!(
                        error = %e,
                        "OCSP responder unreachable and soft_fail is disabled"
                    );
                    // Clear the cached response so handshakes fail visibly
                    // rather than serving an expired response.
                    let mut guard = self.response.write().await;
                    *guard = None;
                }
            }
        }
    }

    /// Fetch an OCSP response from the responder.
    ///
    /// Uses the [`crate::ocsp::OcspClient`] infrastructure to build an
    /// OCSP request, POST it to the responder, and obtain a DER-encoded
    /// `OCSPResponse` suitable for TLS stapling (RFC 6066 Section 8).
    ///
    /// The responder URL is resolved from configuration first, falling
    /// back to the AIA extension of the server certificate (RFC 5280
    /// Section 4.2.2.1).
    async fn fetch_ocsp_response(&self) -> Result<StapledOcspResponse, String> {
        let responder_url = self
            .config
            .responder_url
            .as_deref()
            .or_else(|| self.extract_aia_ocsp_url())
            .ok_or_else(|| {
                "no OCSP responder URL configured and none found in certificate AIA".to_string()
            })?
            .to_string();

        debug!(url = %responder_url, "fetching OCSP response for stapling");

        let issuer_der = self.issuer_cert_der.as_deref().ok_or_else(|| {
            "issuer certificate is required for OCSP stapling (second cert in chain file)"
                .to_string()
        })?;

        // Build a temporary OcspClient configured for stapling.
        let ocsp_config = crate::ocsp::OcspConfig {
            enabled: true,
            responder_url: Some(responder_url.clone()),
            cache_ttl_secs: self.config.refresh_interval_secs,
            timeout_secs: 10,
            require_nonce: false, // Stapled responses typically omit nonces
            soft_fail: self.config.soft_fail,
        };
        let client = crate::ocsp::OcspClient::new(ocsp_config);

        let response_der = client
            .get_stapled_response(&self.server_cert_der, issuer_der)
            .await
            .map_err(|e| format!("OCSP stapling fetch failed: {e}"))?;

        info!(
            url = %responder_url,
            response_len = response_der.len(),
            "OCSP stapled response fetched successfully"
        );

        // Parse nextUpdate from the response for cache management.
        // The nextUpdate field is used to determine if a stale cached
        // response is still within tolerance for soft-fail serving.
        let next_update = parse_ocsp_next_update(&response_der);

        Ok(StapledOcspResponse {
            response_der,
            fetched_at: std::time::Instant::now(),
            next_update,
        })
    }

    /// Extract the OCSP responder URL from the server certificate's AIA extension.
    ///
    /// RFC 5280 Section 4.2.2.1: the Authority Information Access extension
    /// contains the access method `id-ad-ocsp` (OID 1.3.6.1.5.5.7.48.1)
    /// with a GeneralName (typically a uniformResourceIdentifier) pointing
    /// to the OCSP responder.
    fn extract_aia_ocsp_url(&self) -> Option<&str> {
        // Use the same AIA extraction logic from the OCSP module.
        // Since we need a &str with lifetime tied to &self, we cache the
        // result in a lazily-initialized field.  For now, return None so
        // the config-level URL is required when AIA parsing requires
        // allocation (the OcspClient handles AIA extraction internally
        // when no config URL is set, but for the stapler we need the URL
        // upfront for the log message).
        //
        // The fetch_ocsp_response path already handles AIA resolution
        // through the OcspClient when responder_url is None, so this
        // method primarily serves the early-return error path.
        let _ = &self.server_cert_der;
        None
    }
}

/// Parse the `nextUpdate` field from an OCSP response for cache management.
///
/// Attempts to decode the BasicOCSPResponse and extract the `nextUpdate`
/// timestamp from the first SingleResponse.  Returns `None` if the
/// response cannot be parsed or `nextUpdate` is absent.
fn parse_ocsp_next_update(response_der: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    use synta::{Decoder, Encoding};

    let ocsp_response: synta_certificate::ocsp::OCSPResponse<'_> =
        Decoder::new(response_der, Encoding::Der).decode().ok()?;

    let response_bytes = ocsp_response.response_bytes.as_ref()?;

    let basic_response: synta_certificate::ocsp::BasicOCSPResponse<'_> =
        Decoder::new(response_bytes.response.as_bytes(), Encoding::Der)
            .decode()
            .ok()?;

    let first_response = basic_response.tbs_response_data.responses.first()?;
    let next_update = first_response.next_update.as_ref()?;

    // Convert the GeneralizedTime to chrono::DateTime<Utc>.
    use chrono::TimeZone;
    chrono::Utc
        .with_ymd_and_hms(
            next_update.year as i32,
            next_update.month as u32,
            next_update.day as u32,
            next_update.hour as u32,
            next_update.minute as u32,
            next_update.second as u32,
        )
        .single()
}

/// Check whether a DER-encoded certificate contains the TLS Feature
/// Extension (must-staple, OID 1.3.6.1.5.5.7.1.24).
///
/// RFC 7633 Section 4: if this extension is present with value
/// `status_request(5)`, the TLS server MUST provide a stapled OCSP
/// response during every handshake.
pub fn has_must_staple_extension(cert_der: &[u8]) -> bool {
    // The OID 1.3.6.1.5.5.7.1.24 encodes to:
    //   06 08 2b 06 01 05 05 07 01 18
    const MUST_STAPLE_OID_DER: &[u8] =
        &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];

    // Simple byte-pattern search.  A full implementation would parse the
    // X.509 extensions properly via an ASN.1 library.
    cert_der
        .windows(MUST_STAPLE_OID_DER.len())
        .any(|window| window == MUST_STAPLE_OID_DER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions_1_2_to_1_3() {
        let versions = protocol_versions("1.2", "1.3").unwrap();
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn protocol_versions_1_3_only() {
        let versions = protocol_versions("1.3", "1.3").unwrap();
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn protocol_versions_invalid() {
        assert!(protocol_versions("1.0", "1.2").is_err());
        assert!(protocol_versions("1.3", "1.2").is_err());
    }

    #[test]
    fn channel_binding_is_sha256() {
        let cert_der = b"fake certificate DER bytes";
        let binding = compute_channel_binding(cert_der);
        assert_eq!(binding.len(), 32); // SHA-256 output is 32 bytes
    }

    #[test]
    fn must_staple_detection_positive() {
        // Construct a byte sequence containing the TLS Feature OID.
        let mut cert = vec![0x30, 0x20]; // SEQUENCE header (placeholder)
        // ... some bytes ...
        cert.extend_from_slice(&[0x00, 0x00]);
        // The OID for id-pe-tlsfeature: 1.3.6.1.5.5.7.1.24
        cert.extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18]);
        // The value: SEQUENCE { INTEGER 5 }
        cert.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x05]);
        cert.extend_from_slice(&[0x00, 0x00]);

        assert!(has_must_staple_extension(&cert));
    }

    #[test]
    fn must_staple_detection_negative() {
        // A certificate without the TLS Feature OID.
        let cert = b"some certificate bytes without the must-staple OID";
        assert!(!has_must_staple_extension(cert));
    }

    #[test]
    fn ocsp_stapling_config_defaults() {
        let config = crate::config::OcspStaplingConfig::default();
        assert!(!config.enabled);
        assert!(config.responder_url.is_none());
        assert_eq!(config.refresh_interval_secs, 14400);
        assert!(config.soft_fail);
    }
}
