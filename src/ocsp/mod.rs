//! OCSP client for certificate revocation checking per RFC 6960.
//!
//! Provides an [`OcspClient`] that sends OCSP requests to a configured
//! responder URL, caches responses, and integrates with the mTLS
//! authentication layer (RHELBU-3536 R21).
//!
//! # Protocol overview (RFC 6960)
//!
//! An OCSP request identifies the certificate to check via a `CertID`
//! structure (§4.1.1) containing:
//! - Hash algorithm
//! - Hash of issuer's distinguished name
//! - Hash of issuer's public key
//! - Certificate serial number
//!
//! The responder returns a signed `BasicOCSPResponse` (§4.2.1) with a
//! status of `good`, `revoked`, or `unknown` for each queried certificate.
//!
//! # Nonce support
//!
//! Per RFC 6960 §4.4.1, the client MAY include a nonce extension in the
//! request to prevent replay attacks. When [`OcspConfig::require_nonce`]
//! is `true`, the client rejects responses that do not echo the nonce.
//!
//! # Caching
//!
//! Responses are cached in a concurrent `DashMap` keyed by `CertId`.
//! The cache TTL is configurable via [`OcspConfig::cache_ttl_secs`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};

/// OCSP-specific errors.
#[derive(Debug, Error)]
pub enum OcspError {
    /// Failed to build the OCSP request.
    #[error("OCSP request build error: {0}")]
    RequestBuild(String),

    /// HTTP transport error when contacting the responder.
    #[error("OCSP transport error: {0}")]
    Transport(String),

    /// The responder returned a non-successful OCSP response status
    /// (RFC 6960 §4.2.1: malformedRequest, internalError, tryLater, etc.).
    #[error("OCSP response status: {0}")]
    ResponseStatus(String),

    /// Signature verification of the OCSP response failed.
    #[error("OCSP response signature verification failed: {0}")]
    SignatureVerification(String),

    /// The response did not contain a status for the queried certificate.
    #[error("OCSP response missing status for queried certificate")]
    MissingCertStatus,

    /// Nonce mismatch between request and response.
    #[error("OCSP nonce mismatch: replay attack possible")]
    NonceMismatch,

    /// Response parsing error.
    #[error("OCSP response parse error: {0}")]
    Parse(String),

    /// Timeout contacting the OCSP responder.
    #[error("OCSP responder timeout after {0}s")]
    Timeout(u64),
}

/// Result type for OCSP operations.
pub type OcspResult<T> = Result<T, OcspError>;

/// Certificate revocation status per RFC 6960 §4.2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspStatus {
    /// The certificate is not revoked (RFC 6960 §4.2.1, CertStatus `good`).
    Good,

    /// The certificate has been revoked (RFC 6960 §4.2.1, CertStatus `revoked`).
    ///
    /// Includes the CRL reason code (RFC 5280 §5.3.1) and revocation time
    /// as an ISO 8601 string.
    Revoked {
        /// CRL reason code per RFC 5280 §5.3.1 (e.g., "keyCompromise").
        reason: String,
        /// Revocation time as ISO 8601 string.
        revocation_time: String,
    },

    /// The responder does not know the certificate (RFC 6960 §4.2.1,
    /// CertStatus `unknown`).
    Unknown,
}

/// Identifier for a certificate in an OCSP request.
///
/// Per RFC 6960 §4.1.1:
/// ```text
/// CertID ::= SEQUENCE {
///     hashAlgorithm       AlgorithmIdentifier,
///     issuerNameHash      OCTET STRING,
///     issuerKeyHash       OCTET STRING,
///     serialNumber        CertificateSerialNumber
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertId {
    /// Hash algorithm OID (e.g., SHA-256 = "2.16.840.1.101.3.4.2.1").
    pub hash_algorithm: String,
    /// SHA-256 hash of the issuer's distinguished name DER encoding.
    pub issuer_name_hash: Vec<u8>,
    /// SHA-256 hash of the issuer's public key BIT STRING value.
    pub issuer_key_hash: Vec<u8>,
    /// Certificate serial number.
    pub serial_number: Vec<u8>,
}

/// Cached OCSP response with expiry.
#[derive(Debug, Clone)]
struct CachedOcspResponse {
    /// The OCSP status from the response.
    status: OcspStatus,
    /// When this cache entry was stored.
    cached_at: Instant,
    /// TTL for this entry.
    ttl: Duration,
}

impl CachedOcspResponse {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// OCSP configuration.
///
/// Loaded from the `[ocsp]` section of the Kipuka configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OcspConfig {
    /// Whether OCSP checking is enabled. Default: `false`.
    pub enabled: bool,

    /// Override OCSP responder URL. When `None`, the AIA extension
    /// from the certificate is used (RFC 5280 §4.2.2.1).
    pub responder_url: Option<String>,

    /// Cache TTL in seconds. Default: 300 (5 minutes).
    pub cache_ttl_secs: u64,

    /// HTTP timeout in seconds for OCSP requests. Default: 10.
    pub timeout_secs: u64,

    /// Whether to require a nonce in responses (RFC 6960 §4.4.1).
    /// Default: `true`.
    pub require_nonce: bool,

    /// Soft-fail mode: if `true`, accept the certificate when the OCSP
    /// responder is unreachable. If `false`, reject. Default: `false`.
    pub soft_fail: bool,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            responder_url: None,
            cache_ttl_secs: 300,
            timeout_secs: 10,
            require_nonce: true,
            soft_fail: false,
        }
    }
}

/// OCSP client for checking certificate revocation status.
///
/// Thread-safe: all methods take `&self` and the cache uses `DashMap`
/// for lock-free concurrent access.
pub struct OcspClient {
    config: OcspConfig,
    /// Response cache keyed by CertId.
    cache: Arc<DashMap<CertId, CachedOcspResponse>>,
}

impl OcspClient {
    /// Creates a new OCSP client with the given configuration.
    pub fn new(config: OcspConfig) -> Self {
        Self {
            config,
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Check the revocation status of a certificate.
    ///
    /// Per RFC 6960 §4.1, builds an OCSPRequest with a CertID computed
    /// from the certificate and its issuer, sends it to the responder
    /// via HTTP POST with Content-Type `application/ocsp-request`, and
    /// parses the response.
    ///
    /// # Arguments
    ///
    /// * `cert_der` - DER-encoded certificate to check
    /// * `issuer_der` - DER-encoded issuer certificate (needed for CertID)
    ///
    /// # Errors
    ///
    /// Returns `OcspError` if the request fails, the response is invalid,
    /// or the nonce does not match (when required).
    pub async fn check_certificate_status(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
    ) -> OcspResult<OcspStatus> {
        if !self.config.enabled {
            return Ok(OcspStatus::Good);
        }

        // Build CertID from certificate and issuer.
        let cert_id = self.build_cert_id(cert_der, issuer_der)?;

        // Check cache first.
        if let Some(cached) = self.cache.get(&cert_id)
            && !cached.is_expired() {
                debug!("OCSP cache hit for certificate");
                return Ok(cached.status.clone());
            }

        // Determine responder URL: config override or AIA extension.
        let responder_url = self.resolve_responder_url(cert_der)?;

        // Build OCSP request DER.
        let request_der = self.build_ocsp_request(&cert_id)?;

        // Send request via HTTP POST.
        let response_der = self.send_ocsp_request(&responder_url, &request_der).await?;

        // Parse response and extract status.
        let status = self.parse_ocsp_response(&response_der, &cert_id)?;

        // Cache the result.
        self.cache.insert(
            cert_id,
            CachedOcspResponse {
                status: status.clone(),
                cached_at: Instant::now(),
                ttl: Duration::from_secs(self.config.cache_ttl_secs),
            },
        );

        Ok(status)
    }

    /// Returns a stapled OCSP response for the EST server's own certificate.
    ///
    /// OCSP stapling (RFC 6066 §8) allows the server to include a pre-fetched
    /// OCSP response in the TLS handshake, avoiding the client needing to
    /// contact the OCSP responder separately.
    ///
    /// # Arguments
    ///
    /// * `server_cert_der` - DER-encoded server certificate
    /// * `issuer_der` - DER-encoded issuer certificate
    ///
    /// # Returns
    ///
    /// The DER-encoded OCSP response suitable for TLS stapling, or an error
    /// if the response cannot be obtained.
    pub async fn get_stapled_response(
        &self,
        server_cert_der: &[u8],
        issuer_der: &[u8],
    ) -> OcspResult<Vec<u8>> {
        if !self.config.enabled {
            return Err(OcspError::Transport("OCSP not enabled".to_string()));
        }

        let cert_id = self.build_cert_id(server_cert_der, issuer_der)?;
        let responder_url = self.resolve_responder_url(server_cert_der)?;
        let request_der = self.build_ocsp_request(&cert_id)?;

        self.send_ocsp_request(&responder_url, &request_der).await
    }

    /// Evict expired entries from the response cache.
    pub fn evict_expired(&self) {
        self.cache.retain(|_, v| !v.is_expired());
    }

    /// Returns the number of cached responses.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Build a CertID from a certificate and its issuer.
    ///
    /// Per RFC 6960 §4.1.1, the CertID uses SHA-256 hashes of the issuer
    /// name and key, plus the certificate serial number.
    fn build_cert_id(&self, cert_der: &[u8], issuer_der: &[u8]) -> OcspResult<CertId> {
        use sha2::{Digest, Sha256};

        if cert_der.is_empty() {
            return Err(OcspError::RequestBuild("empty certificate DER".to_string()));
        }
        if issuer_der.is_empty() {
            return Err(OcspError::RequestBuild(
                "empty issuer certificate DER".to_string(),
            ));
        }

        // Placeholder hashes — real implementation extracts the issuer Name
        // and public key BIT STRING from the DER-encoded certificates using
        // the synta_certificate parser, then hashes those specific fields.
        let issuer_name_hash = Sha256::digest(issuer_der).to_vec();
        let issuer_key_hash = Sha256::digest(issuer_der).to_vec();

        // Placeholder serial — real implementation extracts from TBSCertificate.
        let serial_number = cert_der.get(..8).unwrap_or(cert_der).to_vec();

        Ok(CertId {
            hash_algorithm: "2.16.840.1.101.3.4.2.1".to_string(), // SHA-256
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }

    /// Resolve the OCSP responder URL from config or the certificate AIA extension.
    fn resolve_responder_url(&self, _cert_der: &[u8]) -> OcspResult<String> {
        if let Some(ref url) = self.config.responder_url {
            return Ok(url.clone());
        }
        // TODO: Extract from Authority Information Access (AIA) extension
        // (OID 1.3.6.1.5.5.7.1.1) in the certificate. The id-ad-ocsp
        // access method (OID 1.3.6.1.5.5.7.48.1) provides the URL.
        Err(OcspError::RequestBuild(
            "no OCSP responder URL configured and AIA extraction not yet implemented".to_string(),
        ))
    }

    /// Build an OCSPRequest DER from a CertID.
    ///
    /// Per RFC 6960 §4.1:
    /// ```text
    /// OCSPRequest ::= SEQUENCE {
    ///     tbsRequest      TBSRequest,
    ///     optionalSignature [0] EXPLICIT Signature OPTIONAL
    /// }
    /// TBSRequest ::= SEQUENCE {
    ///     version           [0] EXPLICIT Version DEFAULT v1,
    ///     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
    ///     requestList           SEQUENCE OF Request,
    ///     requestExtensions [2] EXPLICIT Extensions OPTIONAL
    /// }
    /// ```
    fn build_ocsp_request(&self, _cert_id: &CertId) -> OcspResult<Vec<u8>> {
        // Placeholder — real implementation constructs the ASN.1 DER
        // using the synta crate. The request includes:
        // 1. A single Request with the CertID
        // 2. An optional nonce extension (OID 1.3.6.1.5.5.7.48.1.2)
        //    when require_nonce is true
        Ok(vec![0x30, 0x00]) // minimal SEQUENCE placeholder
    }

    /// Send an OCSP request via HTTP POST.
    ///
    /// Per RFC 6960 §A.1, the request is sent as:
    /// - Method: POST
    /// - Content-Type: application/ocsp-request
    /// - Accept: application/ocsp-response
    async fn send_ocsp_request(
        &self,
        _responder_url: &str,
        _request_der: &[u8],
    ) -> OcspResult<Vec<u8>> {
        // Placeholder — real implementation uses reqwest or hyper to POST
        // the DER-encoded OCSP request to the responder URL.
        //
        // The timeout is set from self.config.timeout_secs.
        warn!("OCSP HTTP transport not yet implemented");
        Err(OcspError::Transport(
            "OCSP HTTP transport not yet implemented".to_string(),
        ))
    }

    /// Parse an OCSP response DER and extract the certificate status.
    ///
    /// Per RFC 6960 §4.2:
    /// ```text
    /// OCSPResponse ::= SEQUENCE {
    ///     responseStatus    OCSPResponseStatus,
    ///     responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
    /// }
    /// ```
    fn parse_ocsp_response(
        &self,
        _response_der: &[u8],
        _cert_id: &CertId,
    ) -> OcspResult<OcspStatus> {
        // Placeholder — real implementation:
        // 1. Parse OCSPResponseStatus (successful=0, malformedRequest=1, etc.)
        // 2. Parse BasicOCSPResponse from responseBytes
        // 3. Verify responder signature
        // 4. Check nonce if require_nonce is true
        // 5. Find the SingleResponse matching our CertID
        // 6. Extract certStatus (good/revoked/unknown)
        Err(OcspError::Parse(
            "OCSP response parsing not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_config_defaults() {
        let config = OcspConfig::default();
        assert!(!config.enabled);
        assert!(config.responder_url.is_none());
        assert_eq!(config.cache_ttl_secs, 300);
        assert_eq!(config.timeout_secs, 10);
        assert!(config.require_nonce);
        assert!(!config.soft_fail);
    }

    #[test]
    fn test_ocsp_status_variants() {
        let good = OcspStatus::Good;
        assert_eq!(good, OcspStatus::Good);

        let revoked = OcspStatus::Revoked {
            reason: "keyCompromise".to_string(),
            revocation_time: "2026-01-15T10:00:00Z".to_string(),
        };
        assert!(matches!(revoked, OcspStatus::Revoked { .. }));

        let unknown = OcspStatus::Unknown;
        assert_eq!(unknown, OcspStatus::Unknown);
    }

    #[test]
    fn test_cert_id_equality() {
        let id1 = CertId {
            hash_algorithm: "2.16.840.1.101.3.4.2.1".to_string(),
            issuer_name_hash: vec![0x01, 0x02],
            issuer_key_hash: vec![0x03, 0x04],
            serial_number: vec![0x05],
        };
        let id2 = id1.clone();
        assert_eq!(id1, id2);
    }

    #[tokio::test]
    async fn test_ocsp_disabled_returns_good() {
        let config = OcspConfig::default(); // enabled = false
        let client = OcspClient::new(config);
        let status = client
            .check_certificate_status(&[0x30, 0x00], &[0x30, 0x00])
            .await
            .unwrap();
        assert_eq!(status, OcspStatus::Good);
    }

    #[test]
    fn test_build_cert_id_empty_cert() {
        let config = OcspConfig::default();
        let client = OcspClient::new(config);
        let result = client.build_cert_id(&[], &[0x30, 0x00]);
        assert!(matches!(result, Err(OcspError::RequestBuild(_))));
    }

    #[test]
    fn test_build_cert_id_empty_issuer() {
        let config = OcspConfig::default();
        let client = OcspClient::new(config);
        let result = client.build_cert_id(&[0x30, 0x00], &[]);
        assert!(matches!(result, Err(OcspError::RequestBuild(_))));
    }

    #[test]
    fn test_resolve_responder_url_from_config() {
        let config = OcspConfig {
            responder_url: Some("http://ocsp.example.com".to_string()),
            ..Default::default()
        };
        let client = OcspClient::new(config);
        let url = client.resolve_responder_url(&[0x30, 0x00]).unwrap();
        assert_eq!(url, "http://ocsp.example.com");
    }

    #[test]
    fn test_resolve_responder_url_no_config() {
        let config = OcspConfig::default();
        let client = OcspClient::new(config);
        let result = client.resolve_responder_url(&[0x30, 0x00]);
        assert!(matches!(result, Err(OcspError::RequestBuild(_))));
    }

    #[test]
    fn test_cache_operations() {
        let config = OcspConfig::default();
        let client = OcspClient::new(config);
        assert_eq!(client.cache_size(), 0);

        // Manually insert a cache entry
        let cert_id = CertId {
            hash_algorithm: "2.16.840.1.101.3.4.2.1".to_string(),
            issuer_name_hash: vec![0x01],
            issuer_key_hash: vec![0x02],
            serial_number: vec![0x03],
        };
        client.cache.insert(
            cert_id,
            CachedOcspResponse {
                status: OcspStatus::Good,
                cached_at: Instant::now(),
                ttl: Duration::from_secs(300),
            },
        );
        assert_eq!(client.cache_size(), 1);

        client.evict_expired();
        assert_eq!(client.cache_size(), 1); // not expired yet
    }
}
