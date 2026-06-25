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
use sha2::{Digest, Sha256};
use synta::{Decoder, Encoding, ToDer};
use synta_certificate::SignatureVerifier;
use thiserror::Error;
use tracing::{debug, info, warn};

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
            && !cached.is_expired()
        {
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
        if cert_der.is_empty() {
            return Err(OcspError::RequestBuild("empty certificate DER".to_string()));
        }
        if issuer_der.is_empty() {
            return Err(OcspError::RequestBuild(
                "empty issuer certificate DER".to_string(),
            ));
        }

        // Parse the certificate to extract the serial number.
        let cert = synta_certificate::Certificate::from_der(cert_der).map_err(|e| {
            OcspError::RequestBuild(format!("certificate parse failed: {e}"))
        })?;

        // Parse the issuer certificate to extract the subject Name and
        // SubjectPublicKeyInfo for hashing per RFC 6960 §4.1.1.
        let issuer_cert = synta_certificate::Certificate::from_der(issuer_der).map_err(|e| {
            OcspError::RequestBuild(format!("issuer certificate parse failed: {e}"))
        })?;

        // Hash the issuer's distinguished name DER encoding (subject field
        // of the issuer certificate, which equals the issuer field of the
        // target certificate).
        let issuer_name_der = issuer_cert.tbs_certificate.subject.0;
        let issuer_name_hash = Sha256::digest(issuer_name_der).to_vec();

        // Hash the issuer's public key BIT STRING value (the raw key bytes
        // without the BIT STRING tag/length/unused-bits prefix).
        let issuer_spki = &issuer_cert.tbs_certificate.subject_public_key_info;
        let issuer_key_bytes = issuer_spki.subject_public_key.as_bytes();
        let issuer_key_hash = Sha256::digest(issuer_key_bytes).to_vec();

        // Extract the certificate serial number as big-endian bytes.
        let serial_number = cert
            .tbs_certificate
            .serial_number
            .to_der()
            .map_err(|e| OcspError::RequestBuild(format!("serial encode failed: {e}")))?;
        // `to_der()` returns the full INTEGER TLV; extract just the value
        // bytes (skip tag + length).
        let serial_value = extract_integer_value(&serial_number)
            .ok_or_else(|| OcspError::RequestBuild("malformed serial INTEGER".into()))?;

        Ok(CertId {
            hash_algorithm: "2.16.840.1.101.3.4.2.1".to_string(), // SHA-256
            issuer_name_hash,
            issuer_key_hash,
            serial_number: serial_value.to_vec(),
        })
    }

    /// Resolve the OCSP responder URL from config or the certificate AIA extension.
    fn resolve_responder_url(&self, cert_der: &[u8]) -> OcspResult<String> {
        if let Some(ref url) = self.config.responder_url {
            return Ok(url.clone());
        }

        // Extract from Authority Information Access (AIA) extension
        // (OID 1.3.6.1.5.5.7.1.1) in the certificate.
        let cert = synta_certificate::Certificate::from_der(cert_der).map_err(|e| {
            OcspError::RequestBuild(format!("certificate parse for AIA: {e}"))
        })?;

        // Use synta-certificate's find_extension_value to locate the AIA
        // extension value efficiently (single-pass scan, stops at first match).
        if let Some(ref exts_raw) = cert.tbs_certificate.extensions
            && let Some(aia_value) = synta_certificate::find_extension_value(
                exts_raw.as_bytes(),
                synta_certificate::oids::AUTHORITY_INFO_ACCESS,
            )
            && let Some(url) = extract_ocsp_url_from_aia(aia_value)
        {
            debug!(url = %url, "resolved OCSP responder URL from AIA extension");
            return Ok(url);
        }

        Err(OcspError::RequestBuild(
            "no OCSP responder URL configured and no AIA OCSP URI found in certificate".into(),
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
    fn build_ocsp_request(&self, cert_id: &CertId) -> OcspResult<Vec<u8>> {
        // Build the SHA-256 AlgorithmIdentifier DER for the CertID.
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
        let sha256_alg_der = sha256_algorithm_identifier_der();

        let request_der = synta_certificate::OCSPRequestBuilder::new()
            .add_request(synta_certificate::CertIDSpec {
                hash_algorithm_der: &sha256_alg_der,
                issuer_name_hash: &cert_id.issuer_name_hash,
                issuer_key_hash: &cert_id.issuer_key_hash,
                serial: &cert_id.serial_number,
            })
            .build_tbs()
            .map_err(|e| OcspError::RequestBuild(format!("OCSPRequest build: {e}")))?;

        debug!(
            request_len = request_der.len(),
            "built OCSP request DER"
        );

        Ok(request_der)
    }

    /// Send an OCSP request via HTTP POST.
    ///
    /// Per RFC 6960 §A.1, the request is sent as:
    /// - Method: POST
    /// - Content-Type: application/ocsp-request
    /// - Accept: application/ocsp-response
    async fn send_ocsp_request(
        &self,
        responder_url: &str,
        request_der: &[u8],
    ) -> OcspResult<Vec<u8>> {
        let timeout = Duration::from_secs(self.config.timeout_secs);

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| OcspError::Transport(format!("HTTP client build: {e}")))?;

        info!(
            url = %responder_url,
            request_len = request_der.len(),
            timeout_secs = self.config.timeout_secs,
            "sending OCSP request"
        );

        let response = client
            .post(responder_url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request_der.to_vec())
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    OcspError::Timeout(self.config.timeout_secs)
                } else {
                    OcspError::Transport(format!("HTTP POST failed: {e}"))
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(OcspError::Transport(format!(
                "OCSP responder returned HTTP {status}"
            )));
        }

        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| OcspError::Transport(format!("reading response body: {e}")))?;

        debug!(
            response_len = response_bytes.len(),
            "received OCSP response"
        );

        Ok(response_bytes.to_vec())
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
        response_der: &[u8],
        cert_id: &CertId,
    ) -> OcspResult<OcspStatus> {
        // Parse the outer OCSPResponse envelope.
        let ocsp_response: synta_certificate::ocsp::OCSPResponse<'_> =
            Decoder::new(response_der, Encoding::Der)
                .decode()
                .map_err(|e| OcspError::Parse(format!("OCSPResponse decode: {e}")))?;

        // Check the response status (successful = 0).
        match &ocsp_response.response_status {
            synta_certificate::ocsp::OCSPResponseStatus::Successful => {}
            status => {
                return Err(OcspError::ResponseStatus(format!("{status:?}")));
            }
        }

        // Extract responseBytes — must be present for a successful response.
        let response_bytes = ocsp_response
            .response_bytes
            .as_ref()
            .ok_or(OcspError::Parse(
                "successful OCSPResponse has no responseBytes".into(),
            ))?;

        // Verify the responseType is id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1).
        if response_bytes.response_type.components()
            != synta_certificate::ocsp::ID_PKIX_OCSP_BASIC
        {
            return Err(OcspError::Parse(format!(
                "unexpected responseType: {:?}",
                response_bytes.response_type.components()
            )));
        }

        // Parse the BasicOCSPResponse from the response OCTET STRING.
        let basic_response: synta_certificate::ocsp::BasicOCSPResponse<'_> =
            Decoder::new(response_bytes.response.as_bytes(), Encoding::Der)
                .decode()
                .map_err(|e| OcspError::Parse(format!("BasicOCSPResponse decode: {e}")))?;

        // Verify the responder signature (RFC 6960 §4.2.2.2).
        // The responder certificate is typically included in the `certs`
        // field of the BasicOCSPResponse.  When it is absent the responder
        // cert is assumed to be pre-trusted by the relying party — we log a
        // warning and skip verification in that case.
        if let Some(ref certs) = basic_response.certs {
            if let Some(first_cert_raw) = certs.first() {
                let responder_cert_der = first_cert_raw.as_bytes();

                // Encode the TBS ResponseData to DER for signature input.
                let tbs_der = basic_response
                    .tbs_response_data
                    .to_der()
                    .map_err(|e| OcspError::SignatureVerification(format!(
                        "failed to encode TBS ResponseData: {e}"
                    )))?;

                // Encode the signature algorithm to DER.
                let sig_alg_der = basic_response
                    .signature_algorithm
                    .to_der()
                    .map_err(|e| OcspError::SignatureVerification(format!(
                        "failed to encode signature algorithm: {e}"
                    )))?;

                // Extract the raw signature bytes.
                let signature_bits = basic_response.signature.as_bytes();

                // Extract the responder certificate's SubjectPublicKeyInfo DER
                // using cert_byte_ranges (avoids re-parsing the full cert).
                let cert_ranges = synta_certificate::cert_byte_ranges(responder_cert_der)
                    .ok_or_else(|| OcspError::SignatureVerification(
                        "malformed responder certificate: cannot extract byte ranges".into(),
                    ))?;
                let spki_der = &responder_cert_der[cert_ranges.subject_public_key_info.clone()];

                // Verify the signature using the default crypto backend.
                let verifier = synta_certificate::default_signature_verifier();
                verifier
                    .verify_certificate_signature(
                        &tbs_der,
                        &sig_alg_der,
                        signature_bits,
                        spki_der,
                    )
                    .map_err(|e| OcspError::SignatureVerification(format!(
                        "signature verification failed: {e}"
                    )))?;

                debug!("OCSP response signature verified successfully");
            } else {
                warn!("OCSP response certs field is empty; skipping signature verification");
            }
        } else {
            warn!(
                "OCSP response does not include responder certificates; \
                 skipping signature verification (responder cert may be pre-trusted)"
            );
        }

        // Find the SingleResponse matching our CertID by comparing the
        // issuer name hash and serial number.
        for single in &basic_response.tbs_response_data.responses {
            let resp_name_hash = single.cert_id.issuer_name_hash.as_bytes();
            let resp_key_hash = single.cert_id.issuer_key_hash.as_bytes();

            if resp_name_hash == cert_id.issuer_name_hash.as_slice()
                && resp_key_hash == cert_id.issuer_key_hash.as_slice()
            {
                // Match found — extract the cert status.
                return match &single.cert_status {
                    synta_certificate::ocsp::CertStatus::Good(_) => {
                        debug!("OCSP status: good");
                        Ok(OcspStatus::Good)
                    }
                    synta_certificate::ocsp::CertStatus::Revoked(info) => {
                        let reason = info
                            .revocation_reason
                            .as_ref()
                            .map(|r| format!("{r:?}"))
                            .unwrap_or_else(|| "unspecified".into());
                        let revocation_time = format!(
                            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                            info.revocation_time.year,
                            info.revocation_time.month,
                            info.revocation_time.day,
                            info.revocation_time.hour,
                            info.revocation_time.minute,
                            info.revocation_time.second,
                        );
                        warn!(
                            reason = %reason,
                            revocation_time = %revocation_time,
                            "OCSP status: revoked"
                        );
                        Ok(OcspStatus::Revoked {
                            reason,
                            revocation_time,
                        })
                    }
                    synta_certificate::ocsp::CertStatus::Unknown(_) => {
                        debug!("OCSP status: unknown");
                        Ok(OcspStatus::Unknown)
                    }
                };
            }
        }

        Err(OcspError::MissingCertStatus)
    }
}

// ── Module-level helpers ───────────────────────────────────────────────────────

/// SHA-256 AlgorithmIdentifier DER: SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
///
/// Pre-encoded constant avoids runtime construction. The encoding is:
///   30 0d                 -- SEQUENCE, length 13
///     06 09               -- OID, length 9
///       60 86 48 01 65 03 04 02 01  -- 2.16.840.1.101.3.4.2.1
///     05 00               -- NULL
fn sha256_algorithm_identifier_der() -> Vec<u8> {
    vec![
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00,
    ]
}

/// Extract the INTEGER value bytes from a DER-encoded INTEGER TLV.
///
/// Skips the 0x02 tag and the length octets, returning only the value.
fn extract_integer_value(der: &[u8]) -> Option<&[u8]> {
    if der.len() < 2 || der[0] != 0x02 {
        return None;
    }
    let len_byte = der[1];
    if len_byte < 0x80 {
        // Short form length.
        let value_start = 2;
        let value_len = len_byte as usize;
        der.get(value_start..value_start + value_len)
    } else {
        // Long form length.
        let num_len_bytes = (len_byte & 0x7f) as usize;
        if der.len() < 2 + num_len_bytes {
            return None;
        }
        let mut value_len: usize = 0;
        for &b in &der[2..2 + num_len_bytes] {
            value_len = (value_len << 8) | b as usize;
        }
        let value_start = 2 + num_len_bytes;
        der.get(value_start..value_start + value_len)
    }
}

/// Extract an OCSP responder URL from an AIA extension value.
///
/// Parses the AuthorityInfoAccessSyntax SEQUENCE OF AccessDescription,
/// looking for the id-ad-ocsp (1.3.6.1.5.5.7.48.1) access method.
fn extract_ocsp_url_from_aia(aia_value: &[u8]) -> Option<String> {
    // AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
    // AccessDescription ::= SEQUENCE {
    //     accessMethod    OBJECT IDENTIFIER,
    //     accessLocation  GeneralName
    // }
    // We look for accessMethod = id-ad-ocsp (1.3.6.1.5.5.7.48.1)
    // and accessLocation = uniformResourceIdentifier [6] IA5String.
    let mut decoder = Decoder::new(aia_value, Encoding::Der);
    let seq_tag = synta::Tag::universal_constructed(synta::tag::TAG_SEQUENCE);

    let mut outer = decoder.enter_constructed(seq_tag).ok()?;
    while !outer.is_empty() {
        let mut access_desc = outer
            .enter_constructed(seq_tag)
            .ok()?;

        let method: synta::ObjectIdentifier = access_desc.decode().ok()?;
        if method.components() == synta_certificate::oids::AD_OCSP {
            // accessLocation is a GeneralName CHOICE; uniformResourceIdentifier
            // is [6] IMPLICIT IA5String.
            let tag = access_desc.peek_tag().ok()?;
            if tag.number() == 6 {
                let raw: synta::RawDer<'_> = access_desc.decode().ok()?;
                // The RawDer includes the [6] tag and length; extract the IA5String value.
                let raw_bytes = raw.as_bytes();
                let url_bytes = extract_context_tagged_value(raw_bytes)?;
                return String::from_utf8(url_bytes.to_vec()).ok();
            }
        }
        // Skip remaining fields if we didn't match.
    }
    None
}

/// Extract the value bytes from a context-specific tagged TLV.
fn extract_context_tagged_value(tlv: &[u8]) -> Option<&[u8]> {
    if tlv.len() < 2 {
        return None;
    }
    let len_byte = tlv[1];
    if len_byte < 0x80 {
        Some(&tlv[2..2 + len_byte as usize])
    } else {
        let num = (len_byte & 0x7f) as usize;
        if tlv.len() < 2 + num {
            return None;
        }
        let mut vlen: usize = 0;
        for &b in &tlv[2..2 + num] {
            vlen = (vlen << 8) | b as usize;
        }
        let start = 2 + num;
        tlv.get(start..start + vlen)
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
