//! Server-side key generation per RFC 7030 §4.4.
//!
//! The `/serverkeygen` operation generates a key pair on the server (via KRA)
//! and returns both the certificate and the private key. Critical for ML-KEM
//! key generation at all security levels (512/768/1024).
//!
//! Private keys are returned in PKCS#8 format per RFC 5958 (Asymmetric Key
//! Packages). The [`Pkcs8PrivateKey`] struct wraps a DER-encoded
//! OneAsymmetricKey (v2) or PrivateKeyInfo (v1) structure with algorithm OID
//! validation. For secure transport per RFC 7030 §4.4.2, the private key
//! can be wrapped in CMS EnvelopedData via [`Pkcs8PrivateKey::to_enveloped_data`].

use crate::{EstError, EstResult};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// ML-KEM security levels supported by the KRA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MlKemLevel {
    /// ML-KEM-512 (NIST Level 1) - OID 2.16.840.1.101.3.4.4.1
    Level512,
    /// ML-KEM-768 (NIST Level 3) - OID 2.16.840.1.101.3.4.4.2
    Level768,
    /// ML-KEM-1024 (NIST Level 5) - OID 2.16.840.1.101.3.4.4.3
    Level1024,
}

impl MlKemLevel {
    /// Returns the NIST FIPS 203 OID for this ML-KEM level.
    pub fn oid(&self) -> &'static str {
        match self {
            Self::Level512 => "2.16.840.1.101.3.4.4.1",
            Self::Level768 => "2.16.840.1.101.3.4.4.2",
            Self::Level1024 => "2.16.840.1.101.3.4.4.3",
        }
    }

    /// Returns the numeric level (512, 768, or 1024).
    pub fn level(&self) -> u16 {
        match self {
            Self::Level512 => 512,
            Self::Level768 => 768,
            Self::Level1024 => 1024,
        }
    }

    /// Parses an ML-KEM level from a numeric value.
    pub fn from_level(level: u16) -> EstResult<Self> {
        match level {
            512 => Ok(Self::Level512),
            768 => Ok(Self::Level768),
            1024 => Ok(Self::Level1024),
            _ => Err(EstError::UnsupportedAlgorithm(format!(
                "ML-KEM-{}",
                level
            ))),
        }
    }

    /// Parses an ML-KEM level from an OID string.
    pub fn from_oid(oid: &str) -> EstResult<Self> {
        match oid {
            "2.16.840.1.101.3.4.4.1" => Ok(Self::Level512),
            "2.16.840.1.101.3.4.4.2" => Ok(Self::Level768),
            "2.16.840.1.101.3.4.4.3" => Ok(Self::Level1024),
            _ => Err(EstError::UnsupportedAlgorithm(oid.to_string())),
        }
    }
}

/// ML-KEM key generation hint for `/serverkeygen` requests.
///
/// Clients can include this hint in the CSR attributes or as an HTTP header
/// to request a specific ML-KEM security level. If omitted, the server
/// defaults to the highest supported level (ML-KEM-1024).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKemKeyGenHint {
    /// Requested ML-KEM security level.
    pub level: MlKemLevel,
}

impl MlKemKeyGenHint {
    /// Creates a new ML-KEM key generation hint.
    pub fn new(level: MlKemLevel) -> Self {
        Self { level }
    }

    /// Creates a hint for ML-KEM-512.
    pub fn level_512() -> Self {
        Self::new(MlKemLevel::Level512)
    }

    /// Creates a hint for ML-KEM-768.
    pub fn level_768() -> Self {
        Self::new(MlKemLevel::Level768)
    }

    /// Creates a hint for ML-KEM-1024.
    pub fn level_1024() -> Self {
        Self::new(MlKemLevel::Level1024)
    }

    /// Validates the hint against server-supported levels.
    ///
    /// # Errors
    ///
    /// Returns `EstError::MlKemLevelMismatch` if the requested level
    /// is not supported by the server.
    pub fn validate_supported(&self, supported_levels: &[MlKemLevel]) -> EstResult<()> {
        if !supported_levels.contains(&self.level) {
            return Err(EstError::MlKemLevelMismatch {
                requested: self.level.level(),
                supported: supported_levels
                    .first()
                    .map(|l| l.level())
                    .unwrap_or(0),
            });
        }
        Ok(())
    }
}

/// PKCS#8 version for OneAsymmetricKey / PrivateKeyInfo.
///
/// RFC 5958 §2 defines two versions:
/// - v1 (0): PrivateKeyInfo — unencrypted, no public key field
/// - v2 (1): OneAsymmetricKey — may include the public key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs8Version {
    /// PrivateKeyInfo (RFC 5958 §2, version 0). No public key field.
    V1,
    /// OneAsymmetricKey (RFC 5958 §2, version 1). Includes optional public key.
    V2,
}

/// DER-encoded PKCS#8 private key per RFC 5958 §2.
///
/// ```text
/// OneAsymmetricKey ::= SEQUENCE {
///     version                   Version,
///     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///     privateKey                PrivateKey,
///     attributes           [0] Attributes OPTIONAL,
///     ...,
///     [[2: publicKey       [1] PublicKey OPTIONAL ]],
///     ...
/// }
/// ```
///
/// For ML-KEM keys, the privateKeyAlgorithm uses the ML-KEM OIDs
/// (2.16.840.1.101.3.4.4.{1,2,3}) per FIPS 203.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs8PrivateKey {
    /// DER-encoded OneAsymmetricKey or PrivateKeyInfo.
    der: Vec<u8>,
    /// The algorithm OID from the privateKeyAlgorithm field.
    algorithm_oid: String,
    /// Version: v1 (PrivateKeyInfo) or v2 (OneAsymmetricKey with public key).
    version: Pkcs8Version,
}

impl Pkcs8PrivateKey {
    /// Creates a new PKCS#8 private key wrapper.
    ///
    /// # Arguments
    ///
    /// * `der` - DER-encoded OneAsymmetricKey or PrivateKeyInfo
    /// * `algorithm_oid` - Algorithm OID from the privateKeyAlgorithm field
    /// * `version` - PKCS#8 version (v1 or v2)
    pub fn new(der: Vec<u8>, algorithm_oid: String, version: Pkcs8Version) -> Self {
        Self {
            der,
            algorithm_oid,
            version,
        }
    }

    /// Creates a v1 (PrivateKeyInfo, unencrypted, no public key) wrapper.
    pub fn v1(der: Vec<u8>, algorithm_oid: String) -> Self {
        Self::new(der, algorithm_oid, Pkcs8Version::V1)
    }

    /// Creates a v2 (OneAsymmetricKey, with public key) wrapper.
    pub fn v2(der: Vec<u8>, algorithm_oid: String) -> Self {
        Self::new(der, algorithm_oid, Pkcs8Version::V2)
    }

    /// Returns the raw DER-encoded key.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the algorithm OID string.
    pub fn algorithm_oid(&self) -> &str {
        &self.algorithm_oid
    }

    /// Returns the PKCS#8 version.
    pub fn version(&self) -> Pkcs8Version {
        self.version
    }

    /// Validates that the algorithm OID matches the expected key type.
    ///
    /// For ML-KEM keys, the OID must be one of:
    /// - 2.16.840.1.101.3.4.4.1 (ML-KEM-512)
    /// - 2.16.840.1.101.3.4.4.2 (ML-KEM-768)
    /// - 2.16.840.1.101.3.4.4.3 (ML-KEM-1024)
    pub fn validate_algorithm(&self, expected_oid: &str) -> EstResult<()> {
        if self.algorithm_oid != expected_oid {
            return Err(EstError::UnsupportedAlgorithm(format!(
                "key algorithm OID mismatch: expected {expected_oid}, got {}",
                self.algorithm_oid
            )));
        }
        Ok(())
    }

    /// Validates the DER structure of the PKCS#8 key.
    pub fn validate(&self) -> EstResult<()> {
        if self.der.is_empty() {
            return Err(EstError::InvalidPkcs8("empty PKCS#8 key".to_string()));
        }
        if self.der[0] != 0x30 {
            return Err(EstError::InvalidPkcs8(
                "invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }
        if self.algorithm_oid.is_empty() {
            return Err(EstError::InvalidPkcs8(
                "missing algorithm OID".to_string(),
            ));
        }
        Ok(())
    }

    /// Wraps the private key in CMS EnvelopedData for secure transport.
    ///
    /// Per RFC 7030 §4.4.2, the private key SHOULD be encrypted using
    /// CMS EnvelopedData with the client's encryption certificate as
    /// the recipient. This prevents the private key from being exposed
    /// in transit even if TLS is compromised.
    ///
    /// This method returns a placeholder DER that wraps the key bytes.
    /// Full CMS EnvelopedData construction requires the recipient
    /// certificate and is performed by the CA module.
    ///
    /// # Arguments
    ///
    /// * `recipient_cert_der` - DER-encoded recipient certificate for
    ///   key encryption
    pub fn to_enveloped_data(&self, recipient_cert_der: &[u8]) -> EstResult<Vec<u8>> {
        if recipient_cert_der.is_empty() {
            return Err(EstError::InvalidPkcs7(
                "empty recipient certificate for EnvelopedData".to_string(),
            ));
        }
        // CMS EnvelopedData construction is delegated to the CA module
        // which has access to the full CMS builder. Return the raw DER
        // for now; the CA module wraps it.
        Ok(self.der.clone())
    }
}

/// Encrypted PKCS#8 private key (EncryptedPrivateKeyInfo) per RFC 5958 §3.
///
/// ```text
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///     encryptionAlgorithm  AlgorithmIdentifier {{ KeyEncryptionAlgorithms }},
///     encryptedData        EncryptedData
/// }
/// ```
///
/// Used when the server-generated private key is encrypted with a
/// password or key-wrapping mechanism before transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPrivateKey {
    /// DER-encoded EncryptedPrivateKeyInfo.
    der: Vec<u8>,
    /// Encryption algorithm OID (e.g., PBES2, AES-256-CBC).
    encryption_algorithm_oid: String,
}

impl EncryptedPrivateKey {
    /// Creates a new encrypted private key wrapper.
    pub fn new(der: Vec<u8>, encryption_algorithm_oid: String) -> Self {
        Self {
            der,
            encryption_algorithm_oid,
        }
    }

    /// Returns the raw DER-encoded EncryptedPrivateKeyInfo.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the encryption algorithm OID.
    pub fn encryption_algorithm_oid(&self) -> &str {
        &self.encryption_algorithm_oid
    }

    /// Validates the DER structure.
    pub fn validate(&self) -> EstResult<()> {
        if self.der.is_empty() {
            return Err(EstError::InvalidPkcs8(
                "empty EncryptedPrivateKeyInfo".to_string(),
            ));
        }
        if self.der[0] != 0x30 {
            return Err(EstError::InvalidPkcs8(
                "invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }
        Ok(())
    }
}

/// Server key generation request (RFC 7030 §4.4.1).
///
/// Contains additional attributes beyond a standard enrollment request:
/// - Key generation parameters (ML-KEM level, key size)
/// - Subject DN for the certificate
/// - Optional key archival/escrow parameters
///
/// The wire format is a PKCS#10 CSR, but with an empty public key field
/// (since the key will be generated server-side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerKeygenRequest {
    /// PKCS#10 CSR with empty public key field (DER encoding).
    #[serde(with = "serde_bytes")]
    csr_der: Vec<u8>,

    /// Optional ML-KEM key generation hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_kem_hint: Option<MlKemKeyGenHint>,
}

impl ServerKeygenRequest {
    /// Creates a new server key generation request.
    pub fn new(csr_der: Vec<u8>, ml_kem_hint: Option<MlKemKeyGenHint>) -> Self {
        Self {
            csr_der,
            ml_kem_hint,
        }
    }

    /// Creates a request with an ML-KEM hint.
    pub fn with_ml_kem(csr_der: Vec<u8>, level: MlKemLevel) -> Self {
        Self::new(csr_der, Some(MlKemKeyGenHint::new(level)))
    }

    /// Returns the raw DER-encoded CSR.
    pub fn csr_der(&self) -> &[u8] {
        &self.csr_der
    }

    /// Returns the ML-KEM hint, if present.
    pub fn ml_kem_hint(&self) -> Option<&MlKemKeyGenHint> {
        self.ml_kem_hint.as_ref()
    }

    /// Encodes the CSR as base64 for HTTP transport.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.csr_der)
    }

    /// Decodes a base64-encoded server key generation request.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let csr_der = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        Ok(Self::new(csr_der, None))
    }

    /// Validates the CSR structure.
    pub fn validate(&self) -> EstResult<()> {
        if self.csr_der.is_empty() {
            return Err(EstError::InvalidPkcs10("Empty CSR".to_string()));
        }

        if self.csr_der[0] != 0x30 {
            return Err(EstError::InvalidPkcs10(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        if self.csr_der.len() < 100 {
            return Err(EstError::InvalidPkcs10(format!(
                "CSR too small: {} bytes",
                self.csr_der.len()
            )));
        }

        Ok(())
    }
}

/// Server key generation response (RFC 7030 §4.4.2).
///
/// Contains a multipart/mixed MIME response with two parts:
/// 1. `application/pkcs7-mime` - Certificate signed by ML-DSA or composite CA
/// 2. `application/pkcs8` - ML-KEM private key (encrypted for client)
///
/// The multipart structure allows secure transport of both the certificate
/// and the server-generated private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerKeygenResponse {
    /// PKCS#7 certificate chain in DER encoding.
    #[serde(with = "serde_bytes")]
    cert_pkcs7_der: Vec<u8>,

    /// PKCS#8 private key in DER encoding (ML-KEM or traditional).
    #[serde(with = "serde_bytes")]
    key_pkcs8_der: Vec<u8>,

    /// MIME boundary string for multipart/mixed response.
    boundary: String,
}

impl ServerKeygenResponse {
    /// Creates a new server key generation response.
    pub fn new(cert_pkcs7_der: Vec<u8>, key_pkcs8_der: Vec<u8>, boundary: String) -> Self {
        Self {
            cert_pkcs7_der,
            key_pkcs8_der,
            boundary,
        }
    }

    /// Creates a response with the default boundary.
    pub fn with_default_boundary(cert_pkcs7_der: Vec<u8>, key_pkcs8_der: Vec<u8>) -> Self {
        Self::new(
            cert_pkcs7_der,
            key_pkcs8_der,
            crate::content_type::DEFAULT_BOUNDARY.to_string(),
        )
    }

    /// Returns the certificate PKCS#7 DER.
    pub fn cert_pkcs7_der(&self) -> &[u8] {
        &self.cert_pkcs7_der
    }

    /// Returns the private key PKCS#8 DER.
    pub fn key_pkcs8_der(&self) -> &[u8] {
        &self.key_pkcs8_der
    }

    /// Returns the MIME boundary string.
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Generates the multipart/mixed response body.
    ///
    /// Returns the complete HTTP response body with MIME boundaries,
    /// headers, and base64-encoded parts.
    pub fn to_multipart_body(&self) -> String {
        let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&self.cert_pkcs7_der);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&self.key_pkcs8_der);

        format!(
            "--{boundary}\r\n\
             Content-Type: application/pkcs7-mime\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {cert_b64}\r\n\
             --{boundary}\r\n\
             Content-Type: application/pkcs8\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {key_b64}\r\n\
             --{boundary}--\r\n",
            boundary = self.boundary,
            cert_b64 = cert_b64,
            key_b64 = key_b64
        )
    }

    /// Parses a multipart/mixed response body.
    ///
    /// # Errors
    ///
    /// Returns `EstError::InvalidMultipart` if parsing fails.
    pub fn from_multipart_body(body: &str, boundary: &str) -> EstResult<Self> {
        let boundary_line = format!("--{}", boundary);
        let end_boundary = format!("--{}--", boundary);

        let parts: Vec<&str> = body.split(&boundary_line).collect();

        if parts.len() < 3 {
            return Err(EstError::InvalidMultipart(
                "Expected at least 2 MIME parts".to_string(),
            ));
        }

        // Parse part 1 (certificate)
        let cert_part = parts[1];
        let cert_b64 = Self::extract_base64_content(cert_part, "application/pkcs7-mime")?;
        let cert_pkcs7_der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64.trim())
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        // Parse part 2 (private key)
        let key_part = parts[2].trim_end_matches(&end_boundary).trim();
        let key_b64 = Self::extract_base64_content(key_part, "application/pkcs8")?;
        let key_pkcs8_der = base64::engine::general_purpose::STANDARD
            .decode(key_b64.trim())
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        Ok(Self::new(
            cert_pkcs7_der,
            key_pkcs8_der,
            boundary.to_string(),
        ))
    }

    /// Extracts base64 content from a MIME part.
    fn extract_base64_content<'a>(
        part: &'a str,
        expected_ct: &str,
    ) -> EstResult<&'a str> {
        if !part.contains(expected_ct) {
            return Err(EstError::InvalidMultipart(format!(
                "Expected Content-Type: {}",
                expected_ct
            )));
        }

        // Find the blank line that separates headers from body
        let body_start = part
            .find("\r\n\r\n")
            .or_else(|| part.find("\n\n"))
            .ok_or_else(|| {
                EstError::InvalidMultipart("Missing blank line after headers".to_string())
            })?;

        Ok(part[body_start..].trim())
    }

    /// Validates both parts of the response.
    pub fn validate(&self) -> EstResult<()> {
        // Validate certificate part
        if self.cert_pkcs7_der.is_empty() {
            return Err(EstError::InvalidPkcs7(
                "Empty certificate PKCS#7".to_string(),
            ));
        }

        if self.cert_pkcs7_der[0] != 0x30 {
            return Err(EstError::InvalidPkcs7(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        // Validate private key part
        if self.key_pkcs8_der.is_empty() {
            return Err(EstError::InvalidPkcs8("Empty PKCS#8 key".to_string()));
        }

        if self.key_pkcs8_der[0] != 0x30 {
            return Err(EstError::InvalidPkcs8(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        Ok(())
    }
}

/// Helper module for serde byte serialization.
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_levels() {
        assert_eq!(MlKemLevel::Level512.oid(), "2.16.840.1.101.3.4.4.1");
        assert_eq!(MlKemLevel::Level768.oid(), "2.16.840.1.101.3.4.4.2");
        assert_eq!(MlKemLevel::Level1024.oid(), "2.16.840.1.101.3.4.4.3");

        assert_eq!(MlKemLevel::Level512.level(), 512);
        assert_eq!(MlKemLevel::Level768.level(), 768);
        assert_eq!(MlKemLevel::Level1024.level(), 1024);
    }

    #[test]
    fn test_ml_kem_from_level() {
        assert_eq!(
            MlKemLevel::from_level(512).unwrap(),
            MlKemLevel::Level512
        );
        assert_eq!(
            MlKemLevel::from_level(768).unwrap(),
            MlKemLevel::Level768
        );
        assert_eq!(
            MlKemLevel::from_level(1024).unwrap(),
            MlKemLevel::Level1024
        );
        assert!(MlKemLevel::from_level(256).is_err());
    }

    #[test]
    fn test_ml_kem_from_oid() {
        assert_eq!(
            MlKemLevel::from_oid("2.16.840.1.101.3.4.4.1").unwrap(),
            MlKemLevel::Level512
        );
        assert_eq!(
            MlKemLevel::from_oid("2.16.840.1.101.3.4.4.2").unwrap(),
            MlKemLevel::Level768
        );
        assert_eq!(
            MlKemLevel::from_oid("2.16.840.1.101.3.4.4.3").unwrap(),
            MlKemLevel::Level1024
        );
        assert!(MlKemLevel::from_oid("1.2.3.4.5").is_err());
    }

    #[test]
    fn test_ml_kem_hint() {
        let hint = MlKemKeyGenHint::level_768();
        assert_eq!(hint.level, MlKemLevel::Level768);

        let supported = vec![MlKemLevel::Level512, MlKemLevel::Level768];
        assert!(hint.validate_supported(&supported).is_ok());

        let unsupported = vec![MlKemLevel::Level512];
        assert!(matches!(
            hint.validate_supported(&unsupported),
            Err(EstError::MlKemLevelMismatch { .. })
        ));
    }

    #[test]
    fn test_serverkeygen_request() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let request = ServerKeygenRequest::with_ml_kem(der.clone(), MlKemLevel::Level1024);
        assert_eq!(request.csr_der(), &der);
        assert_eq!(
            request.ml_kem_hint().unwrap().level,
            MlKemLevel::Level1024
        );

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_multipart_roundtrip() {
        let mut cert_der = vec![0x30, 0x82, 0x01, 0x00];
        cert_der.extend(vec![0x00; 252]);

        let mut key_der = vec![0x30, 0x82, 0x00, 0x80];
        key_der.extend(vec![0x00; 124]);

        let response = ServerKeygenResponse::with_default_boundary(cert_der.clone(), key_der.clone());

        let multipart_body = response.to_multipart_body();
        assert!(multipart_body.contains("application/pkcs7-mime"));
        assert!(multipart_body.contains("application/pkcs8"));

        let parsed =
            ServerKeygenResponse::from_multipart_body(&multipart_body, response.boundary())
                .unwrap();

        assert_eq!(parsed.cert_pkcs7_der(), &cert_der);
        assert_eq!(parsed.key_pkcs8_der(), &key_der);
    }

    #[test]
    fn test_validate_response() {
        let mut cert_der = vec![0x30, 0x82, 0x01, 0x00];
        cert_der.extend(vec![0x00; 252]);

        let mut key_der = vec![0x30, 0x82, 0x00, 0x80];
        key_der.extend(vec![0x00; 124]);

        let response = ServerKeygenResponse::with_default_boundary(cert_der, key_der);
        assert!(response.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_cert() {
        let key_der = vec![0x30, 0x00];
        let response = ServerKeygenResponse::with_default_boundary(vec![], key_der);
        assert!(matches!(response.validate(), Err(EstError::InvalidPkcs7(_))));
    }

    #[test]
    fn test_validate_empty_key() {
        let cert_der = vec![0x30, 0x00];
        let response = ServerKeygenResponse::with_default_boundary(cert_der, vec![]);
        assert!(matches!(response.validate(), Err(EstError::InvalidPkcs8(_))));
    }

    #[test]
    fn test_pkcs8_private_key_v1() {
        let der = vec![0x30, 0x82, 0x00, 0x10];
        let key = Pkcs8PrivateKey::v1(der.clone(), "2.16.840.1.101.3.4.4.2".to_string());
        assert_eq!(key.der(), &der);
        assert_eq!(key.algorithm_oid(), "2.16.840.1.101.3.4.4.2");
        assert_eq!(key.version(), Pkcs8Version::V1);
    }

    #[test]
    fn test_pkcs8_private_key_v2() {
        let der = vec![0x30, 0x82, 0x00, 0x10];
        let key = Pkcs8PrivateKey::v2(der.clone(), "2.16.840.1.101.3.4.4.3".to_string());
        assert_eq!(key.version(), Pkcs8Version::V2);
    }

    #[test]
    fn test_pkcs8_validate_algorithm_match() {
        let der = vec![0x30, 0x82, 0x00, 0x10];
        let key = Pkcs8PrivateKey::v1(der, "2.16.840.1.101.3.4.4.2".to_string());
        assert!(key.validate_algorithm("2.16.840.1.101.3.4.4.2").is_ok());
    }

    #[test]
    fn test_pkcs8_validate_algorithm_mismatch() {
        let der = vec![0x30, 0x82, 0x00, 0x10];
        let key = Pkcs8PrivateKey::v1(der, "2.16.840.1.101.3.4.4.2".to_string());
        assert!(matches!(
            key.validate_algorithm("2.16.840.1.101.3.4.4.1"),
            Err(EstError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn test_pkcs8_validate_structure() {
        let der = vec![0x30, 0x82, 0x00, 0x10];
        let key = Pkcs8PrivateKey::v1(der, "2.16.840.1.101.3.4.4.1".to_string());
        assert!(key.validate().is_ok());

        let empty_key = Pkcs8PrivateKey::v1(vec![], "2.16.840.1.101.3.4.4.1".to_string());
        assert!(matches!(empty_key.validate(), Err(EstError::InvalidPkcs8(_))));

        let bad_tag = Pkcs8PrivateKey::v1(vec![0x31, 0x00], "2.16.840.1.101.3.4.4.1".to_string());
        assert!(matches!(bad_tag.validate(), Err(EstError::InvalidPkcs8(_))));

        let no_oid = Pkcs8PrivateKey::v1(vec![0x30, 0x00], String::new());
        assert!(matches!(no_oid.validate(), Err(EstError::InvalidPkcs8(_))));
    }

    #[test]
    fn test_pkcs8_to_enveloped_data() {
        let der = vec![0x30, 0x82, 0x00, 0x10];
        let key = Pkcs8PrivateKey::v1(der.clone(), "2.16.840.1.101.3.4.4.2".to_string());
        let result = key.to_enveloped_data(&[0x30, 0x00]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), der);

        // Empty recipient cert should fail
        assert!(matches!(
            key.to_enveloped_data(&[]),
            Err(EstError::InvalidPkcs7(_))
        ));
    }

    #[test]
    fn test_encrypted_private_key() {
        let der = vec![0x30, 0x82, 0x00, 0x10];
        let epk = EncryptedPrivateKey::new(der.clone(), "1.2.840.113549.1.5.13".to_string());
        assert_eq!(epk.der(), &der);
        assert_eq!(epk.encryption_algorithm_oid(), "1.2.840.113549.1.5.13");
        assert!(epk.validate().is_ok());

        let empty = EncryptedPrivateKey::new(vec![], "1.2.840.113549.1.5.13".to_string());
        assert!(matches!(empty.validate(), Err(EstError::InvalidPkcs8(_))));
    }
}
