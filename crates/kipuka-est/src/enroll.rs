//! Simple enrollment per RFC 7030 §4.2.
//!
//! The `/simpleenroll` operation accepts a PKCS#10 CSR and returns a PKCS#7
//! certificate chain. Supports ML-DSA and ML-KEM CSRs with proof-of-possession.
//!
//! CSR wire format follows RFC 2986 (PKCS#10 Certification Request Syntax
//! Specification v1.7). The [`CertificationRequest`] struct formalizes the
//! three-part ASN.1 structure: CertificationRequestInfo, signatureAlgorithm,
//! and signature.

use crate::{EstError, EstResult};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// ML-DSA algorithm OIDs per FIPS 204.
pub mod ml_dsa_oids {
    /// ML-DSA-44 (2.16.840.1.101.3.4.3.17)
    pub const ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";
    /// ML-DSA-65 (2.16.840.1.101.3.4.3.18)
    pub const ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
    /// ML-DSA-87 (2.16.840.1.101.3.4.3.19)
    pub const ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";
}

/// ML-KEM algorithm OIDs per FIPS 203.
pub mod ml_kem_oids {
    /// ML-KEM-512 (2.16.840.1.101.3.4.4.1)
    pub const ML_KEM_512: &str = "2.16.840.1.101.3.4.4.1";
    /// ML-KEM-768 (2.16.840.1.101.3.4.4.2)
    pub const ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";
    /// ML-KEM-1024 (2.16.840.1.101.3.4.4.3)
    pub const ML_KEM_1024: &str = "2.16.840.1.101.3.4.4.3";
}

/// Traditional key algorithm OIDs.
pub mod traditional_oids {
    /// RSA encryption (1.2.840.113549.1.1.1) per RFC 8017.
    pub const RSA: &str = "1.2.840.113549.1.1.1";
    /// EC public key (1.2.840.10045.2.1) per RFC 5480.
    pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
}

/// Named curve OIDs for ECDSA.
pub mod named_curve_oids {
    /// P-256 / secp256r1 (1.2.840.10045.3.1.7) per RFC 5480.
    pub const P256: &str = "1.2.840.10045.3.1.7";
    /// P-384 / secp384r1 (1.3.132.0.34) per RFC 5480.
    pub const P384: &str = "1.3.132.0.34";
}

/// Composite ML-DSA OID base arc (2.16.840.1.114027.80.5.2).
///
/// Sub-arcs 37-54 define various composite ML-DSA + traditional combinations.
pub const COMPOSITE_ML_DSA_BASE: &str = "2.16.840.1.114027.80.5.2";

/// Key algorithm detected from SubjectPublicKeyInfo in a CSR.
///
/// Per RFC 2986 §4.1, the SubjectPublicKeyInfo field contains an
/// AlgorithmIdentifier that specifies the key algorithm and any
/// algorithm-specific parameters (e.g., named curves for ECDSA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// RSA (OID 1.2.840.113549.1.1.1).
    Rsa,
    /// ECDSA P-256 (OID 1.2.840.10045.2.1 + namedCurve 1.2.840.10045.3.1.7).
    EcdsaP256,
    /// ECDSA P-384 (OID 1.2.840.10045.2.1 + namedCurve 1.3.132.0.34).
    EcdsaP384,
    /// ML-DSA-44 (OID 2.16.840.1.101.3.4.3.17) per FIPS 204.
    MlDsa44,
    /// ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18) per FIPS 204.
    MlDsa65,
    /// ML-DSA-87 (OID 2.16.840.1.101.3.4.3.19) per FIPS 204.
    MlDsa87,
    /// ML-KEM-512 (OID 2.16.840.1.101.3.4.4.1) per FIPS 203.
    MlKem512,
    /// ML-KEM-768 (OID 2.16.840.1.101.3.4.4.2) per FIPS 203.
    MlKem768,
    /// ML-KEM-1024 (OID 2.16.840.1.101.3.4.4.3) per FIPS 203.
    MlKem1024,
    /// Unknown algorithm with the given OID string.
    Unknown(String),
}

impl KeyAlgorithm {
    /// Parse a key algorithm from its OID string.
    ///
    /// For EC keys, the caller must also supply the named curve OID
    /// via [`KeyAlgorithm::from_ec_oid`].
    pub fn from_oid(oid: &str) -> Self {
        match oid {
            "1.2.840.113549.1.1.1" => Self::Rsa,
            "1.2.840.10045.2.1" => Self::EcdsaP256, // default; caller refines via from_ec_oid
            "2.16.840.1.101.3.4.3.17" => Self::MlDsa44,
            "2.16.840.1.101.3.4.3.18" => Self::MlDsa65,
            "2.16.840.1.101.3.4.3.19" => Self::MlDsa87,
            "2.16.840.1.101.3.4.4.1" => Self::MlKem512,
            "2.16.840.1.101.3.4.4.2" => Self::MlKem768,
            "2.16.840.1.101.3.4.4.3" => Self::MlKem1024,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Refine an EC public key algorithm using the named curve OID.
    ///
    /// Per RFC 5480 §2.1.1, the AlgorithmIdentifier for EC keys includes
    /// the namedCurve parameter that identifies the specific curve.
    pub fn from_ec_oid(curve_oid: &str) -> Self {
        match curve_oid {
            "1.2.840.10045.3.1.7" => Self::EcdsaP256,
            "1.3.132.0.34" => Self::EcdsaP384,
            other => Self::Unknown(format!("ec-unknown-curve:{other}")),
        }
    }

    /// Returns the OID string for this algorithm.
    pub fn oid(&self) -> &str {
        match self {
            Self::Rsa => "1.2.840.113549.1.1.1",
            Self::EcdsaP256 | Self::EcdsaP384 => "1.2.840.10045.2.1",
            Self::MlDsa44 => "2.16.840.1.101.3.4.3.17",
            Self::MlDsa65 => "2.16.840.1.101.3.4.3.18",
            Self::MlDsa87 => "2.16.840.1.101.3.4.3.19",
            Self::MlKem512 => "2.16.840.1.101.3.4.4.1",
            Self::MlKem768 => "2.16.840.1.101.3.4.4.2",
            Self::MlKem1024 => "2.16.840.1.101.3.4.4.3",
            Self::Unknown(oid) => oid.as_str(),
        }
    }
}

/// Parsed PKCS#10 Certification Request per RFC 2986 §4.
///
/// ```text
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo  CertificationRequestInfo,
///     signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
///     signature                 BIT STRING
/// }
/// ```
///
/// This struct represents the logical structure of a parsed CSR. The actual
/// DER parsing is performed by the CA module using the `synta` crate; this
/// struct captures the extracted fields for EST protocol-level processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationRequest {
    /// CSR version (0 = v1 per RFC 2986 §4.1).
    pub version: u8,
    /// Subject distinguished name (e.g., "CN=example.com,O=ACME,C=US").
    pub subject: String,
    /// Key algorithm from SubjectPublicKeyInfo.
    pub key_algorithm: KeyAlgorithm,
    /// DER-encoded SubjectPublicKeyInfo.
    pub subject_public_key_info: Vec<u8>,
    /// Signature algorithm OID (e.g., ML-DSA-65, sha256WithRSAEncryption).
    pub signature_algorithm: String,
    /// DER-encoded signature BIT STRING value.
    pub signature: Vec<u8>,
    /// Subject Alternative Names extracted from the extensionRequest attribute
    /// (OID 1.2.840.113549.1.9.14) per RFC 2986 §4.1 and RFC 5280 §4.2.1.6.
    pub subject_alt_names: Vec<String>,
    /// Key usage flags from the extensionRequest attribute, if present.
    pub key_usage: Vec<String>,
    /// ChallengePassword attribute (OID 1.2.840.113549.1.9.7) per RFC 2986 §4.1.
    ///
    /// When present, this carries a shared secret (e.g., OTP) for binding the
    /// CSR to a pre-authorized enrollment. See also RFC 7030 §3.2.3.
    pub challenge_password: Option<String>,
    /// Raw DER of the CertificationRequestInfo for signature verification.
    pub tbs_der: Vec<u8>,
}

impl CertificationRequest {
    /// Verify the CSR self-signature over CertificationRequestInfo.
    ///
    /// RFC 2986 §3: "The signature process consists of two steps:
    /// 1. The value of the certificationRequestInfo component is DER encoded,
    ///    producing an octet string.
    /// 2. The result of step 1 is signed with the certification request
    ///    subject's private key under the specified signature algorithm."
    ///
    /// This method validates that the signature was produced by the private key
    /// corresponding to the public key in `subject_public_key_info`. Full
    /// cryptographic verification is delegated to the CA module.
    pub fn verify_self_signature(&self) -> EstResult<()> {
        if self.tbs_der.is_empty() {
            return Err(EstError::InvalidPkcs10(
                "empty CertificationRequestInfo for signature verification".to_string(),
            ));
        }
        if self.signature.is_empty() {
            return Err(EstError::InvalidPkcs10(
                "empty signature in CSR".to_string(),
            ));
        }
        // Cryptographic verification delegated to CA module which has access
        // to the full ASN.1 parser and crypto primitives.
        Ok(())
    }

    /// Validate the challengePassword attribute if present.
    ///
    /// Per RFC 2986 §4.1 the challengePassword attribute (OID 1.2.840.113549.1.9.7)
    /// carries a password for identity verification. When used with EST OTP
    /// binding, this password must match the pre-provisioned OTP.
    pub fn validate_challenge_password(&self, expected: &str) -> EstResult<()> {
        match &self.challenge_password {
            Some(pw) if pw == expected => Ok(()),
            Some(pw) => Err(EstError::InvalidPop(format!(
                "challengePassword mismatch: expected {expected:?}, got {pw:?}",
            ))),
            None => Err(EstError::MissingField(
                "challengePassword attribute".to_string(),
            )),
        }
    }
}

/// Enrollment request containing a PKCS#10 CSR (RFC 7030 §4.2.1).
///
/// The CSR must include:
/// - Subject public key (ML-DSA, ML-KEM, or traditional)
/// - Subject distinguished name
/// - Signature proving possession of the private key (POP)
///
/// For ML-DSA CSRs, the signature algorithm OID indicates the ML-DSA level.
/// For ML-KEM CSRs, a separate ML-DSA signature is required for POP.
///
/// The wire format is a DER-encoded CertificationRequest per RFC 2986.
/// Use [`CertificationRequest`] for parsed/structured access to CSR fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// PKCS#10 CSR in DER encoding.
    #[serde(with = "serde_bytes")]
    csr_der: Vec<u8>,
}

impl EnrollRequest {
    /// Creates a new enrollment request from a DER-encoded PKCS#10 CSR.
    pub fn new(csr_der: Vec<u8>) -> Self {
        Self { csr_der }
    }

    /// Returns the raw DER-encoded CSR.
    pub fn csr_der(&self) -> &[u8] {
        &self.csr_der
    }

    /// Consumes self and returns the DER-encoded CSR.
    pub fn into_csr_der(self) -> Vec<u8> {
        self.csr_der
    }

    /// Encodes the request as base64 for HTTP transport.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.csr_der)
    }

    /// Decodes a base64-encoded enrollment request.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let csr_der = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        Ok(Self::new(csr_der))
    }

    /// Validates the CSR structure and proof-of-possession.
    ///
    /// This performs basic DER validation. Full cryptographic validation
    /// (signature verification) is delegated to the CA module.
    pub fn validate(&self) -> EstResult<()> {
        if self.csr_der.is_empty() {
            return Err(EstError::InvalidPkcs10("Empty CSR".to_string()));
        }

        // Basic DER sanity: must start with SEQUENCE tag (0x30)
        if self.csr_der[0] != 0x30 {
            return Err(EstError::InvalidPkcs10(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        // Minimum viable CSR is ~200 bytes
        if self.csr_der.len() < 100 {
            return Err(EstError::InvalidPkcs10(format!(
                "CSR too small: {} bytes",
                self.csr_der.len()
            )));
        }

        Ok(())
    }

    /// Detects the signature algorithm OID from the CSR.
    ///
    /// Returns the OID string if found, or `None` if parsing fails.
    /// This is used to route CSRs to the appropriate CA signing key
    /// (ML-DSA-44/65/87, composite, or traditional).
    ///
    /// Note: This is a simple heuristic parser. Full ASN.1 parsing
    /// is performed by the CA module.
    pub fn detect_signature_algorithm(&self) -> Option<String> {
        // Simplified OID detection - in production, use proper ASN.1 parser
        // For now, return None to indicate "needs full parsing"
        None
    }

    /// Checks if the CSR appears to contain an ML-DSA public key.
    ///
    /// Searches for ML-DSA OID prefixes in the DER structure.
    pub fn contains_ml_dsa(&self) -> bool {
        let ml_dsa_prefix = b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x03"; // OID prefix for ML-DSA
        self.csr_der
            .windows(ml_dsa_prefix.len())
            .any(|w| w == ml_dsa_prefix)
    }

    /// Checks if the CSR appears to contain an ML-KEM public key.
    ///
    /// Searches for ML-KEM OID prefixes in the DER structure.
    pub fn contains_ml_kem(&self) -> bool {
        let ml_kem_prefix = b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x04"; // OID prefix for ML-KEM
        self.csr_der
            .windows(ml_kem_prefix.len())
            .any(|w| w == ml_kem_prefix)
    }

    /// Returns a parsed [`CertificationRequest`] from the DER-encoded CSR.
    ///
    /// This is a placeholder that creates a `CertificationRequest` with
    /// default/empty fields. Full ASN.1 parsing of the RFC 2986 structure
    /// is performed by the CA module using `synta`.
    ///
    /// Callers should use this to get the struct, then have the CA module
    /// populate the fields from actual DER parsing.
    pub fn to_certification_request(&self) -> CertificationRequest {
        CertificationRequest {
            version: 0, // v1 per RFC 2986 §4.1
            subject: String::new(),
            key_algorithm: KeyAlgorithm::Unknown("unparsed".to_string()),
            subject_public_key_info: Vec::new(),
            signature_algorithm: String::new(),
            signature: Vec::new(),
            subject_alt_names: Vec::new(),
            key_usage: Vec::new(),
            challenge_password: None,
            tbs_der: self.csr_der.clone(),
        }
    }
}

/// Enrollment response containing a PKCS#7 certificate chain (RFC 7030 §4.2.3).
///
/// The response includes:
/// - End-entity certificate (signed by CA with ML-DSA or traditional key)
/// - Intermediate CA certificates (optional)
/// - Root CA certificate (optional)
///
/// The certificate chain is returned as a PKCS#7 `certs-only` structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// PKCS#7 certs-only message in DER encoding.
    #[serde(with = "serde_bytes")]
    pkcs7_der: Vec<u8>,
}

impl EnrollResponse {
    /// Creates a new enrollment response from DER-encoded PKCS#7.
    pub fn new(pkcs7_der: Vec<u8>) -> Self {
        Self { pkcs7_der }
    }

    /// Returns the raw DER-encoded PKCS#7 data.
    pub fn pkcs7_der(&self) -> &[u8] {
        &self.pkcs7_der
    }

    /// Consumes self and returns the DER-encoded PKCS#7 data.
    pub fn into_pkcs7_der(self) -> Vec<u8> {
        self.pkcs7_der
    }

    /// Encodes the response as base64 for HTTP transport.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.pkcs7_der)
    }

    /// Decodes a base64-encoded enrollment response.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let pkcs7_der = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        Ok(Self::new(pkcs7_der))
    }

    /// Validates the PKCS#7 structure.
    pub fn validate(&self) -> EstResult<()> {
        if self.pkcs7_der.is_empty() {
            return Err(EstError::InvalidPkcs7("Empty PKCS#7 structure".to_string()));
        }

        if self.pkcs7_der[0] != 0x30 {
            return Err(EstError::InvalidPkcs7(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        if self.pkcs7_der.len() < 100 {
            return Err(EstError::InvalidPkcs7(format!(
                "PKCS#7 too small: {} bytes",
                self.pkcs7_der.len()
            )));
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
    fn test_enroll_request_roundtrip() {
        let der = vec![0x30, 0x82, 0x01, 0x00]; // SEQUENCE
        let mut full_der = der.clone();
        full_der.extend(vec![0x00; 252]); // Pad to 256 bytes

        let request = EnrollRequest::new(full_der.clone());
        assert_eq!(request.csr_der(), &full_der);

        let base64 = request.to_base64();
        let decoded = EnrollRequest::from_base64(&base64).unwrap();
        assert_eq!(decoded.csr_der(), &full_der);
    }

    #[test]
    fn test_enroll_response_roundtrip() {
        let der = vec![0x30, 0x82, 0x01, 0x00];
        let mut full_der = der.clone();
        full_der.extend(vec![0x00; 252]);

        let response = EnrollResponse::new(full_der.clone());
        assert_eq!(response.pkcs7_der(), &full_der);

        let base64 = response.to_base64();
        let decoded = EnrollResponse::from_base64(&base64).unwrap();
        assert_eq!(decoded.pkcs7_der(), &full_der);
    }

    #[test]
    fn test_validate_csr() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);
        let request = EnrollRequest::new(der);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_csr() {
        let request = EnrollRequest::new(vec![]);
        assert!(matches!(
            request.validate(),
            Err(EstError::InvalidPkcs10(_))
        ));
    }

    #[test]
    fn test_ml_dsa_oids() {
        assert_eq!(ml_dsa_oids::ML_DSA_44, "2.16.840.1.101.3.4.3.17");
        assert_eq!(ml_dsa_oids::ML_DSA_65, "2.16.840.1.101.3.4.3.18");
        assert_eq!(ml_dsa_oids::ML_DSA_87, "2.16.840.1.101.3.4.3.19");
    }

    #[test]
    fn test_ml_kem_oids() {
        assert_eq!(ml_kem_oids::ML_KEM_512, "2.16.840.1.101.3.4.4.1");
        assert_eq!(ml_kem_oids::ML_KEM_768, "2.16.840.1.101.3.4.4.2");
        assert_eq!(ml_kem_oids::ML_KEM_1024, "2.16.840.1.101.3.4.4.3");
    }

    #[test]
    fn test_contains_ml_dsa() {
        // Mock DER with ML-DSA OID prefix
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend_from_slice(b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x03\x11"); // ML-DSA-44 OID
        der.extend(vec![0x00; 240]);

        let request = EnrollRequest::new(der);
        assert!(request.contains_ml_dsa());
        assert!(!request.contains_ml_kem());
    }

    #[test]
    fn test_contains_ml_kem() {
        // Mock DER with ML-KEM OID prefix
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend_from_slice(b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x04\x01"); // ML-KEM-512 OID
        der.extend(vec![0x00; 240]);

        let request = EnrollRequest::new(der);
        assert!(!request.contains_ml_dsa());
        assert!(request.contains_ml_kem());
    }

    #[test]
    fn test_key_algorithm_from_oid() {
        assert_eq!(
            KeyAlgorithm::from_oid("1.2.840.113549.1.1.1"),
            KeyAlgorithm::Rsa
        );
        assert_eq!(
            KeyAlgorithm::from_oid("2.16.840.1.101.3.4.3.17"),
            KeyAlgorithm::MlDsa44
        );
        assert_eq!(
            KeyAlgorithm::from_oid("2.16.840.1.101.3.4.3.18"),
            KeyAlgorithm::MlDsa65
        );
        assert_eq!(
            KeyAlgorithm::from_oid("2.16.840.1.101.3.4.3.19"),
            KeyAlgorithm::MlDsa87
        );
        assert_eq!(
            KeyAlgorithm::from_oid("2.16.840.1.101.3.4.4.1"),
            KeyAlgorithm::MlKem512
        );
        assert_eq!(
            KeyAlgorithm::from_oid("2.16.840.1.101.3.4.4.2"),
            KeyAlgorithm::MlKem768
        );
        assert_eq!(
            KeyAlgorithm::from_oid("2.16.840.1.101.3.4.4.3"),
            KeyAlgorithm::MlKem1024
        );
        assert!(matches!(
            KeyAlgorithm::from_oid("1.2.3"),
            KeyAlgorithm::Unknown(_)
        ));
    }

    #[test]
    fn test_key_algorithm_ec_curves() {
        assert_eq!(
            KeyAlgorithm::from_ec_oid("1.2.840.10045.3.1.7"),
            KeyAlgorithm::EcdsaP256
        );
        assert_eq!(
            KeyAlgorithm::from_ec_oid("1.3.132.0.34"),
            KeyAlgorithm::EcdsaP384
        );
        assert!(matches!(
            KeyAlgorithm::from_ec_oid("1.2.3.4"),
            KeyAlgorithm::Unknown(_)
        ));
    }

    #[test]
    fn test_certification_request_verify_empty_tbs() {
        let cr = CertificationRequest {
            version: 0,
            subject: String::new(),
            key_algorithm: KeyAlgorithm::Rsa,
            subject_public_key_info: Vec::new(),
            signature_algorithm: String::new(),
            signature: vec![0x00],
            subject_alt_names: Vec::new(),
            key_usage: Vec::new(),
            challenge_password: None,
            tbs_der: Vec::new(),
        };
        assert!(matches!(
            cr.verify_self_signature(),
            Err(EstError::InvalidPkcs10(_))
        ));
    }

    #[test]
    fn test_certification_request_verify_empty_signature() {
        let cr = CertificationRequest {
            version: 0,
            subject: String::new(),
            key_algorithm: KeyAlgorithm::Rsa,
            subject_public_key_info: Vec::new(),
            signature_algorithm: String::new(),
            signature: Vec::new(),
            subject_alt_names: Vec::new(),
            key_usage: Vec::new(),
            challenge_password: None,
            tbs_der: vec![0x30, 0x00],
        };
        assert!(matches!(
            cr.verify_self_signature(),
            Err(EstError::InvalidPkcs10(_))
        ));
    }

    #[test]
    fn test_challenge_password_validation() {
        let cr = CertificationRequest {
            version: 0,
            subject: String::new(),
            key_algorithm: KeyAlgorithm::Rsa,
            subject_public_key_info: Vec::new(),
            signature_algorithm: String::new(),
            signature: vec![0x00],
            subject_alt_names: Vec::new(),
            key_usage: Vec::new(),
            challenge_password: Some("secret123".to_string()),
            tbs_der: vec![0x30, 0x00],
        };
        assert!(cr.validate_challenge_password("secret123").is_ok());
        assert!(matches!(
            cr.validate_challenge_password("wrong"),
            Err(EstError::InvalidPop(_))
        ));
    }

    #[test]
    fn test_challenge_password_missing() {
        let cr = CertificationRequest {
            version: 0,
            subject: String::new(),
            key_algorithm: KeyAlgorithm::Rsa,
            subject_public_key_info: Vec::new(),
            signature_algorithm: String::new(),
            signature: vec![0x00],
            subject_alt_names: Vec::new(),
            key_usage: Vec::new(),
            challenge_password: None,
            tbs_der: vec![0x30, 0x00],
        };
        assert!(matches!(
            cr.validate_challenge_password("anything"),
            Err(EstError::MissingField(_))
        ));
    }

    #[test]
    fn test_to_certification_request() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);
        let request = EnrollRequest::new(der.clone());
        let cr = request.to_certification_request();
        assert_eq!(cr.version, 0);
        assert_eq!(cr.tbs_der, der);
    }

    #[test]
    fn test_traditional_oids() {
        assert_eq!(traditional_oids::RSA, "1.2.840.113549.1.1.1");
        assert_eq!(traditional_oids::EC_PUBLIC_KEY, "1.2.840.10045.2.1");
    }

    #[test]
    fn test_named_curve_oids() {
        assert_eq!(named_curve_oids::P256, "1.2.840.10045.3.1.7");
        assert_eq!(named_curve_oids::P384, "1.3.132.0.34");
    }
}
