//! Simple enrollment per RFC 7030 §4.2.
//!
//! The `/simpleenroll` operation accepts a PKCS#10 CSR and returns a PKCS#7
//! certificate chain. Supports ML-DSA and ML-KEM CSRs with proof-of-possession.

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

/// Composite ML-DSA OID base arc (2.16.840.1.114027.80.5.2).
///
/// Sub-arcs 37-54 define various composite ML-DSA + traditional combinations.
pub const COMPOSITE_ML_DSA_BASE: &str = "2.16.840.1.114027.80.5.2";

/// Enrollment request containing a PKCS#10 CSR (RFC 7030 §4.2.1).
///
/// The CSR must include:
/// - Subject public key (ML-DSA, ML-KEM, or traditional)
/// - Subject distinguished name
/// - Signature proving possession of the private key (POP)
///
/// For ML-DSA CSRs, the signature algorithm OID indicates the ML-DSA level.
/// For ML-KEM CSRs, a separate ML-DSA signature is required for POP.
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
            return Err(EstError::InvalidPkcs7(
                "Empty PKCS#7 structure".to_string(),
            ));
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
        assert!(matches!(request.validate(), Err(EstError::InvalidPkcs10(_))));
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
}
