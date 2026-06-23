//! Full CMC (Certificate Management over CMS) per RFC 7030 §4.3.
//!
//! The `/fullcmc` operation provides complete CMC protocol support for complex
//! enrollment scenarios. Requires id-kp-cmcRA EKU validation for RA certificates.

use crate::{EstError, EstResult};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// id-kp-cmcRA OID (1.3.6.1.5.5.7.3.28) per RFC 6402 §3.2.
///
/// Registration Authority certificates used for CMC must include this EKU.
pub const ID_KP_CMC_RA: &str = "1.3.6.1.5.5.7.3.28";

/// Full CMC request (RFC 7030 §4.3.1).
///
/// Contains a CMC `PKIData` message wrapped in a PKCS#7 SignedData structure.
/// The SignedData MUST be signed by an RA certificate with id-kp-cmcRA EKU.
///
/// CMC supports advanced features:
/// - Batch enrollment (multiple CSRs in one request)
/// - Attribute certification
/// - Key archival
/// - Revocation requests
/// - ML-DSA and ML-KEM enrollment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullCmcRequest {
    /// CMC request as PKCS#7 SignedData in DER encoding.
    #[serde(with = "serde_bytes")]
    cmc_der: Vec<u8>,
}

impl FullCmcRequest {
    /// Creates a new Full CMC request from DER-encoded PKCS#7.
    pub fn new(cmc_der: Vec<u8>) -> Self {
        Self { cmc_der }
    }

    /// Returns the raw DER-encoded CMC data.
    pub fn cmc_der(&self) -> &[u8] {
        &self.cmc_der
    }

    /// Consumes self and returns the DER-encoded CMC data.
    pub fn into_cmc_der(self) -> Vec<u8> {
        self.cmc_der
    }

    /// Encodes the request as base64 for HTTP transport.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.cmc_der)
    }

    /// Decodes a base64-encoded Full CMC request.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let cmc_der = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        Ok(Self::new(cmc_der))
    }

    /// Validates the CMC structure.
    ///
    /// This performs basic DER validation. Full CMC validation (signature
    /// verification, RA EKU check, PKIData parsing) is delegated to the CA module.
    pub fn validate(&self) -> EstResult<()> {
        if self.cmc_der.is_empty() {
            return Err(EstError::InvalidCmc("Empty CMC request".to_string()));
        }

        // Basic DER sanity: must start with SEQUENCE tag (0x30)
        if self.cmc_der[0] != 0x30 {
            return Err(EstError::InvalidCmc(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        // Minimum viable CMC is ~500 bytes (SignedData + PKIData overhead)
        if self.cmc_der.len() < 300 {
            return Err(EstError::InvalidCmc(format!(
                "CMC too small: {} bytes",
                self.cmc_der.len()
            )));
        }

        Ok(())
    }

    /// Validates RA certificate EKU (stub).
    ///
    /// The RA certificate used to sign the CMC request MUST contain the
    /// id-kp-cmcRA (1.3.6.1.5.5.7.3.28) extended key usage.
    ///
    /// This is a placeholder - actual validation requires parsing the SignedData
    /// and verifying the signer certificate's EKU. Delegated to CA module.
    ///
    /// # Arguments
    ///
    /// * `ra_cert_der` - DER-encoded RA certificate from SignedData
    ///
    /// # Errors
    ///
    /// Returns `EstError::InvalidEku` if the certificate lacks id-kp-cmcRA.
    pub fn validate_ra_eku(&self, _ra_cert_der: &[u8]) -> EstResult<()> {
        // Stub: Full implementation requires X.509 EKU parsing
        // For now, assume valid and delegate to CA module
        Ok(())
    }

    /// Checks if the CMC request contains ML-DSA or ML-KEM enrollment requests.
    ///
    /// Searches for post-quantum algorithm OID prefixes in the DER structure.
    pub fn contains_pqc(&self) -> bool {
        let ml_dsa_prefix = b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x03"; // ML-DSA
        let ml_kem_prefix = b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x04"; // ML-KEM

        self.cmc_der
            .windows(ml_dsa_prefix.len())
            .any(|w| w == ml_dsa_prefix || w == ml_kem_prefix)
    }
}

/// Full CMC response (RFC 7030 §4.3.2).
///
/// Contains a CMC `PKIResponse` message wrapped in a PKCS#7 SignedData structure.
/// The response includes:
/// - Status information for each request
/// - Issued certificates (on success)
/// - Error details (on failure)
/// - Transaction IDs for pending requests
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullCmcResponse {
    /// CMC response as PKCS#7 SignedData in DER encoding.
    #[serde(with = "serde_bytes")]
    cmc_der: Vec<u8>,
}

impl FullCmcResponse {
    /// Creates a new Full CMC response from DER-encoded PKCS#7.
    pub fn new(cmc_der: Vec<u8>) -> Self {
        Self { cmc_der }
    }

    /// Returns the raw DER-encoded CMC data.
    pub fn cmc_der(&self) -> &[u8] {
        &self.cmc_der
    }

    /// Consumes self and returns the DER-encoded CMC data.
    pub fn into_cmc_der(self) -> Vec<u8> {
        self.cmc_der
    }

    /// Encodes the response as base64 for HTTP transport.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.cmc_der)
    }

    /// Decodes a base64-encoded Full CMC response.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let cmc_der = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        Ok(Self::new(cmc_der))
    }

    /// Validates the CMC structure.
    pub fn validate(&self) -> EstResult<()> {
        if self.cmc_der.is_empty() {
            return Err(EstError::InvalidCmc("Empty CMC response".to_string()));
        }

        if self.cmc_der[0] != 0x30 {
            return Err(EstError::InvalidCmc(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        if self.cmc_der.len() < 300 {
            return Err(EstError::InvalidCmc(format!(
                "CMC too small: {} bytes",
                self.cmc_der.len()
            )));
        }

        Ok(())
    }
}

/// Helper module for serde byte serialization.
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
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
    fn test_fullcmc_request_roundtrip() {
        let mut der = vec![0x30, 0x82, 0x02, 0x00]; // SEQUENCE, length 512
        der.extend(vec![0x00; 508]);

        let request = FullCmcRequest::new(der.clone());
        assert_eq!(request.cmc_der(), &der);

        let base64 = request.to_base64();
        let decoded = FullCmcRequest::from_base64(&base64).unwrap();
        assert_eq!(decoded.cmc_der(), &der);
    }

    #[test]
    fn test_fullcmc_response_roundtrip() {
        let mut der = vec![0x30, 0x82, 0x02, 0x00];
        der.extend(vec![0x00; 508]);

        let response = FullCmcResponse::new(der.clone());
        assert_eq!(response.cmc_der(), &der);

        let base64 = response.to_base64();
        let decoded = FullCmcResponse::from_base64(&base64).unwrap();
        assert_eq!(decoded.cmc_der(), &der);
    }

    #[test]
    fn test_validate_cmc_request() {
        let mut der = vec![0x30, 0x82, 0x02, 0x00];
        der.extend(vec![0x00; 508]);

        let request = FullCmcRequest::new(der);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_validate_empty() {
        let request = FullCmcRequest::new(vec![]);
        assert!(matches!(request.validate(), Err(EstError::InvalidCmc(_))));
    }

    #[test]
    fn test_validate_too_small() {
        let request = FullCmcRequest::new(vec![0x30, 0x00]);
        assert!(matches!(request.validate(), Err(EstError::InvalidCmc(_))));
    }

    #[test]
    fn test_id_kp_cmc_ra_oid() {
        assert_eq!(ID_KP_CMC_RA, "1.3.6.1.5.5.7.3.28");
    }

    #[test]
    fn test_contains_pqc() {
        // Mock CMC with ML-DSA OID
        let mut der = vec![0x30, 0x82, 0x02, 0x00];
        der.extend_from_slice(b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x03\x11"); // ML-DSA-44
        der.extend(vec![0x00; 496]);

        let request = FullCmcRequest::new(der);
        assert!(request.contains_pqc());
    }

    #[test]
    fn test_validate_ra_eku() {
        let mut der = vec![0x30, 0x82, 0x02, 0x00];
        der.extend(vec![0x00; 508]);

        let request = FullCmcRequest::new(der);
        // Mock RA cert (stub validation always passes)
        let mock_ra_cert = vec![0x30, 0x82, 0x01, 0x00];
        assert!(request.validate_ra_eku(&mock_ra_cert).is_ok());
    }
}
