//! CA Certificates response per RFC 7030 §4.1.
//!
//! The `/cacerts` operation returns a PKCS#7 certs-only structure containing
//! the CA certificate chain. Supports both traditional and ML-DSA CA certificates.

use crate::{EstError, EstResult};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// CA certificates response (RFC 7030 §4.1.3).
///
/// Contains a PKCS#7 `certs-only` structure with the CA certificate chain.
/// The chain MAY include:
/// - Root CA certificate (self-signed)
/// - Intermediate CA certificates
/// - ML-DSA signing CA certificates
/// - Composite (ML-DSA + traditional) CA certificates
///
/// The structure is DER-encoded and base64-wrapped for transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaCertsResponse {
    /// PKCS#7 certs-only message in DER encoding.
    #[serde(with = "serde_bytes")]
    pkcs7_der: Vec<u8>,
}

impl CaCertsResponse {
    /// Creates a new CA certificates response from DER-encoded PKCS#7.
    ///
    /// # Arguments
    ///
    /// * `pkcs7_der` - DER-encoded PKCS#7 certs-only structure
    ///
    /// # Returns
    ///
    /// A new `CaCertsResponse` instance.
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
    ///
    /// Uses standard base64 encoding per RFC 7030 §4.1.3.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.pkcs7_der)
    }

    /// Decodes a base64-encoded CA certificates response.
    ///
    /// # Arguments
    ///
    /// * `base64_data` - Base64-encoded PKCS#7 certs-only structure
    ///
    /// # Errors
    ///
    /// Returns `EstError::InvalidBase64` if decoding fails.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let pkcs7_der = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        Ok(Self::new(pkcs7_der))
    }

    /// Validates the PKCS#7 structure (basic DER sanity check).
    ///
    /// This is a lightweight validation that checks for basic DER structure.
    /// Full cryptographic validation is performed by the CA module.
    pub fn validate(&self) -> EstResult<()> {
        // Basic DER sanity: must start with SEQUENCE tag (0x30)
        if self.pkcs7_der.is_empty() {
            return Err(EstError::InvalidPkcs7("Empty PKCS#7 structure".to_string()));
        }

        if self.pkcs7_der[0] != 0x30 {
            return Err(EstError::InvalidPkcs7(
                "Invalid DER: expected SEQUENCE tag".to_string(),
            ));
        }

        // Minimum viable PKCS#7 certs-only is ~100 bytes
        if self.pkcs7_der.len() < 50 {
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
    fn test_cacerts_roundtrip() {
        // Minimal valid DER SEQUENCE (mock PKCS#7)
        let der = vec![0x30, 0x82, 0x01, 0x00]; // SEQUENCE, length 256 (placeholder)
        let mut full_der = der.clone();
        full_der.extend(vec![0x00; 252]); // Pad to 256 bytes

        let response = CaCertsResponse::new(full_der.clone());
        assert_eq!(response.pkcs7_der(), &full_der);

        let base64 = response.to_base64();
        let decoded = CaCertsResponse::from_base64(&base64).unwrap();
        assert_eq!(decoded.pkcs7_der(), &full_der);
    }

    #[test]
    fn test_invalid_base64() {
        let result = CaCertsResponse::from_base64("not-valid-base64!!!");
        assert!(matches!(result, Err(EstError::InvalidBase64(_))));
    }

    #[test]
    fn test_validate_empty() {
        let response = CaCertsResponse::new(vec![]);
        assert!(matches!(
            response.validate(),
            Err(EstError::InvalidPkcs7(_))
        ));
    }

    #[test]
    fn test_validate_wrong_tag() {
        let response = CaCertsResponse::new(vec![0x04, 0x00]); // OCTET STRING instead of SEQUENCE
        assert!(matches!(
            response.validate(),
            Err(EstError::InvalidPkcs7(_))
        ));
    }

    #[test]
    fn test_validate_too_small() {
        let response = CaCertsResponse::new(vec![0x30, 0x00]); // Valid SEQUENCE but too small
        assert!(matches!(
            response.validate(),
            Err(EstError::InvalidPkcs7(_))
        ));
    }
}
