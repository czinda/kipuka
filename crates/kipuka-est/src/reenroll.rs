//! Simple re-enrollment per RFC 7030 §4.2.2.
//!
//! The `/simplereenroll` operation renews an existing certificate using mTLS.
//! The subject in the CSR must match the mTLS client certificate subject.

use crate::enroll::{EnrollRequest, EnrollResponse};
use crate::{EstError, EstResult};
use serde::{Deserialize, Serialize};

/// Re-enrollment request (RFC 7030 §4.2.2).
///
/// Identical wire format to `EnrollRequest`, but with additional requirements:
/// - The client MUST present a valid certificate via mTLS
/// - The CSR subject MUST match the mTLS certificate subject
/// - The CSR public key MAY differ (key rotation)
///
/// Subject matching is enforced by the EST server before processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReenrollRequest {
    /// Inner enrollment request (PKCS#10 CSR).
    #[serde(flatten)]
    inner: EnrollRequest,
}

impl ReenrollRequest {
    /// Creates a new re-enrollment request from a DER-encoded PKCS#10 CSR.
    pub fn new(csr_der: Vec<u8>) -> Self {
        Self {
            inner: EnrollRequest::new(csr_der),
        }
    }

    /// Creates from an existing `EnrollRequest`.
    pub fn from_enroll_request(inner: EnrollRequest) -> Self {
        Self { inner }
    }

    /// Returns the inner enrollment request.
    pub fn inner(&self) -> &EnrollRequest {
        &self.inner
    }

    /// Consumes self and returns the inner enrollment request.
    pub fn into_inner(self) -> EnrollRequest {
        self.inner
    }

    /// Returns the raw DER-encoded CSR.
    pub fn csr_der(&self) -> &[u8] {
        self.inner.csr_der()
    }

    /// Consumes self and returns the DER-encoded CSR.
    pub fn into_csr_der(self) -> Vec<u8> {
        self.inner.into_csr_der()
    }

    /// Encodes the request as base64 for HTTP transport.
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    /// Decodes a base64-encoded re-enrollment request.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let inner = EnrollRequest::from_base64(base64_data)?;
        Ok(Self { inner })
    }

    /// Validates the CSR structure.
    pub fn validate(&self) -> EstResult<()> {
        self.inner.validate()
    }

    /// Validates subject matching between CSR and mTLS client certificate.
    ///
    /// # Arguments
    ///
    /// * `mtls_subject` - Distinguished name from mTLS client certificate
    /// * `csr_subject` - Distinguished name from CSR (parsed by caller)
    ///
    /// # Errors
    ///
    /// Returns `EstError::SubjectMismatch` if subjects don't match.
    ///
    /// # Note
    ///
    /// Subject parsing is delegated to the caller (CA module) since it requires
    /// full X.509 ASN.1 parsing. This method only compares the pre-parsed values.
    pub fn validate_subject_match(
        &self,
        mtls_subject: &str,
        csr_subject: &str,
    ) -> EstResult<()> {
        if mtls_subject != csr_subject {
            return Err(EstError::SubjectMismatch {
                expected: mtls_subject.to_string(),
                actual: csr_subject.to_string(),
            });
        }
        Ok(())
    }

    /// Checks if the CSR appears to contain an ML-DSA public key.
    pub fn contains_ml_dsa(&self) -> bool {
        self.inner.contains_ml_dsa()
    }

    /// Checks if the CSR appears to contain an ML-KEM public key.
    pub fn contains_ml_kem(&self) -> bool {
        self.inner.contains_ml_kem()
    }
}

/// Re-enrollment response (RFC 7030 §4.2.2).
///
/// Identical wire format to `EnrollResponse`. Contains the renewed certificate
/// chain as a PKCS#7 certs-only structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReenrollResponse {
    /// Inner enrollment response (PKCS#7 cert chain).
    #[serde(flatten)]
    inner: EnrollResponse,
}

impl ReenrollResponse {
    /// Creates a new re-enrollment response from DER-encoded PKCS#7.
    pub fn new(pkcs7_der: Vec<u8>) -> Self {
        Self {
            inner: EnrollResponse::new(pkcs7_der),
        }
    }

    /// Creates from an existing `EnrollResponse`.
    pub fn from_enroll_response(inner: EnrollResponse) -> Self {
        Self { inner }
    }

    /// Returns the inner enrollment response.
    pub fn inner(&self) -> &EnrollResponse {
        &self.inner
    }

    /// Consumes self and returns the inner enrollment response.
    pub fn into_inner(self) -> EnrollResponse {
        self.inner
    }

    /// Returns the raw DER-encoded PKCS#7 data.
    pub fn pkcs7_der(&self) -> &[u8] {
        self.inner.pkcs7_der()
    }

    /// Consumes self and returns the DER-encoded PKCS#7 data.
    pub fn into_pkcs7_der(self) -> Vec<u8> {
        self.inner.into_pkcs7_der()
    }

    /// Encodes the response as base64 for HTTP transport.
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    /// Decodes a base64-encoded re-enrollment response.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let inner = EnrollResponse::from_base64(base64_data)?;
        Ok(Self { inner })
    }

    /// Validates the PKCS#7 structure.
    pub fn validate(&self) -> EstResult<()> {
        self.inner.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reenroll_request_roundtrip() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let request = ReenrollRequest::new(der.clone());
        assert_eq!(request.csr_der(), &der);

        let base64 = request.to_base64();
        let decoded = ReenrollRequest::from_base64(&base64).unwrap();
        assert_eq!(decoded.csr_der(), &der);
    }

    #[test]
    fn test_reenroll_response_roundtrip() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let response = ReenrollResponse::new(der.clone());
        assert_eq!(response.pkcs7_der(), &der);

        let base64 = response.to_base64();
        let decoded = ReenrollResponse::from_base64(&base64).unwrap();
        assert_eq!(decoded.pkcs7_der(), &der);
    }

    #[test]
    fn test_subject_match_success() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let request = ReenrollRequest::new(der);
        let mtls_subject = "CN=client.example.com,O=Example,C=US";
        let csr_subject = "CN=client.example.com,O=Example,C=US";

        assert!(request
            .validate_subject_match(mtls_subject, csr_subject)
            .is_ok());
    }

    #[test]
    fn test_subject_match_failure() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let request = ReenrollRequest::new(der);
        let mtls_subject = "CN=client.example.com,O=Example,C=US";
        let csr_subject = "CN=attacker.evil.com,O=Evil,C=XX";

        let result = request.validate_subject_match(mtls_subject, csr_subject);
        assert!(matches!(result, Err(EstError::SubjectMismatch { .. })));

        if let Err(EstError::SubjectMismatch { expected, actual }) = result {
            assert_eq!(expected, mtls_subject);
            assert_eq!(actual, csr_subject);
        }
    }

    #[test]
    fn test_from_enroll_request() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let enroll_req = EnrollRequest::new(der.clone());
        let reenroll_req = ReenrollRequest::from_enroll_request(enroll_req);

        assert_eq!(reenroll_req.csr_der(), &der);
    }

    #[test]
    fn test_from_enroll_response() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let enroll_resp = EnrollResponse::new(der.clone());
        let reenroll_resp = ReenrollResponse::from_enroll_response(enroll_resp);

        assert_eq!(reenroll_resp.pkcs7_der(), &der);
    }

    #[test]
    fn test_validate() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(vec![0x00; 252]);

        let request = ReenrollRequest::new(der);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_ml_dsa_detection() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend_from_slice(b"\x06\x0b\x60\x86\x48\x01\x65\x03\x04\x03\x11");
        der.extend(vec![0x00; 240]);

        let request = ReenrollRequest::new(der);
        assert!(request.contains_ml_dsa());
        assert!(!request.contains_ml_kem());
    }
}
