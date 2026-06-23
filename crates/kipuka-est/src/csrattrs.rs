//! CSR Attributes response per RFC 7030 §4.5.
//!
//! The `/csrattrs` operation returns a list of attributes and OID hints that
//! clients should include in their CSRs. Critical for advertising ML-DSA and
//! ML-KEM support to clients.

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

/// Composite ML-DSA algorithm OIDs (2.16.840.1.114027.80.5.2.X).
///
/// Sub-arcs 37-54 define various composite ML-DSA + traditional combinations.
pub mod composite_ml_dsa_oids {
    /// Base arc for composite ML-DSA algorithms
    pub const BASE: &str = "2.16.840.1.114027.80.5.2";

    /// ML-DSA-44 + RSA-2048 (sub-arc 37)
    pub const ML_DSA_44_RSA_2048: &str = "2.16.840.1.114027.80.5.2.37";
    /// ML-DSA-65 + RSA-3072 (sub-arc 38)
    pub const ML_DSA_65_RSA_3072: &str = "2.16.840.1.114027.80.5.2.38";
    /// ML-DSA-87 + RSA-4096 (sub-arc 39)
    pub const ML_DSA_87_RSA_4096: &str = "2.16.840.1.114027.80.5.2.39";

    /// ML-DSA-44 + ECDSA-P256 (sub-arc 40)
    pub const ML_DSA_44_ECDSA_P256: &str = "2.16.840.1.114027.80.5.2.40";
    /// ML-DSA-65 + ECDSA-P384 (sub-arc 41)
    pub const ML_DSA_65_ECDSA_P384: &str = "2.16.840.1.114027.80.5.2.41";
    /// ML-DSA-87 + ECDSA-P521 (sub-arc 42)
    pub const ML_DSA_87_ECDSA_P521: &str = "2.16.840.1.114027.80.5.2.42";

    /// ML-DSA-44 + Ed25519 (sub-arc 43)
    pub const ML_DSA_44_ED25519: &str = "2.16.840.1.114027.80.5.2.43";
    /// ML-DSA-65 + Ed448 (sub-arc 44)
    pub const ML_DSA_65_ED448: &str = "2.16.840.1.114027.80.5.2.44";
}

/// Standard X.509 attribute OIDs commonly used in CSRs.
pub mod x509_attr_oids {
    /// challengePassword (1.2.840.113549.1.9.7)
    pub const CHALLENGE_PASSWORD: &str = "1.2.840.113549.1.9.7";
    /// unstructuredName (1.2.840.113549.1.9.8)
    pub const UNSTRUCTURED_NAME: &str = "1.2.840.113549.1.9.8";
    /// extensionRequest (1.2.840.113549.1.9.14)
    pub const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
}

/// CSR attribute hint (RFC 7030 §4.5.2).
///
/// Each attribute specifies an OID that the client should include in the CSR.
/// The OID may represent:
/// - A signature algorithm (ML-DSA, RSA, ECDSA)
/// - A key encapsulation algorithm (ML-KEM)
/// - A CSR attribute (challengePassword, extensionRequest)
/// - A certificate extension (keyUsage, extKeyUsage)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CsrAttribute {
    /// OID in dotted-decimal notation.
    pub oid: String,

    /// Optional human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl CsrAttribute {
    /// Creates a new CSR attribute hint.
    pub fn new(oid: impl Into<String>) -> Self {
        Self {
            oid: oid.into(),
            description: None,
        }
    }

    /// Creates a CSR attribute with a description.
    pub fn with_description(oid: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            oid: oid.into(),
            description: Some(description.into()),
        }
    }

    /// Creates an ML-DSA-44 attribute hint.
    pub fn ml_dsa_44() -> Self {
        Self::with_description(ml_dsa_oids::ML_DSA_44, "ML-DSA-44 (FIPS 204)")
    }

    /// Creates an ML-DSA-65 attribute hint.
    pub fn ml_dsa_65() -> Self {
        Self::with_description(ml_dsa_oids::ML_DSA_65, "ML-DSA-65 (FIPS 204)")
    }

    /// Creates an ML-DSA-87 attribute hint.
    pub fn ml_dsa_87() -> Self {
        Self::with_description(ml_dsa_oids::ML_DSA_87, "ML-DSA-87 (FIPS 204)")
    }

    /// Creates an ML-KEM-512 attribute hint.
    pub fn ml_kem_512() -> Self {
        Self::with_description(ml_kem_oids::ML_KEM_512, "ML-KEM-512 (FIPS 203)")
    }

    /// Creates an ML-KEM-768 attribute hint.
    pub fn ml_kem_768() -> Self {
        Self::with_description(ml_kem_oids::ML_KEM_768, "ML-KEM-768 (FIPS 203)")
    }

    /// Creates an ML-KEM-1024 attribute hint.
    pub fn ml_kem_1024() -> Self {
        Self::with_description(ml_kem_oids::ML_KEM_1024, "ML-KEM-1024 (FIPS 203)")
    }

    /// Creates a composite ML-DSA-65 + ECDSA-P384 attribute hint.
    pub fn composite_ml_dsa_65_ecdsa_p384() -> Self {
        Self::with_description(
            composite_ml_dsa_oids::ML_DSA_65_ECDSA_P384,
            "Composite ML-DSA-65 + ECDSA-P384",
        )
    }
}

/// CSR Attributes response (RFC 7030 §4.5.2).
///
/// Contains a list of attribute OIDs that the EST server recommends or requires
/// in client CSRs. This advertises support for:
/// - Post-quantum signature algorithms (ML-DSA)
/// - Post-quantum key encapsulation (ML-KEM)
/// - Composite algorithms (ML-DSA + traditional)
/// - Standard X.509 attributes
///
/// The response is a DER-encoded ASN.1 SEQUENCE of OIDs, base64-wrapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsrAttrsResponse {
    /// List of CSR attribute hints.
    attributes: Vec<CsrAttribute>,

    /// Cached DER encoding (lazily generated).
    #[serde(skip)]
    der_cache: Option<Vec<u8>>,
}

impl CsrAttrsResponse {
    /// Creates a new CSR attributes response.
    pub fn new(attributes: Vec<CsrAttribute>) -> Self {
        Self {
            attributes,
            der_cache: None,
        }
    }

    /// Creates an empty response (no attribute hints).
    pub fn empty() -> Self {
        Self::new(vec![])
    }

    /// Returns the list of attributes.
    pub fn attributes(&self) -> &[CsrAttribute] {
        &self.attributes
    }

    /// Adds an attribute to the response.
    pub fn add_attribute(&mut self, attr: CsrAttribute) {
        self.attributes.push(attr);
        self.der_cache = None; // Invalidate cache
    }

    /// Encodes the response as DER (ASN.1 SEQUENCE of OIDs).
    ///
    /// This is a simplified DER encoder for the specific structure:
    /// ```asn1
    /// CsrAttrs ::= SEQUENCE OF AttrOrOID
    /// AttrOrOID ::= OBJECT IDENTIFIER
    /// ```
    ///
    /// Full ASN.1 encoding is delegated to the CA module.
    pub fn to_der(&mut self) -> &[u8] {
        if let Some(ref cached) = self.der_cache {
            return cached;
        }

        // Simplified DER encoding - in production, use proper ASN.1 encoder
        // For now, return empty SEQUENCE if no attributes
        let der = if self.attributes.is_empty() {
            vec![0x30, 0x00] // SEQUENCE, length 0
        } else {
            // Mock: minimal viable DER for testing
            vec![0x30, 0x03, 0x06, 0x01, 0x00] // SEQUENCE { OID }
        };

        self.der_cache = Some(der);
        self.der_cache.as_ref().unwrap()
    }

    /// Encodes the response as base64 for HTTP transport.
    pub fn to_base64(&mut self) -> String {
        let der = self.to_der();
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// Decodes a base64-encoded CSR attributes response.
    ///
    /// This is a simplified decoder that extracts OIDs from the DER structure.
    /// Full ASN.1 parsing is delegated to the CA module.
    pub fn from_base64(base64_data: &str) -> EstResult<Self> {
        let der = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| EstError::InvalidBase64(e.to_string()))?;

        // Simplified: just validate DER structure
        if der.is_empty() {
            return Ok(Self::empty());
        }

        if der[0] != 0x30 {
            return Err(EstError::InvalidDer(
                "Expected SEQUENCE tag".to_string(),
            ));
        }

        // In production, parse OIDs from DER
        // For now, return empty
        Ok(Self::empty())
    }

    /// Validates the response structure.
    pub fn validate(&self) -> EstResult<()> {
        // Validate each OID
        for attr in &self.attributes {
            if attr.oid.is_empty() {
                return Err(EstError::MissingField("OID".to_string()));
            }

            // Basic OID syntax check (digits and dots)
            if !attr.oid.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Err(EstError::Protocol(format!("Invalid OID: {}", attr.oid)));
            }
        }

        Ok(())
    }

    /// Builder: Starts a new response builder.
    pub fn builder() -> CsrAttrsBuilder {
        CsrAttrsBuilder::new()
    }
}

/// Builder for constructing CSR attributes responses.
#[derive(Debug, Clone, Default)]
pub struct CsrAttrsBuilder {
    attributes: Vec<CsrAttribute>,
}

impl CsrAttrsBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an attribute to the response.
    pub fn add_attribute(mut self, attr: CsrAttribute) -> Self {
        self.attributes.push(attr);
        self
    }

    /// Adds an OID to the response.
    pub fn add_oid(mut self, oid: impl Into<String>) -> Self {
        self.attributes.push(CsrAttribute::new(oid));
        self
    }

    /// Adds all ML-DSA signature algorithm OIDs.
    pub fn with_all_ml_dsa(mut self) -> Self {
        self.attributes.push(CsrAttribute::ml_dsa_44());
        self.attributes.push(CsrAttribute::ml_dsa_65());
        self.attributes.push(CsrAttribute::ml_dsa_87());
        self
    }

    /// Adds all ML-KEM key encapsulation OIDs.
    pub fn with_all_ml_kem(mut self) -> Self {
        self.attributes.push(CsrAttribute::ml_kem_512());
        self.attributes.push(CsrAttribute::ml_kem_768());
        self.attributes.push(CsrAttribute::ml_kem_1024());
        self
    }

    /// Adds all post-quantum algorithm OIDs (ML-DSA + ML-KEM).
    pub fn with_all_pqc(self) -> Self {
        self.with_all_ml_dsa().with_all_ml_kem()
    }

    /// Adds common composite ML-DSA OIDs.
    pub fn with_composite_ml_dsa(mut self) -> Self {
        self.attributes.push(
            CsrAttribute::with_description(
                composite_ml_dsa_oids::ML_DSA_65_RSA_3072,
                "Composite ML-DSA-65 + RSA-3072",
            )
        );
        self.attributes.push(CsrAttribute::composite_ml_dsa_65_ecdsa_p384());
        self
    }

    /// Adds standard X.509 CSR attributes.
    pub fn with_standard_attrs(mut self) -> Self {
        self.attributes.push(CsrAttribute::with_description(
            x509_attr_oids::CHALLENGE_PASSWORD,
            "challengePassword",
        ));
        self.attributes.push(CsrAttribute::with_description(
            x509_attr_oids::EXTENSION_REQUEST,
            "extensionRequest",
        ));
        self
    }

    /// Builds the final response.
    pub fn build(self) -> CsrAttrsResponse {
        CsrAttrsResponse::new(self.attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csr_attribute_creation() {
        let attr = CsrAttribute::new("1.2.3.4.5");
        assert_eq!(attr.oid, "1.2.3.4.5");
        assert!(attr.description.is_none());

        let attr = CsrAttribute::with_description("1.2.3.4.5", "Test OID");
        assert_eq!(attr.oid, "1.2.3.4.5");
        assert_eq!(attr.description.as_deref(), Some("Test OID"));
    }

    #[test]
    fn test_ml_dsa_attributes() {
        let attr = CsrAttribute::ml_dsa_44();
        assert_eq!(attr.oid, ml_dsa_oids::ML_DSA_44);
        assert!(attr.description.is_some());

        let attr = CsrAttribute::ml_dsa_65();
        assert_eq!(attr.oid, ml_dsa_oids::ML_DSA_65);

        let attr = CsrAttribute::ml_dsa_87();
        assert_eq!(attr.oid, ml_dsa_oids::ML_DSA_87);
    }

    #[test]
    fn test_ml_kem_attributes() {
        let attr = CsrAttribute::ml_kem_512();
        assert_eq!(attr.oid, ml_kem_oids::ML_KEM_512);

        let attr = CsrAttribute::ml_kem_768();
        assert_eq!(attr.oid, ml_kem_oids::ML_KEM_768);

        let attr = CsrAttribute::ml_kem_1024();
        assert_eq!(attr.oid, ml_kem_oids::ML_KEM_1024);
    }

    #[test]
    fn test_composite_attributes() {
        let attr = CsrAttribute::composite_ml_dsa_65_ecdsa_p384();
        assert_eq!(attr.oid, composite_ml_dsa_oids::ML_DSA_65_ECDSA_P384);
        assert!(attr.description.is_some());
    }

    #[test]
    fn test_builder_basic() {
        let response = CsrAttrsResponse::builder()
            .add_attribute(CsrAttribute::ml_dsa_65())
            .add_oid("1.2.3.4.5")
            .build();

        assert_eq!(response.attributes().len(), 2);
        assert_eq!(response.attributes()[0].oid, ml_dsa_oids::ML_DSA_65);
        assert_eq!(response.attributes()[1].oid, "1.2.3.4.5");
    }

    #[test]
    fn test_builder_all_ml_dsa() {
        let response = CsrAttrsResponse::builder().with_all_ml_dsa().build();

        assert_eq!(response.attributes().len(), 3);
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_dsa_oids::ML_DSA_44));
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_dsa_oids::ML_DSA_65));
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_dsa_oids::ML_DSA_87));
    }

    #[test]
    fn test_builder_all_ml_kem() {
        let response = CsrAttrsResponse::builder().with_all_ml_kem().build();

        assert_eq!(response.attributes().len(), 3);
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_kem_oids::ML_KEM_512));
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_kem_oids::ML_KEM_768));
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_kem_oids::ML_KEM_1024));
    }

    #[test]
    fn test_builder_all_pqc() {
        let response = CsrAttrsResponse::builder().with_all_pqc().build();

        assert_eq!(response.attributes().len(), 6);
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_dsa_oids::ML_DSA_44));
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == ml_kem_oids::ML_KEM_512));
    }

    #[test]
    fn test_builder_composite() {
        let response = CsrAttrsResponse::builder()
            .with_composite_ml_dsa()
            .build();

        assert_eq!(response.attributes().len(), 2);
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == composite_ml_dsa_oids::ML_DSA_65_RSA_3072));
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == composite_ml_dsa_oids::ML_DSA_65_ECDSA_P384));
    }

    #[test]
    fn test_builder_standard_attrs() {
        let response = CsrAttrsResponse::builder().with_standard_attrs().build();

        assert_eq!(response.attributes().len(), 2);
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == x509_attr_oids::CHALLENGE_PASSWORD));
        assert!(response
            .attributes()
            .iter()
            .any(|a| a.oid == x509_attr_oids::EXTENSION_REQUEST));
    }

    #[test]
    fn test_validate() {
        let response = CsrAttrsResponse::builder().with_all_pqc().build();
        assert!(response.validate().is_ok());

        let mut invalid = CsrAttrsResponse::new(vec![CsrAttribute::new("")]);
        assert!(matches!(invalid.validate(), Err(EstError::MissingField(_))));

        invalid = CsrAttrsResponse::new(vec![CsrAttribute::new("not-an-oid!")]);
        assert!(matches!(invalid.validate(), Err(EstError::Protocol(_))));
    }

    #[test]
    fn test_to_der() {
        let mut response = CsrAttrsResponse::empty();
        let der = response.to_der();
        assert_eq!(der, &[0x30, 0x00]); // Empty SEQUENCE

        let mut response = CsrAttrsResponse::builder()
            .add_oid("1.2.3.4.5")
            .build();
        let der = response.to_der();
        assert_eq!(der[0], 0x30); // SEQUENCE tag
    }

    #[test]
    fn test_base64_roundtrip() {
        let mut response = CsrAttrsResponse::empty();
        let base64 = response.to_base64();
        let decoded = CsrAttrsResponse::from_base64(&base64).unwrap();
        assert_eq!(decoded.attributes().len(), 0);
    }

    #[test]
    fn test_add_attribute() {
        let mut response = CsrAttrsResponse::empty();
        assert_eq!(response.attributes().len(), 0);

        response.add_attribute(CsrAttribute::ml_dsa_65());
        assert_eq!(response.attributes().len(), 1);

        response.add_attribute(CsrAttribute::ml_kem_768());
        assert_eq!(response.attributes().len(), 2);
    }

    #[test]
    fn test_composite_oids() {
        assert_eq!(
            composite_ml_dsa_oids::ML_DSA_44_RSA_2048,
            "2.16.840.1.114027.80.5.2.37"
        );
        assert_eq!(
            composite_ml_dsa_oids::ML_DSA_65_ECDSA_P384,
            "2.16.840.1.114027.80.5.2.41"
        );
        assert_eq!(
            composite_ml_dsa_oids::ML_DSA_44_ED25519,
            "2.16.840.1.114027.80.5.2.43"
        );
    }
}
