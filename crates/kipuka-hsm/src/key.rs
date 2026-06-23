//! HSM key pair generation and management with PQC support.

use crate::error::{HsmError, HsmResult};
use crate::providers::HsmProviderConfig;
use crate::slot::HsmSlot;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::types::Ulong;
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

/// Vendor-specific PQC mechanism IDs.
///
/// PQC mechanisms are not yet standardized in PKCS#11 v3.1. Different vendors
/// use different mechanism IDs. This struct holds configurable IDs per provider.
#[derive(Debug, Clone, Deserialize)]
pub struct PqcMechanismIds {
    /// ML-DSA key pair generation (FIPS 204).
    #[serde(default)]
    pub ml_dsa_keygen: Option<u64>,

    /// ML-DSA-44 signing.
    #[serde(default)]
    pub ml_dsa_44: Option<u64>,

    /// ML-DSA-65 signing.
    #[serde(default)]
    pub ml_dsa_65: Option<u64>,

    /// ML-DSA-87 signing.
    #[serde(default)]
    pub ml_dsa_87: Option<u64>,

    /// ML-KEM key pair generation (FIPS 203).
    #[serde(default)]
    pub ml_kem_keygen: Option<u64>,

    /// ML-KEM-512 encapsulate/decapsulate.
    #[serde(default)]
    pub ml_kem_512: Option<u64>,

    /// ML-KEM-768 encapsulate/decapsulate.
    #[serde(default)]
    pub ml_kem_768: Option<u64>,

    /// ML-KEM-1024 encapsulate/decapsulate.
    #[serde(default)]
    pub ml_kem_1024: Option<u64>,
}

impl Default for PqcMechanismIds {
    fn default() -> Self {
        // Placeholder vendor-defined values
        // These should be configured per provider
        Self {
            ml_dsa_keygen: Some(0x8000_0001),
            ml_dsa_44: Some(0x8000_0002),
            ml_dsa_65: Some(0x8000_0003),
            ml_dsa_87: Some(0x8000_0004),
            ml_kem_keygen: Some(0x8000_0010),
            ml_kem_512: Some(0x8000_0011),
            ml_kem_768: Some(0x8000_0012),
            ml_kem_1024: Some(0x8000_0013),
        }
    }
}

/// Key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// RSA with specified bit length.
    Rsa(u32),
    /// ECDSA with named curve.
    Ecdsa(EcdsaCurve),
    /// ML-DSA (FIPS 204) with security level.
    MlDsa(MlDsaLevel),
    /// ML-KEM (FIPS 203) with security level.
    MlKem(MlKemLevel),
}

/// ECDSA curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    P256,
    P384,
    P521,
}

impl EcdsaCurve {
    /// Get the OID for this curve.
    pub fn oid(&self) -> &[u8] {
        match self {
            Self::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            Self::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            Self::P521 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
        }
    }
}

/// ML-DSA security levels (FIPS 204).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaLevel {
    /// ML-DSA-44 (Category 2, ~128-bit security).
    L2,
    /// ML-DSA-65 (Category 3, ~192-bit security).
    L3,
    /// ML-DSA-87 (Category 5, ~256-bit security).
    L5,
}

/// ML-KEM security levels (FIPS 203).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemLevel {
    /// ML-KEM-512 (Category 1, ~128-bit security).
    L1,
    /// ML-KEM-768 (Category 3, ~192-bit security).
    L3,
    /// ML-KEM-1024 (Category 5, ~256-bit security).
    L5,
}

/// HSM key pair reference.
pub struct HsmKeyPair {
    /// PKCS#11 session.
    session: Session,
    /// Private key handle.
    private_key: ObjectHandle,
    /// Public key handle.
    public_key: ObjectHandle,
    /// Key algorithm.
    algorithm: KeyAlgorithm,
}

impl HsmKeyPair {
    /// Generate a new key pair.
    ///
    /// # Arguments
    ///
    /// * `slot` - HSM slot
    /// * `algorithm` - Key algorithm
    /// * `label` - Key label (CKA_LABEL)
    /// * `id` - Key ID (CKA_ID), typically SHA-1 hash of public key
    /// * `provider_config` - Provider configuration (for PQC mechanism IDs)
    ///
    /// # NIAP CA PP Compliance
    ///
    /// Generated keys MUST have:
    /// - `CKA_EXTRACTABLE = false` (FCS_CKM.1)
    /// - `CKA_SENSITIVE = true` (FCS_CKM.1)
    ///
    /// # Errors
    ///
    /// Returns `HsmError::PqcNotSupported` if the HSM does not support the requested
    /// PQC algorithm and fallback to software is not enabled.
    pub fn generate(
        slot: &HsmSlot,
        algorithm: KeyAlgorithm,
        label: &str,
        id: &[u8],
        provider_config: &HsmProviderConfig,
        pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<Self> {
        let session = slot.open_rw_session()?;

        let (private_key, public_key) = match algorithm {
            KeyAlgorithm::Rsa(bits) => {
                Self::generate_rsa(&session, bits, label, id, provider_config)?
            }
            KeyAlgorithm::Ecdsa(curve) => {
                Self::generate_ecdsa(&session, curve, label, id, provider_config)?
            }
            KeyAlgorithm::MlDsa(level) => {
                Self::generate_ml_dsa(&session, level, label, id, provider_config, pqc_mechanisms)?
            }
            KeyAlgorithm::MlKem(level) => {
                Self::generate_ml_kem(&session, level, label, id, provider_config, pqc_mechanisms)?
            }
        };

        Ok(Self {
            session,
            private_key,
            public_key,
            algorithm,
        })
    }

    /// Generate RSA key pair.
    fn generate_rsa(
        session: &Session,
        bits: u32,
        label: &str,
        id: &[u8],
        config: &HsmProviderConfig,
    ) -> HsmResult<(ObjectHandle, ObjectHandle)> {
        if !config
            .supported_mechanisms
            .contains(&MechanismType::RSA_PKCS_KEY_PAIR_GEN)
        {
            return Err(HsmError::UnsupportedMechanism(
                "RSA key generation not supported by HSM".to_string(),
            ));
        }

        let mechanism = Mechanism::RsaPkcsKeyPairGen;

        let public_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Encrypt(true),
            Attribute::Verify(true),
            Attribute::ModulusBits(Ulong::from(bits as u64)),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 65537
        ];

        let private_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Private(true),
            Attribute::Sensitive(true),    // NIAP CA PP FCS_CKM.1
            Attribute::Extractable(false), // NIAP CA PP FCS_CKM.1
            Attribute::Decrypt(true),
            Attribute::Sign(true),
        ];

        session
            .generate_key_pair(&mechanism, &public_key_template, &private_key_template)
            .map_err(|e| HsmError::KeyGeneration(format!("RSA key generation failed: {e}")))
    }

    /// Generate ECDSA key pair.
    fn generate_ecdsa(
        session: &Session,
        curve: EcdsaCurve,
        label: &str,
        id: &[u8],
        config: &HsmProviderConfig,
    ) -> HsmResult<(ObjectHandle, ObjectHandle)> {
        if !config
            .supported_mechanisms
            .contains(&MechanismType::ECC_KEY_PAIR_GEN)
        {
            return Err(HsmError::UnsupportedMechanism(
                "ECDSA key generation not supported by HSM".to_string(),
            ));
        }

        let mechanism = Mechanism::EccKeyPairGen;

        let public_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Verify(true),
            Attribute::EcParams(curve.oid().to_vec()),
        ];

        let private_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Private(true),
            Attribute::Sensitive(true),    // NIAP CA PP FCS_CKM.1
            Attribute::Extractable(false), // NIAP CA PP FCS_CKM.1
            Attribute::Sign(true),
        ];

        session
            .generate_key_pair(&mechanism, &public_key_template, &private_key_template)
            .map_err(|e| HsmError::KeyGeneration(format!("ECDSA key generation failed: {e}")))
    }

    /// Generate ML-DSA key pair (FIPS 204).
    fn generate_ml_dsa(
        _session: &Session,
        _level: MlDsaLevel,
        _label: &str,
        _id: &[u8],
        _config: &HsmProviderConfig,
        pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(ObjectHandle, ObjectHandle)> {
        let mechanism_id = pqc_mechanisms.ml_dsa_keygen.ok_or_else(|| {
            HsmError::PqcNotSupported("ML-DSA mechanism ID not configured".to_string())
        })?;

        // Check if HSM supports this vendor-specific mechanism
        // This is a best-effort check since we can't enumerate vendor mechanisms
        tracing::warn!(
            "Attempting ML-DSA key generation with vendor mechanism ID 0x{:08x}",
            mechanism_id
        );

        // cryptoki 0.7 doesn't support vendor-defined mechanisms directly
        // Fall back to error for now - HSM support requires vendor SDK integration
        Err(HsmError::PqcNotSupported(
            "ML-DSA key generation requires vendor-specific PKCS#11 extensions not available in cryptoki 0.7".to_string()
        ))
    }

    /// Generate ML-KEM key pair (FIPS 203).
    fn generate_ml_kem(
        _session: &Session,
        _level: MlKemLevel,
        _label: &str,
        _id: &[u8],
        _config: &HsmProviderConfig,
        pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(ObjectHandle, ObjectHandle)> {
        let mechanism_id = pqc_mechanisms.ml_kem_keygen.ok_or_else(|| {
            HsmError::PqcNotSupported("ML-KEM mechanism ID not configured".to_string())
        })?;

        tracing::warn!(
            "Attempting ML-KEM key generation with vendor mechanism ID 0x{:08x}",
            mechanism_id
        );

        // cryptoki 0.7 doesn't support vendor-defined mechanisms directly
        // Fall back to error for now - HSM support requires vendor SDK integration
        Err(HsmError::PqcNotSupported(
            "ML-KEM key generation requires vendor-specific PKCS#11 extensions not available in cryptoki 0.7".to_string()
        ))
    }

    /// Find a key pair by label.
    pub fn find_by_label(slot: &HsmSlot, label: &str, algorithm: KeyAlgorithm) -> HsmResult<Self> {
        let session = slot.open_ro_session()?;

        let template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        session.find_objects(&template).map_err(|e| {
            HsmError::KeyNotFound(format!("Failed to search for key '{label}': {e}"))
        })?;

        let private_key = session
            .find_objects(&template)
            .map_err(|e| HsmError::KeyNotFound(format!("Find operation failed: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(format!("Key '{label}' not found")))?;

        // Find matching public key
        let public_template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ];

        let public_key = session
            .find_objects(&public_template)
            .map_err(|e| HsmError::KeyNotFound(format!("Public key search failed: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(format!("Public key '{label}' not found")))?;

        Ok(Self {
            session,
            private_key,
            public_key,
            algorithm,
        })
    }

    /// Find a key pair by CKA_ID.
    pub fn find_by_id(slot: &HsmSlot, id: &[u8], algorithm: KeyAlgorithm) -> HsmResult<Self> {
        let session = slot.open_ro_session()?;

        let template = vec![
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        let private_key = session
            .find_objects(&template)
            .map_err(|e| HsmError::KeyNotFound(format!("Find operation failed: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                HsmError::KeyNotFound(format!("Key with ID {} not found", hex::encode(id)))
            })?;

        let public_template = vec![
            Attribute::Id(id.to_vec()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ];

        let public_key = session
            .find_objects(&public_template)
            .map_err(|e| HsmError::KeyNotFound(format!("Public key search failed: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                HsmError::KeyNotFound(format!("Public key with ID {} not found", hex::encode(id)))
            })?;

        Ok(Self {
            session,
            private_key,
            public_key,
            algorithm,
        })
    }

    /// Parse a PKCS#11 URI and find the corresponding key.
    ///
    /// # URI Format
    ///
    /// `pkcs11:token=MyToken;object=MyKey;type=private`
    ///
    /// Supported attributes:
    /// - `token` - Token label
    /// - `object` - Key label (CKA_LABEL)
    /// - `id` - Key ID (CKA_ID, hex-encoded)
    /// - `type` - Object type (private, public, cert)
    pub fn from_uri(slot: &HsmSlot, uri: &str, algorithm: KeyAlgorithm) -> HsmResult<Self> {
        let url = Url::parse(uri).map_err(|e| HsmError::UriParse(e.to_string()))?;

        if url.scheme() != "pkcs11" {
            return Err(HsmError::UriParse(format!(
                "Invalid scheme '{}', expected 'pkcs11'",
                url.scheme()
            )));
        }

        // Parse query parameters
        let params: HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // Prefer CKA_ID lookup
        if let Some(id_hex) = params.get("id") {
            let id = hex::decode(id_hex)
                .map_err(|e| HsmError::UriParse(format!("Invalid hex ID '{id_hex}': {e}")))?;
            return Self::find_by_id(slot, &id, algorithm);
        }

        // Fallback to CKA_LABEL
        if let Some(label) = params.get("object") {
            return Self::find_by_label(slot, label, algorithm);
        }

        Err(HsmError::UriParse(
            "URI must contain 'id' or 'object' attribute".to_string(),
        ))
    }

    /// Get the private key handle.
    pub fn private_key(&self) -> ObjectHandle {
        self.private_key
    }

    /// Get the public key handle.
    pub fn public_key(&self) -> ObjectHandle {
        self.public_key
    }

    /// Get the session.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Get the key algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_curve_oids() {
        assert_eq!(EcdsaCurve::P256.oid().len(), 10);
        assert_eq!(EcdsaCurve::P384.oid().len(), 7);
        assert_eq!(EcdsaCurve::P521.oid().len(), 7);
    }

    #[test]
    fn test_pqc_mechanism_ids_default() {
        let ids = PqcMechanismIds::default();
        assert!(ids.ml_dsa_keygen.is_some());
        assert!(ids.ml_kem_keygen.is_some());
    }

    #[test]
    fn test_pkcs11_uri_parsing() {
        let uri = "pkcs11:token=MyToken;object=MyKey;type=private";
        let url = Url::parse(uri).unwrap();
        assert_eq!(url.scheme(), "pkcs11");
    }
}
