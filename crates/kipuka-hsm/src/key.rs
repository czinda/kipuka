//! HSM key pair generation and management with PQC support.

use crate::error::{HsmError, HsmResult};
use crate::providers::HsmProviderConfig;
use crate::slot::HsmSlot;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, KeyType, MlDsaParameterSetType, MlKemParameterSetType, ObjectClass, ObjectHandle,
};
use cryptoki::session::Session;
use cryptoki::types::Ulong;
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

/// Vendor-specific PQC mechanism IDs.
///
/// PKCS#11 v3.2 standardizes ML-DSA and ML-KEM mechanisms.  These standard
/// mechanism IDs are now used by default via the `cryptoki` crate's
/// `MechanismType::ML_DSA*` and `MechanismType::ML_KEM*` constants.
///
/// This struct is retained for backward compatibility with vendor-specific
/// configurations that predate PKCS#11 v3.2.  When `None`, the standard
/// PKCS#11 v3.2 mechanism IDs are used automatically.
#[derive(Debug, Clone, Deserialize)]
pub struct PqcMechanismIds {
    /// ML-DSA key pair generation (FIPS 204).
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_DSA_KEY_PAIR_GEN (0x00004030)
    #[serde(default)]
    pub ml_dsa_keygen: Option<u64>,

    /// ML-DSA-44 signing.
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_DSA (0x00004031)
    #[serde(default)]
    pub ml_dsa_44: Option<u64>,

    /// ML-DSA-65 signing.
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_DSA (0x00004031) — level selected via CKA_PARAMETER_SET.
    #[serde(default)]
    pub ml_dsa_65: Option<u64>,

    /// ML-DSA-87 signing.
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_DSA (0x00004031) — level selected via CKA_PARAMETER_SET.
    #[serde(default)]
    pub ml_dsa_87: Option<u64>,

    /// ML-KEM key pair generation (FIPS 203).
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_KEM_KEY_PAIR_GEN (0x00004024)
    #[serde(default)]
    pub ml_kem_keygen: Option<u64>,

    /// ML-KEM-512 encapsulate/decapsulate.
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_KEM (0x00004025)
    #[serde(default)]
    pub ml_kem_512: Option<u64>,

    /// ML-KEM-768 encapsulate/decapsulate.
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_KEM (0x00004025)
    #[serde(default)]
    pub ml_kem_768: Option<u64>,

    /// ML-KEM-1024 encapsulate/decapsulate.
    ///
    /// Standard PKCS#11 v3.2: CKM_ML_KEM (0x00004025)
    #[serde(default)]
    pub ml_kem_1024: Option<u64>,
}

impl Default for PqcMechanismIds {
    fn default() -> Self {
        // Use the standard PKCS#11 v3.2 mechanism values.
        // The cryptoki crate constants (MechanismType::ML_DSA_KEY_PAIR_GEN, etc.)
        // carry these values, so we store them as u64 for config-file compatibility.
        Self {
            ml_dsa_keygen: Some(*MechanismType::ML_DSA_KEY_PAIR_GEN),
            ml_dsa_44: Some(*MechanismType::ML_DSA),
            ml_dsa_65: Some(*MechanismType::ML_DSA),
            ml_dsa_87: Some(*MechanismType::ML_DSA),
            ml_kem_keygen: Some(*MechanismType::ML_KEM_KEY_PAIR_GEN),
            ml_kem_512: Some(*MechanismType::ML_KEM),
            ml_kem_768: Some(*MechanismType::ML_KEM),
            ml_kem_1024: Some(*MechanismType::ML_KEM),
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

    /// Generate ML-DSA key pair (FIPS 204) using PKCS#11 v3.2 CKM_ML_DSA_KEY_PAIR_GEN.
    ///
    /// The parameter set (ML-DSA-44, ML-DSA-65, ML-DSA-87) is specified via
    /// the CKA_PARAMETER_SET attribute in the key templates.
    fn generate_ml_dsa(
        session: &Session,
        level: MlDsaLevel,
        label: &str,
        id: &[u8],
        config: &HsmProviderConfig,
        _pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(ObjectHandle, ObjectHandle)> {
        // Check if HSM supports the standard ML-DSA mechanism
        if !config
            .supported_mechanisms
            .contains(&MechanismType::ML_DSA_KEY_PAIR_GEN)
        {
            return Err(HsmError::PqcNotSupported(
                "ML-DSA key generation (CKM_ML_DSA_KEY_PAIR_GEN) not supported by HSM. \
                 Consider using SoftwarePqcFallback."
                    .to_string(),
            ));
        }

        let mechanism = Mechanism::MlDsaKeyPairGen;

        // Map our level enum to the standard PKCS#11 v3.2 parameter set type
        let param_set = match level {
            MlDsaLevel::L2 => MlDsaParameterSetType::ML_DSA_44,
            MlDsaLevel::L3 => MlDsaParameterSetType::ML_DSA_65,
            MlDsaLevel::L5 => MlDsaParameterSetType::ML_DSA_87,
        };

        let public_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Verify(true),
            Attribute::KeyType(KeyType::ML_DSA),
            Attribute::ParameterSet(param_set.into()),
        ];

        let private_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Private(true),
            Attribute::Sensitive(true),    // NIAP CA PP FCS_CKM.1
            Attribute::Extractable(false), // NIAP CA PP FCS_CKM.1
            Attribute::Sign(true),
            Attribute::KeyType(KeyType::ML_DSA),
            Attribute::ParameterSet(param_set.into()),
        ];

        tracing::info!(
            "Generating ML-DSA key pair with parameter set {:?}",
            level
        );

        session
            .generate_key_pair(&mechanism, &public_key_template, &private_key_template)
            .map_err(|e| HsmError::KeyGeneration(format!("ML-DSA key generation failed: {e}")))
    }

    /// Generate ML-KEM key pair (FIPS 203) using PKCS#11 v3.2 CKM_ML_KEM_KEY_PAIR_GEN.
    ///
    /// The parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024) is specified via
    /// the CKA_PARAMETER_SET attribute in the key templates.
    fn generate_ml_kem(
        session: &Session,
        level: MlKemLevel,
        label: &str,
        id: &[u8],
        config: &HsmProviderConfig,
        _pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(ObjectHandle, ObjectHandle)> {
        // Check if HSM supports the standard ML-KEM mechanism
        if !config
            .supported_mechanisms
            .contains(&MechanismType::ML_KEM_KEY_PAIR_GEN)
        {
            return Err(HsmError::PqcNotSupported(
                "ML-KEM key generation (CKM_ML_KEM_KEY_PAIR_GEN) not supported by HSM. \
                 Consider using SoftwarePqcFallback."
                    .to_string(),
            ));
        }

        let mechanism = Mechanism::MlKemKeyPairGen;

        // Map our level enum to the standard PKCS#11 v3.2 parameter set type
        let param_set = match level {
            MlKemLevel::L1 => MlKemParameterSetType::ML_KEM_512,
            MlKemLevel::L3 => MlKemParameterSetType::ML_KEM_768,
            MlKemLevel::L5 => MlKemParameterSetType::ML_KEM_1024,
        };

        let public_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::KeyType(KeyType::ML_KEM),
            Attribute::ParameterSet(param_set.into()),
        ];

        let private_key_template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Private(true),
            Attribute::Sensitive(true),    // NIAP CA PP FCS_CKM.1
            Attribute::Extractable(false), // NIAP CA PP FCS_CKM.1
            Attribute::KeyType(KeyType::ML_KEM),
            Attribute::ParameterSet(param_set.into()),
        ];

        tracing::info!(
            "Generating ML-KEM key pair with parameter set {:?}",
            level
        );

        session
            .generate_key_pair(&mechanism, &public_key_template, &private_key_template)
            .map_err(|e| HsmError::KeyGeneration(format!("ML-KEM key generation failed: {e}")))
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
    fn test_pqc_mechanism_ids_use_standard_values() {
        let ids = PqcMechanismIds::default();
        // Verify default mechanism IDs match the standard PKCS#11 v3.2 values
        assert_eq!(
            ids.ml_dsa_keygen.unwrap(),
            *MechanismType::ML_DSA_KEY_PAIR_GEN
        );
        assert_eq!(ids.ml_dsa_44.unwrap(), *MechanismType::ML_DSA);
        assert_eq!(ids.ml_dsa_65.unwrap(), *MechanismType::ML_DSA);
        assert_eq!(ids.ml_dsa_87.unwrap(), *MechanismType::ML_DSA);
        assert_eq!(
            ids.ml_kem_keygen.unwrap(),
            *MechanismType::ML_KEM_KEY_PAIR_GEN
        );
        assert_eq!(ids.ml_kem_512.unwrap(), *MechanismType::ML_KEM);
        assert_eq!(ids.ml_kem_768.unwrap(), *MechanismType::ML_KEM);
        assert_eq!(ids.ml_kem_1024.unwrap(), *MechanismType::ML_KEM);
    }

    #[test]
    fn test_pkcs11_uri_parsing() {
        let uri = "pkcs11:token=MyToken;object=MyKey;type=private";
        let url = Url::parse(uri).unwrap();
        assert_eq!(url.scheme(), "pkcs11");
    }
}
