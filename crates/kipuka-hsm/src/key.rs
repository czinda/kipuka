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
use std::collections::HashMap;
use url::Url;

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
    /// * `provider_config` - Provider configuration
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
    ) -> HsmResult<Self> {
        let session = slot.open_rw_session()?;

        let (public_key, private_key) = match algorithm {
            KeyAlgorithm::Rsa(bits) => {
                Self::generate_rsa(&session, bits, label, id, provider_config)?
            }
            KeyAlgorithm::Ecdsa(curve) => {
                Self::generate_ecdsa(&session, curve, label, id, provider_config)?
            }
            KeyAlgorithm::MlDsa(level) => {
                Self::generate_ml_dsa(&session, level, label, id, provider_config)?
            }
            KeyAlgorithm::MlKem(level) => {
                Self::generate_ml_kem(&session, level, label, id, provider_config)?
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

        tracing::info!("Generating ML-DSA key pair with parameter set {:?}", level);

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

        tracing::info!("Generating ML-KEM key pair with parameter set {:?}", level);

        session
            .generate_key_pair(&mechanism, &public_key_template, &private_key_template)
            .map_err(|e| HsmError::KeyGeneration(format!("ML-KEM key generation failed: {e}")))
    }

    /// Find a key pair by label.
    pub fn find_by_label(slot: &HsmSlot, label: &str, algorithm: KeyAlgorithm) -> HsmResult<Self> {
        Self::find_selected(
            slot,
            vec![Attribute::Label(label.as_bytes().to_vec())],
            algorithm,
        )
    }

    pub fn find_by_id(slot: &HsmSlot, id: &[u8], algorithm: KeyAlgorithm) -> HsmResult<Self> {
        Self::find_selected(slot, vec![Attribute::Id(id.to_vec())], algorithm)
    }

    fn find_selected(
        slot: &HsmSlot,
        selector: Vec<Attribute>,
        algorithm: KeyAlgorithm,
    ) -> HsmResult<Self> {
        let session = slot.open_ro_session()?;
        let mut private = selector.clone();
        private.push(Attribute::Class(ObjectClass::PRIVATE_KEY));
        let mut public = selector;
        public.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
        let private_keys = session.find_objects(&private)?;
        let public_keys = session.find_objects(&public)?;
        if private_keys.len() != 1 || public_keys.len() != 1 {
            return Err(HsmError::KeyNotFound(
                "key selector must match exactly one key pair".into(),
            ));
        }
        Ok(Self {
            session,
            private_key: private_keys[0],
            public_key: public_keys[0],
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
        let params = parse_uri(uri)?;
        if let Some(token) = params.get("token")
            && token != slot.token_label()?.as_bytes()
        {
            return Err(HsmError::UriParse(
                "URI token does not match selected slot".into(),
            ));
        }
        if params.get("type").is_some_and(|kind| kind != b"private") {
            return Err(HsmError::UriParse("a private key URI is required".into()));
        }
        let mut selector = Vec::new();
        if let Some(id) = params.get("id") {
            selector.push(Attribute::Id(id.clone()));
        }
        if let Some(label) = params.get("object") {
            selector.push(Attribute::Label(label.clone()));
        }
        if selector.is_empty() {
            return Err(HsmError::UriParse("URI must contain id or object".into()));
        }
        Self::find_selected(slot, selector, algorithm)
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
    fn test_pkcs11_uri_parsing() {
        let uri = "pkcs11:token=MyToken;object=MyKey;type=private";
        let url = Url::parse(uri).unwrap();
        assert_eq!(url.scheme(), "pkcs11");
    }
}

/// Parse the supported RFC 7512 selectors without normalizing binary IDs.
pub fn parse_uri(uri: &str) -> HsmResult<HashMap<String, Vec<u8>>> {
    let url = Url::parse(uri).map_err(|e| HsmError::UriParse(e.to_string()))?;

    if url.scheme() != "pkcs11" {
        return Err(HsmError::UriParse(format!(
            "Invalid scheme '{}', expected 'pkcs11'",
            url.scheme()
        )));
    }

    if url.query().is_some() || url.fragment().is_some() || url.has_host() {
        return Err(HsmError::UriParse(
            "PKCS#11 URI query, fragment, and authority are unsupported".into(),
        ));
    }
    // RFC 7512 attributes live in the opaque path, separated by ';'.
    let mut params: HashMap<String, Vec<u8>> = HashMap::new();
    for part in url.path().split(';') {
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| HsmError::UriParse("invalid PKCS#11 attribute".into()))?;
        if !matches!(name, "token" | "object" | "id" | "type") {
            return Err(HsmError::UriParse("unsupported PKCS#11 selector".into()));
        }
        let raw = value.as_bytes();
        for (i, b) in raw.iter().enumerate() {
            if *b == b'%'
                && (i + 2 >= raw.len()
                    || !raw[i + 1].is_ascii_hexdigit()
                    || !raw[i + 2].is_ascii_hexdigit())
            {
                return Err(HsmError::UriParse("invalid percent escape".into()));
            }
        }
        let bytes = percent_encoding::percent_decode_str(value).collect::<Vec<_>>();
        if params.insert(name.to_string(), bytes).is_some() {
            return Err(HsmError::UriParse("duplicate PKCS#11 attribute".into()));
        }
    }
    Ok(params)
}

#[cfg(test)]
mod uri_regressions {
    use super::*;
    #[test]
    fn standard_binary_id_and_percent_encoded_label() {
        let parsed =
            parse_uri("pkcs11:token=Synthetic%20token;object=TLS%3Bkey;id=%00%ff;type=private")
                .unwrap();
        assert_eq!(parsed["token"], b"Synthetic token");
        assert_eq!(parsed["object"], b"TLS;key");
        assert_eq!(parsed["id"], [0, 255]);
    }
    #[test]
    fn ambiguous_or_ignored_selectors_are_rejected() {
        for uri in [
            "pkcs11:object=a;object=b",
            "pkcs11:object=a%2",
            "pkcs11:object=a;unknown=x",
            "pkcs11:object=a?pin-value=synthetic",
        ] {
            assert!(parse_uri(uri).is_err(), "{uri}");
        }
    }
}
