//! HSM signing operations with PQC support.

use crate::error::{HsmError, HsmResult};
use crate::key::{HsmKeyPair, KeyAlgorithm, MlDsaLevel, MlKemLevel, PqcMechanismIds};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::types::Ulong;

/// HSM signer trait.
pub trait HsmSigner {
    /// Sign a message digest.
    ///
    /// # Arguments
    ///
    /// * `key` - Key pair to sign with
    /// * `digest` - Pre-computed message digest
    ///
    /// # Returns
    ///
    /// The signature bytes.
    fn sign(&self, key: &HsmKeyPair, digest: &[u8]) -> HsmResult<Vec<u8>>;

    /// Sign a message digest with a specific mechanism.
    fn sign_with_mechanism(
        &self,
        key: &HsmKeyPair,
        digest: &[u8],
        mechanism: &Mechanism,
    ) -> HsmResult<Vec<u8>>;

    /// Wrap a key using AES Key Wrap (RFC 3394).
    ///
    /// Used for wrapping ML-KEM private keys during /serverkeygen.
    fn wrap_key_aes(
        &self,
        session: &Session,
        wrapping_key: ObjectHandle,
        key_to_wrap: ObjectHandle,
    ) -> HsmResult<Vec<u8>>;

    /// Wrap a key using RSAES-OAEP with SHA-256.
    fn wrap_key_rsa_oaep(
        &self,
        session: &Session,
        wrapping_key: ObjectHandle,
        key_to_wrap: ObjectHandle,
    ) -> HsmResult<Vec<u8>>;

    /// ML-KEM encapsulate operation via PKCS#11 v3.2 C_EncapsulateKey.
    ///
    /// # Arguments
    ///
    /// * `session` - PKCS#11 session
    /// * `public_key` - ML-KEM public key
    /// * `pqc_mechanisms` - PQC mechanism IDs (ignored for standard PKCS#11 v3.2)
    ///
    /// # Returns
    ///
    /// `(ciphertext, shared_secret_handle)` — the shared secret is returned
    /// as a CKK_GENERIC_SECRET object handle inside the token.  The caller
    /// must extract or use it via PKCS#11 operations.
    fn ml_kem_encapsulate(
        &self,
        session: &Session,
        public_key: ObjectHandle,
        pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)>;

    /// ML-KEM decapsulate operation via PKCS#11 v3.2 C_DecapsulateKey.
    ///
    /// # Arguments
    ///
    /// * `session` - PKCS#11 session
    /// * `private_key` - ML-KEM private key
    /// * `ciphertext` - Ciphertext from encapsulate
    /// * `pqc_mechanisms` - PQC mechanism IDs (ignored for standard PKCS#11 v3.2)
    ///
    /// # Returns
    ///
    /// The shared secret bytes (extracted from the derived key object).
    fn ml_kem_decapsulate(
        &self,
        session: &Session,
        private_key: ObjectHandle,
        ciphertext: &[u8],
        pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<Vec<u8>>;
}

/// Default HSM signer implementation.
pub struct DefaultHsmSigner;

impl HsmSigner for DefaultHsmSigner {
    fn sign(&self, key: &HsmKeyPair, digest: &[u8]) -> HsmResult<Vec<u8>> {
        let mechanism = match key.algorithm() {
            KeyAlgorithm::Rsa(_bits) => {
                // Default to PKCS#1 v1.5 with SHA-256
                Mechanism::Sha256RsaPkcs
            }
            KeyAlgorithm::Ecdsa(_curve) => {
                // ECDSA with pre-computed digest
                Mechanism::Ecdsa
            }
            KeyAlgorithm::MlDsa(_level) => {
                // ML-DSA requires explicit mechanism ID
                return Err(HsmError::PqcNotSupported(
                    "ML-DSA signing requires explicit mechanism ID".to_string(),
                ));
            }
            KeyAlgorithm::MlKem(_level) => {
                return Err(HsmError::UnsupportedMechanism(
                    "ML-KEM is for encapsulation, not signing".to_string(),
                ));
            }
        };

        self.sign_with_mechanism(key, digest, &mechanism)
    }

    fn sign_with_mechanism(
        &self,
        key: &HsmKeyPair,
        digest: &[u8],
        mechanism: &Mechanism,
    ) -> HsmResult<Vec<u8>> {
        let session = key.session();
        let private_key = key.private_key();

        session
            .sign(mechanism, private_key, digest)
            .map_err(|e| HsmError::SigningFailure(format!("Sign operation failed: {e}")))
    }

    fn wrap_key_aes(
        &self,
        session: &Session,
        wrapping_key: ObjectHandle,
        key_to_wrap: ObjectHandle,
    ) -> HsmResult<Vec<u8>> {
        let mechanism = Mechanism::AesKeyWrap;

        session
            .wrap_key(&mechanism, wrapping_key, key_to_wrap)
            .map_err(|e| HsmError::KeyWrap(format!("AES key wrap failed: {e}")))
    }

    fn wrap_key_rsa_oaep(
        &self,
        session: &Session,
        wrapping_key: ObjectHandle,
        key_to_wrap: ObjectHandle,
    ) -> HsmResult<Vec<u8>> {
        // RSA-OAEP with SHA-256 and MGF1-SHA-256 (PKCS#11 v3.2 standard parameters)
        let oaep_params = PkcsOaepParams::new(
            MechanismType::SHA256,
            PkcsMgfType::MGF1_SHA256,
            PkcsOaepSource::empty(),
        );
        let mechanism = Mechanism::RsaPkcsOaep(oaep_params);

        session
            .wrap_key(&mechanism, wrapping_key, key_to_wrap)
            .map_err(|e| HsmError::KeyWrap(format!("RSA-OAEP key wrap failed: {e}")))
    }

    fn ml_kem_encapsulate(
        &self,
        session: &Session,
        public_key: ObjectHandle,
        _pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        // Use the standard PKCS#11 v3.2 CKM_ML_KEM mechanism for encapsulation.
        // C_EncapsulateKey produces a ciphertext and derives a CKK_GENERIC_SECRET
        // key object.  We request an extractable key so that we can read the
        // shared secret bytes back to the caller.
        let mechanism = Mechanism::MlKem;

        // Template for the derived shared-secret key object
        let template = vec![
            Attribute::Token(false),        // session object, not persistent
            Attribute::Extractable(true),    // allow CKA_VALUE extraction
            Attribute::Sensitive(false),     // needed for extraction
        ];

        let (ciphertext, _secret_handle) = session
            .encapsulate_key(&mechanism, public_key, &template)
            .map_err(|e| {
                HsmError::PqcNotSupported(format!("ML-KEM encapsulate failed: {e}"))
            })?;

        // Extract the shared secret value from the derived key object.
        // The returned handle is a CKK_GENERIC_SECRET; read its CKA_VALUE.
        let attrs = session
            .get_attributes(_secret_handle, &[cryptoki::object::AttributeType::Value])
            .map_err(|e| {
                HsmError::PqcNotSupported(format!(
                    "ML-KEM: failed to extract shared secret: {e}"
                ))
            })?;

        let shared_secret = attrs
            .into_iter()
            .find_map(|a| {
                if let Attribute::Value(v) = a {
                    Some(v)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                HsmError::PqcNotSupported(
                    "ML-KEM: derived key has no CKA_VALUE attribute".to_string(),
                )
            })?;

        // Destroy the temporary session object
        let _ = session.destroy_object(_secret_handle);

        Ok((ciphertext, shared_secret))
    }

    fn ml_kem_decapsulate(
        &self,
        session: &Session,
        private_key: ObjectHandle,
        ciphertext: &[u8],
        _pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<Vec<u8>> {
        // Use the standard PKCS#11 v3.2 CKM_ML_KEM mechanism for decapsulation.
        // C_DecapsulateKey takes the ciphertext and private key, and derives
        // a CKK_GENERIC_SECRET key object containing the shared secret.
        let mechanism = Mechanism::MlKem;

        // Template for the derived shared-secret key object
        let template = vec![
            Attribute::Token(false),
            Attribute::Extractable(true),
            Attribute::Sensitive(false),
        ];

        let secret_handle = session
            .decapsulate_key(&mechanism, private_key, &template, ciphertext)
            .map_err(|e| {
                HsmError::PqcNotSupported(format!("ML-KEM decapsulate failed: {e}"))
            })?;

        // Extract the shared secret value
        let attrs = session
            .get_attributes(secret_handle, &[cryptoki::object::AttributeType::Value])
            .map_err(|e| {
                HsmError::PqcNotSupported(format!(
                    "ML-KEM: failed to extract shared secret: {e}"
                ))
            })?;

        let shared_secret = attrs
            .into_iter()
            .find_map(|a| {
                if let Attribute::Value(v) = a {
                    Some(v)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                HsmError::PqcNotSupported(
                    "ML-KEM: derived key has no CKA_VALUE attribute".to_string(),
                )
            })?;

        // Destroy the temporary session object
        let _ = session.destroy_object(secret_handle);

        Ok(shared_secret)
    }
}

/// Sign with RSA PKCS#1 v1.5.
pub fn sign_rsa_pkcs1(
    key: &HsmKeyPair,
    digest: &[u8],
    hash_algorithm: RsaHashAlgorithm,
) -> HsmResult<Vec<u8>> {
    let mechanism = match hash_algorithm {
        RsaHashAlgorithm::Sha256 => Mechanism::Sha256RsaPkcs,
        RsaHashAlgorithm::Sha384 => Mechanism::Sha384RsaPkcs,
        RsaHashAlgorithm::Sha512 => Mechanism::Sha512RsaPkcs,
    };

    let signer = DefaultHsmSigner;
    signer.sign_with_mechanism(key, digest, &mechanism)
}

/// Sign with RSA-PSS.
///
/// Uses the standard PKCS#11 CKM_SHA*_RSA_PKCS_PSS mechanism which
/// performs hashing and PSS padding internally.  The `digest` parameter
/// is the raw TBS (to-be-signed) data — the HSM hashes it.
///
/// The salt length is set equal to the hash output length, matching the
/// CA/B Forum Baseline Requirements recommendation.
pub fn sign_rsa_pss(
    key: &HsmKeyPair,
    digest: &[u8],
    hash_algorithm: RsaHashAlgorithm,
) -> HsmResult<Vec<u8>> {
    let (hash_mech, mgf, salt_len) = match hash_algorithm {
        RsaHashAlgorithm::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32u64),
        RsaHashAlgorithm::Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48u64),
        RsaHashAlgorithm::Sha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64u64),
    };

    let pss_params = PkcsPssParams {
        hash_alg: hash_mech,
        mgf,
        s_len: Ulong::from(salt_len),
    };

    let mechanism = match hash_algorithm {
        RsaHashAlgorithm::Sha256 => Mechanism::Sha256RsaPkcsPss(pss_params),
        RsaHashAlgorithm::Sha384 => Mechanism::Sha384RsaPkcsPss(pss_params),
        RsaHashAlgorithm::Sha512 => Mechanism::Sha512RsaPkcsPss(pss_params),
    };

    let signer = DefaultHsmSigner;
    signer.sign_with_mechanism(key, digest, &mechanism)
}

/// Sign with ECDSA.
pub fn sign_ecdsa(key: &HsmKeyPair, digest: &[u8]) -> HsmResult<Vec<u8>> {
    let mechanism = Mechanism::Ecdsa;
    let signer = DefaultHsmSigner;
    signer.sign_with_mechanism(key, digest, &mechanism)
}

/// Sign with ML-DSA (FIPS 204) using the standard PKCS#11 v3.2 CKM_ML_DSA mechanism.
///
/// ML-DSA signing internally hashes the message before signing.
/// The HSM performs both hashing and signing.
///
/// The `_pqc_mechanisms` parameter is retained for backward compatibility
/// with vendor-specific configurations but is no longer needed — cryptoki
/// 0.12 provides the standard `Mechanism::MlDsa` variant directly.
pub fn sign_ml_dsa(
    key: &HsmKeyPair,
    message: &[u8],
    _level: MlDsaLevel,
    _pqc_mechanisms: &PqcMechanismIds,
) -> HsmResult<Vec<u8>> {
    // Use the standard PKCS#11 v3.2 CKM_ML_DSA mechanism with default
    // hedging (HedgeType::Preferred — the token may create either a
    // hedged or deterministic signature).
    let ctx = SignAdditionalContext::new(HedgeType::Preferred, None);
    let mechanism = Mechanism::MlDsa(ctx);

    let signer = DefaultHsmSigner;
    signer.sign_with_mechanism(key, message, &mechanism)
}

/// RSA hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Software fallback for PQC operations.
///
/// When HSM does not support ML-DSA or ML-KEM, fall back to synta-certificate
/// software implementations.
pub struct SoftwarePqcFallback;

impl SoftwarePqcFallback {
    /// Check if HSM supports the required PQC mechanism.
    pub fn is_hsm_supported(
        mechanism_type: MechanismType,
        provider_mechanisms: &[MechanismType],
    ) -> bool {
        provider_mechanisms.contains(&mechanism_type)
    }

    /// Sign with ML-DSA using software implementation via synta-certificate.
    ///
    /// Falls back to `synta_certificate::BackendPrivateKey::generate_ml_dsa()`
    /// when the HSM does not support ML-DSA natively.
    pub fn sign_ml_dsa_software(
        _message: &[u8],
        _private_key_bytes: &[u8],
        _level: MlDsaLevel,
    ) -> HsmResult<Vec<u8>> {
        // synta-certificate ML-DSA software signing:
        //
        // In a real deployment, the caller would:
        // 1. Deserialize the private key bytes into a BackendPrivateKey
        // 2. Call BackendPrivateKey::sign_ml_dsa(message, level)
        // 3. Return the signature bytes
        //
        // This requires synta-certificate to be compiled with the `pqc` feature.
        // For now we return a clear error indicating the integration point.
        Err(HsmError::PqcNotSupported(
            "Software ML-DSA fallback requires synta-certificate 'pqc' feature. \
             Use BackendPrivateKey::generate_ml_dsa() to create and sign."
                .to_string(),
        ))
    }

    /// ML-KEM encapsulate using software implementation via synta-certificate.
    ///
    /// Falls back to `synta_certificate::BackendPrivateKey::generate_ml_kem()`
    /// when the HSM does not support ML-KEM natively.
    pub fn ml_kem_encapsulate_software(
        _public_key_bytes: &[u8],
        _level: MlKemLevel,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        // synta-certificate ML-KEM software encapsulation:
        //
        // In a real deployment, the caller would:
        // 1. Deserialize the public key bytes
        // 2. Call ml_kem_encapsulate(public_key, level)
        // 3. Return (ciphertext, shared_secret)
        //
        // This requires synta-certificate to be compiled with the `pqc` feature.
        Err(HsmError::PqcNotSupported(
            "Software ML-KEM encapsulate fallback requires synta-certificate 'pqc' feature. \
             Use BackendPrivateKey::generate_ml_kem() to create keys, then encapsulate."
                .to_string(),
        ))
    }

    /// ML-KEM decapsulate using software implementation via synta-certificate.
    ///
    /// Falls back to `synta_certificate::BackendPrivateKey::generate_ml_kem()`
    /// when the HSM does not support ML-KEM natively.
    pub fn ml_kem_decapsulate_software(
        _private_key_bytes: &[u8],
        _ciphertext: &[u8],
        _level: MlKemLevel,
    ) -> HsmResult<Vec<u8>> {
        // synta-certificate ML-KEM software decapsulation:
        //
        // In a real deployment, the caller would:
        // 1. Deserialize the private key bytes
        // 2. Call ml_kem_decapsulate(private_key, ciphertext, level)
        // 3. Return shared_secret
        //
        // This requires synta-certificate to be compiled with the `pqc` feature.
        Err(HsmError::PqcNotSupported(
            "Software ML-KEM decapsulate fallback requires synta-certificate 'pqc' feature. \
             Use BackendPrivateKey::generate_ml_kem() to create keys, then decapsulate."
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_fallback_detection() {
        let mechanisms = vec![
            MechanismType::RSA_PKCS,
            MechanismType::ECDSA,
            MechanismType::AES_KEY_WRAP,
        ];

        assert!(SoftwarePqcFallback::is_hsm_supported(
            MechanismType::RSA_PKCS,
            &mechanisms
        ));
        assert!(!SoftwarePqcFallback::is_hsm_supported(
            MechanismType::ECDSA_SHA256,
            &mechanisms
        ));
    }

    #[test]
    fn test_pqc_mechanism_detection() {
        // Verify we can check for standard PKCS#11 v3.2 PQC mechanisms
        let mechanisms = vec![
            MechanismType::RSA_PKCS,
            MechanismType::ML_DSA_KEY_PAIR_GEN,
            MechanismType::ML_DSA,
            MechanismType::ML_KEM_KEY_PAIR_GEN,
            MechanismType::ML_KEM,
        ];

        assert!(SoftwarePqcFallback::is_hsm_supported(
            MechanismType::ML_DSA,
            &mechanisms
        ));
        assert!(SoftwarePqcFallback::is_hsm_supported(
            MechanismType::ML_KEM,
            &mechanisms
        ));
        assert!(!SoftwarePqcFallback::is_hsm_supported(
            MechanismType::HASH_ML_DSA_SHA256,
            &mechanisms
        ));
    }

    #[test]
    fn test_software_fallback_errors_are_descriptive() {
        let err = SoftwarePqcFallback::sign_ml_dsa_software(&[], &[], MlDsaLevel::L3);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("synta-certificate"));

        let err = SoftwarePqcFallback::ml_kem_encapsulate_software(&[], MlKemLevel::L3);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("synta-certificate"));

        let err = SoftwarePqcFallback::ml_kem_decapsulate_software(&[], &[], MlKemLevel::L3);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("synta-certificate"));
    }
}
