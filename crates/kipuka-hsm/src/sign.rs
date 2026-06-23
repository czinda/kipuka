//! HSM signing operations with PQC support.

use crate::error::{HsmError, HsmResult};
use crate::key::{HsmKeyPair, KeyAlgorithm, MlDsaLevel, MlKemLevel, PqcMechanismIds};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;

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

    /// Wrap a key using RSAES-OAEP.
    fn wrap_key_rsa_oaep(
        &self,
        session: &Session,
        wrapping_key: ObjectHandle,
        key_to_wrap: ObjectHandle,
    ) -> HsmResult<Vec<u8>>;

    /// ML-KEM encapsulate operation.
    ///
    /// # Arguments
    ///
    /// * `session` - PKCS#11 session
    /// * `public_key` - ML-KEM public key
    ///
    /// # Returns
    ///
    /// `(ciphertext, shared_secret)` tuple.
    fn ml_kem_encapsulate(
        &self,
        session: &Session,
        public_key: ObjectHandle,
        pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)>;

    /// ML-KEM decapsulate operation.
    ///
    /// # Arguments
    ///
    /// * `session` - PKCS#11 session
    /// * `private_key` - ML-KEM private key
    /// * `ciphertext` - Ciphertext from encapsulate
    ///
    /// # Returns
    ///
    /// The shared secret.
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
                // ML-DSA requires vendor-specific mechanism
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
        _session: &Session,
        _wrapping_key: ObjectHandle,
        _key_to_wrap: ObjectHandle,
    ) -> HsmResult<Vec<u8>> {
        // RSA-OAEP requires explicit parameters in cryptoki 0.7
        // Placeholder for future implementation
        Err(HsmError::KeyWrap(
            "RSA-OAEP key wrap not yet implemented for cryptoki 0.7".to_string(),
        ))
    }

    fn ml_kem_encapsulate(
        &self,
        _session: &Session,
        _public_key: ObjectHandle,
        _pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        // ML-KEM encapsulation is not directly supported via standard PKCS#11 operations
        // This would require vendor-specific extensions or software fallback
        Err(HsmError::PqcNotSupported(
            "ML-KEM encapsulate not yet implemented (requires vendor extensions)".to_string(),
        ))
    }

    fn ml_kem_decapsulate(
        &self,
        _session: &Session,
        _private_key: ObjectHandle,
        _ciphertext: &[u8],
        _pqc_mechanisms: &PqcMechanismIds,
    ) -> HsmResult<Vec<u8>> {
        // ML-KEM decapsulation is not directly supported via standard PKCS#11 operations
        Err(HsmError::PqcNotSupported(
            "ML-KEM decapsulate not yet implemented (requires vendor extensions)".to_string(),
        ))
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
pub fn sign_rsa_pss(
    _key: &HsmKeyPair,
    _digest: &[u8],
    _hash_algorithm: RsaHashAlgorithm,
) -> HsmResult<Vec<u8>> {
    // RSA-PSS requires explicit parameters in cryptoki 0.7
    // Placeholder for future implementation
    Err(HsmError::UnsupportedMechanism(
        "RSA-PSS signing not yet implemented for cryptoki 0.7".to_string(),
    ))
}

/// Sign with ECDSA.
pub fn sign_ecdsa(key: &HsmKeyPair, digest: &[u8]) -> HsmResult<Vec<u8>> {
    let mechanism = Mechanism::Ecdsa;
    let signer = DefaultHsmSigner;
    signer.sign_with_mechanism(key, digest, &mechanism)
}

/// Sign with ML-DSA (FIPS 204).
///
/// ML-DSA signing internally hashes the message before signing.
/// The HSM performs both hashing and signing.
pub fn sign_ml_dsa(
    _key: &HsmKeyPair,
    _message: &[u8],
    level: MlDsaLevel,
    pqc_mechanisms: &PqcMechanismIds,
) -> HsmResult<Vec<u8>> {
    let mechanism_id = match level {
        MlDsaLevel::L2 => pqc_mechanisms.ml_dsa_44,
        MlDsaLevel::L3 => pqc_mechanisms.ml_dsa_65,
        MlDsaLevel::L5 => pqc_mechanisms.ml_dsa_87,
    }
    .ok_or_else(|| {
        HsmError::PqcNotSupported(format!("ML-DSA level {level:?} mechanism not configured"))
    })?;

    tracing::warn!(
        "Attempting ML-DSA signing with vendor mechanism ID 0x{:08x}",
        mechanism_id
    );

    // cryptoki 0.7 doesn't support vendor-defined mechanisms directly
    // Fall back to error for now - HSM support requires vendor SDK integration
    Err(HsmError::PqcNotSupported(
        "ML-DSA signing requires vendor-specific PKCS#11 extensions not available in cryptoki 0.7"
            .to_string(),
    ))
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

    /// Sign with ML-DSA using software implementation.
    ///
    /// This is a placeholder - actual implementation would use synta-certificate.
    pub fn sign_ml_dsa_software(
        _message: &[u8],
        _private_key_bytes: &[u8],
        _level: MlDsaLevel,
    ) -> HsmResult<Vec<u8>> {
        // Would use synta-certificate ML-DSA implementation
        Err(HsmError::PqcNotSupported(
            "Software ML-DSA fallback not yet implemented".to_string(),
        ))
    }

    /// ML-KEM encapsulate using software implementation.
    pub fn ml_kem_encapsulate_software(
        _public_key_bytes: &[u8],
        _level: MlKemLevel,
    ) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        // Would use synta-certificate ML-KEM implementation
        Err(HsmError::PqcNotSupported(
            "Software ML-KEM encapsulate fallback not yet implemented".to_string(),
        ))
    }

    /// ML-KEM decapsulate using software implementation.
    pub fn ml_kem_decapsulate_software(
        _private_key_bytes: &[u8],
        _ciphertext: &[u8],
        _level: MlKemLevel,
    ) -> HsmResult<Vec<u8>> {
        // Would use synta-certificate ML-KEM implementation
        Err(HsmError::PqcNotSupported(
            "Software ML-KEM decapsulate fallback not yet implemented".to_string(),
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
}
