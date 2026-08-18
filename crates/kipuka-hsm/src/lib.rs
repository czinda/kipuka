//! PKCS#11 HSM abstraction with ML-DSA and ML-KEM support.
//!
//! This crate provides a high-level interface to PKCS#11 Hardware Security Modules (HSMs)
//! with full support for:
//!
//! - **Classical algorithms**: RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521)
//! - **Post-quantum algorithms**: ML-DSA (FIPS 204), ML-KEM (FIPS 203)
//! - **Key wrapping**: AES Key Wrap (RFC 3394), RSAES-OAEP
//! - **NIAP CA PP compliance**: FCS_CKM.1 key generation requirements
//!
//! # Supported Providers
//!
//! - Entrust nShield
//! - Utimaco CryptoServer
//! - Kryoptic (software token)
//! - Thales Luna Cloud HSM (CSP)
//! - Thales Luna Tactical (TCT)
//!
//! # Post-Quantum Cryptography
//!
//! PQC mechanisms (ML-DSA, ML-KEM) use the standard PKCS#11 v3.2 mechanism IDs
//! provided by the `cryptoki` crate (e.g. `MechanismType::ML_DSA`, `MechanismType::ML_KEM`).
//!
//! When HSM does not support PQC, the library can fall back to software implementations
//! using `synta-certificate`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                     Application Layer                    │
//! │                  (kipuka EST server)                     │
//! └─────────────────────────────────────────────────────────┘
//!                           │
//!                           ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                    kipuka-hsm crate                      │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
//! │  │  HsmKeyPair  │  │  HsmSigner   │  │   HsmSlot    │  │
//! │  └──────────────┘  └──────────────┘  └──────────────┘  │
//! │            │              │                  │           │
//! │            └──────────────┴──────────────────┘           │
//! │                           │                              │
//! │                  ┌────────▼────────┐                     │
//! │                  │ Pkcs11Context   │                     │
//! │                  └────────┬────────┘                     │
//! └───────────────────────────┼──────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                     cryptoki crate                       │
//! │              (Rust PKCS#11 bindings)                     │
//! └─────────────────────────────────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │            Vendor PKCS#11 Library (.so/.dll)             │
//! │   (Entrust, Utimaco, Kryoptic, Thales CSP/TCT)          │
//! └─────────────────────────────────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              Hardware Security Module                    │
//! │           (Physical HSM or software token)               │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use kipuka_hsm::{
//!     HsmSlot, HsmKeyPair, KeyAlgorithm, EcdsaCurve,
//!     Pkcs11Context, sign_ecdsa,
//!     providers::HsmProvider,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize PKCS#11 library
//! let provider = HsmProvider::Kryoptic;
//! let config = provider.config();
//! let context = Pkcs11Context::new(&config.library_path)?;
//!
//! // Find HSM slot
//! let slot = HsmSlot::find_first_slot(&context)?;
//!
//! // Generate ECDSA P-256 key pair
//! let key = HsmKeyPair::generate(
//!     &slot,
//!     KeyAlgorithm::Ecdsa(EcdsaCurve::P256),
//!     "my-signing-key",
//!     &[0x01, 0x02, 0x03], // CKA_ID
//!     &config,
//! )?;
//!
//! // Sign a message digest
//! let digest = [0u8; 32]; // SHA-256 digest
//! let signature = sign_ecdsa(&key, &digest)?;
//! # Ok(())
//! # }
//! ```
//!
//! # ML-DSA Example
//!
//! ```rust,no_run
//! use kipuka_hsm::{
//!     HsmSlot, HsmKeyPair, KeyAlgorithm, MlDsaLevel,
//!     Pkcs11Context, sign_ml_dsa,
//!     providers::HsmProvider,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let provider = HsmProvider::Kryoptic;
//! let config = provider.config();
//! let context = Pkcs11Context::new(&config.library_path)?;
//! let slot = HsmSlot::find_first_slot(&context)?;
//!
//! // Generate ML-DSA-65 key pair
//! let key = HsmKeyPair::generate(
//!     &slot,
//!     KeyAlgorithm::MlDsa(MlDsaLevel::L3),
//!     "ml-dsa-signing-key",
//!     &[0x04, 0x05, 0x06],
//!     &config,
//! )?;
//!
//! // Sign a message (ML-DSA hashes internally)
//! let message = b"Hello, post-quantum world!";
//! let signature = sign_ml_dsa(&key, message, MlDsaLevel::L3)?;
//! # Ok(())
//! # }
//! ```

// Core modules
pub mod error;
pub mod key;
pub mod pkcs11;
pub mod sign;
pub mod slot;

// Provider registry
pub mod providers;

// rustls PKCS#11 signing key (TLS server/client key backed by HSM)
pub mod rustls_signer;

// Re-exports for convenience
pub use error::{HsmError, HsmResult};
pub use key::{EcdsaCurve, HsmKeyPair, KeyAlgorithm, MlDsaLevel, MlKemLevel};
pub use pkcs11::Pkcs11Context;
pub use providers::HsmProvider;
pub use rustls_signer::Pkcs11SigningKey;
pub use sign::{
    DefaultHsmSigner, HsmSigner, RsaHashAlgorithm, SoftwarePqcFallback, sign_ecdsa, sign_ml_dsa,
    sign_rsa_pkcs1, sign_rsa_pss,
};
pub use slot::HsmSlot;

/// High-level HSM context wrapping PKCS#11 initialization and provider config.
///
/// Used by `AppState` to hold the HSM connection for the server lifetime.
/// When fully initialized, holds a logged-in PKCS#11 session for signing.
pub struct HsmContext {
    pub context: Pkcs11Context,
    pub provider: HsmProvider,
    /// Active logged-in session for signing operations.
    ///
    /// Wrapped in a `Mutex` because `Session` is not `Send`+`Sync` and
    /// signing requires `&Session` (which takes a lock internally).
    session: std::sync::Mutex<Option<cryptoki::session::Session>>,
    /// The slot used for this context (needed for opening new sessions).
    #[allow(dead_code)]
    slot: Option<HsmSlot>,
}

impl std::fmt::Debug for HsmContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmContext")
            .field("provider", &self.provider)
            .field("session", &"<Mutex<Session>>")
            .finish()
    }
}

// Safety: The `Session` inside `Mutex` is only accessed while locked.
// The cryptoki `Session` is `!Send` but we only use it from within a
// synchronous `Mutex::lock()` guard, which is safe for `Send`+`Sync`.
unsafe impl Send for HsmContext {}
unsafe impl Sync for HsmContext {}

impl HsmContext {
    /// Create a new HSM context with a logged-in session ready for signing.
    pub fn new(
        context: Pkcs11Context,
        provider: HsmProvider,
        slot: HsmSlot,
        session: cryptoki::session::Session,
    ) -> Self {
        Self {
            context,
            provider,
            session: std::sync::Mutex::new(Some(session)),
            slot: Some(slot),
        }
    }

    pub fn placeholder() -> Self {
        Self {
            context: Pkcs11Context::placeholder(),
            provider: HsmProvider::Kryoptic,
            session: std::sync::Mutex::new(None),
            slot: None,
        }
    }

    /// Check that the HSM session is initialized and the mutex is healthy.
    ///
    /// Returns `Ok(())` if a PKCS#11 session exists and the lock is
    /// acquirable.  Used by health probes to verify HSM availability
    /// without performing a signing operation.
    pub fn health_check(&self) -> HsmResult<()> {
        let guard = self
            .session
            .lock()
            .map_err(|_| HsmError::LibraryLoad("HSM session mutex poisoned".into()))?;
        if guard.is_some() {
            Ok(())
        } else {
            Err(HsmError::LibraryLoad(
                "HSM session not initialized (placeholder context)".into(),
            ))
        }
    }

    /// Sign data using the HSM key identified by label.
    ///
    /// Uses `CKM_SHA256_RSA_PKCS` for RSA keys (the mechanism hashes
    /// and signs in one operation, so `data` is the raw TBS bytes).
    ///
    /// # Arguments
    ///
    /// * `key_label` - CKA_LABEL of the private key in the token
    /// * `data` - data to sign (raw TBS certificate bytes)
    /// * `hash_algorithm` - hash algorithm name ("sha256", "sha384", "sha512")
    pub fn sign_data(
        &self,
        key_label: &str,
        data: &[u8],
        hash_algorithm: &str,
    ) -> HsmResult<Vec<u8>> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, ObjectClass};

        let guard = self
            .session
            .lock()
            .map_err(|_| HsmError::LibraryLoad("HSM session mutex poisoned".into()))?;
        let session = guard.as_ref().ok_or_else(|| {
            HsmError::LibraryLoad("HSM session not initialized (placeholder context)".into())
        })?;

        // Find the private key by label.
        let template = vec![
            Attribute::Label(key_label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        let objects = session
            .find_objects(&template)
            .map_err(|e| HsmError::KeyNotFound(format!("Failed to find key '{key_label}': {e}")))?;

        let private_key = objects.into_iter().next().ok_or_else(|| {
            HsmError::KeyNotFound(format!("Private key '{key_label}' not found in token"))
        })?;

        // Select the combined hash+sign mechanism based on algorithm.
        // These mechanisms hash the data internally then sign.
        let mechanism = match hash_algorithm {
            "sha256" => Mechanism::Sha256RsaPkcs,
            "sha384" => Mechanism::Sha384RsaPkcs,
            "sha512" => Mechanism::Sha512RsaPkcs,
            other => {
                return Err(HsmError::UnsupportedMechanism(format!(
                    "Unsupported hash algorithm for RSA signing: {other}"
                )));
            }
        };

        // Sign the data.
        session.sign(&mechanism, private_key, data).map_err(|e| {
            HsmError::SigningFailure(format!("C_Sign failed for key '{key_label}': {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_structure() {
        // Smoke test to ensure all modules compile and link
        let _provider = HsmProvider::Kryoptic;
        let _config = _provider.config();
        assert!(!_config.library_path.is_empty());
    }

    #[test]
    fn test_key_algorithms() {
        let rsa = KeyAlgorithm::Rsa(2048);
        let ecdsa = KeyAlgorithm::Ecdsa(EcdsaCurve::P256);
        let ml_dsa = KeyAlgorithm::MlDsa(MlDsaLevel::L3);
        let ml_kem = KeyAlgorithm::MlKem(MlKemLevel::L3);

        // Just verify they construct
        assert!(matches!(rsa, KeyAlgorithm::Rsa(2048)));
        assert!(matches!(ecdsa, KeyAlgorithm::Ecdsa(_)));
        assert!(matches!(ml_dsa, KeyAlgorithm::MlDsa(_)));
        assert!(matches!(ml_kem, KeyAlgorithm::MlKem(_)));
    }
}
