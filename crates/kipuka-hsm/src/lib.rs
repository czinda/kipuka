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
//! PQC mechanisms (ML-DSA, ML-KEM) are vendor-specific until PKCS#11 v3.2 standardization.
//! Each provider configuration includes vendor-specific mechanism IDs via `PqcMechanismIds`.
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
//!     key::PqcMechanismIds,
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
//! let pqc_mechanisms = PqcMechanismIds::default();
//! let key = HsmKeyPair::generate(
//!     &slot,
//!     KeyAlgorithm::Ecdsa(EcdsaCurve::P256),
//!     "my-signing-key",
//!     &[0x01, 0x02, 0x03], // CKA_ID
//!     &config,
//!     &pqc_mechanisms,
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
//!     key::PqcMechanismIds,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let provider = HsmProvider::Kryoptic;
//! let config = provider.config();
//! let context = Pkcs11Context::new(&config.library_path)?;
//! let slot = HsmSlot::find_first_slot(&context)?;
//!
//! // Configure vendor-specific PQC mechanism IDs
//! let pqc_mechanisms = PqcMechanismIds {
//!     ml_dsa_keygen: Some(0x8000_0001),
//!     ml_dsa_65: Some(0x8000_0003),
//!     ..Default::default()
//! };
//!
//! // Generate ML-DSA-65 key pair
//! let key = HsmKeyPair::generate(
//!     &slot,
//!     KeyAlgorithm::MlDsa(MlDsaLevel::L3),
//!     "ml-dsa-signing-key",
//!     &[0x04, 0x05, 0x06],
//!     &config,
//!     &pqc_mechanisms,
//! )?;
//!
//! // Sign a message (ML-DSA hashes internally)
//! let message = b"Hello, post-quantum world!";
//! let signature = sign_ml_dsa(&key, message, MlDsaLevel::L3, &pqc_mechanisms)?;
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

// Re-exports for convenience
pub use error::{HsmError, HsmResult};
pub use key::{EcdsaCurve, HsmKeyPair, KeyAlgorithm, MlDsaLevel, MlKemLevel, PqcMechanismIds};
pub use pkcs11::Pkcs11Context;
pub use providers::HsmProvider;
pub use sign::{
    DefaultHsmSigner, HsmSigner, RsaHashAlgorithm, SoftwarePqcFallback, sign_ecdsa, sign_ml_dsa,
    sign_rsa_pkcs1, sign_rsa_pss,
};
pub use slot::HsmSlot;

/// High-level HSM context wrapping PKCS#11 initialization and provider config.
///
/// Used by `AppState` to hold the HSM connection for the server lifetime.
pub struct HsmContext {
    pub context: Pkcs11Context,
    pub provider: HsmProvider,
}

impl HsmContext {
    pub fn new(context: Pkcs11Context, provider: HsmProvider) -> Self {
        Self { context, provider }
    }

    pub fn placeholder() -> Self {
        Self {
            context: Pkcs11Context::placeholder(),
            provider: HsmProvider::Kryoptic,
        }
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
    fn test_pqc_mechanism_ids() {
        let ids = PqcMechanismIds::default();
        assert!(ids.ml_dsa_keygen.is_some());
        assert!(ids.ml_kem_keygen.is_some());
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
