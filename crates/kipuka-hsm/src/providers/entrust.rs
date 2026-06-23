//! Entrust nShield HSM provider.
//!
//! The Entrust nShield HSM family (formerly nCipher) provides hardware-backed
//! cryptographic operations with support for Security Worlds and OCS card sets.
//!
//! # Platform-specific Library Paths
//!
//! - Linux: `/opt/nfast/toolkits/pkcs11/libcknfast.so`
//! - macOS: `/opt/nfast/toolkits/pkcs11/libcknfast.dylib`
//! - Windows: `C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.dll`
//!
//! # Security World and OCS
//!
//! nShield HSMs use a "Security World" model where keys are protected by:
//! - Administrator Card Sets (ACS) - for initial setup
//! - Operator Card Sets (OCS) - for routine key access
//!
//! The PKCS#11 interface requires OCS cards to be presented before accessing
//! protected keys. In automated environments, this is typically handled via:
//! - Softcards (passphrase-protected software OCS)
//! - Remote Operator (network-based OCS)
//! - Preload (OCS loaded during system boot)
//!
//! # Mechanism Support
//!
//! nShield supports all standard PKCS#11 mechanisms including:
//! - RSA signing and encryption (PKCS#1 v1.5, PSS, OAEP)
//! - ECDSA signing (P-256, P-384, P-521)
//! - AES Key Wrap (CKM_AES_KEY_WRAP) via nCore
//!
//! Note: Some mechanisms may require specific firmware versions or nCore modules.

use crate::HsmProvider;
use crate::providers::HsmProviderConfig;
use cryptoki::mechanism::MechanismType;

/// Default PKCS#11 library path for Linux.
pub fn default_library_path() -> &'static str {
    #[cfg(target_os = "linux")]
    return "/opt/nfast/toolkits/pkcs11/libcknfast.so";

    #[cfg(target_os = "macos")]
    return "/opt/nfast/toolkits/pkcs11/libcknfast.dylib";

    #[cfg(target_os = "windows")]
    return "C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll";

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return "/opt/nfast/toolkits/pkcs11/libcknfast.so";
}

/// Mechanisms supported by nShield HSMs.
pub fn supported_mechanisms() -> Vec<MechanismType> {
    vec![
        // RSA
        MechanismType::RSA_PKCS,
        MechanismType::RSA_PKCS_KEY_PAIR_GEN,
        MechanismType::SHA256_RSA_PKCS,
        MechanismType::SHA384_RSA_PKCS,
        MechanismType::SHA512_RSA_PKCS,
        MechanismType::RSA_PKCS_PSS,
        MechanismType::SHA256_RSA_PKCS_PSS,
        MechanismType::SHA384_RSA_PKCS_PSS,
        MechanismType::SHA512_RSA_PKCS_PSS,
        MechanismType::RSA_PKCS_OAEP,
        // ECDSA
        MechanismType::ECDSA,
        MechanismType::ECDSA_SHA256,
        MechanismType::ECDSA_SHA384,
        MechanismType::ECDSA_SHA512,
        MechanismType::ECC_KEY_PAIR_GEN,
        // AES
        MechanismType::AES_KEY_GEN,
        MechanismType::AES_ECB,
        MechanismType::AES_CBC,
        MechanismType::AES_GCM,
        MechanismType::AES_KEY_WRAP,
        MechanismType::AES_KEY_WRAP_PAD,
        // Hashing
        MechanismType::SHA256,
        MechanismType::SHA384,
        MechanismType::SHA512,
    ]
}

/// Get the default provider configuration for Entrust nShield.
pub fn provider_config() -> HsmProviderConfig {
    HsmProviderConfig {
        provider: HsmProvider::Entrust,
        library_path: default_library_path().to_string(),
        supported_mechanisms: supported_mechanisms(),
        notes: vec![
            "Requires Security World setup with OCS card sets".to_string(),
            "CKM_AES_KEY_WRAP supported via nCore but may need explicit mechanism mapping"
                .to_string(),
            "Softcard passphrase required for automated key access".to_string(),
            "Check firmware version for PSS and OAEP support".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_path_not_empty() {
        assert!(!default_library_path().is_empty());
    }

    #[test]
    fn test_mechanisms_include_rsa_and_ecdsa() {
        let mechanisms = supported_mechanisms();
        assert!(mechanisms.contains(&MechanismType::RSA_PKCS));
        assert!(mechanisms.contains(&MechanismType::ECDSA));
        assert!(mechanisms.contains(&MechanismType::AES_KEY_WRAP));
    }

    #[test]
    fn test_config_populated() {
        let config = provider_config();
        assert_eq!(config.provider, HsmProvider::Entrust);
        assert!(!config.notes.is_empty());
    }
}
