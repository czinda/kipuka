//! Utimaco CryptoServer HSM provider.
//!
//! The Utimaco CryptoServer family provides high-performance cryptographic
//! operations with flexible firmware-based key management.
//!
//! # Platform-specific Library Paths
//!
//! - Linux: `/usr/lib/libcs_pkcs11_R3.so` (or `/opt/utimaco/...` for custom installs)
//! - Windows: `C:\Program Files\Utimaco\CryptoServer\Lib\cs_pkcs11_R3.dll`
//!
//! # Firmware Slot Configuration
//!
//! CryptoServer uses firmware "slots" which are logical partitions within
//! the HSM. Each slot has:
//! - Independent key storage and access control
//! - Configurable PIN policies
//! - Per-slot mechanism enablement
//!
//! Slot 0 is typically the administrator slot; user slots start at 1.
//!
//! # Key Wrapping Support
//!
//! Utimaco supports both AES Key Wrap and RSA-OAEP for key transport:
//! - CKM_AES_KEY_WRAP (RFC 3394)
//! - CKM_AES_KEY_WRAP_PAD (RFC 5649) for non-aligned key lengths
//! - CKM_RSA_PKCS_OAEP for RSA-based wrapping

use crate::providers::HsmProviderConfig;
use crate::HsmProvider;
use cryptoki::mechanism::MechanismType;

/// Default PKCS#11 library path for Linux.
pub fn default_library_path() -> &'static str {
    #[cfg(target_os = "linux")]
    return "/usr/lib/libcs_pkcs11_R3.so";

    #[cfg(target_os = "windows")]
    return "C:\\Program Files\\Utimaco\\CryptoServer\\Lib\\cs_pkcs11_R3.dll";

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return "/usr/lib/libcs_pkcs11_R3.so";
}

/// Mechanisms supported by Utimaco CryptoServer.
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

/// Get the default provider configuration for Utimaco.
pub fn provider_config() -> HsmProviderConfig {
    HsmProviderConfig {
        provider: HsmProvider::Utimaco,
        library_path: default_library_path().to_string(),
        supported_mechanisms: supported_mechanisms(),
        notes: vec![
            "Firmware slot configuration required before use".to_string(),
            "Slot 0 is typically admin; user slots start at 1".to_string(),
            "Full support for AES_KEY_WRAP and AES_KEY_WRAP_PAD".to_string(),
            "RSAES-OAEP fully supported for key wrapping".to_string(),
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
    fn test_mechanisms_include_key_wrap() {
        let mechanisms = supported_mechanisms();
        assert!(mechanisms.contains(&MechanismType::AES_KEY_WRAP));
        assert!(mechanisms.contains(&MechanismType::AES_KEY_WRAP_PAD));
        assert!(mechanisms.contains(&MechanismType::RSA_PKCS_OAEP));
    }
}
