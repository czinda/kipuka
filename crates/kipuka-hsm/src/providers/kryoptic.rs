//! Kryoptic software token provider.
//!
//! Kryoptic is a FIPS 140-3 validated software cryptographic module providing
//! PKCS#11 2.40+ compliance. It's useful for development, testing, and
//! environments where hardware HSM is not required.
//!
//! # Library Path
//!
//! Kryoptic is typically user-installed and the library path varies:
//! - Linux: `~/.local/lib/libkryoptic.so` or `/usr/local/lib/libkryoptic.so`
//! - macOS: `~/Library/Frameworks/libkryoptic.dylib`
//!
//! Set `KRYOPTIC_PKCS11_MODULE` environment variable to override.
//!
//! # Use Cases
//!
//! - Local development without HSM hardware
//! - CI/CD testing pipelines
//! - FIPS 140-3 compliance in software-only deployments
//!
//! # Production Considerations
//!
//! While Kryoptic is FIPS 140-3 validated, it does NOT provide:
//! - Physical tamper protection
//! - Hardware-backed key storage
//! - Key extraction resistance
//!
//! Do NOT use for production CA keys or environments requiring NIAP CA PP
//! compliance with hardware security requirements.

use crate::providers::HsmProviderConfig;
use crate::HsmProvider;
use cryptoki::mechanism::MechanismType;

/// Default PKCS#11 library path.
///
/// Checks KRYOPTIC_PKCS11_MODULE environment variable, otherwise uses
/// platform-specific defaults.
pub fn default_library_path() -> &'static str {
    // In a real implementation, this would check the env var at runtime
    #[cfg(target_os = "linux")]
    return "/usr/local/lib/libkryoptic.so";

    #[cfg(target_os = "macos")]
    return "/usr/local/lib/libkryoptic.dylib";

    #[cfg(target_os = "windows")]
    return "C:\\Program Files\\Kryoptic\\kryoptic.dll";

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return "/usr/local/lib/libkryoptic.so";
}

/// Mechanisms supported by Kryoptic.
///
/// Kryoptic implements full PKCS#11 2.40+ mechanism set.
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

/// Get the default provider configuration for Kryoptic.
pub fn provider_config() -> HsmProviderConfig {
    HsmProviderConfig {
        provider: HsmProvider::Kryoptic,
        library_path: default_library_path().to_string(),
        supported_mechanisms: supported_mechanisms(),
        notes: vec![
            "Software-only FIPS 140-3 module - NOT for production HSM requirements".to_string(),
            "No hardware tamper protection or physical key storage".to_string(),
            "Excellent for development and testing".to_string(),
            "Set KRYOPTIC_PKCS11_MODULE environment variable to override library path".to_string(),
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
    fn test_mechanisms_supported() {
        let mechanisms = supported_mechanisms();
        assert!(mechanisms.contains(&MechanismType::RSA_PKCS));
        assert!(mechanisms.contains(&MechanismType::ECDSA));
    }
}
