//! Thales Luna Tactical (TCT) HSM provider.
//!
//! The Luna TCT (Tactical) is a ruggedized, battery-backed HSM designed for
//! mobile, field, and disconnected environments with tamper-responsive security.
//!
//! # Platform-specific Library Paths
//!
//! Luna TCT uses the same PKCS#11 library as Luna CSP:
//! - Linux: `/usr/safenet/lunaclient/lib/libCryptoki2_64.so`
//! - Windows: `C:\Program Files\SafeNet\LunaClient\cryptoki.dll`
//!
//! # Tactical/Ruggedized Features
//!
//! - **Battery-backed RAM**: Keys persist through power loss
//! - **Tamper detection**: Physical intrusion triggers key zeroization
//! - **Environmental hardening**: Extended temperature, shock, vibration tolerance
//! - **Portable form factor**: Designed for field deployment
//!
//! # Disconnected/Air-Gapped Environments
//!
//! Luna TCT is specifically designed for disconnected EST use cases per
//! RHELBU-3536 R7-Disconnected:
//!
//! - **No network dependency**: All cryptographic operations local to HSM
//! - **Offline key generation**: CA and EST server keys generated on-device
//! - **Manual key transport**: Physical custody for key backup/recovery
//! - **Audit trail**: Local logging of all key operations
//!
//! For disconnected deployments:
//! 1. Generate CA and EST server keys on TCT in secure facility
//! 2. Configure EST server with PKCS#11 URI pointing to TCT keys
//! 3. Deploy TCT with EST server to disconnected environment
//! 4. All certificate issuance happens locally without network connectivity
//!
//! # Storage Constraints
//!
//! Luna TCT has more conservative limits than cloud HSMs:
//! - Limited slot count (typically 1-4 partitions)
//! - Smaller key storage capacity (hundreds vs thousands of keys)
//! - Battery lifetime considerations for long-term deployments
//!
//! # Mechanism Support
//!
//! Luna TCT provides the same cryptographic mechanisms as Luna CSP:
//! - Full RSA and ECDSA support
//! - AES Key Wrap (CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD)
//! - RSAES-OAEP for key wrapping

use crate::HsmProvider;
use crate::providers::HsmProviderConfig;
use cryptoki::mechanism::MechanismType;

/// Default PKCS#11 library path for Luna TCT.
///
/// Same library as Luna CSP; behavior differs based on connected HSM model.
pub fn default_library_path() -> &'static str {
    #[cfg(target_os = "linux")]
    return "/usr/safenet/lunaclient/lib/libCryptoki2_64.so";

    #[cfg(target_os = "windows")]
    return "C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll";

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return "/usr/safenet/lunaclient/lib/libCryptoki2_64.so";
}

/// Mechanisms supported by Luna TCT.
///
/// Same mechanism set as Luna CSP.
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

/// Get the default provider configuration for Thales Luna TCT.
pub fn provider_config() -> HsmProviderConfig {
    HsmProviderConfig {
        provider: HsmProvider::ThalesTct,
        library_path: default_library_path().to_string(),
        supported_mechanisms: supported_mechanisms(),
        notes: vec![
            "Ruggedized, battery-backed HSM for tactical/field deployment".to_string(),
            "Tamper-responsive with physical intrusion detection".to_string(),
            "Designed for disconnected/air-gapped environments (RHELBU-3536 R7-Disconnected)"
                .to_string(),
            "Limited slot count and key storage vs cloud HSMs".to_string(),
            "Same PKCS#11 mechanisms as Luna CSP".to_string(),
            "CKM_AES_KEY_WRAP and CKM_AES_KEY_WRAP_PAD fully supported".to_string(),
            "RSAES-OAEP fully supported".to_string(),
            "Offline key generation and certificate issuance without network dependency"
                .to_string(),
            "Manual key transport via physical custody for backup/recovery".to_string(),
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
    fn test_mechanisms_same_as_csp() {
        // TCT and CSP use same PKCS#11 library and mechanism set
        let mechanisms = supported_mechanisms();
        assert!(mechanisms.contains(&MechanismType::RSA_PKCS));
        assert!(mechanisms.contains(&MechanismType::ECDSA));
        assert!(mechanisms.contains(&MechanismType::AES_KEY_WRAP));
    }

    #[test]
    fn test_config_has_tactical_notes() {
        let config = provider_config();
        assert!(
            config
                .notes
                .iter()
                .any(|n| n.contains("tactical") || n.contains("Tactical"))
        );
        assert!(
            config
                .notes
                .iter()
                .any(|n| n.contains("disconnected") || n.contains("air-gapped"))
        );
        assert!(config.notes.iter().any(|n| n.contains("battery")));
    }
}
