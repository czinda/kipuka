//! Thales Luna Cloud HSM (CSP) provider.
//!
//! The Thales Luna Cloud HSM provides network-attached hardware security modules
//! with high-availability (HA) group support and partition-based multi-tenancy.
//!
//! # Platform-specific Library Paths
//!
//! - Linux: `/usr/safenet/lunaclient/lib/libCryptoki2_64.so`
//! - Windows: `C:\Program Files\SafeNet\LunaClient\cryptoki.dll`
//!
//! # HA Group Configuration
//!
//! Luna CSP supports High Availability groups where multiple HSM partitions
//! appear as a single virtual HSM:
//! - Automatic failover between members
//! - Load balancing across partitions
//! - Synchronous or asynchronous replication
//!
//! HA groups are configured via `vtl` command-line tool.
//!
//! # Partition Management
//!
//! Each Luna HSM can be partitioned into multiple logical HSMs:
//! - Independent key storage and access control per partition
//! - Partition-level PIN authentication
//! - Separate PKCS#11 slots per partition
//!
//! # Key Wrapping Support
//!
//! Luna CSP fully supports:
//! - CKM_AES_KEY_WRAP (RFC 3394)
//! - CKM_AES_KEY_WRAP_PAD (RFC 5649) for non-aligned keys
//! - CKM_RSA_PKCS_OAEP for RSA-based wrapping
//!
//! All mechanisms are hardware-accelerated.

use crate::providers::HsmProviderConfig;
use crate::HsmProvider;
use cryptoki::mechanism::MechanismType;

/// Default PKCS#11 library path for Luna CSP.
pub fn default_library_path() -> &'static str {
    #[cfg(target_os = "linux")]
    return "/usr/safenet/lunaclient/lib/libCryptoki2_64.so";

    #[cfg(target_os = "windows")]
    return "C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll";

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return "/usr/safenet/lunaclient/lib/libCryptoki2_64.so";
}

/// Mechanisms supported by Luna CSP.
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

/// Get the default provider configuration for Thales Luna CSP.
pub fn provider_config() -> HsmProviderConfig {
    HsmProviderConfig {
        provider: HsmProvider::ThalesCsp,
        library_path: default_library_path().to_string(),
        supported_mechanisms: supported_mechanisms(),
        notes: vec![
            "Supports HA group configuration for failover and load balancing".to_string(),
            "Partition management via vtl command-line tool".to_string(),
            "CKM_AES_KEY_WRAP fully supported".to_string(),
            "CKM_AES_KEY_WRAP_PAD available for non-aligned key lengths".to_string(),
            "RSAES-OAEP fully supported and hardware-accelerated".to_string(),
            "Network-attached; requires Luna Client installation".to_string(),
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

    #[test]
    fn test_config_has_ha_notes() {
        let config = provider_config();
        assert!(config.notes.iter().any(|n| n.contains("HA group")));
    }
}
