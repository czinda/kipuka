//! HSM provider registry and vendor-specific configurations.

pub mod entrust;
pub mod kryoptic;
pub mod thales_csp;
pub mod thales_tct;
pub mod utimaco;

use cryptoki::mechanism::MechanismType;
use serde::Deserialize;

/// Supported HSM providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum HsmProvider {
    /// Entrust nShield HSM.
    Entrust,
    /// Utimaco CryptoServer HSM.
    Utimaco,
    /// Kryoptic software token (FIPS 140-3 module).
    Kryoptic,
    /// Thales Luna Cloud HSM (CSP).
    ThalesCsp,
    /// Thales Luna Tactical (TCT).
    ThalesTct,
}

/// Provider-specific configuration.
#[derive(Debug, Clone)]
pub struct HsmProviderConfig {
    /// Provider identifier.
    pub provider: HsmProvider,
    /// Default PKCS#11 library path.
    pub library_path: String,
    /// Supported PKCS#11 mechanisms.
    pub supported_mechanisms: Vec<MechanismType>,
    /// Provider-specific notes and quirks.
    pub notes: Vec<String>,
}

impl HsmProvider {
    /// Get the default configuration for this provider.
    pub fn config(&self) -> HsmProviderConfig {
        match self {
            Self::Entrust => entrust::provider_config(),
            Self::Utimaco => utimaco::provider_config(),
            Self::Kryoptic => kryoptic::provider_config(),
            Self::ThalesCsp => thales_csp::provider_config(),
            Self::ThalesTct => thales_tct::provider_config(),
        }
    }

    /// Detect provider from PKCS#11 library info.
    ///
    /// This is a best-effort heuristic based on library manufacturer strings.
    pub fn detect_from_library_info(manufacturer: &str, library_description: &str) -> Option<Self> {
        let manufacturer_lower = manufacturer.to_lowercase();
        let description_lower = library_description.to_lowercase();

        if manufacturer_lower.contains("entrust") || manufacturer_lower.contains("ncipher") {
            Some(Self::Entrust)
        } else if manufacturer_lower.contains("utimaco") {
            Some(Self::Utimaco)
        } else if manufacturer_lower.contains("kryoptic") || description_lower.contains("kryoptic")
        {
            Some(Self::Kryoptic)
        } else if manufacturer_lower.contains("thales") || manufacturer_lower.contains("safenet") {
            // Distinguish CSP vs TCT by library path or model
            if description_lower.contains("tactical") || description_lower.contains("tct") {
                Some(Self::ThalesTct)
            } else {
                Some(Self::ThalesCsp)
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_detection() {
        assert_eq!(
            HsmProvider::detect_from_library_info("nCipher Corporation Ltd", "nFast PKCS#11"),
            Some(HsmProvider::Entrust)
        );

        assert_eq!(
            HsmProvider::detect_from_library_info("Utimaco IS GmbH", "CryptoServer PKCS#11"),
            Some(HsmProvider::Utimaco)
        );

        assert_eq!(
            HsmProvider::detect_from_library_info("Thales", "Luna CSP PKCS#11"),
            Some(HsmProvider::ThalesCsp)
        );

        assert_eq!(
            HsmProvider::detect_from_library_info("Thales", "Luna TCT Tactical"),
            Some(HsmProvider::ThalesTct)
        );
    }

    #[test]
    fn test_all_providers_have_configs() {
        for provider in &[
            HsmProvider::Entrust,
            HsmProvider::Utimaco,
            HsmProvider::Kryoptic,
            HsmProvider::ThalesCsp,
            HsmProvider::ThalesTct,
        ] {
            let config = provider.config();
            assert!(!config.library_path.is_empty());
            assert!(!config.supported_mechanisms.is_empty());
        }
    }
}
