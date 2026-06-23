//! OTP token generation with configurable entropy.
//!
//! Implements RHELBU-3536 R7: minimum 128-bit entropy using FIPS-approved
//! RNG (`OsRng`). Tokens are base64url-encoded for safe embedding in
//! HTTP headers and URIs.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;
use uuid::Uuid;

use crate::{OtpError, OtpResult};

/// Configuration for the OTP generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpGeneratorConfig {
    /// Number of random bytes to generate (minimum 16 = 128 bits per R7).
    pub entropy_bytes: usize,
    /// Default token lifetime.
    pub default_ttl_seconds: i64,
    /// Default maximum usage count (1 = single-use).
    pub default_max_uses: u32,
}

impl Default for OtpGeneratorConfig {
    fn default() -> Self {
        Self {
            entropy_bytes: 32,         // 256 bits, well above the 128-bit minimum
            default_ttl_seconds: 3600, // 1 hour
            default_max_uses: 1,
        }
    }
}

/// Metadata attached to a generated OTP token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpMetadata {
    /// Unique record identifier.
    pub id: Uuid,
    /// Entity (host, user, service) this OTP authorizes enrollment for.
    pub entity_id: String,
    /// Human-readable label for the OTP.
    pub label: String,
    /// Enrollment profile to apply when this OTP is consumed.
    pub profile: String,
    /// Timestamp when the OTP was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when the OTP expires.
    pub expires_at: DateTime<Utc>,
    /// Maximum number of times this OTP may be used.
    pub max_uses: u32,
}

/// Result of generating a new OTP.
pub struct GeneratedOtp {
    /// The plaintext token value to deliver to the enrollee.
    /// This is the only time the plaintext is available; the store
    /// receives only the SHA-256 hash.
    pub plaintext_token: String,
    /// SHA-256 hash of the token for storage.
    pub token_hash: Vec<u8>,
    /// Metadata for the OTP record.
    pub metadata: OtpMetadata,
}

/// Generates cryptographically random OTP tokens.
///
/// Uses `OsRng` (FIPS-approved on supported platforms) to produce
/// tokens with at least 128 bits of entropy (RHELBU-3536 R7).
pub struct OtpGenerator {
    config: OtpGeneratorConfig,
}

impl OtpGenerator {
    /// Create a generator with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`OtpError::GenerationError`] if `entropy_bytes < 16`
    /// (below the 128-bit minimum required by RHELBU-3536 R7).
    pub fn new(config: OtpGeneratorConfig) -> OtpResult<Self> {
        if config.entropy_bytes < 16 {
            return Err(OtpError::GenerationError(format!(
                "entropy_bytes {} is below the 128-bit (16-byte) minimum per RHELBU-3536 R7",
                config.entropy_bytes
            )));
        }
        Ok(Self { config })
    }

    /// Generate a new OTP for the given entity and profile.
    ///
    /// Returns a [`GeneratedOtp`] containing the plaintext token (for
    /// delivery to the enrollee) and the SHA-256 hash (for storage).
    /// The plaintext must not be persisted by the caller.
    pub fn generate(&self, entity_id: &str, label: &str, profile: &str) -> OtpResult<GeneratedOtp> {
        self.generate_with_options(
            entity_id,
            label,
            profile,
            self.config.default_ttl_seconds,
            self.config.default_max_uses,
        )
    }

    /// Generate an OTP with explicit TTL and max-use overrides.
    pub fn generate_with_options(
        &self,
        entity_id: &str,
        label: &str,
        profile: &str,
        ttl_seconds: i64,
        max_uses: u32,
    ) -> OtpResult<GeneratedOtp> {
        let mut raw = vec![0u8; self.config.entropy_bytes];
        OsRng.fill_bytes(&mut raw);

        let plaintext_token = URL_SAFE_NO_PAD.encode(&raw);
        let token_hash = Sha256::digest(plaintext_token.as_bytes()).to_vec();

        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds);

        let metadata = OtpMetadata {
            id: Uuid::new_v4(),
            entity_id: entity_id.to_owned(),
            label: label.to_owned(),
            profile: profile.to_owned(),
            created_at: now,
            expires_at,
            max_uses,
        };

        debug!(
            id = %metadata.id,
            entity_id = %entity_id,
            label = %label,
            profile = %profile,
            expires_at = %metadata.expires_at,
            "generated OTP token"
        );

        Ok(GeneratedOtp {
            plaintext_token,
            token_hash,
            metadata,
        })
    }

    /// Hash a plaintext token for lookup.
    ///
    /// Used during validation to compute the hash from the client-supplied
    /// token before querying the store.
    pub fn hash_token(plaintext: &str) -> Vec<u8> {
        Sha256::digest(plaintext.as_bytes()).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_meets_minimum_entropy() {
        let generator = OtpGenerator::new(OtpGeneratorConfig::default()).unwrap();
        let otp = generator
            .generate("host.example.com", "test", "default")
            .unwrap();

        // base64url of 32 bytes = 43 characters
        assert!(
            otp.plaintext_token.len() >= 22,
            "token too short for 128-bit entropy"
        );
        assert_eq!(otp.token_hash.len(), 32, "SHA-256 hash should be 32 bytes");
    }

    #[test]
    fn rejects_insufficient_entropy() {
        let config = OtpGeneratorConfig {
            entropy_bytes: 8, // 64 bits, below minimum
            ..Default::default()
        };
        assert!(OtpGenerator::new(config).is_err());
    }

    #[test]
    fn hash_is_deterministic() {
        let a = OtpGenerator::hash_token("test-token");
        let b = OtpGenerator::hash_token("test-token");
        assert_eq!(a, b);
    }
}
