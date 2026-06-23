//! OTP validation and consumption with timing-safe comparison.
//!
//! Implements RHELBU-3536 R8 (timing-safe comparison) and R9/R10
//! (single-use / multi-use with expiration).

use chrono::Utc;
use tracing::{debug, warn};

use crate::generate::OtpGenerator;
use crate::store::OtpStore;
use crate::{OtpError, OtpResult};

/// Result of a successful OTP validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Entity (host/user/service) authorized by this OTP.
    pub entity_id: String,
    /// Enrollment profile to apply for this entity.
    pub profile: String,
    /// Label from the OTP record.
    pub label: String,
    /// Remaining uses after this consumption (0 for single-use tokens).
    pub remaining_uses: u32,
}

/// Validates and consumes OTP tokens.
///
/// Performs timing-safe hash comparison against the store to prevent
/// timing side-channel attacks (RHELBU-3536 R8).
pub struct OtpValidator<S: OtpStore> {
    store: S,
}

impl<S: OtpStore> OtpValidator<S> {
    /// Create a validator backed by the given store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Validate a plaintext OTP token.
    ///
    /// Checks, in order:
    /// 1. Token exists in the store (by SHA-256 hash lookup)
    /// 2. Token is not revoked
    /// 3. Token has not expired
    /// 4. Token has not exceeded its max-use count
    ///
    /// On success, increments the usage counter and returns entity
    /// metadata for authorization. Single-use tokens are consumed
    /// (marked with `current_uses == max_uses`) on first successful
    /// validation.
    ///
    /// # Timing Safety (RHELBU-3536 R8)
    ///
    /// The store lookup is by hash, not by iterating and comparing
    /// plaintext values. The SHA-256 pre-image resistance ensures that
    /// even if an attacker observes lookup timing, they cannot infer
    /// the token value.
    pub async fn validate(&self, plaintext_token: &str) -> OtpResult<ValidationResult> {
        let token_hash = OtpGenerator::hash_token(plaintext_token);

        let record = self
            .store
            .find_by_hash(&token_hash)
            .await?
            .ok_or(OtpError::NotFound)?;

        // Check revocation.
        if record.revoked {
            warn!(id = %record.id, entity_id = %record.entity_id, "OTP is revoked");
            return Err(OtpError::Revoked);
        }

        // Check expiration.
        let now = Utc::now();
        if now > record.expires_at {
            debug!(id = %record.id, expired_at = %record.expires_at, "OTP has expired");
            return Err(OtpError::Expired {
                expired_at: record.expires_at.to_rfc3339(),
            });
        }

        // Check usage limit.
        if record.current_uses >= record.max_uses {
            warn!(
                id = %record.id,
                current = record.current_uses,
                max = record.max_uses,
                "OTP usage limit exceeded"
            );
            return Err(OtpError::UsageLimitExceeded {
                max_uses: record.max_uses,
            });
        }

        // Consume: increment usage counter.
        let new_uses = record.current_uses + 1;
        self.store.increment_uses(&record.id, new_uses).await?;

        let remaining = record.max_uses - new_uses;

        debug!(
            id = %record.id,
            entity_id = %record.entity_id,
            uses = new_uses,
            remaining,
            "OTP validated and consumed"
        );

        Ok(ValidationResult {
            entity_id: record.entity_id,
            profile: record.profile,
            label: record.label,
            remaining_uses: remaining,
        })
    }

    /// Revoke an OTP by its record ID.
    pub async fn revoke(&self, id: &uuid::Uuid) -> OtpResult<()> {
        self.store.revoke(id).await
    }

    /// Reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}
