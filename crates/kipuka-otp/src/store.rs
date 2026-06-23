//! Pluggable OTP storage backends.
//!
//! Implements RHELBU-3536 R11 (hash-only storage) and R12 (periodic cleanup).
//! Tokens are stored as SHA-256 hashes; the plaintext is never persisted.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{OtpError, OtpResult};

/// Persistent OTP record (RHELBU-3536 R11).
///
/// The `token_hash` field stores the SHA-256 digest of the plaintext
/// token. The plaintext is never written to any storage backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpRecord {
    /// Unique record identifier.
    pub id: Uuid,
    /// SHA-256 hash of the plaintext token (32 bytes).
    pub token_hash: Vec<u8>,
    /// Entity (host, user, service) this OTP authorizes enrollment for.
    pub entity_id: String,
    /// Human-readable label.
    pub label: String,
    /// Enrollment profile to apply.
    pub profile: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Maximum number of allowed uses.
    pub max_uses: u32,
    /// Current number of completed uses.
    pub current_uses: u32,
    /// Whether the OTP has been administratively revoked.
    pub revoked: bool,
}

/// Trait for pluggable OTP storage backends.
///
/// Implementors must be `Send + Sync` for use in async contexts.
pub trait OtpStore: Send + Sync {
    /// Insert a new OTP record.
    fn insert(&self, record: OtpRecord) -> impl std::future::Future<Output = OtpResult<()>> + Send;

    /// Find a record by its token hash.
    fn find_by_hash(
        &self,
        hash: &[u8],
    ) -> impl std::future::Future<Output = OtpResult<Option<OtpRecord>>> + Send;

    /// Increment the usage counter for a record.
    fn increment_uses(
        &self,
        id: &Uuid,
        new_count: u32,
    ) -> impl std::future::Future<Output = OtpResult<()>> + Send;

    /// Mark a record as revoked.
    fn revoke(&self, id: &Uuid) -> impl std::future::Future<Output = OtpResult<()>> + Send;

    /// Remove all expired records (RHELBU-3536 R12).
    fn cleanup_expired(&self) -> impl std::future::Future<Output = OtpResult<u64>> + Send;
}

// ---------------------------------------------------------------------------
// In-memory implementation (testing)
// ---------------------------------------------------------------------------

/// In-memory OTP store for unit testing.
///
/// Not suitable for production; all data is lost on process exit.
#[derive(Clone)]
pub struct InMemoryOtpStore {
    records: Arc<RwLock<HashMap<Uuid, OtpRecord>>>,
}

impl InMemoryOtpStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryOtpStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpStore for InMemoryOtpStore {
    async fn insert(&self, record: OtpRecord) -> OtpResult<()> {
        debug!(id = %record.id, entity_id = %record.entity_id, "inserting OTP record");
        self.records.write().insert(record.id, record);
        Ok(())
    }

    async fn find_by_hash(&self, hash: &[u8]) -> OtpResult<Option<OtpRecord>> {
        let records = self.records.read();
        Ok(records.values().find(|r| r.token_hash == hash).cloned())
    }

    async fn increment_uses(&self, id: &Uuid, new_count: u32) -> OtpResult<()> {
        let mut records = self.records.write();
        match records.get_mut(id) {
            Some(r) => {
                r.current_uses = new_count;
                Ok(())
            }
            None => Err(OtpError::NotFound),
        }
    }

    async fn revoke(&self, id: &Uuid) -> OtpResult<()> {
        let mut records = self.records.write();
        match records.get_mut(id) {
            Some(r) => {
                r.revoked = true;
                Ok(())
            }
            None => Err(OtpError::NotFound),
        }
    }

    async fn cleanup_expired(&self) -> OtpResult<u64> {
        let now = Utc::now();
        let mut records = self.records.write();
        let before = records.len();
        records.retain(|_, r| r.expires_at > now);
        let removed = (before - records.len()) as u64;
        if removed > 0 {
            info!(removed, "cleaned up expired OTP records");
        }
        Ok(removed)
    }
}

// ---------------------------------------------------------------------------
// Database implementation (production stub)
// ---------------------------------------------------------------------------

/// Database-backed OTP store for production use.
///
/// Stores OTP records in kipuka's configured database (SQLite, PostgreSQL,
/// or MariaDB via `sqlx`). Hash-indexed for O(1) lookup during validation.
pub struct DbOtpStore {
    // In a full implementation this would hold an `sqlx::AnyPool`.
    _pool: (),
}

impl DbOtpStore {
    /// Create a database-backed store.
    ///
    /// # Placeholder
    ///
    /// This constructor will accept an `sqlx::AnyPool` once the database
    /// schema and migrations are in place.
    pub fn new() -> Self {
        Self { _pool: () }
    }
}

impl Default for DbOtpStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpStore for DbOtpStore {
    async fn insert(&self, _record: OtpRecord) -> OtpResult<()> {
        // TODO: INSERT INTO otp_tokens (id, token_hash, entity_id, ...)
        Err(OtpError::StorageError(
            "database OTP store not yet implemented".into(),
        ))
    }

    async fn find_by_hash(&self, _hash: &[u8]) -> OtpResult<Option<OtpRecord>> {
        Err(OtpError::StorageError(
            "database OTP store not yet implemented".into(),
        ))
    }

    async fn increment_uses(&self, _id: &Uuid, _new_count: u32) -> OtpResult<()> {
        Err(OtpError::StorageError(
            "database OTP store not yet implemented".into(),
        ))
    }

    async fn revoke(&self, _id: &Uuid) -> OtpResult<()> {
        Err(OtpError::StorageError(
            "database OTP store not yet implemented".into(),
        ))
    }

    async fn cleanup_expired(&self) -> OtpResult<u64> {
        Err(OtpError::StorageError(
            "database OTP store not yet implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::{OtpGenerator, OtpGeneratorConfig};

    #[tokio::test]
    async fn in_memory_store_round_trip() {
        let store = InMemoryOtpStore::new();
        let generator = OtpGenerator::new(OtpGeneratorConfig::default()).unwrap();
        let otp = generator
            .generate("host.example.com", "test", "default")
            .unwrap();

        let record = OtpRecord {
            id: otp.metadata.id,
            token_hash: otp.token_hash.clone(),
            entity_id: otp.metadata.entity_id.clone(),
            label: otp.metadata.label.clone(),
            profile: otp.metadata.profile.clone(),
            created_at: otp.metadata.created_at,
            expires_at: otp.metadata.expires_at,
            max_uses: otp.metadata.max_uses,
            current_uses: 0,
            revoked: false,
        };

        store.insert(record).await.unwrap();

        let found = store.find_by_hash(&otp.token_hash).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().entity_id, "host.example.com");
    }

    #[tokio::test]
    async fn cleanup_removes_expired() {
        let store = InMemoryOtpStore::new();
        let expired = OtpRecord {
            id: Uuid::new_v4(),
            token_hash: vec![0u8; 32],
            entity_id: "expired.example.com".into(),
            label: "expired".into(),
            profile: "default".into(),
            created_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            max_uses: 1,
            current_uses: 0,
            revoked: false,
        };
        store.insert(expired).await.unwrap();

        let removed = store.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1);
    }
}
