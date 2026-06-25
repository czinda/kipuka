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
// Database implementation (production)
// ---------------------------------------------------------------------------

/// Database-backed OTP store for production use.
///
/// Stores OTP records in kipuka's configured database (SQLite, PostgreSQL,
/// or MariaDB via `sqlx`). Hash-indexed for O(1) lookup during validation.
///
/// Token hashes are stored as hex-encoded strings in the `token_hash` TEXT
/// column.  The `id` column is a database auto-increment integer; the
/// `OtpRecord.id` UUID is mapped bijectively via `Uuid::from_u128`.
#[cfg(feature = "db")]
pub struct DbOtpStore {
    pool: sqlx::AnyPool,
    /// Whether the backend is PostgreSQL (requires `$N` parameter style).
    is_postgres: bool,
}

#[cfg(feature = "db")]
impl DbOtpStore {
    /// Create a database-backed store.
    ///
    /// The `is_postgres` flag controls parameter placeholder style:
    /// PostgreSQL requires `$1, $2, …` while SQLite and MariaDB use `?`.
    pub fn new(pool: sqlx::AnyPool, is_postgres: bool) -> Self {
        Self { pool, is_postgres }
    }

    /// Rewrite `?` placeholders to `$1, $2, …` when running against PostgreSQL.
    ///
    /// sqlx 0.8's `AnyPool` does not reliably rewrite placeholders for
    /// PostgreSQL.  This mirrors the `pg_sql` helper from the main crate.
    fn sql(&self, s: &str) -> String {
        if !self.is_postgres {
            return s.to_string();
        }
        let mut result = String::with_capacity(s.len() + 16);
        let mut param_num = 0u32;
        for ch in s.chars() {
            if ch == '?' {
                param_num += 1;
                result.push('$');
                result.push_str(&param_num.to_string());
            } else {
                result.push(ch);
            }
        }
        result
    }

    /// Convert a database auto-increment `id` to a UUID for in-memory use.
    fn id_to_uuid(db_id: i64) -> Uuid {
        Uuid::from_u128(db_id as u128)
    }

    /// Extract the database auto-increment `id` from an in-memory UUID.
    fn uuid_to_id(uuid: &Uuid) -> i64 {
        uuid.as_u128() as i64
    }
}

#[cfg(feature = "db")]
impl OtpStore for DbOtpStore {
    async fn insert(&self, record: OtpRecord) -> OtpResult<()> {
        let token_hash_hex = hex::encode(&record.token_hash);
        let expires_at_str = record.expires_at.to_rfc3339();
        let created_at_str = record.created_at.to_rfc3339();

        debug!(
            entity_id = %record.entity_id,
            label = %record.label,
            profile = %record.profile,
            max_uses = record.max_uses,
            "inserting OTP record into database"
        );

        let sql = self.sql(
            "INSERT INTO otp_tokens (token_hash, entity_id, label, profile, created_at, expires_at, max_uses, current_uses, revoked) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)",
        );

        sqlx::query(&sql)
            .bind(&token_hash_hex)
            .bind(&record.entity_id)
            .bind(&record.label)
            .bind(&record.profile)
            .bind(&created_at_str)
            .bind(&expires_at_str)
            .bind(record.max_uses as i32)
            .execute(&self.pool)
            .await
            .map_err(|e| OtpError::StorageError(format!("insert failed: {e}")))?;

        info!(entity_id = %record.entity_id, "OTP record stored in database");
        Ok(())
    }

    async fn find_by_hash(&self, hash: &[u8]) -> OtpResult<Option<OtpRecord>> {
        let hash_hex = hex::encode(hash);

        let sql = self.sql(
            "SELECT id, token_hash, entity_id, label, profile, created_at, expires_at, max_uses, current_uses, revoked \
             FROM otp_tokens WHERE token_hash = ? AND revoked = 0",
        );

        let row = sqlx::query_as::<_, (
            i64,    // id
            String, // token_hash (hex)
            String, // entity_id
            String, // label
            String, // profile
            String, // created_at
            String, // expires_at
            i32,    // max_uses
            i32,    // current_uses
            i32,    // revoked (integer 0/1 for SQLite compat)
        )>(&sql)
        .bind(&hash_hex)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| OtpError::StorageError(format!("find_by_hash query failed: {e}")))?;

        match row {
            None => Ok(None),
            Some((db_id, token_hash_hex, entity_id, label, profile, created_str, expires_str, max_uses, current_uses, revoked)) => {
                let token_hash = hex::decode(&token_hash_hex)
                    .map_err(|e| OtpError::StorageError(format!("invalid hex in token_hash: {e}")))?;

                let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| OtpError::StorageError(format!("invalid expires_at: {e}")))?;

                Ok(Some(OtpRecord {
                    id: Self::id_to_uuid(db_id),
                    token_hash,
                    entity_id,
                    label,
                    profile,
                    created_at,
                    expires_at,
                    max_uses: max_uses as u32,
                    current_uses: current_uses as u32,
                    revoked: revoked != 0,
                }))
            }
        }
    }

    async fn increment_uses(&self, id: &Uuid, new_count: u32) -> OtpResult<()> {
        let db_id = Self::uuid_to_id(id);

        let sql = self.sql("UPDATE otp_tokens SET current_uses = ? WHERE id = ?");

        let result = sqlx::query(&sql)
            .bind(new_count as i32)
            .bind(db_id)
            .execute(&self.pool)
            .await
            .map_err(|e| OtpError::StorageError(format!("increment_uses failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(OtpError::NotFound);
        }

        debug!(db_id, new_count, "OTP usage count updated");
        Ok(())
    }

    async fn revoke(&self, id: &Uuid) -> OtpResult<()> {
        let db_id = Self::uuid_to_id(id);
        let now_str = Utc::now().to_rfc3339();

        let sql = self.sql("UPDATE otp_tokens SET revoked = 1, revoked_at = ? WHERE id = ?");

        let result = sqlx::query(&sql)
            .bind(&now_str)
            .bind(db_id)
            .execute(&self.pool)
            .await
            .map_err(|e| OtpError::StorageError(format!("revoke failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(OtpError::NotFound);
        }

        info!(db_id, "OTP record revoked");
        Ok(())
    }

    async fn cleanup_expired(&self) -> OtpResult<u64> {
        let now_str = Utc::now().to_rfc3339();

        let sql = self.sql("DELETE FROM otp_tokens WHERE expires_at < ?");

        let result = sqlx::query(&sql)
            .bind(&now_str)
            .execute(&self.pool)
            .await
            .map_err(|e| OtpError::StorageError(format!("cleanup_expired failed: {e}")))?;

        let removed = result.rows_affected();
        if removed > 0 {
            info!(removed, "cleaned up expired OTP records from database");
        }
        Ok(removed)
    }
}

// ---------------------------------------------------------------------------
// Stub (no-db feature)
// ---------------------------------------------------------------------------

/// Stub database-backed OTP store when the `db` feature is disabled.
///
/// All methods return a "not implemented" error.
#[cfg(not(feature = "db"))]
pub struct DbOtpStore {
    _private: (),
}

#[cfg(not(feature = "db"))]
impl DbOtpStore {
    /// Create a stub store (database support not compiled in).
    pub fn new() -> Self {
        Self { _private: () }
    }
}

#[cfg(not(feature = "db"))]
impl Default for DbOtpStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "db"))]
impl OtpStore for DbOtpStore {
    async fn insert(&self, _record: OtpRecord) -> OtpResult<()> {
        Err(OtpError::StorageError(
            "database OTP store not compiled (enable 'db' feature)".into(),
        ))
    }

    async fn find_by_hash(&self, _hash: &[u8]) -> OtpResult<Option<OtpRecord>> {
        Err(OtpError::StorageError(
            "database OTP store not compiled (enable 'db' feature)".into(),
        ))
    }

    async fn increment_uses(&self, _id: &Uuid, _new_count: u32) -> OtpResult<()> {
        Err(OtpError::StorageError(
            "database OTP store not compiled (enable 'db' feature)".into(),
        ))
    }

    async fn revoke(&self, _id: &Uuid) -> OtpResult<()> {
        Err(OtpError::StorageError(
            "database OTP store not compiled (enable 'db' feature)".into(),
        ))
    }

    async fn cleanup_expired(&self) -> OtpResult<u64> {
        Err(OtpError::StorageError(
            "database OTP store not compiled (enable 'db' feature)".into(),
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
