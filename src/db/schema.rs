//! Embedded database migrations and schema version tracking.
//!
//! Migrations are defined as SQL strings and executed in order at startup
//! when `[database].run_migrations = true`.  The `schema_version` table
//! tracks which migrations have been applied.
//!
//! Each migration is idempotent: `CREATE TABLE IF NOT EXISTS` and
//! `CREATE INDEX IF NOT EXISTS` are used throughout so that re-running
//! migrations on an already-initialized database is a no-op.

use crate::error::KipukaError;

/// Current schema version.  Increment this when adding new migrations.
pub const SCHEMA_VERSION: i32 = 1;

/// The initial schema migration (v1).
///
/// Creates the core tables for:
/// - Certificate inventory and lifecycle tracking
/// - Enrollment request log
/// - OTP storage (when using DB backend)
/// - Audit event trail (FAU_GEN.1)
/// - Schema version tracking
const MIGRATION_V1: &str = r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    applied_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Certificate inventory
CREATE TABLE IF NOT EXISTS certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_number   TEXT    NOT NULL UNIQUE,
    ca_id           TEXT    NOT NULL,
    subject_dn      TEXT    NOT NULL,
    issuer_dn       TEXT    NOT NULL,
    not_before      TEXT    NOT NULL,
    not_after       TEXT    NOT NULL,
    cert_der        BLOB   NOT NULL,
    key_hash        TEXT,
    status          TEXT    NOT NULL DEFAULT 'valid',
    revoked_at      TEXT,
    revocation_reason INTEGER,
    est_label       TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);

-- Enrollment request log
CREATE TABLE IF NOT EXISTS enrollment_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id           TEXT    NOT NULL,
    est_label       TEXT,
    request_type    TEXT    NOT NULL,
    subject_dn      TEXT,
    client_identity TEXT,
    auth_method     TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending',
    csr_hash        TEXT,
    cert_serial     TEXT,
    error_detail    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_status ON enrollment_requests(status);

-- OTP storage (DB backend)
CREATE TABLE IF NOT EXISTS otp_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT    NOT NULL UNIQUE,
    identity        TEXT,
    ca_id           TEXT,
    est_label       TEXT,
    usage_count     INTEGER NOT NULL DEFAULT 0,
    max_usage       INTEGER NOT NULL DEFAULT 1,
    expires_at      TEXT    NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires ON otp_tokens(expires_at);

-- Audit event trail (NIAP CA PP FAU_GEN.1)
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT    NOT NULL,
    ca_id           TEXT,
    subject         TEXT,
    detail          TEXT,
    client_addr     TEXT,
    operator        TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at);

-- CRL tracking
CREATE TABLE IF NOT EXISTS crl_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id           TEXT    NOT NULL,
    serial_number   TEXT    NOT NULL,
    revocation_date TEXT    NOT NULL,
    reason          INTEGER,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(ca_id, serial_number)
);

-- Disconnected mode: pending CSRs awaiting CA signing
CREATE TABLE IF NOT EXISTS pending_csrs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id           TEXT    NOT NULL,
    est_label       TEXT,
    csr_der         BLOB   NOT NULL,
    client_identity TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending',
    cert_serial     TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    signed_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_pending_csrs_status ON pending_csrs(status);
"#;

/// Run all pending migrations.
pub async fn run_migrations(pool: &sqlx::AnyPool) -> Result<(), KipukaError> {
    // Check current schema version
    let current = current_version(pool).await?;

    if current < 1 {
        tracing::info!("applying migration v1 (initial schema)");
        // Execute migration statements one at a time (sqlx Any doesn't
        // support multi-statement execution on all backends).
        for statement in MIGRATION_V1.split(';') {
            let trimmed = statement.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }
            sqlx::query(trimmed)
                .execute(pool)
                .await
                .map_err(|e| KipukaError::Db(format!("migration v1 failed: {e}")))?;
        }

        // Record the version
        sqlx::query("INSERT INTO schema_version (version) VALUES (1)")
            .execute(pool)
            .await
            .map_err(|e| KipukaError::Db(format!("recording schema version: {e}")))?;

        tracing::info!("migration v1 applied successfully");
    }

    Ok(())
}

/// Query the current schema version.  Returns 0 if no migrations have
/// been applied (or the schema_version table does not exist).
async fn current_version(pool: &sqlx::AnyPool) -> Result<i32, KipukaError> {
    // The table might not exist yet on a fresh database
    let row = sqlx::query_as::<_, (i32,)>("SELECT COALESCE(MAX(version), 0) FROM schema_version")
        .fetch_one(pool)
        .await;

    match row {
        Ok((version,)) => Ok(version),
        Err(_) => {
            // Table doesn't exist — this is a fresh database
            Ok(0)
        }
    }
}
