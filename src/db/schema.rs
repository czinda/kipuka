//! Embedded database migrations and schema version tracking.
//!
//! Migrations are defined as SQL strings and executed in order at startup
//! when `[database].run_migrations = true`.  The `schema_version` table
//! tracks which migrations have been applied.
//!
//! Each migration is idempotent: `CREATE TABLE IF NOT EXISTS` and
//! `CREATE INDEX IF NOT EXISTS` are used throughout so that re-running
//! migrations on an already-initialized database is a no-op.
//!
//! Dialect-specific constants are selected at runtime based on [`DbKind`].

use crate::db::DbKind;
use crate::error::KipukaError;

/// Current schema version.  Increment this when adding new migrations.
pub const SCHEMA_VERSION: i32 = 2;

// ---------------------------------------------------------------------------
// SQLite migration v1
// ---------------------------------------------------------------------------
const MIGRATION_V1_SQLITE: &str = r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    applied_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Certificate inventory
CREATE TABLE IF NOT EXISTS certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    serial          TEXT    NOT NULL UNIQUE,
    subject_dn      TEXT    NOT NULL,
    issuer_dn       TEXT    NOT NULL,
    not_before      TEXT    NOT NULL,
    not_after       TEXT    NOT NULL,
    der_encoded     BLOB   NOT NULL,
    ca_id           TEXT    NOT NULL,
    profile         TEXT,
    status          TEXT    NOT NULL DEFAULT 'active'
                           CHECK (status IN ('active', 'revoked', 'expired')),
    revocation_reason TEXT,
    revocation_time TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial);
CREATE INDEX IF NOT EXISTS idx_certificates_subject_dn ON certificates (subject_dn);
CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates (ca_id);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates (status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);

-- OTP storage (DB backend)
CREATE TABLE IF NOT EXISTS otp_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT    NOT NULL,
    entity_id       TEXT    NOT NULL,
    label           TEXT,
    profile         TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at      TEXT    NOT NULL,
    max_uses        INTEGER NOT NULL DEFAULT 1,
    current_uses    INTEGER NOT NULL DEFAULT 0,
    revoked         INTEGER NOT NULL DEFAULT 0,
    revoked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_otp_tokens_entity_id ON otp_tokens (entity_id);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires_at ON otp_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_hash ON otp_tokens (entity_id, token_hash);

-- Audit event trail (NIAP CA PP FAU_GEN.1)
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    event_type      TEXT    NOT NULL,
    actor           TEXT,
    target          TEXT,
    detail_json     TEXT,
    source_ip       TEXT,
    session_id      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor);

-- CA health tracking
CREATE TABLE IF NOT EXISTS ca_health (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id                 TEXT    NOT NULL UNIQUE,
    status                TEXT    NOT NULL DEFAULT 'unknown'
                                 CHECK (status IN ('healthy', 'unhealthy', 'unknown')),
    last_check            TEXT,
    last_success          TEXT,
    last_failure          TEXT,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    response_latency_ms   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_ca_health_ca_id ON ca_health (ca_id);

-- Enrollment request log
CREATE TABLE IF NOT EXISTS enrollment_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_type    TEXT    NOT NULL
                           CHECK (request_type IN ('enroll', 'reenroll', 'serverkeygen', 'fullcmc')),
    csr_hash        TEXT    NOT NULL,
    ca_id           TEXT    NOT NULL,
    label           TEXT,
    auth_method     TEXT    NOT NULL,
    entity_id       TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending', 'issued', 'rejected')),
    certificate_id  INTEGER REFERENCES certificates(id),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    completed_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollment_requests_status ON enrollment_requests (status);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_ca_id ON enrollment_requests (ca_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_entity_id ON enrollment_requests (entity_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_csr_hash ON enrollment_requests (csr_hash);

-- Server-generated keys
CREATE TABLE IF NOT EXISTS server_generated_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id   INTEGER NOT NULL REFERENCES enrollment_requests(id),
    key_type        TEXT    NOT NULL,
    key_size        INTEGER NOT NULL,
    archived        INTEGER NOT NULL DEFAULT 0,
    archive_id      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_server_generated_keys_enrollment_id ON server_generated_keys (enrollment_id);

-- STAR (Short-Term Automatic Renewal) tables (RFC 8739)
CREATE TABLE IF NOT EXISTS star_orders (
    id                  TEXT    PRIMARY KEY,
    subject_dn          TEXT    NOT NULL,
    key_type            TEXT    NOT NULL,
    profile             TEXT    NOT NULL,
    renewal_interval_secs INTEGER NOT NULL,
    lifetime_end        TEXT    NOT NULL,
    max_renewals        INTEGER NOT NULL,
    current_renewals    INTEGER NOT NULL DEFAULT 0,
    status              TEXT    NOT NULL DEFAULT 'active'
                               CHECK (status IN ('active', 'cancelled', 'completed', 'expired')),
    requestor_dn        TEXT,
    ca_id               TEXT    NOT NULL,
    csr_der             BLOB   NOT NULL,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    cancelled_at        TEXT
);

CREATE TABLE IF NOT EXISTS star_certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    star_order_id   TEXT    NOT NULL REFERENCES star_orders(id),
    serial_number   TEXT    NOT NULL,
    certificate_der BLOB   NOT NULL,
    not_before      TEXT    NOT NULL,
    not_after       TEXT    NOT NULL,
    renewal_number  INTEGER NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_star_certs_order ON star_certificates(star_order_id, renewal_number DESC);
"#;

// ---------------------------------------------------------------------------
// PostgreSQL migration v1
// ---------------------------------------------------------------------------
const MIGRATION_V1_POSTGRES: &str = r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    applied_at  TEXT NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-- Enum types
DO $$ BEGIN
    CREATE TYPE certificate_status AS ENUM ('active', 'revoked', 'expired');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE enrollment_type AS ENUM ('enroll', 'reenroll', 'serverkeygen', 'fullcmc');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE enrollment_status AS ENUM ('pending', 'issued', 'rejected');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE ca_health_status AS ENUM ('healthy', 'unhealthy', 'unknown');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE star_order_status AS ENUM ('active', 'cancelled', 'completed', 'expired');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Certificate inventory
CREATE TABLE IF NOT EXISTS certificates (
    id                BIGSERIAL    PRIMARY KEY,
    serial            TEXT         NOT NULL UNIQUE,
    subject_dn        TEXT         NOT NULL,
    issuer_dn         TEXT         NOT NULL,
    not_before        TEXT  NOT NULL,
    not_after         TEXT  NOT NULL,
    der_encoded       BYTEA        NOT NULL,
    ca_id             TEXT         NOT NULL,
    profile           TEXT,
    status            certificate_status NOT NULL DEFAULT 'active',
    revocation_reason TEXT,
    revocation_time   TEXT,
    created_at        TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial);
CREATE INDEX IF NOT EXISTS idx_certificates_subject_dn ON certificates (subject_dn);
CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates (ca_id);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates (status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);

-- OTP storage
CREATE TABLE IF NOT EXISTS otp_tokens (
    id              BIGSERIAL    PRIMARY KEY,
    token_hash      TEXT         NOT NULL,
    entity_id       TEXT         NOT NULL,
    label           TEXT,
    profile         TEXT,
    created_at      TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    expires_at      TEXT  NOT NULL,
    max_uses        INTEGER      NOT NULL DEFAULT 1,
    current_uses    INTEGER      NOT NULL DEFAULT 0,
    revoked         BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_otp_tokens_entity_id ON otp_tokens (entity_id);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires_at ON otp_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_hash ON otp_tokens (entity_id, token_hash);

-- Audit event trail
CREATE TABLE IF NOT EXISTS audit_events (
    id              BIGSERIAL    PRIMARY KEY,
    timestamp       TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    event_type      TEXT         NOT NULL,
    actor           TEXT,
    target          TEXT,
    detail_json     TEXT,
    source_ip       TEXT,
    session_id      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor);

-- CA health tracking
CREATE TABLE IF NOT EXISTS ca_health (
    id                    BIGSERIAL        PRIMARY KEY,
    ca_id                 TEXT             NOT NULL UNIQUE,
    status                ca_health_status NOT NULL DEFAULT 'unknown',
    last_check            TEXT,
    last_success          TEXT,
    last_failure          TEXT,
    consecutive_failures  INTEGER          NOT NULL DEFAULT 0,
    response_latency_ms   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_ca_health_ca_id ON ca_health (ca_id);

-- Enrollment request log
CREATE TABLE IF NOT EXISTS enrollment_requests (
    id              BIGSERIAL         PRIMARY KEY,
    request_type    enrollment_type   NOT NULL,
    csr_hash        TEXT              NOT NULL,
    ca_id           TEXT              NOT NULL,
    label           TEXT,
    auth_method     TEXT              NOT NULL,
    entity_id       TEXT,
    status          enrollment_status NOT NULL DEFAULT 'pending',
    certificate_id  BIGINT            REFERENCES certificates(id),
    created_at      TEXT       NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    completed_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollment_requests_status ON enrollment_requests (status);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_ca_id ON enrollment_requests (ca_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_entity_id ON enrollment_requests (entity_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_csr_hash ON enrollment_requests (csr_hash);

-- Server-generated keys
CREATE TABLE IF NOT EXISTS server_generated_keys (
    id              BIGSERIAL    PRIMARY KEY,
    enrollment_id   BIGINT       NOT NULL REFERENCES enrollment_requests(id),
    key_type        TEXT         NOT NULL,
    key_size        INTEGER      NOT NULL,
    archived        BOOLEAN      NOT NULL DEFAULT FALSE,
    archive_id      TEXT,
    created_at      TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX IF NOT EXISTS idx_server_generated_keys_enrollment_id ON server_generated_keys (enrollment_id);

-- STAR (Short-Term Automatic Renewal) tables (RFC 8739)
CREATE TABLE IF NOT EXISTS star_orders (
    id                    TEXT             PRIMARY KEY,
    subject_dn            TEXT             NOT NULL,
    key_type              TEXT             NOT NULL,
    profile               TEXT             NOT NULL,
    renewal_interval_secs INTEGER          NOT NULL,
    lifetime_end          TEXT      NOT NULL,
    max_renewals          INTEGER          NOT NULL,
    current_renewals      INTEGER          NOT NULL DEFAULT 0,
    status                star_order_status NOT NULL DEFAULT 'active',
    requestor_dn          TEXT,
    ca_id                 TEXT             NOT NULL,
    csr_der               BYTEA            NOT NULL,
    created_at            TEXT      NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    cancelled_at          TEXT
);

CREATE TABLE IF NOT EXISTS star_certificates (
    id              BIGSERIAL    PRIMARY KEY,
    star_order_id   TEXT         NOT NULL REFERENCES star_orders(id),
    serial_number   TEXT         NOT NULL,
    certificate_der BYTEA        NOT NULL,
    not_before      TEXT  NOT NULL,
    not_after       TEXT  NOT NULL,
    renewal_number  INTEGER      NOT NULL,
    created_at      TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX IF NOT EXISTS idx_star_certs_order ON star_certificates(star_order_id, renewal_number DESC);
"#;

// ---------------------------------------------------------------------------
// MariaDB migration v1
// ---------------------------------------------------------------------------
const MIGRATION_V1_MARIADB: &str = r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version     INT          NOT NULL,
    applied_at  TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Certificate inventory
CREATE TABLE IF NOT EXISTS certificates (
    id                BIGINT       AUTO_INCREMENT PRIMARY KEY,
    serial            VARCHAR(255) NOT NULL UNIQUE,
    subject_dn        TEXT         NOT NULL,
    issuer_dn         TEXT         NOT NULL,
    not_before        TEXT  NOT NULL,
    not_after         TEXT  NOT NULL,
    der_encoded       LONGBLOB     NOT NULL,
    ca_id             VARCHAR(255) NOT NULL,
    profile           VARCHAR(255),
    status            ENUM('active', 'revoked', 'expired') NOT NULL DEFAULT 'active',
    revocation_reason VARCHAR(255),
    revocation_time   TEXT,
    created_at        TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates (serial);
CREATE INDEX IF NOT EXISTS idx_certificates_subject_dn ON certificates (subject_dn(255));
CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates (ca_id);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates (status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);

-- OTP storage
CREATE TABLE IF NOT EXISTS otp_tokens (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    token_hash      VARCHAR(512)         NOT NULL,
    entity_id       VARCHAR(255) NOT NULL,
    label           VARCHAR(255),
    profile         VARCHAR(255),
    created_at      VARCHAR(64)  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ')),
    expires_at      VARCHAR(64)  NOT NULL,
    max_uses        INT          NOT NULL DEFAULT 1,
    current_uses    INT          NOT NULL DEFAULT 0,
    revoked         BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at      VARCHAR(64)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX IF NOT EXISTS idx_otp_tokens_entity_id ON otp_tokens (entity_id);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires_at ON otp_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_hash ON otp_tokens (entity_id, token_hash);

-- Audit event trail
CREATE TABLE IF NOT EXISTS audit_events (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    timestamp       TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ')),
    event_type      VARCHAR(255) NOT NULL,
    actor           VARCHAR(255),
    target          VARCHAR(255),
    detail_json     TEXT,
    source_ip       VARCHAR(45),
    session_id      VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor);

-- CA health tracking
CREATE TABLE IF NOT EXISTS ca_health (
    id                    BIGINT       AUTO_INCREMENT PRIMARY KEY,
    ca_id                 VARCHAR(255) NOT NULL UNIQUE,
    status                ENUM('healthy', 'unhealthy', 'unknown') NOT NULL DEFAULT 'unknown',
    last_check            TEXT,
    last_success          TEXT,
    last_failure          TEXT,
    consecutive_failures  INT          NOT NULL DEFAULT 0,
    response_latency_ms   INT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX IF NOT EXISTS idx_ca_health_ca_id ON ca_health (ca_id);

-- Enrollment request log
CREATE TABLE IF NOT EXISTS enrollment_requests (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    request_type    ENUM('enroll', 'reenroll', 'serverkeygen', 'fullcmc') NOT NULL,
    csr_hash        VARCHAR(255) NOT NULL,
    ca_id           VARCHAR(255) NOT NULL,
    label           VARCHAR(255),
    auth_method     VARCHAR(255) NOT NULL,
    entity_id       VARCHAR(255),
    status          ENUM('pending', 'issued', 'rejected') NOT NULL DEFAULT 'pending',
    certificate_id  BIGINT,
    created_at      TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ')),
    completed_at    TEXT,
    CONSTRAINT fk_enrollment_certificate
        FOREIGN KEY (certificate_id) REFERENCES certificates(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX IF NOT EXISTS idx_enrollment_requests_status ON enrollment_requests (status);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_ca_id ON enrollment_requests (ca_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_entity_id ON enrollment_requests (entity_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_requests_csr_hash ON enrollment_requests (csr_hash);

-- Server-generated keys
CREATE TABLE IF NOT EXISTS server_generated_keys (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    enrollment_id   BIGINT       NOT NULL,
    key_type        VARCHAR(255) NOT NULL,
    key_size        INT          NOT NULL,
    archived        BOOLEAN      NOT NULL DEFAULT FALSE,
    archive_id      VARCHAR(255),
    created_at      TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ')),
    CONSTRAINT fk_sgk_enrollment
        FOREIGN KEY (enrollment_id) REFERENCES enrollment_requests(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX IF NOT EXISTS idx_server_generated_keys_enrollment_id ON server_generated_keys (enrollment_id);

-- STAR (Short-Term Automatic Renewal) tables (RFC 8739)
CREATE TABLE IF NOT EXISTS star_orders (
    id                    VARCHAR(255) PRIMARY KEY,
    subject_dn            TEXT         NOT NULL,
    key_type              VARCHAR(255) NOT NULL,
    profile               VARCHAR(255) NOT NULL,
    renewal_interval_secs INT          NOT NULL,
    lifetime_end          TEXT  NOT NULL,
    max_renewals          INT          NOT NULL,
    current_renewals      INT          NOT NULL DEFAULT 0,
    status                ENUM('active', 'cancelled', 'completed', 'expired') NOT NULL DEFAULT 'active',
    requestor_dn          TEXT,
    ca_id                 VARCHAR(255) NOT NULL,
    csr_der               LONGBLOB     NOT NULL,
    created_at            TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ')),
    cancelled_at          TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS star_certificates (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    star_order_id   VARCHAR(255) NOT NULL,
    serial_number   VARCHAR(255) NOT NULL,
    certificate_der LONGBLOB     NOT NULL,
    not_before      TEXT  NOT NULL,
    not_after       TEXT  NOT NULL,
    renewal_number  INT          NOT NULL,
    created_at      TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ')),
    CONSTRAINT fk_star_certs_order
        FOREIGN KEY (star_order_id) REFERENCES star_orders(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX IF NOT EXISTS idx_star_certs_order ON star_certificates(star_order_id, renewal_number DESC);
"#;

/// Run all pending migrations.
///
/// The `kind` parameter selects the dialect-specific DDL so that the
/// correct data types, defaults, and syntax are used for each backend.
pub async fn run_migrations(pool: &sqlx::AnyPool, kind: DbKind) -> Result<(), KipukaError> {
    // Check current schema version
    let current = current_version(pool).await?;

    if current < 1 {
        tracing::info!("applying migration v1 (initial schema)");

        let migration_sql = match kind {
            DbKind::Sqlite => MIGRATION_V1_SQLITE,
            DbKind::Postgres => MIGRATION_V1_POSTGRES,
            DbKind::MariaDb => MIGRATION_V1_MARIADB,
        };

        // Execute migration statements one at a time (sqlx Any doesn't
        // support multi-statement execution on all backends).
        //
        // PostgreSQL DO blocks contain semicolons inside $$ delimiters,
        // so we use a smarter splitter that respects dollar-quoting.
        for statement in split_sql_statements(migration_sql) {
            let stripped: String = statement
                .lines()
                .filter(|l| !l.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            let trimmed = stripped.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed)
                .execute(pool)
                .await
                .map_err(|e| KipukaError::Db(format!("migration v1 failed on [{trimmed}]: {e}")))?;
        }

        // Record the version
        sqlx::query("INSERT INTO schema_version (version) VALUES (1)")
            .execute(pool)
            .await
            .map_err(|e| KipukaError::Db(format!("recording schema version: {e}")))?;

        tracing::info!("migration v1 applied successfully");
    }

    if current < 2 {
        tracing::info!("applying migration v2 (OTP hash index)");
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_otp_tokens_hash ON otp_tokens (entity_id, token_hash)",
        )
        .execute(pool)
        .await
        .map_err(|e| KipukaError::Db(format!("migration v2 failed: {e}")))?;

        sqlx::query("INSERT INTO schema_version (version) VALUES (2)")
            .execute(pool)
            .await
            .map_err(|e| KipukaError::Db(format!("recording schema version: {e}")))?;

        tracing::info!("migration v2 applied successfully");
    }

    Ok(())
}

/// Split SQL text into individual statements, respecting PostgreSQL
/// dollar-quoted blocks (`$$ ... $$` or `$tag$ ... $tag$`).
///
/// A naive `split(';')` would break inside `DO $$ ... END $$;` blocks
/// that contain internal semicolons.
fn split_sql_statements(sql: &str) -> Vec<&str> {
    let mut statements = Vec::new();
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut start = 0;
    let mut i = 0;
    let mut in_dollar_quote = false;
    let mut dollar_tag = String::new();

    while i < len {
        if bytes[i] == b'$' && !in_dollar_quote {
            // Try to read a dollar-quote tag: $tag$ or $$
            if let Some(tag) = read_dollar_tag(sql, i) {
                in_dollar_quote = true;
                dollar_tag = tag.clone();
                i += tag.len();
                continue;
            }
        } else if bytes[i] == b'$' && in_dollar_quote {
            // Check if this is the closing dollar-quote tag
            if sql[i..].starts_with(&dollar_tag) {
                in_dollar_quote = false;
                i += dollar_tag.len();
                dollar_tag.clear();
                continue;
            }
        }

        if bytes[i] == b';' && !in_dollar_quote {
            let stmt = &sql[start..i];
            if !stmt.trim().is_empty() {
                statements.push(stmt);
            }
            start = i + 1;
        }

        i += 1;
    }

    // Trailing text after the last semicolon
    let tail = &sql[start..];
    if !tail.trim().is_empty() {
        statements.push(tail);
    }

    statements
}

/// Try to read a dollar-quote tag starting at position `pos`.
///
/// Returns the full tag (e.g. `$$` or `$tag$`) if found.
fn read_dollar_tag(sql: &str, pos: usize) -> Option<String> {
    let rest = &sql[pos..];
    if !rest.starts_with('$') {
        return None;
    }

    // Look for the closing '$' of the tag
    for (j, ch) in rest[1..].char_indices() {
        if ch == '$' {
            let tag = &rest[..j + 2]; // includes both dollar signs
            return Some(tag.to_string());
        }
        if !ch.is_alphanumeric() && ch != '_' {
            break;
        }
    }

    None
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
