-- kipuka initial schema for SQLite
-- Tracks certificates, OTP tokens, audit events, CA health, and enrollments.

CREATE TABLE IF NOT EXISTS certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    serial          TEXT    NOT NULL UNIQUE,
    subject_dn      TEXT    NOT NULL,
    issuer_dn       TEXT    NOT NULL,
    not_before      TEXT    NOT NULL,  -- ISO 8601
    not_after       TEXT    NOT NULL,  -- ISO 8601
    der_encoded     BLOB   NOT NULL,
    ca_id           TEXT    NOT NULL,
    profile         TEXT,
    status          TEXT    NOT NULL DEFAULT 'active'
                           CHECK (status IN ('active', 'revoked', 'expired')),
    revocation_reason TEXT,
    revocation_time TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_certificates_serial ON certificates (serial);
CREATE INDEX idx_certificates_subject_dn ON certificates (subject_dn);
CREATE INDEX idx_certificates_ca_id ON certificates (ca_id);
CREATE INDEX idx_certificates_status ON certificates (status);
CREATE INDEX idx_certificates_not_after ON certificates (not_after);

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
    revoked         INTEGER NOT NULL DEFAULT 0,  -- SQLite has no BOOLEAN
    revoked_at      TEXT
);

CREATE INDEX idx_otp_tokens_entity_id ON otp_tokens (entity_id);
CREATE INDEX idx_otp_tokens_expires_at ON otp_tokens (expires_at);

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

CREATE INDEX idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX idx_audit_events_actor ON audit_events (actor);

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

CREATE INDEX idx_ca_health_ca_id ON ca_health (ca_id);

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

CREATE INDEX idx_enrollment_requests_status ON enrollment_requests (status);
CREATE INDEX idx_enrollment_requests_ca_id ON enrollment_requests (ca_id);
CREATE INDEX idx_enrollment_requests_entity_id ON enrollment_requests (entity_id);
CREATE INDEX idx_enrollment_requests_csr_hash ON enrollment_requests (csr_hash);

CREATE TABLE IF NOT EXISTS server_generated_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id   INTEGER NOT NULL REFERENCES enrollment_requests(id),
    key_type        TEXT    NOT NULL,
    key_size        INTEGER NOT NULL,
    archived        INTEGER NOT NULL DEFAULT 0,
    archive_id      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_server_generated_keys_enrollment_id ON server_generated_keys (enrollment_id);

-- STAR (Short-Term Automatic Renewal) tables (RFC 8739).
-- Tracks STAR orders and their automatically renewed certificates.

CREATE TABLE IF NOT EXISTS star_orders (
    id                  TEXT    PRIMARY KEY,
    subject_dn          TEXT    NOT NULL,
    key_type            TEXT    NOT NULL,
    profile             TEXT    NOT NULL,
    renewal_interval_secs INTEGER NOT NULL,
    lifetime_end        TEXT    NOT NULL,  -- ISO 8601
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
    not_before      TEXT    NOT NULL,  -- ISO 8601
    not_after       TEXT    NOT NULL,  -- ISO 8601
    renewal_number  INTEGER NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_star_certs_order ON star_certificates(star_order_id, renewal_number DESC);
