-- kipuka initial schema for PostgreSQL
-- Tracks certificates, OTP tokens, audit events, CA health, and enrollments.

CREATE TYPE certificate_status AS ENUM ('active', 'revoked', 'expired');
CREATE TYPE enrollment_type AS ENUM ('enroll', 'reenroll', 'serverkeygen', 'fullcmc');
CREATE TYPE enrollment_status AS ENUM ('pending', 'issued', 'rejected');
CREATE TYPE ca_health_status AS ENUM ('healthy', 'unhealthy', 'unknown');

CREATE TABLE certificates (
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

CREATE INDEX idx_certificates_serial ON certificates (serial);
CREATE INDEX idx_certificates_subject_dn ON certificates (subject_dn);
CREATE INDEX idx_certificates_ca_id ON certificates (ca_id);
CREATE INDEX idx_certificates_status ON certificates (status);
CREATE INDEX idx_certificates_not_after ON certificates (not_after);

CREATE TABLE otp_tokens (
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

CREATE INDEX idx_otp_tokens_entity_id ON otp_tokens (entity_id);
CREATE INDEX idx_otp_tokens_expires_at ON otp_tokens (expires_at);
CREATE INDEX idx_otp_tokens_hash ON otp_tokens (entity_id, token_hash);

CREATE TABLE audit_events (
    id              BIGSERIAL    PRIMARY KEY,
    timestamp       TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    event_type      TEXT         NOT NULL,
    actor           TEXT,
    target          TEXT,
    detail_json     TEXT,
    source_ip       TEXT,
    session_id      TEXT
);

CREATE INDEX idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX idx_audit_events_actor ON audit_events (actor);

CREATE TABLE ca_health (
    id                    BIGSERIAL        PRIMARY KEY,
    ca_id                 TEXT             NOT NULL UNIQUE,
    status                ca_health_status NOT NULL DEFAULT 'unknown',
    last_check            TEXT,
    last_success          TEXT,
    last_failure          TEXT,
    consecutive_failures  INTEGER          NOT NULL DEFAULT 0,
    response_latency_ms   INTEGER
);

CREATE INDEX idx_ca_health_ca_id ON ca_health (ca_id);

CREATE TABLE enrollment_requests (
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

CREATE INDEX idx_enrollment_requests_status ON enrollment_requests (status);
CREATE INDEX idx_enrollment_requests_ca_id ON enrollment_requests (ca_id);
CREATE INDEX idx_enrollment_requests_entity_id ON enrollment_requests (entity_id);
CREATE INDEX idx_enrollment_requests_csr_hash ON enrollment_requests (csr_hash);

CREATE TABLE server_generated_keys (
    id              BIGSERIAL    PRIMARY KEY,
    enrollment_id   BIGINT       NOT NULL REFERENCES enrollment_requests(id),
    key_type        TEXT         NOT NULL,
    key_size        INTEGER      NOT NULL,
    archived        BOOLEAN      NOT NULL DEFAULT FALSE,
    archive_id      TEXT,
    created_at      TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX idx_server_generated_keys_enrollment_id ON server_generated_keys (enrollment_id);

-- STAR (Short-Term Automatic Renewal) tables (RFC 8739).
-- Tracks STAR orders and their automatically renewed certificates.

CREATE TYPE star_order_status AS ENUM ('active', 'cancelled', 'completed', 'expired');

CREATE TABLE star_orders (
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

CREATE TABLE star_certificates (
    id              BIGSERIAL    PRIMARY KEY,
    star_order_id   TEXT         NOT NULL REFERENCES star_orders(id),
    serial_number   TEXT         NOT NULL,
    certificate_der BYTEA        NOT NULL,
    not_before      TEXT  NOT NULL,
    not_after       TEXT  NOT NULL,
    renewal_number  INTEGER      NOT NULL,
    created_at      TEXT  NOT NULL DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX idx_star_certs_order ON star_certificates(star_order_id, renewal_number DESC);
