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
    not_before        TIMESTAMPTZ  NOT NULL,
    not_after         TIMESTAMPTZ  NOT NULL,
    der_encoded       BYTEA        NOT NULL,
    ca_id             TEXT         NOT NULL,
    profile           TEXT,
    status            certificate_status NOT NULL DEFAULT 'active',
    revocation_reason TEXT,
    revocation_time   TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
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
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL,
    max_uses        INTEGER      NOT NULL DEFAULT 1,
    current_uses    INTEGER      NOT NULL DEFAULT 0,
    revoked         BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_otp_tokens_entity_id ON otp_tokens (entity_id);
CREATE INDEX idx_otp_tokens_expires_at ON otp_tokens (expires_at);

CREATE TABLE audit_events (
    id              BIGSERIAL    PRIMARY KEY,
    timestamp       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    event_type      TEXT         NOT NULL,
    actor           TEXT,
    target          TEXT,
    detail_json     JSONB,
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
    last_check            TIMESTAMPTZ,
    last_success          TIMESTAMPTZ,
    last_failure          TIMESTAMPTZ,
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
    created_at      TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
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
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_server_generated_keys_enrollment_id ON server_generated_keys (enrollment_id);
