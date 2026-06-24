-- kipuka initial schema for MariaDB
-- Tracks certificates, OTP tokens, audit events, CA health, and enrollments.

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

CREATE INDEX idx_certificates_serial ON certificates (serial);
CREATE INDEX idx_certificates_subject_dn ON certificates (subject_dn(255));
CREATE INDEX idx_certificates_ca_id ON certificates (ca_id);
CREATE INDEX idx_certificates_status ON certificates (status);
CREATE INDEX idx_certificates_not_after ON certificates (not_after);

CREATE TABLE IF NOT EXISTS otp_tokens (
    id              BIGINT       AUTO_INCREMENT PRIMARY KEY,
    token_hash      TEXT         NOT NULL,
    entity_id       VARCHAR(255) NOT NULL,
    label           VARCHAR(255),
    profile         VARCHAR(255),
    created_at      TEXT  NOT NULL DEFAULT (DATE_FORMAT(NOW(6), '%Y-%m-%dT%H:%i:%S.%fZ')),
    expires_at      TEXT  NOT NULL,
    max_uses        INT          NOT NULL DEFAULT 1,
    current_uses    INT          NOT NULL DEFAULT 0,
    revoked         BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at      TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_otp_tokens_entity_id ON otp_tokens (entity_id);
CREATE INDEX idx_otp_tokens_expires_at ON otp_tokens (expires_at);

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

CREATE INDEX idx_audit_events_timestamp ON audit_events (timestamp);
CREATE INDEX idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX idx_audit_events_actor ON audit_events (actor);

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

CREATE INDEX idx_ca_health_ca_id ON ca_health (ca_id);

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

CREATE INDEX idx_enrollment_requests_status ON enrollment_requests (status);
CREATE INDEX idx_enrollment_requests_ca_id ON enrollment_requests (ca_id);
CREATE INDEX idx_enrollment_requests_entity_id ON enrollment_requests (entity_id);
CREATE INDEX idx_enrollment_requests_csr_hash ON enrollment_requests (csr_hash);

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

CREATE INDEX idx_server_generated_keys_enrollment_id ON server_generated_keys (enrollment_id);

-- STAR (Short-Term Automatic Renewal) tables (RFC 8739).
-- Tracks STAR orders and their automatically renewed certificates.

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

CREATE INDEX idx_star_certs_order ON star_certificates(star_order_id, renewal_number DESC);
