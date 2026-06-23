# kipuka Architecture

## Component Overview

```
                              Clients
                   (EST clients, CMC agents, MDM)
                                |
                          HTTPS (TLS 1.2+)
                          mTLS / OTP / GSSAPI
                                |
                    +-----------+-----------+
                    |     axum HTTP Server  |
                    |   src/routes/         |
                    +-----------+-----------+
                          |           |
                   EST Routes      Admin API
                   /cacerts        /admin/otp
                   /simpleenroll   /admin/ca
                   /simplereenroll /admin/audit
                   /fullcmc
                   /serverkeygen
                   /csrattrs
                          |
              +-----------+-----------+
              |                       |
     +--------+--------+    +--------+--------+
     |   kipuka-est     |    |   Auth Layer    |
     |   crates/est/    |    |   src/auth/     |
     |                  |    |                 |
     |  - CSR parsing   |    |  - mTLS verify  |
     |  - Cert building |    |  - OTP validate |
     |  - CMC handling  |    |  - GSSAPI/Krb5  |
     |  - PKCS#7 encode |    |  - Rate limiting|
     +--------+---------+    +--------+--------+
              |                       |
              |              +--------+--------+
              |              |   kipuka-otp    |
              |              |   crates/otp/   |
              |              |                 |
              |              |  - Token gen    |
              |              |  - Hash/verify  |
              |              |  - Lifecycle    |
              |              +--------+--------+
              |                       |
     +--------+---------+            |
     |   kipuka-hsm     |            |
     |   crates/hsm/    |            |
     |                  |            |
     |  - PKCS#11 ops   |            |
     |  - Key generation|            |
     |  - Signing       |            |
     |  - Key wrapping  |            |
     +--------+---------+            |
              |                       |
              |   +-------------------+
              |   |
     +--------+---+--------+
     |     Data Layer      |
     |     src/db/         |
     |                     |
     |  - sqlx (async)     |
     |  - SQLite           |
     |  - PostgreSQL       |
     |  - MariaDB          |
     +--------+------------+
              |
     +--------+------------+
     |   Audit Subsystem   |
     |   src/audit/        |
     |                     |
     |  - DB audit_events  |
     |  - File (JSON)      |
     |  - Syslog           |
     +---------------------+
```

## Crate Responsibilities

### kipuka (root crate)
- Binary entry point, CLI argument parsing
- axum HTTP server setup and TLS configuration
- Route registration and middleware
- Configuration loading and validation
- Database connection management
- Audit subsystem initialization

### kipuka-est
- EST protocol implementation (RFC 7030)
- CSR parsing and validation via Synta
- Certificate construction and signing
- PKCS#7/CMS response encoding
- CMC request/response handling (RFC 5272)
- CSR attributes response building
- Server key generation logic

### kipuka-hsm
- PKCS#11 abstraction layer (via `cryptoki` crate)
- HSM session management and pooling
- Key generation (RSA, ECDSA)
- Signing operations (delegated from kipuka-est)
- Key wrapping for /serverkeygen
- Health check (slot availability, key accessibility)

### kipuka-otp
- OTP token generation (CSPRNG)
- Token hashing (argon2id, bcrypt, sha256-hmac)
- Token validation with timing-safe comparison
- Lifecycle management (expiration, use counting, revocation)
- Rate limiting primitives

### kipuka-util
- Shared error types
- Configuration structs and deserialization
- Common traits (AuditEvent, HealthCheck)
- Base64 encoding/decoding helpers
- Certificate utility functions

## EST Operation Data Flows

### GET /cacerts

```
Client                    kipuka                     CA Config
  |                         |                           |
  |-- GET /cacerts -------->|                           |
  |                         |-- load CA cert + chain ---|
  |                         |-- build PKCS#7 certs-only |
  |                         |-- base64 encode           |
  |<-- 200 OK --------------|                           |
  |    application/pkcs7-mime                            |
  |    smime-type=certs-only                             |
```

No authentication required. Returns the CA certificate chain as a
PKCS#7 degenerate (certs-only) structure, base64-encoded.

### POST /simpleenroll

```
Client                    kipuka                    CA/HSM          DB
  |                         |                         |              |
  |-- POST /simpleenroll -->|                         |              |
  |   Content-Type: pkcs10  |                         |              |
  |   Authorization: Basic  |                         |              |
  |                         |-- validate OTP -------->|              |
  |                         |                         |-- check DB --|
  |                         |                         |<- OTP valid -|
  |                         |-- decode base64 CSR     |              |
  |                         |-- parse & validate CSR  |              |
  |                         |   (key type, subject,   |              |
  |                         |    SANs, extensions)    |              |
  |                         |-- build certificate     |              |
  |                         |-- sign cert ----------->|              |
  |                         |                  (PKCS#11 or Synta)    |
  |                         |<-- signed cert ---------|              |
  |                         |-- store cert ---------->|              |
  |                         |                         |-- INSERT --->|
  |                         |-- audit event --------->|              |
  |                         |                         |-- INSERT --->|
  |                         |-- consume OTP --------->|              |
  |                         |                         |-- UPDATE --->|
  |                         |-- build PKCS#7 response |              |
  |<-- 200 OK --------------|                         |              |
  |    application/pkcs7-mime                          |              |
```

### POST /simplereenroll

```
Client                    kipuka                    CA/HSM          DB
  |                         |                         |              |
  |-- POST /simplereenroll->|                         |              |
  |   (mTLS client cert)    |                         |              |
  |   Content-Type: pkcs10  |                         |              |
  |                         |-- verify client cert    |              |
  |                         |   (TLS layer, automatic)|              |
  |                         |-- check cert not revoked|-- SELECT --->|
  |                         |-- decode & validate CSR |              |
  |                         |-- verify CSR subject    |              |
  |                         |   matches client cert   |              |
  |                         |-- sign new cert ------->|              |
  |                         |<-- signed cert ---------|              |
  |                         |-- store + audit ------->|-- INSERT --->|
  |<-- 200 OK --------------|                         |              |
```

### POST /serverkeygen

```
Client                    kipuka                    HSM             DB
  |                         |                         |              |
  |-- POST /serverkeygen -->|                         |              |
  |   (OTP or mTLS auth)    |                         |              |
  |                         |-- authenticate          |              |
  |                         |-- generate key pair --->|              |
  |                         |<-- key pair ------------|              |
  |                         |-- build cert from CSR   |              |
  |                         |   (use generated pubkey)|              |
  |                         |-- sign cert ----------->|              |
  |                         |<-- signed cert ---------|              |
  |                         |-- wrap private key      |              |
  |                         |   (PKCS#7 EnvelopedData)|              |
  |                         |-- archive key (optional)|-- INSERT --->|
  |                         |-- store cert + audit -->|-- INSERT --->|
  |<-- 200 OK --------------|                         |              |
  |    multipart/mixed      |                         |              |
  |    Part 1: cert (pkcs7) |                         |              |
  |    Part 2: key (pkcs8)  |                         |              |
```

### POST /fullcmc

```
Client                    kipuka                    CA/HSM          DB
  |                         |                         |              |
  |-- POST /fullcmc ------->|                         |              |
  |   application/pkcs7-mime|                         |              |
  |   smime-type=CMC-request|                         |              |
  |                         |-- parse CMC request     |              |
  |                         |   (PKCS#7 SignedData)   |              |
  |                         |-- verify RA signature   |              |
  |                         |-- extract embedded CSRs |              |
  |                         |-- process each CSR      |              |
  |                         |-- sign certs ---------->|              |
  |                         |<-- signed certs --------|              |
  |                         |-- build CMC response    |              |
  |                         |-- store + audit ------->|-- INSERT --->|
  |<-- 200 OK --------------|                         |              |
  |    application/pkcs7-mime                          |              |
  |    smime-type=CMC-response                         |              |
```

## Multi-CA HA Failover

```
                    EST Request
                        |
                  +-----+------+
                  | HA Router  |
                  | src/ha/    |
                  +-----+------+
                        |
            +-----------+-----------+
            |           |           |
     +------+--+  +-----+---+  +---+------+
     | CA #1   |  | CA #2   |  | CA #3   |
     | Primary |  | Standby |  | Standby |
     | Healthy |  | Healthy |  | Unhealthy|
     +---------+  +---------+  +----------+

Strategy: active-passive
  1. Route to CA #1 (primary, healthy)
  2. If CA #1 fails -> route to CA #2
  3. CA #3 excluded (unhealthy, consecutive_failures > threshold)
  4. Background: health check CA #3 every check_interval
  5. When CA #3 recovers -> mark healthy, add back to pool

Strategy: round-robin
  1. Distribute across all healthy CAs
  2. Skip unhealthy CAs
  3. Health status updated by background checker

Strategy: weighted
  1. Distribute proportionally to CA weight
  2. E.g., CA #1 weight=3, CA #2 weight=1 -> 75%/25% split
  3. Unhealthy CAs get weight=0

Health Check Flow:
  +---------+     +-------+     +--------+
  | Timer   |---->| Check |---->| Update |
  | 30s     |     | HSM   |     | Status |
  |         |     | Sign  |     | in DB  |
  +---------+     | Verify|     +--------+
                  +-------+
```

## Authentication Flow

```
              Incoming TLS Connection
                      |
              +-------+-------+
              | TLS Handshake |
              | (rustls)      |
              +-------+-------+
                      |
            Client cert present?
           /                      \
         Yes                       No
          |                         |
  +-------+-------+       +--------+--------+
  | Verify cert   |       | Check endpoint  |
  | against trust |       | requires auth?  |
  | anchors       |       +--------+--------+
  +-------+-------+                |
          |                   +---------+----------+
     Valid?                   |                    |
    /     \              /cacerts              Other endpoints
  Yes      No          /csrattrs                   |
   |        |          (no auth)           +-------+-------+
   |   401 error           |               | Check HTTP    |
   |                  200 response         | Authorization |
   |                                       +-------+-------+
   |                                               |
   +--- mTLS authenticated              +---------+---------+
   |    (reenroll path)                  |                   |
   |                               Basic auth          GSSAPI
   |                               (OTP)              (Kerberos)
   |                                  |                    |
   |                           +------+------+    +--------+--------+
   |                           | Validate    |    | Validate        |
   |                           | OTP token   |    | SPNEGO token    |
   |                           | (argon2id   |    | (gss-accept)    |
   |                           |  verify)    |    +--------+--------+
   |                           +------+------+             |
   |                                  |                    |
   +----------------------------------+--------------------+
                      |
              Authenticated identity
              bound to request context
                      |
              +-------+--------+
              | Audit: AUTH    |
              | event recorded |
              +----------------+
```

## Database Schema Overview

See `migrations/` for full DDL. Key relationships:

```
enrollment_requests ──┬── certificates
                      │   (1:0..1 — issued cert)
                      │
                      └── server_generated_keys
                          (1:0..1 — for /serverkeygen)

otp_tokens ──── enrollment_requests
                (via entity_id match)

ca_health ──── [[ca]] config
               (via ca_id)

audit_events   (standalone, append-only)
```

## HSM Integration Points

```
                       kipuka-hsm
                      /     |     \
                     /      |      \
            +-------+  +---+---+  +--------+
            | Init  |  | Sign  |  | KeyGen |
            | Open  |  | RSA   |  | RSA    |
            | slot, |  | ECDSA |  | ECDSA  |
            | login |  +---+---+  +---+----+
            +-------+      |         |
                            \       /
                          +--+-----+--+
                          | PKCS#11   |
                          | C_Sign    |
                          | C_Generate|
                          | C_Wrap    |
                          +-----------+
                               |
                     +---------+---------+
                     |    HSM Hardware   |
                     |  (or SoftHSM /   |
                     |   Kryoptic)      |
                     +-------------------+

Initialization (startup):
  1. Load PKCS#11 library (dlopen)
  2. C_Initialize
  3. C_OpenSession for each configured slot
  4. C_Login with PIN
  5. C_FindObjects to locate CA keys by label
  6. Verify key accessibility (test sign + verify)

Signing (per request):
  1. Acquire session from pool
  2. C_SignInit with mechanism (e.g., CKM_ECDSA_SHA384)
  3. C_Sign with TBS (to-be-signed) data
  4. Return session to pool

Health check (periodic):
  1. C_GetSlotInfo — slot present?
  2. C_SignInit + C_Sign — can sign?
  3. Verify signature — correct output?
  4. Update ca_health table
```
