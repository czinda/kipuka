# Changelog

All notable changes to kipuka are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### CoAP/DTLS Transport (`crates/kipuka-coap/`)
- OpenSSL DTLS transport with client certificate extraction for mTLS authentication
- CoapDtlsServer with UDP socket binding and configurable listen address
- EST bridge for CoAP operations: `/cacerts`, `/simpleenroll`, `/simplereenroll`,
  `/serverkeygen`, `/csrattrs` mapped to CoAP request/response
- Block-wise transfer (RFC 7959) for constrained devices with large payloads
- 69 new tests covering DTLS handshake, CoAP message parsing, EST bridging,
  block-wise transfer, error handling, and concurrent connection scenarios
- RFC 7252 (CoAP), RFC 9483 (DTLS transport for EST), RFC 9148 (EST-coaps) compliance

#### EST Protocol Implementation (RFC 7030)
- Complete EST enrollment server with all six operations:
  - `GET /cacerts` — CA certificate distribution (no authentication required)
  - `POST /simpleenroll` — Initial certificate enrollment with OTP or GSSAPI authentication
  - `POST /simplereenroll` — Certificate renewal with mTLS client authentication
  - `POST /fullcmc` — Full CMC (RFC 5272) request passthrough for complex workflows
  - `POST /serverkeygen` — Server-side key generation with encrypted private key return
  - `GET /csrattrs` — CSR attribute hints for proper certificate request construction
- EST label support for path-based routing to multiple certificate profiles
- Base64 PKCS#7/CMS response encoding per EST specification
- Correct Content-Type headers for each operation (`application/pkcs7-mime`, `application/csrattrs`, `multipart/mixed`)
- RFC 8951 EST clarifications compliance

#### Multi-CA High Availability (`src/ha/`)
- Multi-CA backend support with independent health tracking (pools up to N CA instances)
- Four failover strategies (`src/ha/strategy.rs`):
  - **Active-Passive** — Primary CA with automatic failover to standby on circuit break
  - **Round-Robin** — Distribute load evenly across healthy CAs
  - **Weighted** — Proportional load distribution based on CA capacity
  - **Latency-Based** — Route to lowest-latency healthy CA (adaptive selection)
- Circuit breaker pattern (`src/ha/pool.rs`) with configurable cooldown and failure thresholds
- Five-state health machine (`src/ha/health.rs`): Healthy → Degraded → Unhealthy → CircuitOpen → Recovering
- Automatic failover on CA unavailability with graceful degradation when all CAs are down
- Health probes with state machine transitions based on consecutive success/failure counts
- Configurable behavior when no CA is available (fail-closed vs best-effort)

#### Authentication (`src/auth/`)
- **mTLS client authentication** (`src/auth/mtls.rs`):
  - Client certificate verification against configurable trust anchors
  - Separate truststores for EST client authentication vs admin API access
  - EKU validation: id-kp-cmcRA (1.3.6.1.5.5.7.3.28) required for `/fullcmc` operations
  - OCSP stapling and CRL revocation checking (planned)
  - Subject DN and SAN policy enforcement
- **OTP authentication** (`crates/kipuka-otp/`):
  - One-time password generation with 128-bit minimum entropy (FIPS-approved CSPRNG via `rand` crate)
  - Timing-safe comparison using `subtle::ConstantTimeEq` to prevent side-channel attacks
  - Single-use and multi-use token support with configurable expiration and max-use limits
  - Tokens stored as SHA-256 hashes (never plaintext) in `otp_tokens` table
  - Periodic cleanup of expired tokens
  - Per-profile binding (tokens optionally restricted to specific EST label)
  - HTTP Basic authentication presentation (RFC 7617, username ignored per RFC 7030)
  - LDAP backend support for OTP storage (planned)
- **GSSAPI/Kerberos authentication** (`src/auth/gssapi.rs`):
  - Enterprise SSO integration via Negotiate/SPNEGO
  - Channel binding to prevent MITM attacks
  - Principal mapping to certificate subject DN
- Rate limiting per source IP with configurable lockout after N failed attempts

#### HSM Support (`crates/kipuka-hsm/`)
- PKCS#11 abstraction layer via `cryptoki` crate for vendor-neutral HSM integration
- Vendor-specific provider modules (`src/providers/`):
  - **Entrust nShield** (`nshield.rs`) — Connect, Solo, Edge models; PKCS#11 v2.40
  - **Utimaco CryptoServer** (`utimaco.rs`) — Se, CP5 models; library path `/usr/lib/libcs_pkcs11_R3.so`
  - **Kryoptic** (`kryoptic.rs`) — SoftHSM-compatible dev/test HSM with software token
  - **Thales Luna CSP** (`thales_csp.rs`) — Luna 7 HSM with standard CSP11 library
  - **Thales Luna TCT** (`thales_tct.rs`) — Disconnected/air-gapped deployments with TCT protocol
- HSM operations:
  - Key generation (RSA 2048/3072/4096, ECDSA P-256/P-384/P-521)
  - Signing (RSA-PKCS#1v1.5, RSA-PSS, ECDSA with SHA-256/384/512)
  - Key wrapping (AES-WRAP, RSA-OAEP) for `/serverkeygen` encrypted private key return
- HSM session management and connection pooling for concurrent EST operations
- Health check probes (slot availability, key accessibility, signing test)
- Configurable PIN management (`pin` plaintext, `pin_env` environment variable, `pin_file` secure read)
- Vendor-specific PQC mechanism ID configuration (ML-DSA, ML-KEM OIDs vary by HSM firmware)

#### Post-Quantum Cryptography (PQC)
- **ML-DSA** (FIPS 204) signing support via Synta:
  - ML-DSA-44 (OID 2.16.840.1.101.3.4.3.17) — 128-bit security, 2420-byte signatures
  - ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18) — 192-bit security, 3309-byte signatures
  - ML-DSA-87 (OID 2.16.840.1.101.3.4.3.19) — 256-bit security, 4627-byte signatures
- **ML-KEM** (FIPS 203) key encapsulation for `/serverkeygen`:
  - ML-KEM-512 (OID 2.16.840.1.101.3.4.4.1) — 128-bit security, 768-byte ciphertexts
  - ML-KEM-768 (OID 2.16.840.1.101.3.4.4.2) — 192-bit security, 1088-byte ciphertexts
  - ML-KEM-1024 (OID 2.16.840.1.101.3.4.4.3) — 256-bit security, 1568-byte ciphertexts
- **Composite hybrid algorithms** (draft-ietf-lamps-pq-composite-sigs-19):
  - RSA+ML-DSA paired certificates for gradual migration
  - ECDSA+ML-DSA paired certificates
  - Sub-arc OIDs 2.16.840.1.114027.80.8.1.37-54 for composite signature algorithms
- Dual certificate enrollment support (`src/ca/issue.rs`) for simultaneous legacy + PQC certificate issuance per IDM-5563

#### Dogtag PKI Integration (`crates/kipuka-dogtag/`)
- REST API client for Red Hat Certificate System / Dogtag PKI:
  - Certificate enrollment via `/ca/rest/certrequests` (POST, GET)
  - Certificate retrieval and revocation
  - Certificate profile queries
  - Full CMC passthrough (RFC 5272 wrapped requests)
  - Multi-CA connection pool with circuit breaker for HA integration
- KRA (Key Recovery Authority) server-side key generation:
  - Integration with `/serverkeygen` endpoint
  - ML-KEM-512/768/1024 key generation and archival
  - Encrypted private key return via KRA key transport certificate
- CMC error code mapping to HTTP status codes (RFC 5272 FailInfo to 400/403/500)
- Async request/response handling via `reqwest` and `tokio`

#### Database Support (`src/db/`)
- Multiple backend support via `sqlx` (compile-time checked queries):
  - **SQLite** — Single-file deployment, WAL mode for concurrency
  - **PostgreSQL** — Multi-replica HA deployment with connection pooling
  - **MariaDB** — Enterprise deployment with Galera clustering
- Schema migrations in `migrations/{sqlite,postgres,mariadb}/` with sequential numbering
- Tables:
  - `otp_tokens` — OTP hash, entity_id, expiration, use count, profile binding
  - `audit_events` — Security audit log with timestamp, event_type, actor, target, detail JSON
  - `issued_certs` — Certificate serial number tracking for revocation and renewal
- Auto-detect backend from connection URL (`sqlite://`, `postgres://`, `mysql://`)
- `cargo run -- migrate` command for schema initialization

#### Audit Logging (`src/audit/`)
- NIAP CA Protection Profile v2.0 FAU_GEN.1 compliant event recording
- 22 audit event types:
  - **Lifecycle**: ServerStartup, ServerShutdown, ConfigReload
  - **Authentication**: AuthSuccess, AuthFailure, OtpGenerated, OtpValidated, OtpExpired
  - **Certificate Operations**: CertIssued, CertRevoked, CertRenewed
  - **Key Operations**: KeyGenerated, KeyDestroyed, HsmKeyAccess
  - **Admin Actions**: AdminLogin, AdminLogout, OtpProvisioned, OtpRevoked
  - **Errors**: EnrollmentFailed, RevocationFailed, HsmError, DatabaseError
- Audit record format:
  - Timestamp (RFC 3339, system monotonic + wall-clock)
  - Event type (enum discriminant)
  - Actor (client cert DN, OTP entity ID, admin principal, or source IP)
  - Target (certificate serial, OTP token ID, CA ID)
  - Detail (JSON payload with operation-specific fields)
  - Source IP and session ID
- Multiple output targets:
  - Database table `audit_events` (INSERT-only, no DELETE permission)
  - File-based JSON log (append-only mode)
  - Syslog over TLS for centralized SIEM integration
- FAU_STG.4 halt-on-full behavior (planned): reject operations when audit storage is exhausted

#### TLS Configuration (`src/tls/`)
- rustls with ring crypto backend (FIPS 140-3 module planned via BoringSSL)
- TLS 1.2 minimum enforced per NIAP FTP_TRP.1 (configurable to require TLS 1.3)
- FIPS-approved cipher suites only:
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
  - TLS 1.3 cipher suites (AES-GCM and ChaCha20-Poly1305)
- Server certificate with configurable chain
- Client certificate verification (mTLS) with trust anchor configuration
- Separate listen addresses for EST and admin API endpoints
- OCSP stapling support for server certificate (planned)

#### Admin API (`src/routes/admin/`)
- `/admin/ca` endpoints:
  - `GET /admin/ca/list` — List all configured CAs with health status
  - `GET /admin/ca/:id/health` — Detailed health state for specific CA
  - `POST /admin/ca/:id/probe` — Force immediate health check
- `/admin/otp` endpoints:
  - `POST /admin/otp/generate` — Create new OTP token (returns plaintext token once)
  - `GET /admin/otp/list` — List all active OTPs (hashes only, no plaintext)
  - `DELETE /admin/otp/:id` — Revoke OTP before expiration
  - `POST /admin/otp/cleanup` — Manually trigger expired token cleanup
- `/admin/certs` endpoints:
  - `GET /admin/certs/:serial` — Retrieve issued certificate details
  - `POST /admin/certs/:serial/revoke` — Revoke certificate (CRL/OCSP update)
- `/admin/health` endpoint:
  - `GET /admin/health` — System health check (database, HSM, CA connectivity)
- Authentication: mTLS required with separate trust anchor from EST client authentication

#### Beaker Deployment (`beaker/`)
- RHEL 10.0 provisioning job XML for Beaker lab automation
- System requirements:
  - RHEL 10.0 nightly compose (for OpenSSL 3.5+ PQC provider)
  - 8 GB RAM, 4 CPU cores (for Rust compilation)
  - x86_64 architecture
- Automated setup script (`setup.sh`):
  - DNF package installation (rust, cargo, openssl-devel, pkgconf-pkg-config, sqlite, git)
  - OpenSSL PQC readiness validation (ML-DSA/ML-KEM provider check)
  - kipuka repository clone from `codeberg.org`
  - Cargo build (release mode with vendored dependencies)
  - Database migration execution
- RHCS 11 integration (Dogtag PKI):
  - pkispawn configuration for CA subsystem (CA.cfg)
  - pkispawn configuration for KRA subsystem (KRA.cfg)
  - CA admin certificate generation
  - KRA transport certificate setup for server-side key generation
- systemd service unit (`kipuka.service`):
  - Security hardening: `PrivateTmp=true`, `NoNewPrivileges=true`, `ProtectSystem=strict`
  - User/group isolation (`kipuka` service account)
  - Automatic restart on failure
- Production TOML configuration (`kipuka-production.toml`):
  - TLS 1.2+ enforcement
  - mTLS client authentication enabled
  - SQLite database with WAL mode
  - OTP authentication configured
  - Single CA backend (RHCS CA)
- 10-test smoke validation script:
  - Server startup and port binding
  - `/cacerts` fetch and PKCS#7 decode
  - OTP generation via admin API
  - `/simpleenroll` with OTP authentication
  - `/simplereenroll` with mTLS authentication
  - `/csrattrs` attribute fetch
  - Certificate serial number tracking
  - Admin API health check
  - Database query validation
  - Graceful shutdown

#### Compliance Documentation
- **NIAP CA Protection Profile v2.0** mapping (`docs/compliance/niap-ca-pp.md`):
  - FAU (Security Audit): FAU_GEN.1, FAU_GEN.2, FAU_STG.1, FAU_STG.4
  - FCS (Cryptographic Support): FCS_CKM.1/2/4, FCS_COP.1, FCS_RBG_EXT.1, FCS_TLSS_EXT.1
  - FDP (User Data Protection): FDP_ITC.1/2
  - FIA (Identification/Authentication): FIA_AFL.1, FIA_UAU.1, FIA_UID.1
  - FMT (Security Management): FMT_SMR.1, FMT_SMF.1, FMT_MOF.1
  - FPT (Protection of TSF): FPT_TST.1, FPT_STM.1
  - FTP (Trusted Path): FTP_TRP.1, FTP_ITC.1
- **CA/Browser Forum Baseline Requirements** (`docs/compliance/cab-forum.md`):
  - Certificate serial number generation (64+ bits CSPRNG per BR S7.1)
  - Validity period enforcement (398 days for subscriber certificates)
  - Key usage and extended key usage compliance
  - Subject DN policy and SAN validation
- **HSM compatibility matrix** (`docs/compliance/hsm-compatibility.md`):
  - Per-vendor PKCS#11 library paths and configuration
  - Key generation, signing, and key wrap support matrix
  - Known limitations and vendor-specific quirks
  - FIPS 140-3 certification status for each HSM model
- **Architecture documentation** (`docs/architecture.md`):
  - Component interaction diagrams
  - EST operation data flows (cacerts, simpleenroll, simplereenroll, fullcmc, serverkeygen)
  - Crate responsibility breakdown
  - Security invariants and threat model

#### synta-cmc Crate (RFC 5272 CMC Protocol)
- PKIData/PKIResponse builders and parsers with full CMC control attribute support
- CMCStatus/CMCFailInfo with HTTP status mapping
- All 35+ CMC control OIDs (id-cmc arc)
- CNSA Suite profile validation (RFC 8603)
- ML-DSA digest pairing and ML-KEM wrap validation (RFC 9688)
- RFC 5274 compliance checks per agent type (EE/RA/CA)
- Coverage across 13 RFCs (5272, 6402, 5273, 5274, 5652, 4211, 2986, 5280, 5753, 5754, 5816, 8603, 7906)

#### CMP Protocol (RFC 4210)
- Certificate enrollment and revocation via CMP messages
- General messages for CA capability discovery
- MAC-based protection with PBKDF2 key derivation (RFC 4210 S5.1.3.1)
- Signature-based protection verification over header||body
- Revocation authorization checking

#### CMS-EST Endpoints (RFC 8295)
- `/cms/simpleenroll` — CMS-wrapped initial enrollment
- `/cms/simplereenroll` — CMS-wrapped certificate renewal
- `/cms/serverkeygen` — CMS-wrapped server-side key generation
- `/cms/fullcmc` — CMS-wrapped Full CMC operations

#### STAR Certificates (RFC 8739)
- Short-lived certificate issuance with auto-renewal
- Configurable lifetime and renewal window
- Automatic renewal scheduling

#### CMS Operations (RFC 5652)
- CMS SignedData verification with signedAttrs support (RFC 5652 S5.4)
- CMS EnvelopedData construction for encrypted EST responses
- Signer certificate matching by SignerIdentifier (sid)

#### Certificate Validation
- OCSP response signature verification and stapling
- CRL distribution point fetching with 10s timeout and 10MB size limit
- CSR self-signature validation with key size enforcement
- CNSA Suite profile validation (RFC 8603)
- Post-quantum algorithm pairing validation (RFC 9688/9882/9936)

#### Server-Side Key Generation Enhancements
- Real key generation via synta-certificate PrivateKeyBuilder (RSA, ECDSA, ML-DSA, ML-KEM)
- Encrypted private key return via CMS EnvelopedData

#### Admin API Enhancements
- Certificate listing with database query, filters, and pagination
- Query limit capped at 1000

#### Disconnected EST Support
- CSR queue for deferred signing in DMZ deployments with limited CA connectivity
- Configurable CA connection behavior (fail-fast vs queue-and-retry)
- Manual CSR approval workflow via admin API
- Batch certificate issuance for queued requests

#### Developer Tooling
- `contrib/gen-test-certs.sh` — Generate test CA and server certificates for local development
- `kipuka.toml.example` — Fully annotated configuration file with all supported options
- `curl` and `openssl` testing examples in `docs/PROJECT.md`
- Kryoptic setup guide for HSM development without hardware

### Requirements Coverage

This release implements the following requirements from **RHELBU-3536**:

| Requirement | Description | Implementation |
|------------|-------------|----------------|
| **R1** | Multiple CA backend support with independent health tracking | `src/ha/pool.rs` — CA pool with per-backend health state |
| **R2** | Circuit-breaker pattern with configurable cooldown | `src/ha/pool.rs` — `record_failure()` with cooldown timer |
| **R3** | Pluggable failover strategies | `src/ha/strategy.rs` — ActivePassive, RoundRobin, Weighted, LatencyBased |
| **R4** | Health probes with state machine transitions | `src/ha/health.rs` — 5-state machine (Healthy → Degraded → Unhealthy → CircuitOpen → Recovering) |
| **R5** | Automatic failover on CA unavailability | `src/ha/pool.rs` — `get_healthy_ca()` skips CircuitOpen CAs |
| **R6** | Graceful degradation when all CAs are unhealthy | `src/config/ha.rs` — `DegradationBehavior::FailClosed` vs `BestEffort` |
| **R7** | Minimum 128-bit entropy for OTP tokens | `crates/kipuka-otp/src/generate.rs` — CSPRNG with 16+ byte output |
| **R8** | Timing-safe comparison during OTP validation | `crates/kipuka-otp/src/validate.rs` — `subtle::ConstantTimeEq` |
| **R9** | Single-use and multi-use token support | `crates/kipuka-otp/src/store.rs` — `use_count` and `max_uses` tracking |
| **R10** | Configurable expiration and max-use limits | `src/config/otp.rs` — `default_ttl` and `max_uses` per profile |
| **R11** | Tokens stored as SHA-256 hashes | `crates/kipuka-otp/src/store.rs` — `hash` field, never plaintext |
| **R12** | Periodic cleanup of expired tokens | `crates/kipuka-otp/src/store.rs` — `cleanup_expired()` cron job |
| **R13** | Full CMC passthrough support | `src/routes/fullcmc.rs` — RFC 5272 request forwarding to Dogtag |
| **R14** | CMC request signature validation | `src/routes/fullcmc.rs` — PKCS#7 signature verification |
| **R15** | EKU validation for CMC signer certificate | `src/auth/mtls.rs` — id-kp-cmcRA (1.3.6.1.5.5.7.3.28) check |
| **R16** | CMC response encoding | `src/routes/fullcmc.rs` — PKCS#7 CMC response with StatusInfo |
| **R17** | CMC error code mapping | `src/routes/fullcmc.rs` — FailInfo to HTTP 400/403/500 |
| **R18** | Separate truststores for EST and admin | `src/config/tls.rs` — `est_trust_anchors` vs `admin_trust_anchors` |
| **R19** | Client certificate subject DN policy enforcement | `src/auth/mtls.rs` — DN pattern matching (planned) |
| **R21** | OCSP/CRL revocation checking | `src/auth/mtls.rs` — revocation check hooks (planned) |
| **R23** | Server-side key generation via `/serverkeygen` | `src/routes/serverkeygen.rs` — CSR-less enrollment |
| **R24** | Private key encryption for `/serverkeygen` | `src/routes/serverkeygen.rs` — AES-WRAP or RSA-OAEP via HSM |
| **R25** | Private key archival in KRA | `crates/kipuka-dogtag/src/kra.rs` — key deposit to Dogtag KRA |
| **R26** | ML-KEM key generation for `/serverkeygen` | `crates/kipuka-hsm/` — ML-KEM-512/768/1024 via PKCS#11 |
| **R27** | Authentication required for `/serverkeygen` | `src/routes/serverkeygen.rs` — mTLS or OTP mandatory |
| **R28** | Encrypted private key return in multipart/mixed response | `src/routes/serverkeygen.rs` — PKCS#7 cert + encrypted key blob |
| **R31** | Per-label CSR attribute variation | `src/routes/csrattrs.rs` — label-specific OID and extension hints |
| **R7-Disconnected** | Disconnected EST support for DMZ deployments | `src/routes/simpleenroll.rs` — CSR queue when CA unreachable |

Additional compliance:
- **IDM-5563**: Dual certificate enrollment (legacy + PQC paired issuance) — `src/ca/issue.rs`
- **NIAP CA PP v2.0**: 17 SFRs mapped and implemented (see `docs/compliance/niap-ca-pp.md`)
- **CA/B Forum BR**: Serial number entropy, validity period, key usage enforcement
- **FIPS 140-3**: Via HSM integration (Entrust nShield, Utimaco, Thales Luna certified modules)

### Changed
- Replaced 60+ placeholder functions with real synta-certificate parsing
- Extracted CA signing key resolver (ResolvedSigningKey) eliminating 8-site duplication
- CMP protection verification: signature over header||body, revocation authorization
- Upgraded Beaker deployment from RHEL 9.6 to RHEL 10.0 for OpenSSL 3.5+ PQC provider support
- Bumped Beaker host requirements to 8 GB RAM / 4 CPU for Rust compilation
- Updated Beaker setup URLs to use `codeberg.org` public repository

### Fixed
- CMS signedAttrs re-tagged from 0xa0 to 0x31 for RFC 5652 compliance
- CMS signer cert matched by SignerIdentifier (sid) not position
- Dogtag REST API field name casing (ProfileID, cert_request_type, response aliases)
- reqwest TLS identity type conflict (native-tls vs rustls-tls)
- OCSP signature verification uses original DER bytes (not re-encoded)
- CRL fetch with 10s timeout and 10MB size limit
- pkcs11_uri unwrap panic replaced with proper error handling (8 files)
- Admin certs query limit capped at 1000
- Removed comments with double-dashes and non-ASCII characters from Beaker job XML for strict XML parser compliance
- Escaped `>=` operators as `&gt;=` in Beaker XML attribute values

### Security
- All OTP tokens stored as SHA-256 hashes (never plaintext) to prevent credential leakage on database compromise
- Timing-safe comparison for OTP validation prevents timing side-channel attacks
- CA private keys zeroized from memory after loading (via `zeroize` crate)
- Separate truststores for EST client authentication vs admin API access prevent privilege escalation
- TLS 1.2+ enforcement with FIPS-approved cipher suites only
- Audit write failures cause operation to fail (fail-closed, not fail-open)

[Unreleased]: https://codeberg.org/czinda/kipuka
