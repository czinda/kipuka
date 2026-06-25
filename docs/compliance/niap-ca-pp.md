# NIAP CA Protection Profile v2.0 Compliance Mapping

This document maps each Security Functional Requirement (SFR) from the
NIAP Protection Profile for Certificate Authorities (CA PP v2.0) to
the corresponding kipuka implementation.

## Status Legend

| Status | Meaning |
|--------|---------|
| Done | Fully implemented and tested |
| Partial | Implemented but not all sub-requirements met |
| Planned | Designed, not yet implemented |
| N/A | Not applicable to this deployment model |

## Security Functional Requirements

### FAU -- Security Audit

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FAU_GEN.1 | Audit Data Generation | Done | `src/audit/` module records all security-relevant events to the `audit_events` table. Full `AuditEventType` enum with 22 event types organized by category: CA lifecycle (ca.start, ca.stop, ca.health-change), enrollment (enroll.request, cert.issue, cert.reenroll, enroll.reject), certificate operations (cert.revoke, crl.generate), key management (key.generate, key.load, key.destroy), OTP (otp.create, otp.use, otp.expire, otp.revoke), authentication (auth.success, auth.failure), admin (admin.login, admin.logout, admin.action), and security (security.violation). Protocol-specific event detail strings via state.rs dispatch: simpleenroll_success, simpleenroll_deferred, fullcmc_success, star_order_created, star_renewal_success, star_order_cancelled, cmp_* events. Each event captures timestamp, event type, actor, target, detail JSON, source IP, and session ID. |
| FAU_GEN.2 | User Identity Association | Done | Every audit event includes the authenticated identity (client cert subject DN, OTP entity ID, or admin principal). Unauthenticated events record the source IP. |
| FAU_STG.1 | Protected Audit Trail Storage | Done | Audit events are stored in the database with INSERT-only access for the application. File-based audit log uses append-only mode. Database table has no DELETE permission for the application role. |
| FAU_STG.4 | Prevention of Audit Data Loss | Partial | Fail-closed behavior for security violations (security.violation events cause operation rejection). Severity-based event routing. Still needs: configurable overflow behavior. |

### FCS -- Cryptographic Support

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FCS_CKM.1 | Cryptographic Key Generation | Done | CA key generation through PKCS#11 (HSM) or Synta library via `KeyType` enum in `src/ca/keygen.rs`. Supported algorithms: RSA (2048, 3072, 4096 bits), ECDSA (P-256, P-384, P-521), ML-DSA (FIPS 204: ML-DSA-44, ML-DSA-65, ML-DSA-87), ML-KEM (FIPS 203: ML-KEM-512, ML-KEM-768, ML-KEM-1024), and composite ML-DSA + classical hybrid signing. Uses synta-certificate's `PrivateKeyBuilder` for key generation. Certificate serial numbers use 64+ bits from CSPRNG. `/serverkeygen` uses CSPRNG for subscriber key generation. |
| FCS_CKM.2 | Cryptographic Key Distribution | Done | CA certificates distributed via `/cacerts` endpoint. Server-generated keys returned encrypted via `/serverkeygen`. CMS EnvelopedData (RFC 5652 §6) for encrypted key transport via `build_cms_enveloped_data()` in `src/auth/cms_auth.rs`. CMS-EST layer (RFC 8295) wraps responses in EnvelopedData for confidentiality. Supports AES-CBC content encryption. Key wrapping via CKM_AES_KEY_WRAP or CKM_RSA_PKCS_OAEP for HSM. |
| FCS_CKM.4 | Cryptographic Key Destruction | Partial | HSM keys destroyed via C_DestroyObject. File-based keys zeroized on drop using `zeroize` crate. Memory zeroization on process exit is best-effort. |
| FCS_COP.1(1) | Cryptographic Operation -- Signing | Done | RSA (PKCS#1 v1.5, PSS) and ECDSA signing via PKCS#11 or Synta. SHA-256, SHA-384, SHA-512 hash algorithms. |
| FCS_COP.1(2) | Cryptographic Operation -- Hashing | Done | SHA-256/384/512 via `sha2` crate (ring backend). Used for CSR hashing, audit integrity, OTP token hashing. |
| FCS_COP.1(3) | Cryptographic Operation -- TLS | Done | TLS 1.2/1.3 via rustls with ring crypto backend. AEAD-only cipher suites. ECDHE key exchange. |
| FCS_RBG_EXT.1 | Random Bit Generation | Done | `rand` crate with OS-provided CSPRNG (getrandom). PKCS#11 C_GenerateRandom for HSM-backed randomness. |

### FCS -- TLS

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FCS_TLSC_EXT.1 | TLS Client (EST client mode) | N/A | kipuka is a server, not a client. Upstream CA communication (if any) would use this. |
| FCS_TLSS_EXT.1 | TLS Server | Done | rustls with configurable minimum TLS version (1.2 or 1.3). Server certificate with id-kp-cmcRA EKU. Client certificate verification via configurable trust anchors. |

### FDP -- User Data Protection

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FDP_ITC.1 | Import of User Data | Done | CSR import via `/simpleenroll` and `/simplereenroll`. CSR validation includes: signature verification, key type/size checks, Subject DN policy, SAN policy, key usage constraints. |
| FDP_ITC.2 | Import with Security Attributes | Done | Client certificate chain validation during mTLS. Trust anchor verification. Revocation status checking (if CRL/OCSP configured). |

### FIA -- Identification and Authentication

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FIA_AFL.1 | Authentication Failure Handling | Done | Configurable rate limiting per source IP. After `max_failures` within `failure_window`, the source is locked out for `lockout_duration`. Failed attempts produce audit events. |
| FIA_UAU.1 | Timing of Authentication | Done | `/cacerts` and `/csrattrs` are accessible without authentication. All other EST operations require authentication (OTP, mTLS, or GSSAPI) before processing. |
| FIA_UID.1 | Timing of Identification | Done | Identity established during TLS handshake (mTLS) or HTTP authentication (OTP/GSSAPI). Identity is bound to the audit session before any enrollment processing. |
| FIA_X509_EXT.1 | X.509 Certificate Validation | Done | X.509 certificate parsing via synta-certificate. CRL checking via `check_crl_fallback()` in `src/auth/mtls.rs` with CRL fetching, serial number lookup, and signature verification. OCSP verification in `src/ocsp/mod.rs` with response caching. |
| FIA_X509_EXT.2 | X.509 Certificate Path Validation | Done | Chain validation using synta-certificate's `default_signature_verifier()` for signature verification at each chain link. Trust anchor matching against configured CA certificates. Used in mTLS authentication, CMS SignedData verification, and CMP message protection. |

### FMT -- Security Management

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FMT_SMR.1 | Security Management Roles | Done | Two roles: operator (admin API access for OTP provisioning, CA management) and user (EST enrollment client). Role determined by authentication method and endpoint. |
| FMT_SMF.1 | Specification of Management Functions | Partial | Admin API provides: OTP token provisioning/revocation, CA status monitoring, audit log review. CA key management delegated to HSM administration tools. |
| FMT_MOF.1 | Management of Security Functions | Planned | Runtime configuration changes via admin API with audit trail. Restart required for TLS and CA certificate changes. |

### FPT -- Protection of the TSF

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FPT_TST.1 | TSF Self-Test | Partial | Health checks implemented: CA key accessibility verification at startup, HSM connectivity testing, database connectivity testing, periodic HA health checks (sign + verify test per CA). Still missing: comprehensive startup self-test suite. |
| FPT_STM.1 | Reliable Timestamps | Done | Timestamps from system clock (monotonic for ordering, wall-clock for certificates). NTP synchronization is an operational requirement documented in deployment guide. |

### FTP -- Trusted Path/Channels

| SFR | Title | Status | kipuka Implementation |
|-----|-------|--------|----------------------|
| FTP_TRP.1 | Trusted Path | Done | All EST operations over TLS 1.2+ with three authentication methods: mTLS with certificate chain validation and revocation checking (OCSP + CRL), GSSAPI/Kerberos authentication via libgssapi (SPNEGO token validation, AP-REQ processing), and OTP with argon2id password hashing and timing-safe comparison. CMS-EST (RFC 8295) for message-level security when TLS is terminated by a proxy. Admin API over separate TLS endpoint with mTLS requirement. |
| FTP_ITC.1 | Inter-TSF Trusted Channel | Done | PKCS#11 communication (local or network HSM), database connections with TLS, syslog over TLS for remote audit, Dogtag PKI integration over mTLS (agent certificate authentication), and CMP v3 message protection (signature-based and MAC-based). |

## Operational Environment Requirements

The following requirements are met by the deployment environment, not by kipuka itself:

- **OE.PHYSICAL**: Physical protection of the server and HSM hardware.
- **OE.NETWORK**: Network segmentation and firewall rules.
- **OE.TIME**: NTP synchronization for reliable timestamps.
- **OE.ADMIN**: Trained administrators following documented procedures.
