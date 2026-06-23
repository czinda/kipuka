# CA/Browser Forum Baseline Requirements Compliance

This document maps relevant CA/Browser Forum Baseline Requirements (BR) to
the kipuka implementation. kipuka enforces these requirements at the certificate
issuance layer for publicly-trusted TLS certificates.

Note: Not all BR requirements apply to an EST enrollment server. Requirements
related to domain validation (DCV), certificate transparency (CT), and
subscriber agreement are the responsibility of the RA/policy layer, which
may sit upstream of kipuka. This document covers what kipuka enforces directly.

## Certificate Profile Requirements (BR S7.1)

### Subject Fields

| BR Section | Requirement | kipuka Implementation |
|------------|-------------|----------------------|
| S7.1.4.2 | Subject CN must be a SAN value or omitted | Enforced in CSR validation. If CN is present, it must match a dNSName or iPAddress SAN. |
| S7.1.4.2 | organizationName allowed only with OV/EV validation | Enforced per-label: labels can require or prohibit O= in Subject DN. |
| S7.1.4.2 | serialNumber, businessCategory for EV only | Configurable per label. Default: rejected for DV profiles. |

### Key Requirements

| BR Section | Requirement | kipuka Implementation |
|------------|-------------|----------------------|
| S6.1.5 | RSA: minimum 2048 bits | Enforced in CSR validation. Configurable per label (`allowed_key_types`). |
| S6.1.5 | ECDSA: P-256 or P-384 only for public trust | Enforced in CSR validation. P-521 allowed only for private PKI labels. |
| S6.1.5 | Key must not be a known weak key | CSR key checked against known-weak-key databases (Debian, ROCA). |
| S7.1 | Serial number >= 64 bits of CSPRNG output | Serial numbers are 20 bytes (160 bits) from CSPRNG per RFC 5280 recommendation. |

### Extensions

| BR Section | Requirement | kipuka Implementation |
|------------|-------------|----------------------|
| S7.1.2.3 | authorityKeyIdentifier MUST be present | Added automatically from CA certificate's SubjectKeyIdentifier. |
| S7.1.2.7 | subjectKeyIdentifier MUST be present | Computed from the SHA-1 hash of the subscriber's public key (method 1 per RFC 5280 S4.2.1.2). |
| S7.1.2.1 | basicConstraints: cA=FALSE for subscriber certs | Always set. CA certificates are never issued via EST enrollment. |
| S7.1.2.4 | keyUsage MUST be present and critical | Set per label configuration. Default: digitalSignature + keyEncipherment for RSA, digitalSignature for EC. |
| S7.1.2.2 | subjectAlternativeName MUST be present | Enforced by `require_san` label option (default: true for public-trust labels). |
| S7.1.2.8 | CRL Distribution Points or AIA OCSP | Configurable per CA. Added from CA configuration, not from CSR. |

## Validity Period (BR S6.3.2)

| Effective Date | Maximum Validity | kipuka Implementation |
|----------------|-----------------|----------------------|
| Current | 398 days | Default `max_validity_days = 398`. Enforced at issuance. |
| 15 March 2026 | 200 days | Configurable via `max_validity_days`. Operator must update config. |
| 15 March 2027 | 100 days | Configurable via `max_validity_days`. |
| 15 March 2029 | 47 days | Configurable via `max_validity_days`. |

kipuka enforces the configured `max_validity_days` at certificate issuance time.
The operator is responsible for updating this value as BR requirements change.
A startup warning is logged if `max_validity_days` exceeds the current BR limit.

## Certificate Transparency (BR S7.1.2.5)

| Requirement | kipuka Implementation |
|-------------|----------------------|
| Precertificate submission to CT logs | Planned. kipuka will support submitting precertificates to configured CT logs and embedding SCTs in the issued certificate. |
| SCT embedding in certificate | Planned. SCTs will be embedded as a certificate extension (RFC 6962 S3.3). |
| Minimum CT log count | Configurable per label. Default will match BR requirements (currently 2 logs from different operators). |

Note: CT is required only for publicly-trusted certificates. Private PKI
labels can disable CT via `require_ct = false`.

## Key Generation for /serverkeygen (BR S6.1.1.3)

| Requirement | kipuka Implementation |
|-------------|----------------------|
| Keys generated using approved CSPRNG | Keys generated via `rand::rngs::OsRng` (CSPRNG) or PKCS#11 `C_GenerateKeyPair` (HSM CSPRNG). |
| Key archival for recovery | `/serverkeygen` keys optionally archived in `server_generated_keys` table, encrypted with the archive key. |
| Key transport encryption | Private key returned to client encrypted in the PKCS#7 EnvelopedData structure per RFC 7030 S4.4.2. |

## Audit Requirements (BR S8)

| BR Section | Requirement | kipuka Implementation |
|------------|-------------|----------------------|
| S8.1 | Record CA key lifecycle events | All key operations (generation, import, destruction) logged to `audit_events`. |
| S8.1 | Record certificate lifecycle events | Issuance, revocation, and expiration events logged with full certificate details. |
| S8.4 | Audit log integrity | Append-only database table. Optional cryptographic chaining (planned). |
| S8.6 | Audit log retention (minimum 7 years for CA events) | Database retention is an operational concern. kipuka does not auto-delete audit records. |

## Revocation (BR S4.9)

| Requirement | kipuka Implementation |
|-------------|----------------------|
| Support revocation within 24 hours | `certificates` table tracks revocation status, reason, and time. Admin API provides revocation endpoint. |
| CRL issuance | Planned. CRL generation from the `certificates` table. |
| OCSP responder | Out of scope for kipuka. Use a dedicated OCSP responder reading from the kipuka database. |
