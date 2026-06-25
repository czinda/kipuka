# PROJECT.md -- kipuka-specific development rules

These rules extend the base CLAUDE.md and apply to all work in this project.

## Project Status

kipuka is a fully functional EST (RFC 7030) enrollment server with the following
capabilities implemented and tested:

### Core EST Operations
- `/cacerts` — CA certificate chain distribution (PKCS#7 certs-only)
- `/simpleenroll` — Initial enrollment with OTP, mTLS, or GSSAPI authentication
- `/simplereenroll` — Re-enrollment with mTLS client certificate
- `/fullcmc` — Full CMC enrollment/management (RFC 5272) via synta-cmc
- `/serverkeygen` — Server-side key generation with encrypted private key return
- `/csrattrs` — CSR attributes template for clients

### Extended Protocols
- **CMP v3** (RFC 9810) — Certificate Management Protocol at `/.well-known/cmp`
  supporting ir/cr/kur/rr/genm message types with signature and MAC protection
- **CMS-EST** (RFC 8295) — CMS-wrapped EST endpoints at `/.well-known/est/cms/`
  for message-level security when TLS is terminated by a proxy
- **STAR** (RFC 8739) — Short-Term Automatic Renewal certificates with background
  renewal task and order lifecycle management
- **EST-coaps** (RFC 9148) — CoAP transport for constrained networks (kipuka-coap)

### CA Backends
- **Local signing** — PEM-based CA keys with synta-certificate
- **PKCS#11 HSM** — Entrust nShield, Utimaco CryptoServer, Kryoptic (dev), Thales Luna 7
- **Dogtag PKI** — Full RHCS integration with enrollment, revocation, KRA key
  generation, CMC passthrough, and multi-CA connection pooling

### Authentication
- **mTLS** — Client certificate with chain validation, OCSP + CRL revocation checking
- **OTP** — One-time password with argon2id hashing, rate limiting, lifecycle management
- **GSSAPI/Kerberos** — SPNEGO authentication via libgssapi with configurable
  cryptographic verification

### Security
- **Audit** — 22 event types across 7 categories with database and file backends
- **Multi-CA HA** — Active-passive, round-robin, weighted, and latency-based failover
- **Key generation** — RSA, ECDSA, ML-DSA (FIPS 204), ML-KEM (FIPS 203), composite hybrids
- **OCSP client** — Response caching, CRL fallback
- **ResolvedSigningKey** — Unified PEM/HSM key abstraction

### Database
- SQLite, PostgreSQL, MariaDB via sqlx Any driver
- Sequential migrations with three-backend parity

## EST Protocol Development

- Every EST endpoint MUST return the correct Content-Type per RFC 7030:
  - `/cacerts`: `application/pkcs7-mime; smime-type=certs-only`
  - `/simpleenroll`, `/simplereenroll`: `application/pkcs7-mime; smime-type=certs-only`
  - `/fullcmc`: `application/pkcs7-mime; smime-type=CMC-response`
  - `/serverkeygen`: `multipart/mixed` (cert + encrypted key)
  - `/csrattrs`: `application/csrattrs`
  - CMP endpoint (`/.well-known/cmp`): `application/pkixcmp`
  - CMS-EST endpoints (`/.well-known/est/cms/*`): `application/pkcs7-mime`
  - STAR endpoints (`/.well-known/est/*/star`): `application/json`
- Base64 encoding: EST uses base64 (not base64url). Do not confuse with ACME/JOSE.
- EST errors MUST return HTTP status codes per RFC 7030 S4.2.3, not JSON error bodies.
- The `/cacerts` endpoint MUST be accessible without authentication.
- The `/simplereenroll` endpoint MUST require mTLS (the existing client certificate).

## Testing with curl and openssl

```bash
# Fetch CA certs (no auth required)
curl -k https://localhost:8443/.well-known/est/cacerts | base64 -d | openssl pkcs7 -inform DER -print_certs

# Enroll with OTP (HTTP Basic auth, username is ignored per RFC 7030)
curl -k -X POST \
  -u ":otp-token-here" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @csr.b64 \
  https://localhost:8443/.well-known/est/simpleenroll

# Re-enroll with client cert
curl -k -X POST \
  --cert client.pem --key client.key \
  -H "Content-Type: application/pkcs10" \
  --data-binary @csr.b64 \
  https://localhost:8443/.well-known/est/simplereenroll

# Enroll with label
curl -k -X POST \
  -u ":otp-token-here" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @csr.b64 \
  https://localhost:8443/.well-known/est/server-tls/simpleenroll

# CMP initialization request (binary DER)
curl -k -X POST \
  -H "Content-Type: application/pkixcmp" \
  --data-binary @ir.der \
  https://localhost:8443/.well-known/cmp

# STAR order creation
curl -k -X POST \
  -u ":otp-token-here" \
  -H "Content-Type: application/json" \
  --data '{"csr": "...", "lifetime": 86400, "not_before": "2026-01-01T00:00:00Z"}' \
  https://localhost:8443/.well-known/est/server-tls/star

# TLS handshake inspection
openssl s_client -connect localhost:8443 -showcerts
```

## HSM Development Setup

Use Kryoptic as the development HSM. It provides a PKCS#11 interface backed by
a software token, suitable for integration testing without physical hardware.

```bash
# Install Kryoptic (Fedora/RHEL)
dnf install kryoptic

# Initialize a test token
kryoptic-init --token-label kipuka-dev --pin 1234 --so-pin 12345678

# Generate a test CA key in the token
pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
  --login --pin 1234 \
  --keypairgen --key-type EC:secp384r1 \
  --label "dev-ca-key" --id 01

# Point kipuka at the token
# [hsm]
# library = "/usr/lib/libkryoptic_pkcs11.so"
# token_label = "kipuka-dev"
# pin = "1234"
```

For CI, set `KIPUKA_HSM_PIN=1234` and use `pin_env = "KIPUKA_HSM_PIN"`.

## Dogtag Development Setup

To use Dogtag PKI as a CA backend, configure the `[dogtag]` section in your config:

```toml
[dogtag]
ca_url = "https://pki.example.com:8443"
profile_id = "caServerCert"
agent_cert = "/path/to/agent.pem"
agent_key = "/path/to/agent-key.pem"
ca_cert = "/path/to/ca-cert.pem"
```

The kipuka-dogtag crate handles connection pooling, health-based routing, and
profile caching. For development, use a containerized Dogtag instance.

## Database Migrations

Migrations live in `migrations/{sqlite,postgres,mariadb}/` with sequential numbering.

Rules:
- Every migration MUST have a counterpart for all three backends.
- Use `0001_`, `0002_`, etc. numbering (zero-padded to 4 digits).
- Test migrations against all three backends before merging.
- Never modify a migration that has been released. Add a new one instead.
- The `cargo run -- migrate` command auto-detects the backend from the DB URL.

To test migrations locally:

```bash
# SQLite (simplest, use for local dev)
cargo run -- migrate --config kipuka.toml

# PostgreSQL (use podman for local testing)
podman run -d --name kipuka-pg -e POSTGRES_PASSWORD=dev -p 5432:5432 postgres:16
cargo run -- migrate --config kipuka-pg.toml

# MariaDB
podman run -d --name kipuka-maria -e MARIADB_ROOT_PASSWORD=dev -p 3306:3306 mariadb:11
cargo run -- migrate --config kipuka-maria.toml
```

## Security Invariants

These invariants MUST hold at all times. Violations are bugs.

1. OTP tokens are NEVER stored in plaintext. Only the hash is persisted.
2. CA private keys loaded from files are zeroized from memory after loading into the TLS/signing context.
3. All authentication failures MUST produce an audit event before returning the HTTP response.
4. `/serverkeygen` private keys MUST be encrypted before storage or transmission.
5. Timing-safe comparison MUST be used for all secret comparisons (OTP, bearer tokens).
6. Certificate serial numbers MUST be generated from a CSPRNG with at least 64 bits of entropy (CA/B Forum BR S7.1).
