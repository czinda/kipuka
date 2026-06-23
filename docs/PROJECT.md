# PROJECT.md -- kipuka-specific development rules

These rules extend the base CLAUDE.md and apply to all work in this project.

## EST Protocol Development

- Every EST endpoint MUST return the correct Content-Type per RFC 7030:
  - `/cacerts`: `application/pkcs7-mime; smime-type=certs-only`
  - `/simpleenroll`, `/simplereenroll`: `application/pkcs7-mime; smime-type=certs-only`
  - `/fullcmc`: `application/pkcs7-mime; smime-type=CMC-response`
  - `/serverkeygen`: `multipart/mixed` (cert + encrypted key)
  - `/csrattrs`: `application/csrattrs`
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
