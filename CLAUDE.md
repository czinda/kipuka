# CLAUDE.md — kipuka EST Server

## Project Overview
kipuka is a Rust-based EST (RFC 7030) enrollment server with Multi-CA High Availability,
HSM support (Entrust, Utimaco, Kryoptic, Thales CSP/TCT), and NIAP CA PP compliance.
Built on the Synta ASN.1/X.509 library. Architecture inspired by Akamu ACME server.

## Build & Test
- Build: `cargo build`
- Test: `cargo test`
- Check: `cargo check --all-features`
- Clippy: `cargo clippy --all-features -- -D warnings`
- Run: `cargo run -- --config kipuka.toml`

## Architecture
- Workspace with 6 internal crates: kipuka-est, kipuka-hsm, kipuka-otp, kipuka-util, kipuka-dogtag, kipuka-coap
- EST operations: /cacerts, /simpleenroll, /simplereenroll, /fullcmc, /serverkeygen, /csrattrs
- Multi-CA with HA failover (active-passive, round-robin, weighted, latency-based)
- PKCS#11 HSM integration for CA key protection
- Dogtag PKI integration (enrollment, revocation, KRA key generation)
- OTP, mTLS, and GSSAPI/Kerberos authentication for enrollment
- SQLite/PostgreSQL/MariaDB database backends (via sqlx Any driver)
- Container image: registry.heebh.st/heebus/kipuka (x86_64 latest, arm64 latest-arm64)
- API docs: kipuka.heebh.st (GitLab Pages, cargo doc)
- CI/CD: GitLab CI on gitlab.heebh.st and gitlab.cee.redhat.com

## Compliance
- RFC 7030 (EST), RFC 8951 (EST clarifications), RFC 5272 (CMC)
- CA/B Forum Baseline Requirements
- NIAP CA Protection Profile v2.0
- FIPS 140-3 (via HSM or FIPS-validated crypto modules)

## Conventions
- Match Akamu patterns: config TOML, multi-CA, axum routes, sqlx DB
- All crypto operations through Synta or PKCS#11
- Audit every security-relevant event (NIAP FAU_GEN.1)
- Never store plaintext OTP tokens or private keys
