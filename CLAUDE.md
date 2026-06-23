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
- Workspace with 4 internal crates: kipuka-est, kipuka-hsm, kipuka-otp, kipuka-util
- EST operations: /cacerts, /simpleenroll, /simplereenroll, /fullcmc, /serverkeygen, /csrattrs
- Multi-CA with HA failover (active-passive, round-robin, weighted)
- PKCS#11 HSM integration for CA key protection
- OTP and mTLS authentication for enrollment
- SQLite/PostgreSQL/MariaDB database backends

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
