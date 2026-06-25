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
- Container image: registry.kipuka.dev/heebus/kipuka (x86_64 latest, arm64 latest-arm64)
- API docs: kipuka.dev (GitLab Pages, cargo doc)
- CI/CD: GitLab CI on codeberg.org

## Compliance

### Core Protocol RFCs
- RFC 7030 (EST — Enrollment over Secure Transport)
- RFC 8951 (EST clarifications)
- RFC 5272 (CMC — Certificate Management over CMS) + RFC 6402 (CMC Updates)
- RFC 5273 (CMC Transport Protocols)
- RFC 5274 (CMC Compliance Requirements)
- RFC 5652 (CMS — Cryptographic Message Syntax)
- RFC 4211 (CRMF — Certificate Request Message Format)
- RFC 2986 (PKCS#10 — Certification Request Syntax)
- RFC 5280 (X.509 PKI Certificate and CRL Profile)
- draft-ietf-lamps-rfc5272bis (CMC next-gen, tracking)

### Algorithm and Security RFCs
- RFC 5753 (ECC Algorithms in CMS)
- RFC 5754 (SHA-2 Algorithms with CMS)
- RFC 5816 (ESSCertIDv2 for CMS)
- RFC 8603 (CNSA Suite Profile)
- RFC 9688/9882/9936 (Post-Quantum ML-DSA/ML-KEM in CMS)
- RFC 7906 (NSA CMS Key Management Attributes)

### Compliance Frameworks
- CA/B Forum Baseline Requirements
- NIAP CA Protection Profile v2.0
- FIPS 140-3 (via HSM or FIPS-validated crypto modules)

### synta-cmc Coverage (RFC 5272 implementation)
- PKIData/PKIResponse builders and parsers
- CMCStatus/CMCFailInfo with HTTP status mapping
- All 35+ CMC control OIDs (id-cmc arc)
- CNSA Suite profile validation (RFC 8603)
- ML-DSA digest pairing and ML-KEM wrap validation (RFC 9688)
- RFC 5274 compliance checks per agent type (EE/RA/CA)

## Conventions
- Match Akamu patterns: config TOML, multi-CA, axum routes, sqlx DB
- All crypto operations through Synta or PKCS#11
- Audit every security-relevant event (NIAP FAU_GEN.1)
- Never store plaintext OTP tokens or private keys
