# CLAUDE.md — kipuka EST Server

## Project Overview
kipuka is a Rust-based EST (RFC 7030) enrollment server. Built on the Synta ASN.1/X.509
library; architecture inspired by the Akamu ACME server. It targets Multi-CA High
Availability, PKCS#11 HSM support (Entrust, Utimaco, Kryoptic, Thales CSP/TCT), and NIAP
CA PP compliance — but see **Status legend** below: several of these are implemented in the
tree yet not wired into the running server today.

## Status legend
Capability claims in this file are tagged:
- ✅ **working** — reachable and exercised at runtime.
- 🟡 **partial** — implemented but limited, or a subset works.
- ⛔ **not wired** — code exists but is dead at runtime (routes commented out, `Option` field
  never set, feature gate undefined) or the claim is unimplemented.

A gap audit on 2026-09-15 filed tracking issues **#9–#26** for every ⛔/🟡 item. Do not
describe a ⛔ item as working in commits, docs, or user-facing output until its issue closes.

## Build & Test
- Build: `cargo build`
- Test: `cargo test`
- Check: `cargo check --all-features`
- Clippy: `cargo clippy --all-features -- -D warnings`
- Run: `cargo run -- --config kipuka.toml`

## Architecture
- Workspace with internal crates: kipuka-est, kipuka-hsm, kipuka-otp, kipuka-util, kipuka-dogtag, kipuka-coap (plus kipuka-cli, kipuka-keygen)
- ✅ EST operations: /cacerts, /simpleenroll, /simplereenroll, /csrattrs
- 🟡 /serverkeygen — reachable but signs the client CSR; does **not** generate a server-side key pair (RFC 7030 §4.4) — #21
- ⛔ /fullcmc — route commented out and `fullcmc` feature gate undefined (#15); CRMF requests unsupported even once enabled (#20)
- ⛔ CMS-EST endpoints (RFC 8295) /cms/* — router nest commented out; not reachable (#14)
- 🟡 CMP protocol (RFC 4210) — general-message (genm) returns empty GenRepContent; request/response ASN.1 partial (#19)
- ⛔ STAR certificates (RFC 8739) — fully implemented but StarManager/renewal task never started; routes return 503 (#11)
- 🟡 synta-cmc: RFC 5272 CMC (PKIData/PKIResponse builders/parsers) — PKCS#10 only; see #20/#24/#25
- ✅ CMS SignedData verification and EnvelopedData construction (RFC 5652)
- 🟡 Multi-CA HA failover — HaManager **is** wired (main.rs:328-331) and runs when `[ha].enabled`; failover strategies, circuit breaker, and the health loop are exercised by `tests/ha_failover.rs`/`tests/multi_ca_ha.rs`. Residual gaps (#12): `QueueAndRetry` unreachable (`Reject` hardcoded), no shipped `[ha]` example config; the HA-*disabled* `/admin/health` count that used to falsely report "healthy" is now fixed (merged: 7568d75, PR #31 / MR !6)
- ✅ PKCS#11 HSM integration for CA key protection (generic PKCS#11; vendors are library-path mappings, no FIPS-mode enforcement — #18)
- ✅ Dogtag PKI integration (CA enrollment, KRA key generation, CMC passthrough)
- ✅ mTLS and GSSAPI/Kerberos authentication; ⛔ OTP authentication — `OtpStore::placeholder()` wired instead of the real store; non-functional (#10)
- 🟡 Revocation/security: OCSP checking ✅; CRL fallback only on mTLS re-enroll path (#23); OCSP stapling built but not wired into TLS (#16); CSR self-signature/PoP **not** enforced (#9)
- ⛔ CoAP transport (RFC 7252/9148/9483): EST-coaps enrollment works over **plaintext** CoAP; DTLS not implemented (#13); serverkeygen over CoAP returns error (#22)
- ✅ SQLite/PostgreSQL/MariaDB database backends (via sqlx Any driver)
- Container image: quay.io/czinda/kipuka (x86_64 latest, arm64 latest-arm64)
- API docs: kipuka.dev (GitLab Pages, cargo doc)
- CI/CD: GitLab CI (see `.gitlab-ci.yml`)

### Not wired / partial today (see tracking issues #9–#26)
These are advertised elsewhere but do **not** serve traffic in the current build:
CSR proof-of-possession (#9), OTP auth (#10), STAR runtime (#11),
EST-coaps DTLS (#13), CMS-EST routes (#14), /fullcmc (#15), OCSP stapling (#16),
PQC issuance (#17), server-side keygen (#21/#22), CNSA validation (#24), RFC 9688 CMC
validation (#25).

## Compliance

Legend: ✅ working · 🟡 partial · ⛔ not wired at runtime (see #9–#26).

### Core Protocol RFCs
- ✅ RFC 7030 (EST — Enrollment over Secure Transport) — /cacerts, /simpleenroll, /simplereenroll, /csrattrs; ⛔ /fullcmc (#15), 🟡 /serverkeygen (#21)
- ✅ RFC 8951 (EST clarifications)
- ⛔ RFC 8295 (CMS-EST — EST with CMS) — routes disabled (#14)
- 🟡 RFC 4210 (CMP — Certificate Management Protocol) — genm empty, ASN.1 partial (#19)
- ⛔ RFC 8739 (STAR — Short-Term Automatic Renewal) — not wired at runtime (#11)
- 🟡 RFC 5272 (CMC — Certificate Management over CMS) + RFC 6402 (CMC Updates) — PKCS#10 only (#20)
- RFC 5273 (CMC Transport Protocols)
- RFC 5274 (CMC Compliance Requirements)
- RFC 5652 (CMS — Cryptographic Message Syntax)
- RFC 4211 (CRMF — Certificate Request Message Format)
- RFC 2986 (PKCS#10 — Certification Request Syntax)
- RFC 5280 (X.509 PKI Certificate and CRL Profile)
- draft-ietf-lamps-rfc5272bis (CMC next-gen, tracking)
- draft-ietf-lamps-est-renewal-info (EST Renewal Information)
- RFC 9908 (CSR Attributes Clarification — draft-ietf-lamps-rfc7030-csrattrs)

### CoAP/DTLS Transport RFCs
- ✅ RFC 7252 (CoAP — Constrained Application Protocol) — plaintext only
- ⛔ RFC 9483 (DTLS as Transport for EST) — DTLS not bound to the CoAP listener (#13)
- 🟡 RFC 9148 (EST-coaps — EST over CoAP) — enrollment/authz work over plaintext; DTLS missing (#13), serverkeygen missing (#22)
- ✅ RFC 7959 (CoAP Block-Wise Transfers)

### Algorithm and Security RFCs
- RFC 5753 (ECC Algorithms in CMS)
- RFC 5754 (SHA-2 Algorithms with CMS)
- RFC 5816 (ESSCertIDv2 for CMS)
- ⛔ RFC 8603 (CNSA Suite Profile) — OIDs defined; profile validation not implemented (#24)
- ⛔ RFC 9688/9882/9936 (Post-Quantum ML-DSA/ML-KEM in CMS) — signing unreachable (no provider advertises the mechanisms) and CMC pairing validation absent (#17, #25)
- 🟡 RFC 7906 (NSA CMS Key Management Attributes)

### Compliance Frameworks
- CA/B Forum Baseline Requirements (target)
- NIAP CA Protection Profile v2.0 — Tier 1 authz/RBAC/lockout landed (issues #3–#7, MR !1); gap work ongoing
- 🟡 FIPS 140-3 (via HSM) — depends on a FIPS-validated token; kipuka does not assert/enforce FIPS mode (#18)

### synta-cmc Coverage (RFC 5272 implementation)
- ✅ PKIData/PKIResponse builders and parsers
- ✅ CMCStatus/CMCFailInfo with HTTP status mapping
- 🟡 CMC control OIDs — the id-cmc arc is defined, but only a small subset (~5) is exercised in enrollment paths; the "35+" figure describes defined constants, not enforced controls
- ⛔ CNSA Suite profile validation (RFC 8603) — delegated to synta-x509-verification, not implemented (#24)
- ⛔ ML-DSA digest pairing and ML-KEM wrap validation (RFC 9688) — not implemented in the CMC module (#25)
- 🟡 RFC 5274 compliance checks per agent type (EE/RA/CA)

## Conventions
- Match Akamu patterns: config TOML, multi-CA, axum routes, sqlx DB
- All crypto operations through Synta or PKCS#11
- Audit every security-relevant event (NIAP FAU_GEN.1)
- Never store plaintext OTP tokens or private keys
