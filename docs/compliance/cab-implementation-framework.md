# CA/B Forum Public Trust — Implementation Framework

**RHELBU-3179** | **BR Version:** 2.2.8 (June 2026) | **Target:** Production readiness mid-2027

This document is the engineering specification for making the kipuka + Dogtag
stack eligible for browser root trust stores. It consolidates gap analysis
across all compliance areas and organizes work by priority tier.

## Severity Classification

| Tier | Meaning | SLA |
|------|---------|-----|
| **T0** | Live bug or audit blocker — would fail CA/B audit today | Fix this week |
| **T1** | BR mandatory — required for compliance, not yet implemented | Fix this quarter |
| **T2** | Customer or operational — not BR-mandated but needed for production | Plan this quarter |
| **T3** | Defense in depth — good practice, low audit risk | Backlog |

---

## T0: Audit Blockers (Week 1)

### T0-1: Validity Period — Hardcoded 398 Days

**BR §6.3.2 / Ballot SC-081v3** — Live bug. Current maximum is **200 days**
(2026-03-15 through 2027-03-14).

**Locations (10):**

| File | Line | Code |
|------|------|------|
| `src/ca/issue.rs` | 314 | `max_validity_days: 398` (default profile) |
| `src/ca/issue.rs` | 823 | `const CAB_CURRENT_MAX_DAYS: u32 = 398` |
| `src/routes/simpleenroll.rs` | 289 | `.min(398)` |
| `src/routes/simplereenroll.rs` | 147 | `.min(398)` |
| `src/routes/serverkeygen.rs` | 267 | `.min(398)` |
| `src/routes/fullcmc.rs` | 272 | `.min(398)` |
| `src/routes/cms_est.rs` | 619 | `.min(398)` |
| `src/routes/cmp.rs` | 1038 | `.min(398)` |
| `src/routes/coap.rs` | 113 | `.min(398)` |
| `src/config/ca.rs` | 93–136 | Doc comments reference "398 days" |

**Fix:** Add `pub fn cab_forum_max_validity_days() -> u32` to `src/ca/issue.rs`:

```rust
pub fn cab_forum_max_validity_days() -> u32 {
    use chrono::{NaiveDate, Utc};
    let today = Utc::now().date_naive();
    let p200 = NaiveDate::from_ymd_opt(2026, 3, 15).unwrap();
    let p100 = NaiveDate::from_ymd_opt(2027, 3, 15).unwrap();
    let p47  = NaiveDate::from_ymd_opt(2029, 3, 15).unwrap();
    if today < p200 { 398 }
    else if today < p100 { 200 }
    else if today < p47 { 100 }
    else { 47 }
}
```

Replace all 10 occurrences. Route files use
`ca.validity_days.min(crate::ca::issue::cab_forum_max_validity_days())`.

**Tests:** Unit test with injected date; conformance test in
`contrib/conformance/cabf-sc081v3.sh`.

**Effort:** ~30 lines new + 10 substitutions.

---

### T0-2: Default EKU — Includes `clientAuth`

**Chrome Root Program v1.6 / BR §7.1.2.7.10** — Deadline June 15, 2026 (passed).

**Location:** `src/ca/issue.rs:316`

```rust
// BEFORE:
extended_key_usage: vec!["serverAuth".into(), "clientAuth".into()],

// AFTER:
extended_key_usage: vec!["serverAuth".into()],
```

**Effort:** 1 line.

---

### T0-3: AIA / CDP Extension Injection

**BR §7.1.2.7.7** — Certs without revocation info will **fail any CA/B audit**.

**Current state:** `ocsp_url` and `crl_url` exist in config (`src/config/ca.rs:113-116`)
and state (`src/state.rs:181-184`) but are **never injected** into issued
certificates.

**Insert at:** `src/ca/issue.rs:520` (after AKI injection, before must-staple).

Needs two new encoding functions:
- `encode_aia_extension(ocsp_url)` — AuthorityInfoAccessSyntax (OID 1.3.6.1.5.5.7.1.1)
- `encode_cdp_extension(crl_url)` — CRLDistributionPoints (OID 2.5.29.31)

Both use synta Encoder with IMPLICIT context tags for GeneralName [6]
(uniformResourceIdentifier).

**Effort:** ~80 lines (two ASN.1 encoding functions + integration).

---

### T0-4: Certificate Policies OID

**BR §7.1.2.7.9** — DV certs must include `certificatePolicies` with OID
`2.23.140.1.2.1` (domain-validated). Currently **not implemented**.

**Fix:** Add `certificate_policies: Vec<String>` to `EnrollmentProfile`, encode
and inject after EKU (line 488).

**Effort:** ~40 lines.

---

### T0-5: OU Field Prohibition

**BR §7.1.2.10.2** — `organizationalUnitName` prohibited in publicly-trusted
certs since September 2022.

**Fix:** Add `check_subject_dn_compliance()` to CSR validation. Parse RDNs,
reject OID 2.5.4.11.

**Effort:** ~30 lines.

---

## T1: BR Mandatory (Phases 2–3, Q3–Q4 2026)

### T1-1: CAA Record Checking (P2)

**BR §4.2.2.1 / RFC 8659** — Mandatory. Must query DNS CAA before issuance.

**New module:** `src/caa/` (6 files, ~1,350 lines)

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 150 | Public API, `CaaChecker` struct |
| `check.rs` | 350 | Authorization evaluation, RFC 8659 §5 |
| `dns.rs` | 400 | Resolver + tree-climbing algorithm |
| `cache.rs` | 250 | TTL-aware record caching |
| `config.rs` | 120 | `CaaConfig` with DNSSEC toggle |
| `error.rs` | 80 | CAA-specific error types |

**Key design decisions:**
- `hickory-resolver` crate with DNSSEC enabled (mandatory since March 2026)
- RFC 8659 tree-climbing: FQDN → parent → grandparent until CAA found
- RFC 8657 `accounturi` + `validationmethods` parameters (MUST by March 2027)
- Configurable `ca_identity` per CA section in TOML
- Insert after CSR validation, before signing

**Dependency:** `hickory-resolver = "0.24"` with `dnssec-ring` feature.

---

### T1-2: Pre-Issuance Linting (P3)

**BR §4.3.1.2 / Ballot SC-075** — Mandatory since March 2025.

**New module:** `src/lint/` (4 files, ~590 lines)

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 130 | `lint_certificate_der()` public API |
| `client.rs` | 100 | pkimetal HTTP client with retry |
| `config.rs` | 95 | `LintConfig` (URL, severity, fail-open) |
| `result.rs` | 85 | `LintResult`, `Finding`, `Severity` |

**Integration:** pkimetal container sidecar. kipuka calls
`POST /lintcert` with base64-encoded cert DER.

**Two integration points:**
1. Direct signing path (`src/ca/issue.rs`) — after `builder.sign()`, before return
2. Dogtag path (`src/routes/simpleenroll.rs`) — after cert received, before PKCS#7 wrap

**Fail-closed by default** (BR-compliant). Fail-open mode for development only.

**Rollout:** Observation → warning → production (3-week ramp).

---

### T1-3: Key Blocklisting (P4)

**BR §6.1.1.3 / Ballot SC-073** — Mandatory since November 2024.

**New module:** `src/blocked_keys/` (7 files, ~600 lines)

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 80 | Types: `BlockSource`, `CompromiseReason` |
| `checker.rs` | 200 | Orchestrator: DB → Debian → ROCA → Fermat → exponent |
| `debian_weak.rs` | 60 | CVE-2008-0166 dataset (embedded SHA-256 hashes) |
| `roca.rs` | 80 | CVE-2017-15361 fingerprint detection |
| `fermat.rs` | 60 | Close-prime factorization (100 rounds) |
| `weak_exponent.rs` | 40 | Reject e ∈ {1, 2, 3} |
| `admin.rs` | 80 | Admin API: POST/DELETE/GET `/admin/blocked-keys` |

**Database:** New `blocked_keys` table (SHA-256 of SPKI DER) with
cascade flagging to `certificates` table.

**Dependencies:** `num-bigint`, `num-integer` (Fermat/ROCA math).

---

### T1-4: MPIC Integration (P6)

**BR §3.2.2.9 / Ballot SC-067v3** — Already mandatory.

**New module:** `src/mpic/` (6 files, ~300 lines kipuka-side)

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 40 | Re-exports |
| `client.rs` | 100 | Open MPIC Coordinator HTTP client |
| `config.rs` | 60 | `MpicConfig` (URL, perspectives, quorum) |
| `types.rs` | 60 | Request/response structs (OpenAPI match) |
| `error.rs` | 30 | MPIC-specific errors |
| `validation.rs` | 60 | `check_caa()` pipeline integration |

**Infrastructure deployment** (separate from kipuka code):

| Region | Provider | RIR |
|--------|----------|-----|
| us-east (primary) | OpenShift | ARIN |
| us-west-2 | AWS | ARIN |
| eu-west | Azure | RIPE |
| ap-southeast-1 | GCP | APNIC |
| sa-east-1 | AWS | LACNIC |

**Current requirement:** 4 perspectives, quorum 3, 2 RIR regions.
December 2026 increases to 5 perspectives.

**Insert after:** Local CAA check (T1-1). MPIC corroborates, doesn't replace.

---

## T2: Customer Requirements (Phase 4, Q1 2027)

### T2-1: ACME Protocol (P5)

**RFC 8555** — Not BR-mandated, but essential at 47-day validity (March 2029).

**New workspace crate:** `crates/kipuka-acme/` (~9,000 lines, 3.5 person-months)

| Component | Files | Lines |
|-----------|-------|-------|
| Core types (account, order, authz, JWS/JWK) | 8 | 1,200 |
| Challenge validators (HTTP-01, DNS-01, TLS-ALPN-01) | 4 | 800 |
| Route handlers (12 ACME endpoints under `/acme/`) | 10 | 2,500 |
| Database schema (6 tables: accounts, orders, authz, challenges, nonces, EAB) | 3 | 400 |
| Config + state integration | 2 | 300 |
| Tests | 15 | 3,000 |

**Shared with EST:** CA backend, CAA checking, key blocklist, linting, audit.

**Phased delivery:**
1. MVP: Core ACME + HTTP-01 (3 weeks)
2. DNS-01 + wildcards (2 weeks)
3. TLS-ALPN-01 + EAB (2 weeks)
4. Testing + conformance (4 weeks)

---

## T3: Defense in Depth (Backlog)

| Gap | Location | Lines | Notes |
|-----|----------|-------|-------|
| SHA-1 CSR rejection (§7.1.3.2) | `src/ca/issue.rs` validate_csr | ~10 | Check OID 1.2.840.113549.1.1.5 |
| RSA exponent ≥ 65537 (§6.1.6) | `src/ca/issue.rs:718` | ~10 | Already in check_key_size |
| notBefore 48-hour cap (§7.1.2.7) | `src/ca/issue.rs:446` | ~5 | Sanity check only |
| CA hierarchy docs (P7) | docs only | 0 | Operational guidance |

---

## Dependency Graph

```
T0-1 (validity) ──────┐
T0-2 (EKU)      ──────┤
T0-3 (AIA/CDP)  ──────┼── All T0 fixes ── cargo test ── release v0.2.0
T0-4 (cert policies) ─┤
T0-5 (OU prohibition) ┘

T1-1 (CAA) ─────────────────┐
T1-2 (linting) ─────────────┤
T1-3 (key blocklist) ───────┼── T1 complete ── conformance suite update
T1-4 (MPIC) ── depends on ──┘      │
              T1-1 (CAA)            │
                                    ▼
                          T2-1 (ACME) ── reuses T1-1, T1-2, T1-3
```

---

## Timeline

```
Week 1 (Jul 2026)
  ████ T0: Fix all 5 audit blockers
  ████ Release v0.2.0

Weeks 2-5 (Jul–Aug 2026)
  ████████████████ T1-1: CAA checking (~1,350 lines)
  ████████████████ T1-3: Key blocklisting (~600 lines)

Weeks 3-5 (Aug 2026)
  ████████████ T1-2: Pre-issuance linting (~590 lines)

Weeks 6-9 (Sep–Oct 2026)
  ████████████████ T1-4: MPIC integration + infrastructure

Week 10 (Oct 2026)
  ████ Conformance suite v2 (all T1 features)
  ████ Release v0.3.0

Weeks 11-24 (Nov 2026–Feb 2027)
  ████████████████████████████ T2-1: ACME protocol (~9,000 lines)

Week 25 (Mar 2027)
  ████ Release v1.0.0 — public trust ready
  ████ WebTrust / ETSI audit engagement
```

---

## Total Scope

| Tier | New Lines | Files | Effort |
|------|-----------|-------|--------|
| T0 | ~180 | 12 modified | 1 week |
| T1 (CAA) | ~1,350 | 6 new + 4 modified | 4 weeks |
| T1 (linting) | ~590 | 4 new + 3 modified | 2 weeks |
| T1 (blocklist) | ~600 | 7 new + 3 modified | 3 weeks |
| T1 (MPIC) | ~300 | 6 new + 3 modified | 4 weeks (incl. infra) |
| T2 (ACME) | ~9,000 | 45 new + 5 modified | 14 weeks |
| T3 | ~25 | 1 modified | 1 day |
| **Total** | **~12,045** | **~68 new, ~20 modified** | **~28 weeks** |

---

## Component Ownership

All gaps are **kipuka-layer** enforcement. Dogtag provides:
- Certificate signing
- CT log submission
- CRL generation
- OCSP responder
- Key archival (KRA)
- Sub-CA management (P7 hierarchy)

kipuka is the **policy enforcement point** — it validates CSRs, checks CAA,
runs linting, queries MPIC, and blocks weak keys **before** forwarding to
Dogtag for signing.

---

Generated-by: Claude Code (claude.ai/code)
