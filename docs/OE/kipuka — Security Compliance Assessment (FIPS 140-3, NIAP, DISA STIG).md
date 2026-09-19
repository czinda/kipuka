# kipuka — Security Compliance Assessment

2026-09-18 · @Someone

> **Editor's note (2026-09-19):** verified against the assessed commit `adf5361` (now `main`). The original file:line citations were accurate for that commit and are left as written; the only correction is the admin-role count — kipuka's `AdminRole` enum defines **two** roles (operator, auditor), not three.

## Scope

This assessment covers kipuka 0.2.0 as published on the GitHub mirror [czinda/kipuka](https://github.com/czinda/kipuka) (commit `adf5361`, 15 Sep 2026; the canonical Codeberg repository is not reachable from this environment), the pinned [synta](https://github.com/czinda/synta) revision `1fbba09` that supplies its X.509, CMS, and PKCS#12 handling, and the public pages of kipuka.dev. The kipuka.dev site source was not reachable, so documentation findings come from the rendered site and from the `docs/` directory in the code repository.

| Framework | Version assessed against | kipuka scope |
| --- | --- | --- |
| FIPS 140-3 | CMVP program as of Sept 2026 | Every cryptographic operation in the EST, CMP, CMS-EST, CoAP/DTLS, admin, OTP, and Dogtag-client paths |
| Red Hat Enterprise Linux crypto libraries | OpenSSL 3.x FIPS provider on Red Hat Enterprise Linux 9 and 10 | Whether kipuka consumes the operating system's validated module |
| NIAP Protection Profile for Certification Authorities | v2.1 (PP 420); the repo and site map to "v2.0" | kipuka as an RA/enrollment component of a composite TOE with Red Hat Certificate System, or as a standalone issuing CA when configured with local keys |
| NIAP Protection Profile for Application Software | v1.4 | Full application |
| NIAP Functional Package for TLS | v1.1 (v2.x noted where it changes the answer) | EST and admin listeners, DTLS listener, Dogtag and OCSP clients, LDAP |
| DISA Application Security and Development STIG | Current release | Admin API and dashboard, audit, session, crypto, release process |
| DISA Red Hat Enterprise Linux STIG and Container Platform SRG | Red Hat Enterprise Linux 9 STIG; Container Platform SRG | Host, RPM, and image posture |

Evidence was taken from `Cargo.toml` and `Cargo.lock`, `src/tls/`, `src/config/`, `src/auth/`, `src/audit/`, `src/routes/admin/`, `crates/kipuka-coap/src/dtls.rs`, `crates/kipuka-hsm`, `crates/kipuka-otp`, `synta-certificate/src/crypto` and `openssl_backend`, `Containerfile`, `kipuka.spec`, `.github/workflows/ci.yml`, and the repo's own `docs/compliance/niap-ca-pp.md`, `docs/support-boundaries.md`, and remediation ledgers. Where this report disagrees with those documents or with kipuka.dev, the code is treated as authoritative.

## Executive summary

kipuka is considerably further along than hoike. Certificate signing, verification, CMS, PKCS#12, composite ML-DSA, and the DTLS listener already run through OpenSSL by way of synta's `openssl` backend; the RPM spec requires `openssl-libs`; the container is built on Red Hat's Hummingbird images; per-identity lockout, two admin roles (operator and auditor), a 22-event audit catalog with identity attribution, constant-time token comparison, configurable ciphersuites, and `cargo deny` are all in place. The remaining gaps are narrower but two of them sit on the main data plane.

| Framework | Verdict | Blocking gap |
| --- | --- | --- |
| FIPS 140-3 | Not achievable as built | The EST and admin HTTPS listeners terminate TLS in rustls on the `ring` provider, which has no FIPS variant; CSR/CMS digests, OTP hashing, HMAC for CMP MAC protection, and serial/OTP randomness come from RustCrypto `sha2`/`hmac` and `rand` |
| Red Hat Enterprise Linux crypto libraries | Mostly used | PKI operations and DTLS already go through `libcrypto`; the HTTPS data plane and the digest/HMAC/RNG calls do not |
| NIAP PP for Certification Authorities v2.1 | Strong mapping, several overclaims and one scoping problem | Both the repo and site map to "v2.0"; the site claims Argon2id/bcrypt OTP hashing and config keys that do not exist; the intro says kipuka is not a CA while the code issues certificates and generates CRLs from local keys |
| NIAP PP for Application Software v1.4 | Four open SFRs | FPT\_TUD (unsigned releases), FPT\_IDV (verify), FPT\_AEX (no hardened release profile asserted), FCS\_STO partially met via `secret.rs` sources |
| NIAP Functional Package for TLS | Server side largely met | Suite allow-list exists but defaults to provider defaults; DTLS and HTTPS use different stacks with different behaviors; client-side activities (Dogtag, OCSP, LDAP) untested |
| DISA Application Security and Development STIG | Roughly 12 open findings | Shared bearer tokens instead of individual admin accounts, no consent banner, no HTTP security headers, no re-authentication, audit trail not tamper-evident despite the site's claim, unsigned artifacts |

The findings that matter most:

1. **The HTTPS data plane is the FIPS gap.** Every EST, CMP, and admin request terminates in rustls with `ring`. Unlike hoike, this is not a wholesale crypto rewrite: the project already links OpenSSL for DTLS, Dogtag mTLS, and all PKI operations, so the fix is to terminate HTTPS the same way (OpenSSL via `tokio-openssl` or `hyper-openssl`) and retire rustls. The site's technology table still lists rustls as the TLS stack and should not.
2. **Digests, HMAC, and randomness bypass the module.** `sha2::Sha256` hashes CSRs for CMS auth and stores OTP tokens; `hmac` protects CMP messages; `rand::thread_rng` and `OsRng` produce serials and OTPs. All three have direct OpenSSL equivalents already linked into the binary.
3. **Admin authentication is two shared secrets.** `admin.bearer_token` and `auditor_bearer_token` are single tokens per role, so the audit trail records a role, not a person, unless mTLS DN allow-lists are used. That fails STIG individual-accountability requirements and weakens the FAU\_GEN.2 claim the site makes.
4. **kipuka.dev overstates the security posture.** "FIPS 140-3 via HSM", "Argon2id/bcrypt" OTP hashing, "tamper-evident" audit logs, "NIAP CA PP v2.0", RFC 9483 for EST-over-CoAP (it is RFC 9148), and RFC 8739 STAR conformance are all contradicted either by the code or by the repo's own `docs/support-boundaries.md`, which says plainly that none of those conformance claims are established. Federal buyers will read the site, not the support-boundaries file.
5. **Releases and images are unsigned**, and the site points at `quay.io/kipuka/kipuka:latest` with no verification path.

## FIPS 140-3 and Red Hat Enterprise Linux cryptographic libraries

kipuka already routes its PKI cryptography through the operating system's OpenSSL, dynamically linked (`openssl` 0.10 without `vendored`; synta's `openssl` feature via `native-ossl`; `Requires: openssl-libs` in the RPM spec). What has not been moved is the HTTPS transport and a handful of primitive calls. The table separates the two.

### Where each cryptographic operation runs today

| Operation | Implementation | Through the host module? | Evidence |
| --- | --- | --- | --- |
| Certificate and CSR signing, local keys (RSA, ECDSA, ML-DSA, composite) | synta `openssl_backend` → `libcrypto` | Yes; ML-DSA and composite only via the non-validated default provider | `synta-certificate/src/openssl_backend/{private_key,composite}.rs` |
| Certificate and CSR signing, HSM keys | `cryptoki` 0.12 over PKCS#11 | Depends on the HSM | `crates/kipuka-hsm` |
| Signature and chain verification (mTLS, CMS, CMP, CRL, OCSP) | synta `default_signature_verifier()` → OpenSSL | Yes | `synta-certificate/src/crypto/signature.rs:290` |
| CMS SignedData/EnvelopedData, PKCS#12, AES key wrap | synta `openssl_backend/{cms,pkcs12,symmetric,key_transport}.rs` | Yes | — |
| DTLS 1.2/1.3 for EST-over-CoAP | `openssl` `SslMethod::dtls()`, min DTLS 1.2 | Yes | `crates/kipuka-coap/src/dtls.rs:339` |
| Dogtag REST client mTLS, OCSP fetches, CLI | `reqwest` `native-tls` → OpenSSL | Yes | `crates/kipuka-dogtag`, `crates/kipuka-cli` |
| **EST and admin HTTPS termination** | `rustls` 0.23 with the **`ring`** provider | **No.** `ring` has no FIPS build; `aws-lc-rs` would, but is not what is configured | `Cargo.toml:` `rustls = { features = ["ring"] }`, `src/tls/mod.rs` |
| CSR/CMS digests for CMS authentication | RustCrypto `sha2` 0.11 | No | `src/auth/cms_auth.rs:742` |
| OTP token storage hash | RustCrypto `sha2` (unsalted SHA-256 of a 256-bit random token) | No; acceptable construction for a high-entropy token, wrong module | `crates/kipuka-otp/src/generate.rs:124`, `src/auth/otp.rs:246` |
| CMP MAC-based protection | RustCrypto `hmac` | No | `src/routes/cmp.rs:1379` |
| Serial numbers, OTP generation, CMP nonces | `rand::thread_rng` / `OsRng` (`getrandom`) | No; kernel entropy, not the module's DRBG | `src/ca/issue.rs:696`, `crates/kipuka-otp/src/generate.rs`, `src/routes/fullcmc.rs:399` |
| Server TLS certificate fingerprint for logs | RustCrypto `sha2` | Not security-relevant | `src/tls/mod.rs:275` |
| Admin bearer and OTP comparison | `subtle::ConstantTimeEq` | Not cryptographic | `src/routes/admin/mod.rs:171` |

### What this means

- The **validated-module story is one change away on the transport side**: replace rustls with OpenSSL termination for the axum listeners. `tokio-openssl` plus `hyper-util`'s server-auto builder (already a dependency) or `axum-server` with `tls-openssl` both work; `synta` and `kipuka-coap` already show the project can drive OpenSSL's `SslContext` correctly, and the DTLS code is a template for the version/ciphersuite/client-auth wiring. This also removes the second TLS stack from the binary, which the repo's own comment in `Cargo.toml` warns about.
- The **primitive calls are small, local edits**: `openssl::hash::hash(MessageDigest::sha256, …)` for the CMS and OTP digests, `openssl::sign::Signer` with `PKey::hmac` for CMP MACs, `openssl::rand::rand_bytes` for serials, OTPs, and nonces. Each site is one function.
- **ML-DSA and ML-KEM** ride on the OpenSSL 3.5 default provider (Red Hat Enterprise Linux 10.1) or a PKCS#11 token. The validated Red Hat Enterprise Linux FIPS provider is still 3.0.7-based and has no FIPS 203/204 algorithms, so a FIPS-validated ML-DSA signature is possible only with an HSM whose certificate lists `CKM_ML_DSA`; the HSM compatibility matrix already says every vendor except Kryoptic has that as "planned". The site's "FIPS 140-3 via HSM" bullet must be narrowed accordingly.
- **No FIPS-mode awareness exists.** Nothing checks `/proc/sys/crypto/fips_enabled` or `EVP_default_properties_is_fips_enabled`; software CA keys, unsalted SHA-256 OTP storage, and software ML-DSA would all run silently on a FIPS host.

### Concrete changes

| # | Change | Replaces | Notes |
| --- | --- | --- | --- |
| 1 | Terminate HTTPS with OpenSSL (`tokio-openssl` on the existing `hyper-util` auto builder), reusing `src/config/tls.rs` for versions, `ciphersuites`, and `client_auth`; delete `rustls`, `tokio-rustls`, `rustls-pemfile` | rustls + ring | Ciphersuites then also obey the host `FIPS` crypto policy; add the same explicit allow-list check the DTLS path should get |
| 2 | Route the four RustCrypto call sites to `openssl::hash`, `openssl::sign` (HMAC), and `openssl::rand`; drop `sha2`, `hmac`, `rand` from `src` and `kipuka-otp` | RustCrypto primitives | Keep `subtle` for comparisons |
| 3 | Salt OTP storage: HMAC-SHA-256 with a per-deployment key from `secret.rs`, or PBKDF2 for human-chosen secrets | Unsalted SHA-256 | Not a FIPS requirement for random tokens, but closes a database-disclosure risk and matches what the site already claims |
| 4 | `kipuka --check-fips` preflight and startup gate: report provider and mode, refuse `key_type` software keys, software ML-DSA, and the unsalted OTP hash format when FIPS mode is on | Nothing | Doubles as STIG and NIAP evidence |
| 5 | Make `secret.rs` sources (`env:`, `file:`, `keyring:`) mandatory for `bearer_token`, `auditor_bearer_token`, `hsm_pin`, `bind_password`, `cmp_mac_secrets`; refuse literal values | Literal secrets allowed in TOML | The mechanism exists; only the enforcement is missing |
| 6 | Assert the module at build and packaging time: `openssl-devel` from the Red Hat Enterprise Linux repositories, `rust-toolset`, Hummingbird or UBI runtime, and a `%check` in `kipuka.spec` that runs the KAT suite | Upstream `rust:1.97-slim`-style builder assumptions | The Hummingbird base already inherits FIPS mode from the host |

Effort: item 1 is two to three weeks including behavioral parity tests; items 2–6 are about a week between them.
