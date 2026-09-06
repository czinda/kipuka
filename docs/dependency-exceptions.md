# Dependency review — 2026-09-05

Synta is pinned to commit `1fbba09dd92fdd37ac87426c0cac202c36bd55fe`.
The lockfile updates h2 to 0.4.16 (RUSTSEC-2026-0258), anyhow to 1.0.103,
and event-listener to 5.4.2, removing the reported fixed-version findings.

## Scoped exception: RSA 0.9.10 / RUSTSEC-2023-0071

Expires: **2026-10-05**. Reassess earlier on a SQLx/RSA dependency change.
The dependency is introduced by sqlx-mysql 0.8.6 (including SQLx macros).
Inspection of its `src/connection/auth.rs` shows only `RsaPublicKey`, public-key
parsing and OAEP encryption of the database authentication secret. It does not
perform RSA private-key signing or decryption. Kipuka's CA private-key operations
use OpenSSL/Synta or PKCS#11, not this crate. Consequently the reported private-key
timing operation is not reachable through this dependency path. The package is
still affected and must not be reused for private-key operations.

`contrib/security/audit.py` reports this exception explicitly, matches the exact
package version and refuses it after expiry. Other vulnerability advisories and
unsoundness warnings fail the job. This replaces blanket CI suppression.

## Remaining informational findings

`rustls-pemfile` is unmaintained and `spin` 0.9.8 is yanked in the current graph.
These remain visible in the audit output. Neither is treated as proof of a
remotely exploitable CA key issue. Migration to maintained PEM parsing and the
transitive RSA/spin replacement requires separate compatibility verification.
