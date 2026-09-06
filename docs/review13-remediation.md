# Follow-up code review remediation

The 2026-09-05 review identified 13 regressions or unclosed issues in the initial remediation. This document records the subsequent corrections on `fix/review-38-findings`. No release, deployment or certification is implied.

| Review ID | Correction | Regression evidence |
|---|---|---|
| R01 | Tracker capacity never blocks unrelated valid credentials. Failed OTP identities are admitted to tracking only if internally provisioned with a usable token; unknown identities receive the same public failure. Existing targeted lockouts are retained. | Capacity unit tests and `auth_capacity_regression`: invented identities do not consume state, known identities lock out, valid credentials remain usable. |
| R02 | MAC-protected CMP revocation is rejected before mutation. | Independently MAC-protected revocation request is denied and inventory remains unchanged. |
| R03 | CMP signer validation checks validity, signing usage, verified issuer and configured revocation. Exact signer certificates revoked in local inventory are rejected independently of remote OCSP enablement. | Expired/wrong-usage signers rejected; successful self-revocation makes the same credential unusable. |
| R04 | Completed GSS contexts must carry the negotiated channel-bound flag before an authenticated identity is returned. | Negotiated-flag unit cases with the `gssapi` feature. Live Kerberos interoperability remains an environment test. |
| R05 | CMS routes reject global/per-label disconnected mode before signing. They do not bypass approval. | CMS disconnected-mode request produces no certificate. Deferred enrollment remains available through the ordinary EST workflow; CMS queueing is not implemented. |
| R06 | CMP request verification encodes the complete DER ProtectedPart SEQUENCE. | Independent signed request succeeds; legacy concatenated framing is rejected; independently MAC-protected request verifies before policy rejection. |
| R07 | Dedicated admin TLS derives client-certificate requirements from the admin method, independently of EST settings. | Actual OpenSSL-client/rustls-server handshake supplies the expected admin certificate when EST has client authentication disabled. |
| R08 | STAR completion is based on certificate coverage of the order lifetime, not an overlap-blind issuance count. Informational estimates include overlap, and premature completed orders are reopened during restore. | Simulated full-day renewal horizons at 0.1/0.5/0.9 overlap; durable legacy-order restoration regression. |
| R09 | MariaDB STAR policy storage is TEXT, including migration v5 for existing databases. Renewal inventory stores the short profile name rather than the serialized policy. | SQLite migration/restore and inventory profile checks; MariaDB DDL inspected, but no live MariaDB environment exercised. |
| R10 | STAR inventory, order progress and the certificate-issue audit event commit in one transaction before in-memory publication. Audit persistence/commit failures propagate and latch configured halt. | Initial issuance and real renewal worker fail at audit capacity without publishing/persisting progress; deferred-constraint commit failure rolls back audit and latches halt. |
| R11 | DTLS maintenance runs on an independent periodic timer with priority over a continuously readable UDP socket. | Real DTLS test drops a server flight while unrelated UDP traffic arrives every 5ms; handshake recovers and encrypted enrollment/replay tests succeed. |
| R12 | Dogtag recovered keys use the PKCS#8-specific exporter. | RSA and EC outputs are decoded with a strict PKCS#8 parser. No live Dogtag/KRA run. |
| R13 | CMP self-revocation queries `subject_dn`. | Successful signature-authenticated self-revocation against actual inventory. |

## Remaining support and validation boundaries

- At capacity occupied by 10,000 provisioned identities, the tracker retains existing counters/lockouts and validates additional credentials without allocating new records. Invented OTP usernames cannot fill that state. Deployments should still enforce ingress rate limits; bounded per-identity memory does not establish unlimited attack resistance.
- CMS disconnected operation fails explicitly; a CMS approval queue is not implemented.
- Live Kerberos, MariaDB/PostgreSQL, Dogtag/KRA and hardware HSM interoperability remain environment-dependent checks. Existing ignored tests are not counted as evidence for those integrations.
- The existing scoped RSA dependency exception, DTLS 1.2 limit, unsupported signed audit configuration and single-worker STAR deployment constraint remain as documented in the original remediation and support-boundaries documents.

## Aggregate validation

- `cargo test --workspace --all-features --locked --offline`: **420 passed, 0 failed, 62 ignored**, including doctests.
- `cargo clippy --workspace --all-features --all-targets --locked --offline -- -D warnings`: passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.

Validation used disposable build output and local synthetic certificates. No commits, pushes or deployment were performed.
