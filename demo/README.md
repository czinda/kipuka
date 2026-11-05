# kipuka executive demo

A self-contained, **live** demonstration of the kipuka EST (RFC 7030) enrollment
server. It stands up a real kipuka instance on `localhost`, issues a real
certificate over mutual TLS, proves the server rejects a tampered request, runs
a full STAR order lifecycle — server-driven renewal, plain-GET certificate
fetch, cancellation as implicit revocation — and shows the tamper-evident audit
ledger, then closes with an honestly-labeled roadmap of what is *not* yet in
the build.

Everything in Acts 1–7 runs against the actual server binary. Nothing is
mocked or faked.

## What it demonstrates (all working today)

| Act | Capability | Standard |
| --- | ---------- | -------- |
| 1 | CA distribution — `GET /cacerts` | RFC 7030 §4.1 |
| 2 | Discoverable enrollment policy — `GET /csrattrs` | RFC 7030 §4.5 / RFC 9908 |
| 3 | Certificate issuance over mTLS — `POST /simpleenroll` | RFC 7030 §4.2 |
| 4 | CSR proof-of-possession enforced (tampered CSR → HTTP 400) | RFC 2986 / RFC 7030 |
| 5 | Authenticated audit review — `GET /admin/audit` | NIAP FAU_GEN.1 / FAU_SAR.1 |
| 6 | Tamper-evident audit hash chain (+ verifier unit tests) | NIAP FAU_STG.1 |
| 7 | STAR order lifecycle: create (201 + first cert), fetch current cert (plain GET), renewal history, cancel (204), fetch refused (410 — implicit revocation) | RFC 8739 model over EST |

The **roadmap** act (8) names capabilities that exist in the tree but are **not
wired at runtime today** (Multi-CA HA, EST-coaps DTLS, server-side keygen,
`/fullcmc`, CMS-EST, PQC issuance, OTP auth). These are presented only as
roadmap, never demonstrated — see the repo's `CLAUDE.md`
status legend and tracking issues #9–#26.

## Prerequisites

- The kipuka repo, built at least once (`cargo build`). The demo prefers a
  prebuilt `target/debug/kipuka`; if none exists it will build one.
- Command-line tools: `openssl`, `curl`, `jq`, `sqlite3`, `python3`.
  (`cargo` is only needed for the optional `--with-tests` proof and the
  first-time build.)

All of these are standard on a developer laptop. The demo binds only to
`127.0.0.1:18443` and touches nothing outside `demo/`.

## Running it

```bash
./demo/setup.sh      # one-time: generate throwaway PKI + config
./demo/run.sh        # the narrated walkthrough (pauses between acts)
```

Useful flags for `run.sh`:

| Flag | Effect |
| ---- | ------ |
| `--no-pause` | Run start-to-finish without waiting (recording / CI). |
| `--with-tests` | Also run the audit-chain tamper **unit tests** as live proof. |
| `--keep` | Leave the server running after the demo (inspect it yourself). |

Tear down when finished:

```bash
./demo/cleanup.sh          # stop server, remove demo/state/
./demo/cleanup.sh --all    # also remove generated PKI + config
```

## Files

| File | Purpose |
| ---- | ------- |
| `lib.sh` | Shared paths, ports, colours, and the pause/narrate helpers. |
| `setup.sh` | Generates a throwaway EC P-256 PKI and `kipuka-demo.toml`. |
| `run.sh` | The seven-act walkthrough orchestrator. |
| `cleanup.sh` | Teardown. |
| `talk-track.md` | Presenter script: what to say, timings, and Q&A. |
| `pki/` | Generated demo certificates/keys (git-ignored, throwaway). |
| `state/` | Per-run artifacts: DB, server log, issued cert (git-ignored). |

## Honesty & scope (read before presenting)

This demo is deliberately restricted to capabilities that are **reachable and
exercised at runtime**. The design rule, taken from the project's `CLAUDE.md`:

> Do not describe a ⛔ (not-wired) item as working in commits, docs, or
> user-facing output until its issue closes.

Two specifics worth understanding so you can answer questions accurately:

1. **The live server does not self-verify the audit chain.** It *writes* the
   keyed hash chain on every event (you see it in Act 6). Verification is
   exercised by the `verify_chain` unit tests, which `--with-tests` runs live.
   Do not claim the running server re-verifies the ledger on read.

2. **The demo credentials are throwaway.** The audit integrity key and admin
   bearer token are non-secret demo values, supplied via environment variables
   (never plaintext in the config file) to model the product's real secret
   handling. Regenerated on every `setup.sh`.

## Security notes

- Nothing here is a real credential. The PKI is a self-signed throwaway root
  regenerated on demand; keys never leave `demo/pki/` and are chmod 600.
- `demo/pki/` and `demo/state/` are git-ignored — no keys or databases are
  ever committed.
- TLS validation is real: every `curl` validates the server certificate against
  the demo CA (`--cacert`), never `--insecure`.
