# kipuka executive demo — presenter talk-track

**Audience:** customer / prospect executives (security, platform, and risk owners).
**Duration:** ~10–12 minutes live; ~6 minutes with `--no-pause`.
**Goal:** show that kipuka issues certificates that can be *trusted* — the
enrollment is authenticated, requests are cryptographically proven, and every
action is recorded in a tamper-evident ledger — while being precise about what
ships today versus what is on the roadmap.

**Golden rule:** demo only what runs. If asked about a roadmap item, say
"that's on the roadmap, not in today's build" — do not imply otherwise. This
honesty is itself a selling point to a security buyer.

---

## Before the room

```bash
./demo/setup.sh            # once, ahead of time
# rehearse:
./demo/run.sh --no-pause --with-tests
```

Present with:

```bash
./demo/run.sh --with-tests   # pauses between acts; press Enter to advance
```

Have a second terminal ready if someone wants to poke at the running server
(`./demo/run.sh --keep` leaves it up on https://127.0.0.1:18443).

---

## Opening (30s)

> "Every device, workload, and service in a modern enterprise needs an
> identity — and that identity is a certificate. The hard part isn't making
> certificates; it's *issuing them safely at scale*: proving who's asking,
> proving they own what they're asking for, and being able to show an auditor
> exactly what happened. That's what kipuka does. Everything you're about to
> see is running live on this laptop — not slides."

---

## Act 1 · Establishing trust — `/cacerts` (60s)

**What the audience sees:** an anonymous request returns the CA certificate.

> "Before a device trusts our CA, it has to *get* our CA. This is the public
> bootstrap step — no credentials yet. Standard, interoperable: any RFC 7030
> client speaks this."

**Business point:** open standard → no vendor lock-in on the client side.

---

## Act 2 · Policy up front — `/csrattrs` (45s)

> "A well-run CA publishes what a request must contain *before* the client
> asks. That makes enrollment predictable and reduces failed requests — the
> rules are discoverable, not tribal knowledge."

**Business point:** operational maturity; fewer support tickets.

---

## Act 3 · Issuing a certificate over mTLS (90s)

**What the audience sees:** a device presents a client certificate (mutual TLS),
submits a CSR, and gets a signed certificate back — with real subject, serial,
and validity dates.

> "Now the device authenticates itself with mutual TLS and asks for a
> certificate. The server checks *who* is calling, then issues. That's the
> whole enrollment loop, authenticated end to end — the foundation for
> automated, hands-off certificate lifecycle."

**Business point:** automation-ready identity issuance; no human in the hot path.

---

## Act 4 · Trust, but verify — proof-of-possession (90s) — **the key moment**

**What the audience sees:** we tamper with the CSR's signature and resubmit. An
already-authenticated caller is still refused — **HTTP 400**.

> "Here's what separates a real CA from a rubber stamp. A certificate request
> is self-signed — it proves the requester actually holds the private key.
> Watch: I take a *valid, authenticated* request and corrupt its signature.
> The server rejects it. Authentication and proof-of-possession are two
> separate gates, and kipuka fails closed on both."

**Business point:** this is the control that stops an attacker from getting a
certificate for a key they don't own — directly relevant to any zero-trust or
compliance story.

---

## Act 5 · Accountability — the audit trail (60s)

> "Every security-relevant action we just took was recorded — the successful
> issuance and the rejected tampered request. An operator, or a read-only
> auditor with separate credentials, reviews it through an authenticated API.
> Note this review is itself audited — you'll see it as the final entry in a
> moment."

**Business point:** separation of duties (operator vs. read-only auditor) and
a complete record — what an auditor actually asks for.

---

## Act 6 · Tamper-evidence — the hash chain (90s) — **the differentiator**

**What the audience sees:** the audit rows in the database, each linked to the
previous by a keyed HMAC-SHA256 hash. With `--with-tests`, the verifier unit
tests run live and pass.

> "Recording events isn't enough for a certificate authority — the record has
> to be *tamper-evident*. Each audit entry carries a keyed hash that chains
> from the one before it. Delete a row, reorder rows, or edit a single field,
> and every later link stops verifying — and because the key is secret, an
> attacker can't recompute the chain to cover their tracks. Here's the live
> chain; and here's the built-in verifier catching exactly that."

**Honest caveat (own it):** the running server *writes* the chain on every
event; the *verification* is exercised by the test suite you just saw pass.
That's the correct, honest framing — don't claim the server re-verifies on read.

**Business point:** aligns with NIAP FAU_STG.1 (audit storage protection) — the
kind of assurance language that shortens security review.

---

## Act 7 · Server-driven renewal — STAR orders (2 min) — **the operational payoff**

**What the audience sees:** a full STAR order lifecycle against the live
server — order created (HTTP 201, first certificate in the response), the
current certificate fetched with a plain GET, the renewal history with its
serials, the order cancelled (HTTP 204), and the next fetch refused
(HTTP 410 Gone).

> "Everything so far puts the renewal burden on the client — fine for a RHEL
> host with certmonger, wrong for a sealed device that will never get a
> firmware update. STAR inverts the loop: the server owns the renewal schedule
> and re-issues on it; the device's entire job is a plain GET. No renewal
> logic in firmware, and no standing enrollment credentials on the device — a
> compromised device can read its own certificate and nothing else.
>
> And revocation becomes cancellation. Watch: delete the order — 204 — and the
> next fetch is 410 Gone. No CRL push, no revocation urgency: the identity
> simply stops being issued."

**Honest caveats (own them):** the demo interval is one hour (the configured
floor), so a fresh order shows its first renewal in history — say so, and note
that a running server accrues a new serial every interval on its own. The STAR
model is specified for ACME in RFC 8739; this is that model applied over EST,
implemented in kipuka — say "the STAR model over EST," not "STAR per RFC 8739."
And the fetch uses the bootstrap client's mTLS in this demo; on a constrained
fleet the fetch is the only authenticated thing the device does.

**Business point:** this is the answer to fleet-renewal cost — renewal
correctness lives in one place, the server, instead of in ten thousand
firmwares. It is also the 47-day-mandate answer for devices that cannot
participate in client-driven renewal.

---

## Act 8 · Roadmap — what's next (45s)

> "I want to be precise about what ships today versus what's coming. Everything
> in the last seven acts ran live in front of you. These items —" (gesture at the
> list) "— Multi-CA high availability, EST over constrained/IoT transports,
> post-quantum issuance, and others — are in development and tracked, but *not*
> in today's build. For a CA vendor, being exact about that line is how we earn
> your trust."

**Business point:** the roadmap shows ambition; the honesty shows integrity.
Both matter to a buyer betting their PKI on you.

---

## Close (30s)

> "So: standards-based enrollment, authenticated end to end, with
> proof-of-possession enforced and a tamper-evident audit trail — running, not
> promised. Where would certificate automation move the needle most for your
> team?"

---

## Q&A — anticipated questions

**"Is this production-ready?"**
> The enrollment, authentication, proof-of-possession, and audit capabilities
> you saw are implemented and exercised. High-availability, HSM-mode
> enforcement, and several transports are on the roadmap (issues #9–#26). We'd
> scope a pilot against your specific requirements.

**"Does it work with our HSM?"**
> kipuka integrates with PKCS#11 HSMs for CA key protection (Entrust, Utimaco,
> Thales, Kryoptic). Note: kipuka does not itself *assert* FIPS mode — that
> depends on a FIPS-validated token (tracking #18). Happy to go deeper offline.

**"What database does it use?"**
> SQLite, PostgreSQL, or MariaDB via a common driver. This demo uses SQLite for
> portability; production would typically be PostgreSQL.

**"Can the audit log be altered by an insider?"**
> The chain is keyed with a secret HMAC key held outside the config. Editing
> any row breaks verification and the key can't be recovered from the data, so
> silent tampering is detectable. The verifier you saw is what an auditor runs.

**"Post-quantum?"**
> The algorithm OIDs and CMS plumbing exist in the tree, but PQC *issuance* is
> not wired at runtime yet (tracking #17). On the roadmap, not in today's build.

**"Is this a Red Hat product?"**
> kipuka is an EST server built on the Synta ASN.1/X.509 library. Position per
> current program guidance — do not represent roadmap items as committed
> product features.
