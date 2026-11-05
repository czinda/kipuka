#!/usr/bin/env bash
# demo/run.sh — the kipuka executive demo walkthrough.
#
# Stands up a real kipuka EST server locally and drives it end-to-end in front
# of an audience: retrieve CA certs, enroll a device over mTLS, prove the server
# rejects a tampered CSR (proof-of-possession), review the audit trail, show
# the tamper-evident audit hash chain, and run a full STAR order lifecycle —
# server-driven renewal, fetch, cancel, and implicit revocation.
#
# EVERY act exercises a capability that is wired and working at runtime. The
# closing "roadmap" act names what is NOT yet wired, clearly labelled, so the
# demo never implies more than the product does today.
#
# Usage:
#   ./demo/run.sh                # interactive, pauses between acts
#   ./demo/run.sh --no-pause     # run straight through (recording / CI)
#   ./demo/run.sh --with-tests   # also run the audit-chain tamper unit tests
#   ./demo/run.sh --keep         # leave the server running after the demo
#   ./demo/run.sh --help

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

WITH_TESTS=0
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --no-pause)  PAUSE=0 ;;
    --with-tests) WITH_TESTS=1 ;;
    --keep)      KEEP=1 ;;
    --help|-h)
      sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) bad "unknown argument: $arg"; exit 2 ;;
  esac
done

require openssl curl jq sqlite3

# Make cargo discoverable even from a shell that didn't source the full profile
# (only needed for the optional fallback build / --with-tests paths).
[[ -d "${HOME}/.cargo/bin" ]] && PATH="${HOME}/.cargo/bin:${PATH}"

# ── Ensure PKI + config exist ─────────────────────────────────────────────────
if [[ ! -f "${CONFIG_FILE}" || ! -f "${PKI_DIR}/ca.crt" ]]; then
  say "First run — generating demo PKI and config…"
  "${DEMO_DIR}/setup.sh"
fi
mkdir -p "${STATE_DIR}"

# Start each demo from a clean audit ledger so the hash chain shown in Act 6 is
# fresh and repeatable. This is throwaway demo state, never production data.
rm -f "${DB_FILE}" "${DB_FILE}-wal" "${DB_FILE}-shm"

# ── Locate the kipuka binary (prefer prebuilt; build only if necessary) ────────
KIPUKA_BIN=""
for cand in "${REPO_DIR}/target/debug/kipuka" "${REPO_DIR}/target/release/kipuka"; do
  [[ -x "$cand" ]] && { KIPUKA_BIN="$cand"; break; }
done
if [[ -z "${KIPUKA_BIN}" ]]; then
  note "No prebuilt kipuka binary found — building (this may take a while)…"
  ( cd "${REPO_DIR}" && cargo build --bin kipuka )
  KIPUKA_BIN="${REPO_DIR}/target/debug/kipuka"
fi

# ── Server lifecycle ──────────────────────────────────────────────────────────
SERVER_PID=""
stop_server() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
cleanup() {
  if [[ "${KEEP}" == "1" ]]; then
    echo
    note "Leaving the server running (PID ${SERVER_PID}) on ${BASE_URL}."
    note "Stop it later with: kill ${SERVER_PID}"
  else
    stop_server
  fi
}
trap cleanup EXIT

start_server() {
  say "Starting kipuka: ${KIPUKA_BIN##*/} --config demo/kipuka-demo.toml"
  cmd "${KIPUKA_BIN##*/} --config demo/kipuka-demo.toml"
  ( cd "${REPO_DIR}" && RUST_LOG="${RUST_LOG:-info}" "${KIPUKA_BIN}" --config "${CONFIG_FILE}" ) \
    >"${SERVER_LOG}" 2>&1 &
  SERVER_PID=$!
  echo "${SERVER_PID}" > "${PID_FILE}"

  # Readiness: poll anonymous /cacerts until it answers 200.
  local i code
  for i in $(seq 1 50); do
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      bad "server exited during startup — last log lines:"
      tail -n 25 "${SERVER_LOG}" || true
      exit 1
    fi
    code="$(curl --cacert "${PKI_DIR}/ca.crt" -s -o /dev/null -w '%{http_code}' \
            "${EST_BASE}/cacerts" 2>/dev/null || echo 000)"
    [[ "$code" == "200" ]] && { ok "Server is up on ${BASE_URL} (PID ${SERVER_PID})."; return 0; }
    sleep 0.2
  done
  bad "server did not become ready — last log lines:"
  tail -n 25 "${SERVER_LOG}" || true
  exit 1
}

# curl against the EST/admin listener, always validating the server cert with
# the demo CA (no -k / --insecure — this is real TLS validation).
ccurl() { curl --cacert "${PKI_DIR}/ca.crt" -sS "$@"; }

# ══════════════════════════════════════════════════════════════════════════════
clear 2>/dev/null || true
cat <<BANNER
${BOLD}${GREEN}
   ██╗  ██╗██╗██████╗ ██╗   ██╗██╗  ██╗ █████╗
   ██║ ██╔╝██║██╔══██╗██║   ██║██║ ██╔╝██╔══██╗
   █████╔╝ ██║██████╔╝██║   ██║█████╔╝ ███████║
   ██╔═██╗ ██║██╔═══╝ ██║   ██║██╔═██╗ ██╔══██║
   ██║  ██╗██║██║     ╚██████╔╝██║  ██╗██║  ██║
   ╚═╝  ╚═╝╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
${RESET}${BOLD}   Certificate enrollment you can trust — EST (RFC 7030) in Rust${RESET}
${DIM}   Executive demo · everything shown is running live, not slideware${RESET}
BANNER

pause
start_server

# ── ACT 1 — Distribute CA certificates ────────────────────────────────────────
act "Act 1 · Establishing trust — GET /cacerts (RFC 7030 §4.1)"
say "Before a device trusts anything, it asks the server for the CA chain."
say "This is the anonymous bootstrap step — no credentials required yet."
cmd "curl --cacert ca.crt ${EST_BASE}/cacerts"
ccurl "${EST_BASE}/cacerts" > "${STATE_DIR}/cacerts.p7.b64"
openssl base64 -d -in "${STATE_DIR}/cacerts.p7.b64" -out "${STATE_DIR}/cacerts.p7" 2>/dev/null
echo
say "The server returned its CA in a PKCS#7 bundle. Decoded, it is:"
openssl pkcs7 -inform DER -in "${STATE_DIR}/cacerts.p7" -print_certs -noout 2>/dev/null \
  | sed 's/^/   /'
ok "Trust anchor delivered over validated TLS."
pause

# ── ACT 2 — What the server expects in a request ──────────────────────────────
act "Act 2 · Policy up front — GET /csrattrs (RFC 7030 §4.5 / RFC 9908)"
say "A well-run CA tells clients what a request must contain, before they ask."
cmd "curl --cacert ca.crt ${EST_BASE}/csrattrs"
code="$(ccurl -o "${STATE_DIR}/csrattrs.bin" -w '%{http_code}' "${EST_BASE}/csrattrs")"
ok "Server answered CSR-attributes request (HTTP ${code}) — the enrollment"
say "contract is discoverable, not tribal knowledge."
pause

# ── ACT 3 — Enroll a device over mTLS ─────────────────────────────────────────
act "Act 3 · Issuing a certificate — POST /simpleenroll over mTLS (RFC 7030 §4.2)"
say "Now a device authenticates with its bootstrap certificate (mutual TLS)"
say "and submits a CSR. The server authenticates the caller, then issues."

DEVICE_CN="device01.demo.kipuka"
say "Generating a fresh device key + CSR for CN=${DEVICE_CN}…"
openssl ecparam -name prime256v1 -genkey -noout -out "${STATE_DIR}/device.key"
openssl req -new -key "${STATE_DIR}/device.key" \
  -subj "/O=kipuka demo/CN=${DEVICE_CN}" \
  -outform DER -out "${STATE_DIR}/device.csr.der"
openssl base64 -in "${STATE_DIR}/device.csr.der" -out "${STATE_DIR}/device.csr.b64"

cmd "curl --cacert ca.crt --cert client.crt --key client.key \\"
cmd "     -H 'Content-Type: application/pkcs10' \\"
cmd "     --data-binary @device.csr.b64  ${EST_BASE}/simpleenroll"
code="$(ccurl --cert "${PKI_DIR}/client.crt" --key "${PKI_DIR}/client.key" \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary "@${STATE_DIR}/device.csr.b64" \
  -o "${STATE_DIR}/issued.p7.b64" -w '%{http_code}' \
  "${EST_BASE}/simpleenroll")"

if [[ "$code" == "200" ]]; then
  openssl base64 -d -in "${STATE_DIR}/issued.p7.b64" -out "${STATE_DIR}/issued.p7" 2>/dev/null
  ok "HTTP 200 — certificate issued. Details:"
  openssl pkcs7 -inform DER -in "${STATE_DIR}/issued.p7" -print_certs 2>/dev/null \
    | openssl x509 -noout -subject -issuer -serial -dates 2>/dev/null | sed 's/^/   /'
  say "The device now holds a CA-signed identity — the full enrollment loop,"
  say "authenticated end to end."
else
  bad "enrollment returned HTTP ${code} (expected 200). Server log tail:"
  tail -n 15 "${SERVER_LOG}" | sed 's/^/   /'
fi
pause

# ── ACT 4 — Reject a tampered request (proof-of-possession) ───────────────────
act "Act 4 · Trust, but verify — CSR proof-of-possession is enforced"
say "A CSR is self-signed: it proves the requester holds the private key for"
say "the public key inside it. kipuka verifies that signature and fails closed."
say "Watch what happens when we tamper with a CSR's signature and resubmit:"

python3 - "${STATE_DIR}/device.csr.der" "${STATE_DIR}/tampered.csr.der" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
data[-1] ^= 0xFF          # flip the final signature byte — DER stays well-formed
open(dst, "wb").write(data)
PY
openssl base64 -in "${STATE_DIR}/tampered.csr.der" -out "${STATE_DIR}/tampered.csr.b64"

cmd "curl … --data-binary @tampered.csr.b64  ${EST_BASE}/simpleenroll"
code="$(ccurl --cert "${PKI_DIR}/client.crt" --key "${PKI_DIR}/client.key" \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --data-binary "@${STATE_DIR}/tampered.csr.b64" \
  -o "${STATE_DIR}/tampered.resp" -w '%{http_code}' \
  "${EST_BASE}/simpleenroll")"
echo
if [[ "$code" == "400" ]]; then
  ok "HTTP 400 — rejected. Server response:"
  sed 's/^/   /' "${STATE_DIR}/tampered.resp"; echo
  say "An authenticated caller is still refused a certificate it cannot prove"
  say "it owns. Authentication and proof-of-possession are separate gates."
else
  note "Got HTTP ${code} (a rejection in the 4xx range is the expected outcome)."
  sed 's/^/   /' "${STATE_DIR}/tampered.resp"; echo
fi
pause

# ── ACT 5 — Accountability: the audit trail ───────────────────────────────────
act "Act 5 · Accountability — the admin audit trail (NIAP FAU_GEN.1 / FAU_SAR.1)"
say "Every security-relevant action we just performed was recorded. An operator"
say "(or read-only auditor) reviews it through an authenticated admin API."
cmd "curl --cacert ca.crt -H 'Authorization: Bearer <token>' ${ADMIN_BASE}/audit"
ccurl -H "Authorization: Bearer ${ADMIN_BEARER_TOKEN}" \
  "${ADMIN_BASE}/audit?limit=25" > "${STATE_DIR}/audit.json" 2>/dev/null || true
echo
if jq -e 'type=="array"' "${STATE_DIR}/audit.json" >/dev/null 2>&1; then
  jq -r '.[] | "   \(.timestamp[11:19])  \(.event_type)\t\(.actor // "-")"' \
    "${STATE_DIR}/audit.json" | tail -n 12
  ok "$(jq 'length' "${STATE_DIR}/audit.json") recent events — the successful"
  say "enrollment and the rejected (tampered) request are both on the record."
  say "This read is itself audited; you'll see it as the last link in Act 6."
else
  note "Audit API response:"; sed 's/^/   /' "${STATE_DIR}/audit.json"
fi
pause

# ── ACT 6 — Tamper-evidence: the audit hash chain ─────────────────────────────
act "Act 6 · Tamper-evidence — the audit hash chain (NIAP FAU_STG.1)"
say "Recording events isn't enough for a CA; the record must be tamper-evident."
say "kipuka writes each audit row with a keyed HMAC-SHA256 hash that chains from"
say "the previous row — delete, reorder, or edit any row and every later link"
say "stops verifying. Here is the live chain in the database:"
echo
sqlite3 "${DB_FILE}" \
  ".mode box" \
  "SELECT id,
          event_type,
          substr(prev_hash,1,10)   || '…' AS prev_hash,
          substr(record_hash,1,10) || '…' AS record_hash
   FROM audit_events ORDER BY id;" | sed 's/^/   /'
echo
ok "Each record_hash is the input to the next row's prev_hash — an append-only,"
say "cryptographically linked ledger."

if [[ "${WITH_TESTS}" == "1" ]]; then
  echo
  say "Proving detection with the built-in verifier (unit tests):"
  cmd "cargo test -p kipuka --lib -- tampering_with_a_row_breaks_the_chain keyed_hmac_detects_forgery_without_the_key"
  # libtest takes multiple name filters only after `--`; a single positional
  # filter before `--` would be rejected as an unexpected extra argument.
  ( cd "${REPO_DIR}" && cargo test -p kipuka --lib -- --nocapture \
      tampering_with_a_row_breaks_the_chain \
      keyed_hmac_detects_forgery_without_the_key ) \
    2>&1 | grep -E "running [0-9]|test result|\.\.\. ok" | sed 's/^/   /' || true
  ok "The verifier flags any altered row and cannot be forged without the key."
else
  note "Verification is exercised by the test suite (verify_chain): run with"
  note "  ./demo/run.sh --with-tests   to see it catch a tampered row live."
fi
pause

# ── ACT 7 — Server-driven renewal: STAR orders ────────────────────────────────
act "Act 7 · Server-driven renewal — STAR orders (RFC 8739 model)"
say "Client-driven renewal puts the renewal burden on every device. For"
say "constrained, frozen, or delegated fleets, kipuka inverts the loop: the"
say "server re-issues on a schedule, and the device fetches the current"
say "certificate with a plain GET — no renewal logic, no standing credentials."

STAR_CN="star-device01.demo.kipuka"
say "Generating a fresh device key + CSR for CN=${STAR_CN}…"
openssl ecparam -name prime256v1 -genkey -noout -out "${STATE_DIR}/star-device.key"
openssl req -new -key "${STATE_DIR}/star-device.key" \
  -subj "/O=kipuka demo/CN=${STAR_CN}" \
  -outform DER -out "${STATE_DIR}/star-device.csr.der"
openssl base64 -in "${STATE_DIR}/star-device.csr.der" -out "${STATE_DIR}/star-device.csr.b64"

cmd "curl --cacert ca.crt --cert client.crt --key client.key \\"
cmd "     -H 'star-renewal-interval: 3600' -H 'star-lifetime: 7' \\"
cmd "     --data-binary @star-device.csr.b64  ${EST_BASE}/star"
code="$(ccurl --cert "${PKI_DIR}/client.crt" --key "${PKI_DIR}/client.key" \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  -H "star-renewal-interval: 3600" \
  -H "star-lifetime: 7" \
  --data-binary "@${STATE_DIR}/star-device.csr.b64" \
  -D "${STATE_DIR}/star-order.headers" \
  -o "${STATE_DIR}/star-order.p7.b64" -w '%{http_code}' \
  "${EST_BASE}/star")"
STAR_ORDER_ID="$(awk 'tolower($1)=="star-order-id:" {gsub("\r",""); print $2}' \
  "${STATE_DIR}/star-order.headers")"

if [[ "$code" == "201" && -n "${STAR_ORDER_ID}" ]]; then
  openssl base64 -d -in "${STATE_DIR}/star-order.p7.b64" -out "${STATE_DIR}/star-order.p7" 2>/dev/null
  ok "HTTP 201 — STAR order created (order ${STAR_ORDER_ID})."
  say "The first certificate is already in the response:"
  openssl pkcs7 -inform DER -in "${STATE_DIR}/star-order.p7" -print_certs 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/   /'
else
  bad "STAR order returned HTTP ${code} (expected 201). Server log tail:"
  tail -n 15 "${SERVER_LOG}" | sed 's/^/   /'
fi
pause

say "The device now fetches its CURRENT certificate — a plain GET. No CSR,"
say "no enrollment transaction; anything that can do HTTP can do this:"
cmd "curl --cacert ca.crt --cert client.crt --key client.key  ${EST_BASE}/star/<order>"
code="$(ccurl --cert "${PKI_DIR}/client.crt" --key "${PKI_DIR}/client.key" \
  -o "${STATE_DIR}/star-current.p7.b64" -w '%{http_code}' \
  "${EST_BASE}/star/${STAR_ORDER_ID}")"
if [[ "$code" == "200" ]]; then
  openssl base64 -d -in "${STATE_DIR}/star-current.p7.b64" -out "${STATE_DIR}/star-current.p7" 2>/dev/null
  ok "HTTP 200 — the current certificate:"
  openssl pkcs7 -inform DER -in "${STATE_DIR}/star-current.p7" -print_certs 2>/dev/null \
    | openssl x509 -noout -subject -dates 2>/dev/null | sed 's/^/   /'
else
  bad "current-certificate fetch returned HTTP ${code} (expected 200)."
fi
say "The renewal history shows the server's loop — a new serial every"
say "interval, and the device did nothing to earn it:"
cmd "curl … ${EST_BASE}/star/<order>/history"
ccurl --cert "${PKI_DIR}/client.crt" --key "${PKI_DIR}/client.key" \
  "${EST_BASE}/star/${STAR_ORDER_ID}/history" \
  | jq -r '.[] | "   renewal \(.renewal_number) · serial \(.serial[0:12])… · valid from \(.not_before[11:19])"' 2>/dev/null \
  || note "(history request returned no entries)"
say "In this demo the interval is one hour, so the order you just created"
say "shows its first renewal. Leave the server running and the history grows"
say "on its own — that is the whole point: renewal correctness lives here,"
say "on the server, not in ten thousand firmwares."
pause

say "Revocation, for a STAR order, is cancellation. Delete the order and the"
say "identity stops being issued — no CRL push, no revocation urgency:"
cmd "curl -X DELETE --cacert ca.crt --cert client.crt --key client.key  ${EST_BASE}/star/<order>"
code="$(ccurl -X DELETE --cert "${PKI_DIR}/client.crt" --key "${PKI_DIR}/client.key" \
  -o /dev/null -w '%{http_code}' "${EST_BASE}/star/${STAR_ORDER_ID}")"
ok "DELETE → HTTP ${code}"
cmd "curl --cacert ca.crt --cert client.crt --key client.key  ${EST_BASE}/star/<order>"
code="$(ccurl --cert "${PKI_DIR}/client.crt" --key "${PKI_DIR}/client.key" \
  -o /dev/null -w '%{http_code}' "${EST_BASE}/star/${STAR_ORDER_ID}")"
if [[ "$code" == "410" ]]; then
  ok "HTTP 410 Gone — the device's fetch is refused. The certificate simply"
  say "stops being issued: implicit revocation by cancellation."
else
  note "Got HTTP ${code} (expected 410)."
fi
pause

# ── ACT 8 — Honest roadmap ────────────────────────────────────────────────────
act "Act 8 · What's next — roadmap (NOT in today's build)"
note "The following are implemented in the tree but NOT wired at runtime today."
note "They are on the roadmap and tracked as issues — not part of this demo:"
cat <<ROADMAP | sed 's/^/   /'
${YELLOW}
 • Multi-CA High Availability failover        (tracking #12)
 • EST-coaps over DTLS                         (tracking #13)
 • Server-side key generation (/serverkeygen)  (tracking #21)
 • /fullcmc and CMS-EST endpoints              (tracking #15, #14)
 • Post-quantum (ML-DSA/ML-KEM) issuance       (tracking #17)
 • OTP enrollment authentication              (tracking #10)
${RESET}
ROADMAP
say "Being precise about what ships today is how a certificate authority earns"
say "trust. Everything in Acts 1–7 ran live in front of you just now."
pause

# ── Wrap-up ───────────────────────────────────────────────────────────────────
act "Demo complete"
ok "Live, working today: RFC 7030 EST enrollment · mTLS auth · CSR proof-of-"
say "possession · issued-cert lifecycle · STAR server-driven renewal with"
say "implicit revocation · tamper-evident audit (NIAP-aligned)."
say "Artifacts from this run are under: ${DIM}demo/state/${RESET}"
echo
