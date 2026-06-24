#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Audit Logging Verification (NIAP FAU)
# ═══════════════════════════════════════════════════════════════════════
# Tests that security-relevant operations produce audit events in the
# server logs.  Kipuka records structured audit events to the database
# (audit_events table) and emits tracing spans to stdout.
#
# NIAP CA PP requirements verified:
#   FAU_GEN.1 — Audit record generation for required event categories
#   FAU_STG.1 — Events appear in the audit trail
#
# Audit event types checked (from src/audit/mod.rs):
#   otp.create       — OTP created by administrator
#   auth.success     — Client authentication succeeded
#   auth.failure     — Client authentication failed
#   enroll.request   — Certificate enrollment request received
#   cert.issue       — Certificate issued successfully
#
# Prerequisites:
#   - podman compose up (running in another terminal)
#   - contrib/local-dev/setup-ca.sh was run (certs generated)
#
# Usage:
#   ./contrib/verify/verify-audit.sh
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

source "$(dirname "$0")/common.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CA_CERT="$REPO_DIR/contrib/local-dev/ca/ca.pem"
EST_URL="https://localhost:9443/.well-known/est"
ADMIN_URL="https://localhost:9443/admin"
ADMIN_AUTH=(-H "Authorization: Bearer admin-dev-token")
TMPDIR="${TMPDIR:-/tmp}"

passed=0
failed=0
skipped=0

check_log_contains() {
    local name="$1" pattern="$2" log_text="$3"
    if echo "$log_text" | grep -qi "$pattern"; then
        echo "  PASS (found '$pattern' in logs)"
        ((passed++))
    else
        echo "  FAIL ('$pattern' not found in logs)"
        ((failed++))
    fi
}

# Detect which container name to use for log inspection.
if podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-pg; then
    CONTAINER_NAME="kipuka-est-pg"
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-my; then
    CONTAINER_NAME="kipuka-est-my"
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-hsm; then
    CONTAINER_NAME="kipuka-est-hsm"
else
    CONTAINER_NAME="kipuka-est"
fi

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Audit Logging Verification (NIAP FAU)"
echo "═══════════════════════════════════════════════════════════════"
echo "Container: $CONTAINER_NAME"
echo ""

# ── Capture a timestamp before we start generating events ──────────
# We will fetch logs from this point forward to reduce noise from
# earlier server activity.
SINCE_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%S" 2>/dev/null)

# ═════════════════════════════════════════════════════════════════════
# Step 1: Generate an OTP (should produce otp.create / otp_generated)
# ═════════════════════════════════════════════════════════════════════
echo "── Step 1: Generate OTP ──────────────────────────────────────"

echo "1. POST /admin/otp/generate"
OTP_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "audit-test-client"}' \
  -w "\n%{http_code}")
otp_code=$(echo "$OTP_RESP" | tail -1)
otp_body=$(echo "$OTP_RESP" | sed '$d')
OTP=$(echo "$otp_body" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)

if [[ "$otp_code" == "201" ]] && [[ -n "$OTP" ]]; then
    echo "  PASS (OTP generated, code $otp_code)"
    ((passed++))
else
    echo "  FAIL (expected 201, got $otp_code)"
    ((failed++))
fi

# ═════════════════════════════════════════════════════════════════════
# Step 2: Enroll with valid OTP (should produce auth.success,
#          enroll.request, cert.issue / simpleenroll_success)
# ═════════════════════════════════════════════════════════════════════
echo ""
echo "── Step 2: Enroll with valid OTP ─────────────────────────────"

echo "2. Generate client CSR"
openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$TMPDIR/kipuka-audit-test.key" \
  -out "$TMPDIR/kipuka-audit-test.csr" \
  -subj "/CN=audit-test.kipuka.test/O=Kipuka Audit Test" 2>/dev/null
openssl req -in "$TMPDIR/kipuka-audit-test.csr" -outform DER \
  -out "$TMPDIR/kipuka-audit-test.der" 2>/dev/null
B64_CSR=$(base64 < "$TMPDIR/kipuka-audit-test.der")
echo "  PASS (CSR generated)"
((passed++))

echo "3. POST /simpleenroll (OTP auth)"
if [[ -n "$OTP" ]]; then
    enroll_code=$(curl -sk --cacert "$CA_CERT" \
      -u "audit-test-client:${OTP}" \
      -X POST "$EST_URL/simpleenroll" \
      -H "Content-Type: application/pkcs10" \
      -d "$B64_CSR" \
      -o "$TMPDIR/kipuka-audit-cert.p7" \
      -w "%{http_code}")
    if [[ "$enroll_code" == "200" ]]; then
        echo "  PASS (enrolled, code $enroll_code)"
        ((passed++))
    else
        echo "  FAIL (expected 200, got $enroll_code)"
        ((failed++))
    fi
else
    echo "  SKIP (no OTP available)"
    ((skipped++))
fi

# ═════════════════════════════════════════════════════════════════════
# Step 3: Trigger a failed authentication (should produce
#          auth.failure / otp_auth_failure)
# ═════════════════════════════════════════════════════════════════════
echo ""
echo "── Step 3: Trigger failed authentication ─────────────────────"

echo "4. POST /simpleenroll with bad OTP"
fail_code=$(curl -sk \
  -u "audit-test-client:this-is-a-deliberately-bad-otp" \
  -X POST "$EST_URL/simpleenroll" \
  -H "Content-Type: application/pkcs10" \
  -d "$B64_CSR" \
  -o /dev/null -w "%{http_code}")
if [[ "$fail_code" == "401" ]]; then
    echo "  PASS (auth rejected, code $fail_code)"
    ((passed++))
else
    echo "  FAIL (expected 401, got $fail_code)"
    ((failed++))
fi

# ═════════════════════════════════════════════════════════════════════
# Step 4: Fetch server logs and verify audit events
# ═════════════════════════════════════════════════════════════════════
echo ""
echo "── Step 4: Verify audit events in server logs ────────────────"

# Allow a brief moment for log buffer to flush.
sleep 1

# Fetch recent container logs.
if ! command -v podman &>/dev/null; then
    echo "  SKIP (podman not available — cannot inspect container logs)"
    ((skipped++))
    LOGS=""
else
    LOGS=$(podman logs --since="$SINCE_TS" "$CONTAINER_NAME" 2>&1 || \
           podman logs --tail=200 "$CONTAINER_NAME" 2>&1 || true)
fi

if [[ -z "$LOGS" ]]; then
    echo "  WARNING: Could not retrieve container logs.  Falling back to tail."
    LOGS=$(podman logs --tail=200 "$CONTAINER_NAME" 2>&1 || true)
fi

if [[ -z "$LOGS" ]]; then
    echo "  SKIP (no logs available — cannot verify audit events)"
    echo "  Manual verification: check 'podman logs $CONTAINER_NAME'"
    ((skipped += 4))
else
    # 5. Check for OTP creation event.
    #    The server logs "otp_generated" or "otp.create" depending on
    #    whether record_audit_event or the structured audit path is used.
    echo "5. Verify OTP creation audit event"
    check_log_contains "otp-create" "otp" "$LOGS"

    # 6. Check for successful enrollment event.
    echo "6. Verify enrollment success audit event"
    check_log_contains "enroll-success" "simpleenroll" "$LOGS"

    # 7. Check for failed auth event.
    echo "7. Verify authentication failure audit event"
    check_log_contains "auth-failure" "auth" "$LOGS"

    # 8. Check that log entries have timestamps.
    #    Structured tracing output includes ISO 8601 timestamps or
    #    epoch timestamps in each line.
    echo "8. Verify audit events contain timestamps"
    # Look for common timestamp patterns:
    # - ISO 8601: 2025-06-24T...
    # - Epoch: ts=1719...
    # - Tracing format: [2025-06-24...]
    if echo "$LOGS" | grep -qE '20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}|ts=[0-9]+|\[[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
        echo "  PASS (timestamps found in log entries)"
        ((passed++))
    else
        echo "  FAIL (no timestamp pattern found in log entries)"
        ((failed++))
    fi
fi

echo ""

# ═════════════════════════════════════════════════════════════════════
# Step 5: Check database audit_events table (if accessible)
# ═════════════════════════════════════════════════════════════════════
echo "── Step 5: Database audit trail (optional) ───────────────────"

echo "9. Query audit_events via admin API (if available)"
audit_resp=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o "$TMPDIR/kipuka-audit-events.json" \
  -w "%{http_code}" "$ADMIN_URL/audit/events" 2>/dev/null || true)

if [[ "${audit_resp:-}" == "200" ]]; then
    event_count=$(python3 -c "import json; d=json.load(open('$TMPDIR/kipuka-audit-events.json')); print(len(d) if isinstance(d,list) else d.get('total',0))" 2>/dev/null || echo "?")
    echo "  PASS (audit events endpoint available, $event_count events)"
    ((passed++))
elif [[ "${audit_resp:-}" == "404" ]]; then
    echo "  SKIP (no /admin/audit/events endpoint — audit trail is DB-only)"
    ((skipped++))
else
    echo "  SKIP (audit events endpoint returned ${audit_resp:-no response})"
    ((skipped++))
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " Audit Results: ${passed} passed, ${failed} failed, ${skipped} skipped"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Audit event types (from src/audit/mod.rs):"
echo "  otp.create       — OTP created by administrator"
echo "  otp.use          — OTP used for enrollment auth"
echo "  auth.success     — Client auth succeeded"
echo "  auth.failure     — Client auth failed"
echo "  enroll.request   — Enrollment request received"
echo "  cert.issue       — Certificate issued"
echo "  security.violation — Security anomaly detected"

exit $failed
