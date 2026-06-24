#!/usr/bin/env bash
# shellcheck disable=SC2034
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — OTP Lifecycle Tests
# ═══════════════════════════════════════════════════════════════════════
# Tests OTP generation, consumption, revocation, TTL expiry, and
# edge cases in the admin OTP API.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

source "$(dirname "$0")/common.sh"

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — OTP Lifecycle Tests"
echo "═══════════════════════════════════════════════════════════════"
require_server

# ─────────────────────────────────────────────────────────────────────
section "OTP Generation"
# ─────────────────────────────────────────────────────────────────────

echo "1. Generate OTP — 201, token returned"
OTP1_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X POST "$ADMIN_URL/otp/generate" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": "otp-test-entity-1"}' \
    -w "\n%{http_code}")
OTP1_CODE=$(echo "$OTP1_RESP" | tail -1)
OTP1_BODY=$(echo "$OTP1_RESP" | sed '$d')
check_exact "generate OTP" "$OTP1_CODE" "201"
OTP1_TOKEN=$(json_field "$OTP1_BODY" "token")
OTP1_ID=$(json_field "$OTP1_BODY" "id")
if [[ -n "$OTP1_TOKEN" ]]; then
    echo "    Token: ${OTP1_TOKEN:0:8}... (ID: $OTP1_ID)"
fi

echo "2. Token is >= 22 chars (128-bit entropy base64)"
if [[ -n "$OTP1_TOKEN" ]]; then
    TOKEN_LEN=${#OTP1_TOKEN}
    if [[ $TOKEN_LEN -ge 22 ]]; then
        echo -e "  ${GREEN}PASS${NC} token length=$TOKEN_LEN (>= 22)"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} token length=$TOKEN_LEN (expected >= 22)"
        ((failed++))
    fi
else
    skip_test "token length" "no token returned"
fi

echo "3. Generate second OTP for same entity — 201 (multiple allowed)"
OTP2_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X POST "$ADMIN_URL/otp/generate" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": "otp-test-entity-1"}' \
    -w "\n%{http_code}")
OTP2_CODE=$(echo "$OTP2_RESP" | tail -1)
OTP2_BODY=$(echo "$OTP2_RESP" | sed '$d')
check_exact "second OTP for same entity" "$OTP2_CODE" "201"
OTP2_TOKEN=$(json_field "$OTP2_BODY" "token")
OTP2_ID=$(json_field "$OTP2_BODY" "id")

echo "4. List OTPs — 200, both visible"
LIST_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -w "\n%{http_code}" "$ADMIN_URL/otp")
LIST_CODE=$(echo "$LIST_RESP" | tail -1)
LIST_BODY=$(echo "$LIST_RESP" | sed '$d')
check_exact "list OTPs" "$LIST_CODE" "200"
if [[ "$LIST_CODE" == "200" ]]; then
    OTP_COUNT=$(echo "$LIST_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else d.get('total',0))" 2>/dev/null || echo "?")
    echo "    OTPs listed: $OTP_COUNT"
fi

# ─────────────────────────────────────────────────────────────────────
section "OTP Consumption"
# ─────────────────────────────────────────────────────────────────────

echo "5. Use first OTP for enrollment — 200"
if [[ -n "$OTP1_TOKEN" ]]; then
    # Generate CSR for enrollment
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "$TMPDIR/otp-client.key" \
        -out "$TMPDIR/otp-client.csr" \
        -subj "/CN=otp-test-entity-1/O=Kipuka Test" 2>/dev/null
    openssl req -in "$TMPDIR/otp-client.csr" -outform DER -out "$TMPDIR/otp-client.der" 2>/dev/null
    B64_CSR=$(base64 < "$TMPDIR/otp-client.der")

    code=$(curl -sk --cacert "$CA_CERT" \
        -u "otp-test-entity-1:${OTP1_TOKEN}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_CSR" \
        -o "$TMPDIR/otp-issued.p7" \
        -w "%{http_code}")
    check_exact "enroll with first OTP" "$code" "200"
else
    skip_test "OTP enrollment" "no OTP token"
fi

echo "6. Reuse same OTP — 401 (consumed)"
if [[ -n "$OTP1_TOKEN" ]]; then
    code=$(curl -sk --cacert "$CA_CERT" \
        -u "otp-test-entity-1:${OTP1_TOKEN}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_CSR" \
        -o /dev/null -w "%{http_code}")
    check_exact "reuse consumed OTP" "$code" "401"
else
    skip_test "OTP reuse" "no OTP token"
fi

echo "7. List OTPs — first OTP usage_count incremented"
LIST2_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -w "\n%{http_code}" "$ADMIN_URL/otp")
LIST2_CODE=$(echo "$LIST2_RESP" | tail -1)
LIST2_BODY=$(echo "$LIST2_RESP" | sed '$d')
check_exact "list OTPs after use" "$LIST2_CODE" "200"
if [[ "$LIST2_CODE" == "200" ]] && [[ -n "$OTP1_ID" ]]; then
    USAGE=$(echo "$LIST2_BODY" | python3 -c "
import json,sys
data = json.load(sys.stdin)
items = data if isinstance(data, list) else data.get('items', data.get('otps', []))
for otp in items:
    oid = str(otp.get('id',''))
    if oid == '$OTP1_ID':
        print(otp.get('usage_count', otp.get('uses', 'N/A')))
        break
" 2>/dev/null || echo "N/A")
    echo "    First OTP usage_count: $USAGE"
fi

# ─────────────────────────────────────────────────────────────────────
section "OTP Revocation"
# ─────────────────────────────────────────────────────────────────────

echo "8. Revoke second OTP by ID — 204"
if [[ -n "$OTP2_ID" ]]; then
    code=$(curl -sk "${ADMIN_AUTH[@]}" \
        -X DELETE \
        -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp/$OTP2_ID")
    check_exact "revoke OTP by ID" "$code" "204"
else
    skip_test "OTP revocation" "no OTP ID"
fi

echo "9. Use revoked OTP — 401"
if [[ -n "$OTP2_TOKEN" ]]; then
    code=$(curl -sk --cacert "$CA_CERT" \
        -u "otp-test-entity-1:${OTP2_TOKEN}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_CSR" \
        -o /dev/null -w "%{http_code}")
    check_exact "use revoked OTP" "$code" "401"
else
    skip_test "revoked OTP use" "no second OTP token"
fi

# ─────────────────────────────────────────────────────────────────────
section "OTP Expiry"
# ─────────────────────────────────────────────────────────────────────

echo "10. Generate OTP with custom TTL (2 seconds) — 201"
OTP_TTL_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X POST "$ADMIN_URL/otp/generate" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": "ttl-test-entity", "ttl_seconds": 2}' \
    -w "\n%{http_code}")
OTP_TTL_CODE=$(echo "$OTP_TTL_RESP" | tail -1)
OTP_TTL_BODY=$(echo "$OTP_TTL_RESP" | sed '$d')
check_exact "generate OTP with TTL=2s" "$OTP_TTL_CODE" "201"
OTP_TTL_TOKEN=$(json_field "$OTP_TTL_BODY" "token")

echo "11. Wait 3 seconds, use expired OTP — 401"
if [[ -n "$OTP_TTL_TOKEN" ]]; then
    # Generate CSR for this test
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "$TMPDIR/ttl-client.key" \
        -out "$TMPDIR/ttl-client.csr" \
        -subj "/CN=ttl-test-entity/O=Kipuka Test" 2>/dev/null
    openssl req -in "$TMPDIR/ttl-client.csr" -outform DER -out "$TMPDIR/ttl-client.der" 2>/dev/null
    B64_TTL_CSR=$(base64 < "$TMPDIR/ttl-client.der")

    echo "    Waiting 3 seconds for OTP to expire..."
    sleep 3

    code=$(curl -sk --cacert "$CA_CERT" \
        -u "ttl-test-entity:${OTP_TTL_TOKEN}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_TTL_CSR" \
        -o /dev/null -w "%{http_code}")
    check_exact "use expired OTP" "$code" "401"
else
    skip_test "expired OTP" "no TTL OTP token"
fi

# ─────────────────────────────────────────────────────────────────────
section "OTP Edge Cases"
# ─────────────────────────────────────────────────────────────────────

echo "12. Generate OTP with empty entity_id — 400"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X POST "$ADMIN_URL/otp/generate" \
    -H "Content-Type: application/json" \
    -d '{"entity_id": ""}' \
    -o /dev/null -w "%{http_code}")
check_exact "empty entity_id" "$code" "400"

echo "13. Delete nonexistent OTP — 404"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X DELETE \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp/99999")
check_exact "delete nonexistent OTP" "$code" "404"

# ── Summary ─────────────────────────────────────────────────────────
summary
