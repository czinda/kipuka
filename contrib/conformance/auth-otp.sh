#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — OTP Authentication Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " OTP Enrollment Authentication"
echo "═══════════════════════════════════════════════════════════════"

section "OTP Generation (Admin API)"

echo "1. POST /admin/otp/generate — valid entity"
RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X POST "$ADMIN_URL/otp/generate" \
    -H "Content-Type: application/json" \
    -d '{"entity_id":"otp-test-1"}' \
    -w "\n%{http_code}")
CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_exact "OTP generate" "$CODE" "201"

echo "2. Response JSON has 'token' field"
TOKEN=$(json_field "$BODY" "token")
check_true "token field present" test -n "$TOKEN"

echo "3. Response JSON has 'entity_id' field"
ENTITY=$(json_field "$BODY" "entity_id")
check_true "entity_id field present" test -n "$ENTITY"

echo "4. Token has sufficient entropy (≥16 chars)"
TOKEN_LEN=${#TOKEN}
check_true "token length ≥16 ($TOKEN_LEN)" test "$TOKEN_LEN" -ge 16

echo "5. POST /admin/otp/generate — empty entity_id → 400"
CODE=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X POST "$ADMIN_URL/otp/generate" \
    -H "Content-Type: application/json" \
    -d '{"entity_id":""}' \
    -o /dev/null -w "%{http_code}")
check_exact "empty entity → 400" "$CODE" "400"

section "OTP Consumption via Enrollment"

KEY="$TMPDIR/otp-enroll.key"
CSR_DER="$TMPDIR/otp-enroll.der"
generate_csr_der "otp-test-1.kipuka.test" "$KEY" "$CSR_DER"
B64=$(base64 < "$CSR_DER")

echo "6. POST /simpleenroll with valid OTP → 200"
CODE=$(curl_est POST /simpleenroll /dev/null /dev/null \
    -u "otp-test-1:${TOKEN}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64")
check_exact "enroll with OTP" "$CODE" "200"

echo "7. Reuse consumed OTP → 401"
CODE=$(curl_est POST /simpleenroll /dev/null /dev/null \
    -u "otp-test-1:${TOKEN}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64")
check_exact "reused OTP rejected" "$CODE" "401"

section "OTP Revocation"

echo "8. Generate second OTP for revocation"
RESP2=$(curl -sk "${ADMIN_AUTH[@]}" \
    -X POST "$ADMIN_URL/otp/generate" \
    -H "Content-Type: application/json" \
    -d '{"entity_id":"otp-revoke-test"}' \
    -w "\n%{http_code}")
CODE2=$(echo "$RESP2" | tail -1)
BODY2=$(echo "$RESP2" | sed '$d')
check_exact "generate for revoke" "$CODE2" "201"
OTP2_TOKEN=$(json_field "$BODY2" "token")

# The generate endpoint doesn't return an ID — look it up via the list endpoint.
OTP2_ID=$(curl -sk "${ADMIN_AUTH[@]}" "$ADMIN_URL/otp" 2>/dev/null | \
    python3 -c "import json,sys; otps=json.load(sys.stdin); print(next((o['id'] for o in otps if o['entity_id']=='otp-revoke-test' and o['usage_count']==0), ''))" 2>/dev/null || true)

echo "9. DELETE /admin/otp/{id} → 204"
if [[ -n "$OTP2_ID" ]]; then
    CODE=$(curl -sk "${ADMIN_AUTH[@]}" -X DELETE -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp/$OTP2_ID")
    check_exact "revoke OTP" "$CODE" "204"
else
    skip_test "revoke OTP" "could not find OTP ID via list"
fi

echo "10. Enroll with revoked OTP → 401"
if [[ -n "$OTP2_TOKEN" ]]; then
    CODE=$(curl_est POST /simpleenroll /dev/null /dev/null \
        -u "otp-revoke-test:${OTP2_TOKEN}" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64")
    check_exact "revoked OTP rejected" "$CODE" "401"
else
    skip_test "revoked OTP rejected" "no token"
fi

section "OTP Listing"

echo "11. GET /admin/otp — returns JSON array"
RESP=$(curl -sk "${ADMIN_AUTH[@]}" -w "\n%{http_code}" "$ADMIN_URL/otp")
CODE=$(echo "$RESP" | tail -1)
check_exact "list OTPs" "$CODE" "200"

echo "12. DELETE /admin/otp/99999 (nonexistent) → 404"
CODE=$(curl -sk "${ADMIN_AUTH[@]}" -X DELETE -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp/99999")
check_exact "delete nonexistent" "$CODE" "404"

summary "OTP Authentication Conformance"
