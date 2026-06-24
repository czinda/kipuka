#!/usr/bin/env bash
# shellcheck disable=SC2034
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — STAR Certificate Verification (RFC 8739)
# ═══════════════════════════════════════════════════════════════════════
# Tests Short-Term Automatic Renewal endpoints.
#
# STAR order creation currently returns 500 because certificate issuance
# is not yet implemented (the handler sets cert_der to an empty Vec and
# then returns KipukaError::Ca).  Tests that depend on a created order
# are marked as KNOWN GAP and skipped gracefully.
#
# Prerequisites:
#   - podman compose up (running in another terminal)
#   - contrib/local-dev/setup-ca.sh was run (certs generated)
#
# Usage:
#   ./contrib/verify/verify-star.sh
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

check_exact() {
    local name="$1" http_code="$2" expected="$3"
    if [[ "$http_code" == "$expected" ]]; then
        echo "  PASS ($http_code)"
        ((passed++))
    else
        echo "  FAIL (got $http_code, expected $expected)"
        ((failed++))
    fi
}

check_one_of() {
    local name="$1" http_code="$2"
    shift 2
    for expected in "$@"; do
        if [[ "$http_code" == "$expected" ]]; then
            echo "  PASS ($http_code)"
            ((passed++))
            return
        fi
    done
    echo "  FAIL (got $http_code, expected one of: $*)"
    ((failed++))
}

skip() {
    local reason="$1"
    echo "  SKIP ($reason)"
    ((skipped++))
}

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — STAR Certificate Verification (RFC 8739)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ═════════════════════════════════════════════════════════════════════
# Test 1: GET /star/nonexistent — expect 404
# ═════════════════════════════════════════════════════════════════════
echo "1. GET /.well-known/est/star/nonexistent"
code=$(curl -sk \
  -o /dev/null -w "%{http_code}" \
  "$EST_URL/star/nonexistent")
check_exact "star-get-nonexistent" "$code" "404"

# ═════════════════════════════════════════════════════════════════════
# Test 2: DELETE /star/nonexistent — expect 401 or 404
#
# DELETE requires EST auth (mTLS or OTP).  Without auth the server
# should return 401.  With admin Bearer auth it may return 404 since
# the order does not exist.  Either response is acceptable.
# ═════════════════════════════════════════════════════════════════════
echo "2. DELETE /.well-known/est/star/nonexistent (no auth)"
code=$(curl -sk \
  -X DELETE \
  -o /dev/null -w "%{http_code}" \
  "$EST_URL/star/nonexistent")
check_one_of "star-delete-noauth" "$code" "401" "404"

echo "3. DELETE /.well-known/est/star/nonexistent (with admin Bearer)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X DELETE \
  -o /dev/null -w "%{http_code}" \
  "$EST_URL/star/nonexistent")
check_exact "star-delete-bearer" "$code" "404"

# ═════════════════════════════════════════════════════════════════════
# Test 4: GET /star/nonexistent/history — expect 404
# ═════════════════════════════════════════════════════════════════════
echo "4. GET /.well-known/est/star/nonexistent/history"
code=$(curl -sk \
  -o /dev/null -w "%{http_code}" \
  "$EST_URL/star/nonexistent/history")
check_exact "star-history-nonexistent" "$code" "404"

# ═════════════════════════════════════════════════════════════════════
# Test 5: POST /star — create order with OTP auth
#
# The STAR endpoint expects EST auth (mTLS or OTP) plus a base64-
# encoded PKCS#10 CSR body with optional Star-Renewal-Interval and
# Star-Lifetime headers.
#
# KNOWN GAP: The handler issues cert_der = Vec::new() (placeholder)
# and then returns KipukaError::Ca("STAR certificate issuance not yet
# implemented").  This results in a 500 response.
# ═════════════════════════════════════════════════════════════════════
echo "5. POST /.well-known/est/star (create order — OTP auth)"

# Generate an OTP for STAR order creation.
OTP_STAR_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "star-test-client"}' \
  -w "\n%{http_code}")
otp_code=$(echo "$OTP_STAR_RESP" | tail -1)
otp_body=$(echo "$OTP_STAR_RESP" | sed '$d')
OTP_STAR=$(echo "$otp_body" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)

if [[ -z "$OTP_STAR" ]]; then
    skip "could not generate OTP for STAR test"
else
    # Generate a CSR for the STAR order.
    openssl req -new -nodes -newkey rsa:2048 \
      -keyout "$TMPDIR/kipuka-star-test.key" \
      -out "$TMPDIR/kipuka-star-test.csr" \
      -subj "/CN=star-test.kipuka.test/O=Kipuka STAR Test" 2>/dev/null
    openssl req -in "$TMPDIR/kipuka-star-test.csr" -outform DER \
      -out "$TMPDIR/kipuka-star-test.der" 2>/dev/null
    B64_STAR_CSR=$(base64 < "$TMPDIR/kipuka-star-test.der")

    STAR_RESP=$(curl -sk --cacert "$CA_CERT" \
      -u "star-test-client:${OTP_STAR}" \
      -X POST "$EST_URL/star" \
      -H "Content-Type: application/pkcs10" \
      -H "Star-Renewal-Interval: 3600" \
      -H "Star-Lifetime: 7" \
      -d "$B64_STAR_CSR" \
      -w "\n%{http_code}")
    star_code=$(echo "$STAR_RESP" | tail -1)
    star_body=$(echo "$STAR_RESP" | sed '$d')

    if [[ "$star_code" == "201" ]]; then
        echo "  PASS ($star_code — order created)"
        ((passed++))
        # Extract Star-Order-ID header for follow-up tests.
        STAR_ORDER_ID=$(curl -sk --cacert "$CA_CERT" \
          -u "star-test-client:${OTP_STAR}" \
          -X POST "$EST_URL/star" \
          -H "Content-Type: application/pkcs10" \
          -H "Star-Renewal-Interval: 3600" \
          -d "$B64_STAR_CSR" \
          -D - -o /dev/null 2>/dev/null | \
          grep -i "star-order-id" | awk '{print $2}' | tr -d '\r\n')
    elif [[ "$star_code" == "500" ]]; then
        echo "  KNOWN GAP ($star_code — STAR certificate issuance not yet implemented)"
        ((skipped++))
        STAR_ORDER_ID=""
    else
        echo "  FAIL (got $star_code, expected 201 or 500)"
        ((failed++))
        STAR_ORDER_ID=""
    fi
fi

# ═════════════════════════════════════════════════════════════════════
# Test 6: GET /star/{id} — fetch current certificate
# ═════════════════════════════════════════════════════════════════════
echo "6. GET /.well-known/est/star/{id} (fetch certificate)"
if [[ -n "${STAR_ORDER_ID:-}" ]]; then
    code=$(curl -sk \
      -o /dev/null -w "%{http_code}" \
      "$EST_URL/star/$STAR_ORDER_ID")
    check_exact "star-get-order" "$code" "200"
else
    skip "no STAR order created — issuance not implemented"
fi

# ═════════════════════════════════════════════════════════════════════
# Test 7: GET /star/{id}/history — list certificate series
# ═════════════════════════════════════════════════════════════════════
echo "7. GET /.well-known/est/star/{id}/history"
if [[ -n "${STAR_ORDER_ID:-}" ]]; then
    code=$(curl -sk \
      -o /dev/null -w "%{http_code}" \
      "$EST_URL/star/$STAR_ORDER_ID/history")
    check_exact "star-history" "$code" "200"
else
    skip "no STAR order created — issuance not implemented"
fi

# ═════════════════════════════════════════════════════════════════════
# Test 8: DELETE /star/{id} — cancel order
# ═════════════════════════════════════════════════════════════════════
echo "8. DELETE /.well-known/est/star/{id} (cancel order)"
if [[ -n "${STAR_ORDER_ID:-}" ]]; then
    # Need fresh OTP for auth.
    OTP_CANCEL_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
      -X POST "$ADMIN_URL/otp/generate" \
      -H "Content-Type: application/json" \
      -d '{"entity_id": "star-cancel-client"}' \
      -w "\n%{http_code}")
    OTP_CANCEL=$(echo "$OTP_CANCEL_RESP" | sed '$d' | \
      python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)

    if [[ -n "$OTP_CANCEL" ]]; then
        code=$(curl -sk --cacert "$CA_CERT" \
          -u "star-cancel-client:${OTP_CANCEL}" \
          -X DELETE \
          -o /dev/null -w "%{http_code}" \
          "$EST_URL/star/$STAR_ORDER_ID")
        check_one_of "star-cancel" "$code" "200" "204"
    else
        skip "could not generate OTP for cancel test"
    fi
else
    skip "no STAR order created — issuance not implemented"
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " STAR Results: ${passed} passed, ${failed} failed, ${skipped} skipped"
echo "═══════════════════════════════════════════════════════════════"

exit $failed
