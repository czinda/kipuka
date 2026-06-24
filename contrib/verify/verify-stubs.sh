#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Stub Endpoint Behavior Verification
# ═══════════════════════════════════════════════════════════════════════
# Tests that unimplemented / stub endpoints respond gracefully without
# crashing the server.  Each endpoint's current behavior is documented
# as the expected response.
#
# These endpoints are coded with placeholder logic and return error
# responses because the underlying crypto/CA operations are not yet
# wired up.  The key property we test is: the server returns a valid
# HTTP response and stays alive afterward.
#
# Prerequisites:
#   - podman compose up (running in another terminal)
#   - contrib/local-dev/setup-ca.sh was run (certs generated)
#
# Usage:
#   ./contrib/verify/verify-stubs.sh
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

# check_responds verifies the server returns *any* valid HTTP response
# (i.e., the process did not crash or hang).
check_responds() {
    local name="$1" http_code="$2"
    if [[ "$http_code" =~ ^[0-9]+$ ]] && [[ "$http_code" -gt 0 ]]; then
        echo "  PASS (responds $http_code)"
        ((passed++))
    else
        echo "  FAIL (no response — server may have crashed)"
        ((failed++))
    fi
}

# check_alive confirms the server is still healthy after a stub test.
check_alive() {
    local code
    code=$(curl -sk "${ADMIN_AUTH[@]}" \
      -o /dev/null -w "%{http_code}" "$ADMIN_URL/health")
    if [[ "$code" == "200" ]]; then
        return 0
    else
        echo "  WARNING: server health check failed after previous test (got $code)"
        return 1
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Stub Endpoint Behavior Verification"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── Prepare a test CSR for endpoints that expect one ────────────────
openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$TMPDIR/kipuka-stub-test.key" \
  -out "$TMPDIR/kipuka-stub-test.csr" \
  -subj "/CN=stub-test.kipuka.test/O=Kipuka Stub Test" 2>/dev/null
openssl req -in "$TMPDIR/kipuka-stub-test.csr" -outform DER \
  -out "$TMPDIR/kipuka-stub-test.der" 2>/dev/null
B64_CSR=$(base64 < "$TMPDIR/kipuka-stub-test.der")

# Generate an OTP so we can test auth-required stubs.
OTP_STUB_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "stub-test-client"}' \
  -w "\n%{http_code}")
OTP_STUB=$(echo "$OTP_STUB_RESP" | sed '$d' | \
  python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)

echo "── Core EST Stubs ────────────────────────────────────────────"

# ═════════════════════════════════════════════════════════════════════
# Test 1: POST /serverkeygen with auth + CSR
#
# Current behavior: The handler checks that serverkeygen is enabled,
# then attempts key generation which is not implemented.  Returns 500
# with "server-side key generation not yet implemented" or 403 if
# serverkeygen is disabled in config.
# ═════════════════════════════════════════════════════════════════════
echo "1. POST /serverkeygen (OTP auth + CSR)"
if [[ -n "$OTP_STUB" ]]; then
    code=$(curl -sk --cacert "$CA_CERT" \
      -u "stub-test-client:${OTP_STUB}" \
      -X POST "$EST_URL/serverkeygen" \
      -H "Content-Type: application/pkcs10" \
      -d "$B64_CSR" \
      -o /dev/null -w "%{http_code}")
    check_responds "serverkeygen-otp" "$code"
    echo "    Current behavior: $code"
else
    # Fall back to admin Bearer auth.
    code=$(curl -sk "${ADMIN_AUTH[@]}" \
      -X POST "$EST_URL/serverkeygen" \
      -H "Content-Type: application/pkcs10" \
      -d "$B64_CSR" \
      -o /dev/null -w "%{http_code}")
    check_responds "serverkeygen-bearer" "$code"
    echo "    Current behavior: $code"
fi
check_alive

# ═════════════════════════════════════════════════════════════════════
# Test 2: POST /fullcmc with auth + CMC body
#
# Current behavior: Requires mTLS with id-kp-cmcRA EKU.  With OTP or
# Bearer auth, returns 401 (auth type mismatch).  With no auth returns
# 401.  The CMC processing itself is not implemented (returns 500 if
# all auth checks pass).
# ═════════════════════════════════════════════════════════════════════
echo "2. POST /fullcmc (Bearer auth + dummy CMC body)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$EST_URL/fullcmc" \
  -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "fullcmc-bearer" "$code"
echo "    Current behavior: $code"
check_alive

echo ""
echo "── CMS-Wrapped EST Stubs (RFC 8295) ──────────────────────────"

# ═════════════════════════════════════════════════════════════════════
# Test 3: POST /cms/simpleenroll
#
# Current behavior: CMS-EST endpoints verify the CMS SignedData
# wrapper.  With a dummy body that is not valid CMS, returns 400 or
# 500.  If CMS-EST is disabled, returns 500 with "CMS-EST is not
# enabled".
# ═════════════════════════════════════════════════════════════════════
echo "3. POST /.well-known/est/cms/simpleenroll"
code=$(curl -sk \
  -X POST "https://localhost:9443/.well-known/est/cms/simpleenroll" \
  -H "Content-Type: application/pkcs7-mime" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cms-simpleenroll" "$code"
echo "    Current behavior: $code"
check_alive

# ═════════════════════════════════════════════════════════════════════
# Test 4: POST /cms/simplereenroll
# ═════════════════════════════════════════════════════════════════════
echo "4. POST /.well-known/est/cms/simplereenroll"
code=$(curl -sk \
  -X POST "https://localhost:9443/.well-known/est/cms/simplereenroll" \
  -H "Content-Type: application/pkcs7-mime" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cms-simplereenroll" "$code"
echo "    Current behavior: $code"
check_alive

# ═════════════════════════════════════════════════════════════════════
# Test 5: POST /cms/serverkeygen
# ═════════════════════════════════════════════════════════════════════
echo "5. POST /.well-known/est/cms/serverkeygen"
code=$(curl -sk \
  -X POST "https://localhost:9443/.well-known/est/cms/serverkeygen" \
  -H "Content-Type: application/pkcs7-mime" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cms-serverkeygen" "$code"
echo "    Current behavior: $code"
check_alive

# ═════════════════════════════════════════════════════════════════════
# Test 6: POST /cms/fullcmc
# ═════════════════════════════════════════════════════════════════════
echo "6. POST /.well-known/est/cms/fullcmc"
code=$(curl -sk \
  -X POST "https://localhost:9443/.well-known/est/cms/fullcmc" \
  -H "Content-Type: application/pkcs7-mime" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cms-fullcmc" "$code"
echo "    Current behavior: $code"
check_alive

echo ""
echo "── CMP Stub (RFC 9810) ───────────────────────────────────────"

# ═════════════════════════════════════════════════════════════════════
# Test 7: POST /.well-known/cmp
#
# Current behavior: If CMP is disabled in config, returns 500 with
# "CMP is not enabled".  If enabled, the ASN.1 parser is not
# implemented, returning 500 "CMP PKIMessage parsing not yet
# implemented".
# ═════════════════════════════════════════════════════════════════════
echo "7. POST /.well-known/cmp (dummy PKIMessage)"
code=$(curl -sk \
  -X POST "https://localhost:9443/.well-known/cmp" \
  -H "Content-Type: application/pkixcmp" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cmp" "$code"
echo "    Current behavior: $code"
check_alive

echo ""
echo "── Edge Cases ────────────────────────────────────────────────"

# ═════════════════════════════════════════════════════════════════════
# Test 8: POST /serverkeygen with empty body
# ═════════════════════════════════════════════════════════════════════
echo "8. POST /serverkeygen with empty body"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$EST_URL/serverkeygen" \
  -H "Content-Type: application/pkcs10" \
  -d "" \
  -o /dev/null -w "%{http_code}")
check_responds "serverkeygen-empty" "$code"
echo "    Current behavior: $code"
check_alive

# ═════════════════════════════════════════════════════════════════════
# Test 9: POST /fullcmc with empty body
# ═════════════════════════════════════════════════════════════════════
echo "9. POST /fullcmc with empty body"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$EST_URL/fullcmc" \
  -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
  -d "" \
  -o /dev/null -w "%{http_code}")
check_responds "fullcmc-empty" "$code"
echo "    Current behavior: $code"
check_alive

# ═════════════════════════════════════════════════════════════════════
# Test 10: POST /.well-known/cmp with empty body
# ═════════════════════════════════════════════════════════════════════
echo "10. POST /.well-known/cmp with empty body"
code=$(curl -sk \
  -X POST "https://localhost:9443/.well-known/cmp" \
  -H "Content-Type: application/pkixcmp" \
  -d "" \
  -o /dev/null -w "%{http_code}")
check_responds "cmp-empty" "$code"
echo "    Current behavior: $code"
check_alive

echo ""

# ── Final server liveness check ─────────────────────────────────────
echo "── Final Liveness Check ──────────────────────────────────────"
echo "11. GET /admin/health (server survived all stub tests)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health")
if [[ "$code" == "200" ]]; then
    echo "  PASS — server is still alive after all stub tests"
    ((passed++))
else
    echo "  FAIL — server health check returned $code"
    ((failed++))
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " Stub Results: ${passed} passed, ${failed} failed"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Current behavior summary:"
echo "  serverkeygen  — returns error (key gen not implemented)"
echo "  fullcmc       — returns error (CMC processing not implemented)"
echo "  cms/*         — returns error (CMS-EST not implemented)"
echo "  cmp           — returns error (CMP parsing not implemented)"
echo "  All endpoints respond without crashing the server."

exit $failed
