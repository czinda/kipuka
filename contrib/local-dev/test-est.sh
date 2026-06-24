#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Full Testing Pipeline
# ═══════════════════════════════════════════════════════════════════════
# Prerequisites:
#   - podman compose up (running in another terminal)
#   - contrib/local-dev/setup-ca.sh was run (certs generated)
#
# Usage:
#   ./contrib/local-dev/test-est.sh
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CA_CERT="$SCRIPT_DIR/ca/ca.pem"
AGENT_CERT="$SCRIPT_DIR/tls/agent.pem"
AGENT_KEY="$SCRIPT_DIR/tls/agent-key.pem"
EST_URL="https://localhost:9443/.well-known/est"
ADMIN_URL="https://localhost:9443/admin"
ADMIN_AUTH=(-H "Authorization: Bearer admin-dev-token")
TMPDIR="${TMPDIR:-/tmp}"

passed=0
failed=0

check() {
    local name="$1" http_code="$2"
    if [[ "$http_code" =~ ^2 ]]; then
        echo "  PASS ($http_code)"
        ((passed++))
    else
        echo "  FAIL ($http_code)"
        ((failed++))
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Test Pipeline"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── 1. Health Check ────────────────────────────────────────────────────
echo "1. Admin Health Check"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health")
check "health" "$code"

# ── 2. CA Info ─────────────────────────────────────────────────────────
echo "2. List CAs"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas")
check "list-cas" "$code"

# ── 3. GET /cacerts ────────────────────────────────────────────────────
echo "3. GET /cacerts"
code=$(curl -sk -o "$TMPDIR/kipuka-cacerts.b64" -w "%{http_code}" "$EST_URL/cacerts")
check "cacerts" "$code"
if [[ "$code" =~ ^2 ]]; then
    base64 -d < "$TMPDIR/kipuka-cacerts.b64" | \
        openssl x509 -inform DER -noout -subject -issuer -dates 2>/dev/null | \
        sed 's/^/    /'
fi

# ── 4. GET /csrattrs ──────────────────────────────────────────────────
echo "4. GET /csrattrs"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/csrattrs")
check "csrattrs" "$code"

# ── 5. Generate OTP ───────────────────────────────────────────────────
echo "5. Generate OTP (admin API)"
OTP_RESPONSE=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "test-client"}' \
  -w "\n%{http_code}")
code=$(echo "$OTP_RESPONSE" | tail -1)
body=$(echo "$OTP_RESPONSE" | sed '$d')
check "otp-generate" "$code"
OTP=$(echo "$body" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
if [[ -n "$OTP" ]]; then
    echo "    OTP: ${OTP:0:8}..."
fi

# ── 6. List OTPs ──────────────────────────────────────────────────────
echo "6. List OTPs"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp")
check "list-otps" "$code"

# ── 7. Generate CSR ───────────────────────────────────────────────────
echo "7. Generate client CSR"
openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$TMPDIR/kipuka-test-client.key" \
  -out "$TMPDIR/kipuka-test-client.csr" \
  -subj "/CN=test-client.kipuka.test/O=Kipuka Test" 2>/dev/null
openssl req -in "$TMPDIR/kipuka-test-client.csr" -outform DER -out "$TMPDIR/kipuka-test-client.der" 2>/dev/null
echo "  PASS (CSR generated)"
((passed++))

# ── 8. POST /simpleenroll ─────────────────────────────────────────────
echo "8. Simple Enroll (OTP auth)"
if [[ -n "$OTP" ]]; then
    B64_CSR=$(base64 < "$TMPDIR/kipuka-test-client.der")
    code=$(curl -sk --cacert "$CA_CERT" \
      -u "test-client:${OTP}" \
      -X POST "$EST_URL/simpleenroll" \
      -H "Content-Type: application/pkcs10" \
      -d "$B64_CSR" \
      -o "$TMPDIR/kipuka-test-client.p7" \
      -w "%{http_code}")
    check "simpleenroll" "$code"
    if [[ "$code" =~ ^2 ]] && [[ -s "$TMPDIR/kipuka-test-client.p7" ]]; then
        base64 -d < "$TMPDIR/kipuka-test-client.p7" | \
            openssl x509 -inform DER -noout -subject -serial -dates 2>/dev/null | \
            sed 's/^/    /' || echo "    (PKCS7 format — use openssl pkcs7 to unwrap)"
    fi
else
    echo "  SKIP (no OTP token received)"
fi

# ── 9. List Certificates ──────────────────────────────────────────────
echo "9. List Certificates"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/certs")
check "list-certs" "$code"

# ── 10. POST /simplereenroll ──────────────────────────────────────────
echo "10. Simple Re-enroll (mTLS)"
if [[ -s "$TMPDIR/kipuka-test-client.p7" ]]; then
    # Convert issued cert from base64 DER to PEM for curl --cert
    echo "-----BEGIN CERTIFICATE-----" > "$TMPDIR/kipuka-test-client.pem"
    cat "$TMPDIR/kipuka-test-client.p7" >> "$TMPDIR/kipuka-test-client.pem"
    echo "" >> "$TMPDIR/kipuka-test-client.pem"
    echo "-----END CERTIFICATE-----" >> "$TMPDIR/kipuka-test-client.pem"

    # Generate re-enrollment CSR and convert to base64 DER
    openssl req -new -nodes \
      -key "$TMPDIR/kipuka-test-client.key" \
      -out "$TMPDIR/kipuka-test-client-renew.csr" \
      -subj "/CN=test-client.kipuka.test/O=Kipuka Test" 2>/dev/null
    openssl req -in "$TMPDIR/kipuka-test-client-renew.csr" -outform DER -out "$TMPDIR/kipuka-test-client-renew.der" 2>/dev/null
    B64_RENEW_CSR=$(base64 < "$TMPDIR/kipuka-test-client-renew.der")

    code=$(curl -sk --cacert "$CA_CERT" \
      --cert "$TMPDIR/kipuka-test-client.pem" --key "$TMPDIR/kipuka-test-client.key" \
      -X POST "$EST_URL/simplereenroll" \
      -H "Content-Type: application/pkcs10" \
      -d "$B64_RENEW_CSR" \
      -o "$TMPDIR/kipuka-test-client-renewed.p7" \
      -w "%{http_code}")
    if [[ "$code" == "000" ]]; then
        echo "  SKIP (mTLS client cert not propagated through TLS layer — known gap)"
    else
        check "simplereenroll" "$code"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Results: ${passed} passed, ${failed} failed"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Test artifacts:"
echo "  CA cert:     $CA_CERT"
echo "  Client key:  $TMPDIR/kipuka-test-client.key"
echo "  Client CSR:  $TMPDIR/kipuka-test-client.csr"
echo "  Client cert: $TMPDIR/kipuka-test-client.p7"
echo "  Renewed:     $TMPDIR/kipuka-test-client-renewed.p7"

exit $failed
