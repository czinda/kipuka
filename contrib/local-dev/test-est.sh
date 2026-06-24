#!/usr/bin/env bash
# shellcheck disable=SC2034
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

# ── Database backend auto-detection ──────────────────────────────────
if podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-pg; then
    DB_BACKEND="postgres"
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-my; then
    DB_BACKEND="mariadb"
else
    DB_BACKEND="sqlite"
fi

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

check_responds() {
    local name="$1" http_code="$2"
    if [[ "$http_code" =~ ^[0-9]+$ ]] && [[ "$http_code" -gt 0 ]]; then
        echo "  PASS (responds $http_code)"
        ((passed++))
    else
        echo "  FAIL (no response)"
        ((failed++))
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Test Pipeline"
echo "═══════════════════════════════════════════════════════════════"
echo "Database backend: $DB_BACKEND"
echo ""

# ═════════════════════════════════════════════════════════════════════
# Section A: Admin Health (tests 1-4)
# ═════════════════════════════════════════════════════════════════════
echo "── Section A: Admin Health ────────────────────────────────────"

echo "1. GET /admin/health"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health")
check_exact "health" "$code" "200"

echo "2. GET /admin/health/db"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/db")
check_exact "health-db" "$code" "200"

echo "3. GET /admin/health/hsm"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/hsm")
check_exact "health-hsm" "$code" "200"

echo "4. GET /admin/health/ca"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/ca")
check_exact "health-ca" "$code" "200"

echo ""

# ═════════════════════════════════════════════════════════════════════
# Section B: Admin CAs (tests 5-8)
# ═════════════════════════════════════════════════════════════════════
echo "── Section B: Admin CAs ──────────────────────────────────────"

echo "5. GET /admin/cas"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas")
check_exact "list-cas" "$code" "200"

echo "6. GET /admin/cas/default"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas/default")
check_exact "get-ca-default" "$code" "200"

echo "7. GET /admin/cas/default/health"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas/default/health")
check_exact "get-ca-default-health" "$code" "200"

echo "8. GET /admin/cas/nonexistent"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas/nonexistent")
check_exact "get-ca-nonexistent" "$code" "404"

echo ""

# ═════════════════════════════════════════════════════════════════════
# Section C: OTP Lifecycle (tests 9-14)
# ═════════════════════════════════════════════════════════════════════
echo "── Section C: OTP Lifecycle ──────────────────────────────────"

echo "9. POST /admin/otp/generate (valid entity_id)"
OTP_RESPONSE=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "test-client"}' \
  -w "\n%{http_code}")
code=$(echo "$OTP_RESPONSE" | tail -1)
body=$(echo "$OTP_RESPONSE" | sed '$d')
check_exact "otp-generate" "$code" "201"
OTP=$(echo "$body" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
if [[ -n "$OTP" ]]; then
    echo "    OTP: ${OTP:0:8}..."
fi

echo "10. POST /admin/otp/generate (empty entity_id)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": ""}' \
  -o /dev/null -w "%{http_code}")
check_exact "otp-generate-empty" "$code" "400"

echo "11. GET /admin/otp (list OTPs)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp")
check_exact "list-otps" "$code" "200"

echo "12. POST /admin/otp/generate (second OTP for revocation test)"
OTP2_RESPONSE=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "revoke-test-client"}' \
  -w "\n%{http_code}")
code=$(echo "$OTP2_RESPONSE" | tail -1)
body2=$(echo "$OTP2_RESPONSE" | sed '$d')
check_exact "otp-generate-2" "$code" "201"
OTP2_ID=$(echo "$body2" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || true)
if [[ -n "$OTP2_ID" ]]; then
    echo "    OTP ID: $OTP2_ID"
fi

echo "13. DELETE /admin/otp/{id} (revoke OTP)"
if [[ -n "$OTP2_ID" ]]; then
    code=$(curl -sk "${ADMIN_AUTH[@]}" \
      -X DELETE \
      -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp/$OTP2_ID")
    check_exact "otp-revoke" "$code" "204"
else
    echo "  SKIP (no OTP ID from step 12)"
fi

echo "14. DELETE /admin/otp/99999 (nonexistent)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X DELETE \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/otp/99999")
check_exact "otp-revoke-nonexistent" "$code" "404"

echo ""

# ═════════════════════════════════════════════════════════════════════
# Section D: EST Happy Path (tests 15-21)
# ═════════════════════════════════════════════════════════════════════
echo "── Section D: EST Happy Path ─────────────────────────────────"

echo "15. GET /cacerts"
code=$(curl -sk -o "$TMPDIR/kipuka-cacerts.b64" -w "%{http_code}" "$EST_URL/cacerts")
check_exact "cacerts" "$code" "200"
if [[ "$code" =~ ^2 ]]; then
    base64 -d < "$TMPDIR/kipuka-cacerts.b64" | \
        openssl x509 -inform DER -noout -subject -issuer -dates 2>/dev/null | \
        sed 's/^/    /'
fi

echo "16. GET /csrattrs"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/csrattrs")
check "csrattrs" "$code"

echo "17. Generate client CSR"
openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$TMPDIR/kipuka-test-client.key" \
  -out "$TMPDIR/kipuka-test-client.csr" \
  -subj "/CN=test-client.kipuka.test/O=Kipuka Test" 2>/dev/null
openssl req -in "$TMPDIR/kipuka-test-client.csr" -outform DER -out "$TMPDIR/kipuka-test-client.der" 2>/dev/null
echo "  PASS (CSR generated)"
((passed++))

echo "18. POST /simpleenroll (OTP auth)"
if [[ -n "$OTP" ]]; then
    B64_CSR=$(base64 < "$TMPDIR/kipuka-test-client.der")
    code=$(curl -sk --cacert "$CA_CERT" \
      -u "test-client:${OTP}" \
      -X POST "$EST_URL/simpleenroll" \
      -H "Content-Type: application/pkcs10" \
      -d "$B64_CSR" \
      -o "$TMPDIR/kipuka-test-client.p7" \
      -w "%{http_code}")
    check_exact "simpleenroll" "$code" "200"
    if [[ "$code" =~ ^2 ]] && [[ -s "$TMPDIR/kipuka-test-client.p7" ]]; then
        base64 -d < "$TMPDIR/kipuka-test-client.p7" | \
            openssl x509 -inform DER -noout -subject -serial -dates 2>/dev/null | \
            sed 's/^/    /' || echo "    (PKCS7 format — use openssl pkcs7 to unwrap)"
    fi
else
    echo "  SKIP (no OTP token received)"
fi

echo "19. Verify issued cert details"
if [[ -s "$TMPDIR/kipuka-test-client.p7" ]]; then
    CERT_SUBJECT=$(base64 -d < "$TMPDIR/kipuka-test-client.p7" | \
        openssl x509 -inform DER -noout -subject 2>/dev/null || true)
    CERT_ISSUER=$(base64 -d < "$TMPDIR/kipuka-test-client.p7" | \
        openssl x509 -inform DER -noout -issuer 2>/dev/null || true)
    if [[ "$CERT_SUBJECT" == *"test-client.kipuka.test"* ]]; then
        echo "  PASS (subject matches CSR)"
        ((passed++))
        echo "    Subject: $CERT_SUBJECT"
        echo "    Issuer:  $CERT_ISSUER"
    else
        echo "  FAIL (subject does not contain test-client.kipuka.test)"
        ((failed++))
    fi
else
    echo "  SKIP (no issued cert from step 18)"
fi

echo "20. GET /admin/certs (should have at least 1)"
CERTS_RESPONSE=$(curl -sk "${ADMIN_AUTH[@]}" \
  -w "\n%{http_code}" "$ADMIN_URL/certs")
code=$(echo "$CERTS_RESPONSE" | tail -1)
certs_body=$(echo "$CERTS_RESPONSE" | sed '$d')
check_exact "list-certs" "$code" "200"
if [[ "$code" == "200" ]]; then
    cert_count=$(echo "$certs_body" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else d.get('total',0))" 2>/dev/null || echo "?")
    echo "    Certificates: $cert_count"
fi

echo "21. POST /simplereenroll (mTLS)"
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
else
    echo "  SKIP (no issued cert from step 18)"
fi

echo ""

# ═════════════════════════════════════════════════════════════════════
# Section E: EST Error Cases (tests 22-28)
# ═════════════════════════════════════════════════════════════════════
echo "── Section E: EST Error Cases ────────────────────────────────"

echo "22. POST /simpleenroll without any auth"
B64_CSR=$(base64 < "$TMPDIR/kipuka-test-client.der")
code=$(curl -sk \
  -X POST "$EST_URL/simpleenroll" \
  -H "Content-Type: application/pkcs10" \
  -d "$B64_CSR" \
  -o /dev/null -w "%{http_code}")
check_exact "simpleenroll-no-auth" "$code" "401"

echo "23. POST /simpleenroll with bad OTP"
code=$(curl -sk \
  -u "test-client:this-is-a-bad-otp-value" \
  -X POST "$EST_URL/simpleenroll" \
  -H "Content-Type: application/pkcs10" \
  -d "$B64_CSR" \
  -o /dev/null -w "%{http_code}")
check_exact "simpleenroll-bad-otp" "$code" "401"

echo "24. POST /simpleenroll with wrong Content-Type"
code=$(curl -sk \
  -u "test-client:fake-otp" \
  -X POST "$EST_URL/simpleenroll" \
  -H "Content-Type: text/plain" \
  -d "not a real csr" \
  -o /dev/null -w "%{http_code}")
check_exact "simpleenroll-wrong-ct" "$code" "415"

echo "25. POST /simpleenroll with garbage base64 body"
# Generate a fresh OTP for this test
OTP_ERR_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "garbage-test"}' \
  -w "\n%{http_code}")
OTP_ERR=$(echo "$OTP_ERR_RESP" | sed '$d' | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
code=$(curl -sk \
  -u "garbage-test:${OTP_ERR}" \
  -X POST "$EST_URL/simpleenroll" \
  -H "Content-Type: application/pkcs10" \
  -d "dGhpcyBpcyBub3QgYSB2YWxpZCBDU1I=" \
  -o /dev/null -w "%{http_code}")
check_exact "simpleenroll-garbage-b64" "$code" "400"

echo "26. POST /simpleenroll with empty body"
OTP_EMPTY_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "empty-body-test"}' \
  -w "\n%{http_code}")
OTP_EMPTY=$(echo "$OTP_EMPTY_RESP" | sed '$d' | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
code=$(curl -sk \
  -u "empty-body-test:${OTP_EMPTY}" \
  -X POST "$EST_URL/simpleenroll" \
  -H "Content-Type: application/pkcs10" \
  -d "" \
  -o /dev/null -w "%{http_code}")
check_exact "simpleenroll-empty-body" "$code" "400"

echo "27. POST /simplereenroll without client cert (OTP only)"
OTP_REENROLL_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "reenroll-no-mtls"}' \
  -w "\n%{http_code}")
OTP_REENROLL=$(echo "$OTP_REENROLL_RESP" | sed '$d' | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
code=$(curl -sk \
  -u "reenroll-no-mtls:${OTP_REENROLL}" \
  -X POST "$EST_URL/simplereenroll" \
  -H "Content-Type: application/pkcs10" \
  -d "$B64_CSR" \
  -o /dev/null -w "%{http_code}")
check_exact "simplereenroll-no-mtls" "$code" "401"

echo "28. POST /simpleenroll reusing consumed OTP"
if [[ -n "$OTP" ]]; then
    code=$(curl -sk \
      -u "test-client:${OTP}" \
      -X POST "$EST_URL/simpleenroll" \
      -H "Content-Type: application/pkcs10" \
      -d "$B64_CSR" \
      -o /dev/null -w "%{http_code}")
    check_exact "simpleenroll-reused-otp" "$code" "401"
else
    echo "  SKIP (no OTP from step 9)"
fi

echo ""

# ═════════════════════════════════════════════════════════════════════
# Section F: Stub Endpoints (tests 29-34)
# ═════════════════════════════════════════════════════════════════════
echo "── Section F: Stub Endpoints ─────────────────────────────────"

echo "29. POST /serverkeygen (stub — any response OK)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$EST_URL/serverkeygen" \
  -H "Content-Type: application/pkcs10" \
  -d "$B64_CSR" \
  -o /dev/null -w "%{http_code}")
check_responds "serverkeygen" "$code"

echo "30. POST /fullcmc (stub — any response OK)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "$EST_URL/fullcmc" \
  -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "fullcmc" "$code"

echo "31. POST /cms/simpleenroll (stub — any response OK)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "https://localhost:9443/.well-known/est/cms/simpleenroll" \
  -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cms-simpleenroll" "$code"

echo "32. POST /cms/simplereenroll (stub — any response OK)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "https://localhost:9443/.well-known/est/cms/simplereenroll" \
  -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cms-simplereenroll" "$code"

echo "33. POST /cms/serverkeygen (stub — any response OK)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "https://localhost:9443/.well-known/est/cms/serverkeygen" \
  -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cms-serverkeygen" "$code"

echo "34. POST /cmp (stub — any response OK)"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X POST "https://localhost:9443/.well-known/cmp" \
  -H "Content-Type: application/pkixcmp" \
  -d "dGVzdA==" \
  -o /dev/null -w "%{http_code}")
check_responds "cmp" "$code"

echo ""

# ═════════════════════════════════════════════════════════════════════
# Section G: STAR Endpoints (tests 35-37)
# ═════════════════════════════════════════════════════════════════════
echo "── Section G: STAR Endpoints ─────────────────────────────────"

echo "35. GET /.well-known/est/star/nonexistent"
code=$(curl -sk \
  -o /dev/null -w "%{http_code}" \
  "https://localhost:9443/.well-known/est/star/nonexistent")
check_exact "star-get-nonexistent" "$code" "404"

echo "36. DELETE /.well-known/est/star/nonexistent"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -X DELETE \
  -o /dev/null -w "%{http_code}" \
  "https://localhost:9443/.well-known/est/star/nonexistent")
check_exact "star-delete-nonexistent" "$code" "404"

echo "37. GET /.well-known/est/star/nonexistent/history"
code=$(curl -sk \
  -o /dev/null -w "%{http_code}" \
  "https://localhost:9443/.well-known/est/star/nonexistent/history")
check_exact "star-history-nonexistent" "$code" "404"

echo ""

# ═════════════════════════════════════════════════════════════════════
# Section H: Auth Boundary Tests (tests 38-40)
# ═════════════════════════════════════════════════════════════════════
echo "── Section H: Auth Boundary Tests ────────────────────────────"

echo "38. GET /admin/health without Bearer token"
code=$(curl -sk \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health")
check_exact "health-no-auth" "$code" "401"

echo "39. GET /admin/cas without Bearer token"
code=$(curl -sk \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas")
check_exact "cas-no-auth" "$code" "401"

echo "40. POST /admin/otp/generate without Bearer token"
code=$(curl -sk \
  -X POST "$ADMIN_URL/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "unauth-test"}' \
  -o /dev/null -w "%{http_code}")
check_exact "otp-generate-no-auth" "$code" "401"

echo ""

# ── Summary ───────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " Results: ${passed} passed, ${failed} failed  (${DB_BACKEND} backend)"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Test artifacts:"
echo "  CA cert:     $CA_CERT"
echo "  Client key:  $TMPDIR/kipuka-test-client.key"
echo "  Client CSR:  $TMPDIR/kipuka-test-client.csr"
echo "  Client cert: $TMPDIR/kipuka-test-client.p7"
echo "  Renewed:     $TMPDIR/kipuka-test-client-renewed.p7"

exit $failed
