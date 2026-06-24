#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Error Handling Tests
# ═══════════════════════════════════════════════════════════════════════
# Tests EST protocol error responses: bad auth, wrong content types,
# malformed requests, missing mTLS, wrong methods, and concurrency.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

source "$(dirname "$0")/common.sh"

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Error Handling Tests"
echo "═══════════════════════════════════════════════════════════════"
require_server

# Generate a CSR once for reuse across error tests
openssl req -new -nodes -newkey rsa:2048 \
    -keyout "$TMPDIR/err-client.key" \
    -out "$TMPDIR/err-client.csr" \
    -subj "/CN=error-test.kipuka.test/O=Kipuka Test" 2>/dev/null
openssl req -in "$TMPDIR/err-client.csr" -outform DER -out "$TMPDIR/err-client.der" 2>/dev/null
B64_CSR=$(base64 < "$TMPDIR/err-client.der")

# ─────────────────────────────────────────────────────────────────────
section "Authentication Errors"
# ─────────────────────────────────────────────────────────────────────

echo "1. POST /simpleenroll no auth — 401"
code=$(curl -sk \
    -X POST "$EST_URL/simpleenroll" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR" \
    -o /dev/null -w "%{http_code}")
check_exact "no auth" "$code" "401"

echo "2. POST /simpleenroll bad OTP — 401"
code=$(curl -sk \
    -u "error-test:this-is-not-a-valid-otp" \
    -X POST "$EST_URL/simpleenroll" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR" \
    -o /dev/null -w "%{http_code}")
check_exact "bad OTP" "$code" "401"

# ─────────────────────────────────────────────────────────────────────
section "Content Type Errors"
# ─────────────────────────────────────────────────────────────────────

echo "3. POST /simpleenroll wrong Content-Type — 415"
code=$(curl -sk \
    -u "error-test:fake-otp" \
    -X POST "$EST_URL/simpleenroll" \
    -H "Content-Type: text/plain" \
    -d "not a real csr" \
    -o /dev/null -w "%{http_code}")
check_exact "wrong Content-Type" "$code" "415"

# ─────────────────────────────────────────────────────────────────────
section "Malformed Request Body"
# ─────────────────────────────────────────────────────────────────────

echo "4. POST /simpleenroll garbage body — 400"
# Get a valid OTP so auth passes but body is bad
OTP_GARBAGE_BODY=$(generate_otp "garbage-body-test")
OTP_GARBAGE=$(json_field "$OTP_GARBAGE_BODY" "token")
if [[ -n "$OTP_GARBAGE" ]]; then
    code=$(curl -sk \
        -u "garbage-body-test:${OTP_GARBAGE}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "dGhpcyBpcyBub3QgYSB2YWxpZCBDU1I=" \
        -o /dev/null -w "%{http_code}")
    check_exact "garbage body" "$code" "400"
else
    skip_test "garbage body" "no OTP generated"
fi

echo "5. POST /simpleenroll empty body — 400"
OTP_EMPTY_BODY=$(generate_otp "empty-body-test")
OTP_EMPTY=$(json_field "$OTP_EMPTY_BODY" "token")
if [[ -n "$OTP_EMPTY" ]]; then
    code=$(curl -sk \
        -u "empty-body-test:${OTP_EMPTY}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "" \
        -o /dev/null -w "%{http_code}")
    check_exact "empty body" "$code" "400"
else
    skip_test "empty body" "no OTP generated"
fi

# ─────────────────────────────────────────────────────────────────────
section "mTLS Requirement"
# ─────────────────────────────────────────────────────────────────────

echo "6. POST /simplereenroll without mTLS cert — 401"
OTP_NOMTLS_BODY=$(generate_otp "no-mtls-test")
OTP_NOMTLS=$(json_field "$OTP_NOMTLS_BODY" "token")
if [[ -n "$OTP_NOMTLS" ]]; then
    code=$(curl -sk \
        -u "no-mtls-test:${OTP_NOMTLS}" \
        -X POST "$EST_URL/simplereenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_CSR" \
        -o /dev/null -w "%{http_code}")
    check_exact "simplereenroll no mTLS" "$code" "401"
else
    skip_test "simplereenroll no mTLS" "no OTP generated"
fi

# ─────────────────────────────────────────────────────────────────────
section "Routing Errors"
# ─────────────────────────────────────────────────────────────────────

echo "7. GET /nonexistent — 404"
code=$(curl -sk \
    -o /dev/null -w "%{http_code}" \
    "https://localhost:9443/.well-known/est/nonexistent-endpoint")
check_exact "nonexistent endpoint" "$code" "404"

echo "8. POST /cacerts (wrong method) — 405"
code=$(curl -sk \
    -X POST "$EST_URL/cacerts" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR" \
    -o /dev/null -w "%{http_code}")
check_exact "POST /cacerts (wrong method)" "$code" "405"

# ─────────────────────────────────────────────────────────────────────
section "Invalid CSR"
# ─────────────────────────────────────────────────────────────────────

echo "9. POST /simpleenroll valid OTP but invalid CSR (too short) — 400"
OTP_BADCSR_BODY=$(generate_otp "bad-csr-test")
OTP_BADCSR=$(json_field "$OTP_BADCSR_BODY" "token")
if [[ -n "$OTP_BADCSR" ]]; then
    # A very short base64 string that is not a valid DER CSR
    code=$(curl -sk \
        -u "bad-csr-test:${OTP_BADCSR}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "MIIBC" \
        -o /dev/null -w "%{http_code}")
    check_exact "invalid CSR (too short)" "$code" "400"
else
    skip_test "invalid CSR" "no OTP generated"
fi

# ─────────────────────────────────────────────────────────────────────
section "Concurrent OTP Validation"
# ─────────────────────────────────────────────────────────────────────

echo "10. Multiple rapid OTP validations (same entity, different OTPs)"
RAPID_OK=0
RAPID_TOTAL=3
for i in $(seq 1 $RAPID_TOTAL); do
    RAPID_OTP_BODY=$(generate_otp "rapid-test-entity")
    RAPID_OTP=$(json_field "$RAPID_OTP_BODY" "token")
    if [[ -n "$RAPID_OTP" ]]; then
        # Generate unique CSR per enrollment
        openssl req -new -nodes -newkey rsa:2048 \
            -keyout "$TMPDIR/rapid-$i.key" \
            -out "$TMPDIR/rapid-$i.csr" \
            -subj "/CN=rapid-test-entity-$i/O=Kipuka Test" 2>/dev/null
        openssl req -in "$TMPDIR/rapid-$i.csr" -outform DER -out "$TMPDIR/rapid-$i.der" 2>/dev/null
        RAPID_B64=$(base64 < "$TMPDIR/rapid-$i.der")

        code=$(curl -sk --cacert "$CA_CERT" \
            -u "rapid-test-entity:${RAPID_OTP}" \
            -X POST "$EST_URL/simpleenroll" \
            -H "Content-Type: application/pkcs10" \
            -d "$RAPID_B64" \
            -o /dev/null -w "%{http_code}")
        if [[ "$code" == "200" ]]; then
            ((RAPID_OK++))
        else
            echo "    Attempt $i: HTTP $code (expected 200)"
        fi
    fi
done

if [[ $RAPID_OK -eq $RAPID_TOTAL ]]; then
    echo -e "  ${GREEN}PASS${NC} all $RAPID_TOTAL rapid enrollments succeeded"
    ((passed++))
else
    echo -e "  ${RED}FAIL${NC} $RAPID_OK/$RAPID_TOTAL rapid enrollments succeeded"
    ((failed++))
fi

# ── Summary ─────────────────────────────────────────────────────────
summary
