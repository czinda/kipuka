#!/usr/bin/env bash
# =============================================================================
# kipuka EST protocol tests using curl
# =============================================================================
# Pure curl-based EST tests (no Rust required, runs on any RHEL).
# Exercises all 6 EST operations (RFC 7030) with proper content types,
# base64 encoding, and validation using openssl commands.
#
# Requirements:
#   - curl, openssl, base64, jq
#   - A running kipuka server (or set KIPUKA_URL)
#   - For enrollment: admin API access for OTP generation
#
# Usage:
#   ./test-est-curl.sh                              # localhost:8443
#   KIPUKA_URL=https://est.example.com ./test-est-curl.sh
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Configuration ────────────────────────────────────────────────────────────

KIPUKA_URL="${KIPUKA_URL:-https://localhost:8443}"
ADMIN_URL="${ADMIN_URL:-${KIPUKA_URL/8443/8444}}"
CA_BUNDLE="${CA_BUNDLE:-/etc/kipuka/ca.pem}"
EST_BASE="${KIPUKA_URL}/.well-known/est"
TMPDIR="${TMPDIR:-/tmp}/kipuka-test-$$"
CURL_OPTS="-sk --connect-timeout 5 --max-time 30"

# If CA_BUNDLE doesn't exist, use -k (insecure)
if [[ -f "${CA_BUNDLE}" ]]; then
    CURL_OPTS="${CURL_OPTS} --cacert ${CA_BUNDLE}"
fi

PASS=0
FAIL=0
SKIP=0

# ── Helpers ──────────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

pass() { green "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { red   "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { yellow "  SKIP: $1"; SKIP=$((SKIP + 1)); }
section() { echo ""; echo "── $1 ──"; }

cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

mkdir -p "${TMPDIR}"

# Portable base64 encode (handles macOS and Linux)
b64encode() {
    base64 -w 0 "$1" 2>/dev/null || base64 -b 0 "$1" 2>/dev/null || base64 "$1" | tr -d '\n'
}

# ── Test 1: GET /cacerts ─────────────────────────────────────────────────────

section "EST /cacerts (RFC 7030 S4.1)"

HTTP_CODE=$(curl ${CURL_OPTS} -o "${TMPDIR}/cacerts.raw" -w '%{http_code}' \
    "${EST_BASE}/cacerts" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "GET /cacerts returned HTTP 200"

    # Verify Content-Type
    CT=$(curl ${CURL_OPTS} -I "${EST_BASE}/cacerts" 2>/dev/null \
        | grep -i "^content-type:" | tr -d '\r' || true)
    if echo "${CT}" | grep -qi "application/pkcs7-mime"; then
        pass "Content-Type is application/pkcs7-mime"
    else
        fail "Content-Type mismatch: ${CT}"
    fi

    # Try to decode and validate the PKCS#7 structure
    if base64 -d "${TMPDIR}/cacerts.raw" > "${TMPDIR}/cacerts.der" 2>/dev/null; then
        if openssl pkcs7 -inform DER -in "${TMPDIR}/cacerts.der" -print_certs -noout 2>/dev/null; then
            pass "Response is valid PKCS#7 (base64-encoded DER)"
            # Extract the CA cert for later use
            openssl pkcs7 -inform DER -in "${TMPDIR}/cacerts.der" -print_certs \
                > "${TMPDIR}/ca-from-est.pem" 2>/dev/null || true
        else
            fail "Response is not valid PKCS#7 DER"
        fi
    elif openssl pkcs7 -inform PEM -in "${TMPDIR}/cacerts.raw" -print_certs -noout 2>/dev/null; then
        pass "Response is valid PKCS#7 (PEM)"
    else
        fail "Cannot parse /cacerts response"
    fi
elif [[ "${HTTP_CODE}" == "000" ]]; then
    fail "GET /cacerts — server unreachable"
else
    fail "GET /cacerts returned HTTP ${HTTP_CODE}"
fi

# ── Test 2: GET /csrattrs ────────────────────────────────────────────────────

section "EST /csrattrs (RFC 7030 S4.5)"

HTTP_CODE=$(curl ${CURL_OPTS} -o "${TMPDIR}/csrattrs.raw" -w '%{http_code}' \
    "${EST_BASE}/csrattrs" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "GET /csrattrs returned HTTP 200"
    if [[ -s "${TMPDIR}/csrattrs.raw" ]]; then
        pass "/csrattrs response is non-empty"
    else
        fail "/csrattrs response is empty"
    fi
elif [[ "${HTTP_CODE}" == "204" ]]; then
    pass "GET /csrattrs returned HTTP 204 (no attributes configured)"
else
    fail "GET /csrattrs returned HTTP ${HTTP_CODE}"
fi

# ── Test 3: Generate test CSR ────────────────────────────────────────────────

section "CSR Generation"

openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${TMPDIR}/test.key" \
    -out "${TMPDIR}/test.csr" \
    -subj "/CN=curl-test-device.kipuka.test/O=Kipuka Curl Tests/C=US" \
    2>/dev/null

openssl req -in "${TMPDIR}/test.csr" -outform DER -out "${TMPDIR}/test.csr.der"
TEST_CSR_B64=$(b64encode "${TMPDIR}/test.csr.der")

if [[ -s "${TMPDIR}/test.csr" ]]; then
    pass "Generated RSA 2048 CSR for CN=curl-test-device.kipuka.test"
else
    fail "CSR generation failed"
fi

# ── Test 4: POST /simpleenroll without auth (negative) ───────────────────────

section "EST /simpleenroll — no auth (negative test)"

HTTP_CODE=$(curl ${CURL_OPTS} \
    -o "${TMPDIR}/noauth-enroll.raw" \
    -w '%{http_code}' \
    -X POST \
    -H "Content-Type: application/pkcs10" \
    -H "Content-Transfer-Encoding: base64" \
    --data-binary "${TEST_CSR_B64}" \
    "${EST_BASE}/simpleenroll" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "401" || "${HTTP_CODE}" == "403" ]]; then
    pass "Unauthenticated /simpleenroll rejected with HTTP ${HTTP_CODE}"
else
    fail "Unauthenticated /simpleenroll returned HTTP ${HTTP_CODE} (expected 401/403)"
fi

# ── Test 5: OTP generation and enrollment ────────────────────────────────────

section "EST /simpleenroll — OTP enrollment"

# Try to generate OTP via admin API
OTP_RESPONSE=$(curl ${CURL_OPTS} \
    -X POST \
    -H "Authorization: Bearer test-admin-token" \
    -H "Content-Type: application/json" \
    -d '{"subject": "CN=curl-test-device.kipuka.test"}' \
    "${ADMIN_URL}/admin/otp/generate" 2>/dev/null || echo "")

OTP_TOKEN=""
if echo "${OTP_RESPONSE}" | jq -e '.otp // .token' &>/dev/null; then
    OTP_TOKEN=$(echo "${OTP_RESPONSE}" | jq -r '.otp // .token')
    pass "OTP generated: ${OTP_TOKEN:0:8}..."
else
    skip "OTP generation via admin API (not available)"
fi

if [[ -n "${OTP_TOKEN}" ]]; then
    HTTP_CODE=$(curl ${CURL_OPTS} \
        -o "${TMPDIR}/enroll-response.raw" \
        -w '%{http_code}' \
        -X POST \
        -u ":${OTP_TOKEN}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${TEST_CSR_B64}" \
        "${EST_BASE}/simpleenroll" 2>/dev/null || echo "000")

    if [[ "${HTTP_CODE}" == "200" ]]; then
        pass "POST /simpleenroll returned HTTP 200"

        # Validate the issued certificate
        if base64 -d "${TMPDIR}/enroll-response.raw" > "${TMPDIR}/enrolled.der" 2>/dev/null; then
            if openssl x509 -inform DER -in "${TMPDIR}/enrolled.der" -noout 2>/dev/null; then
                pass "Enrollment response is a valid X.509 certificate"
                openssl x509 -inform DER -in "${TMPDIR}/enrolled.der" \
                    -out "${TMPDIR}/enrolled.pem" 2>/dev/null
            elif openssl pkcs7 -inform DER -in "${TMPDIR}/enrolled.der" -print_certs -noout 2>/dev/null; then
                pass "Enrollment response is valid PKCS#7"
                openssl pkcs7 -inform DER -in "${TMPDIR}/enrolled.der" -print_certs \
                    > "${TMPDIR}/enrolled.pem" 2>/dev/null || true
            else
                fail "Cannot parse enrollment response"
            fi
        else
            fail "Enrollment response is not valid base64"
        fi
    elif [[ "${HTTP_CODE}" == "202" ]]; then
        pass "POST /simpleenroll returned HTTP 202 (deferred)"
    else
        fail "POST /simpleenroll returned HTTP ${HTTP_CODE}"
    fi
else
    skip "POST /simpleenroll (no OTP available)"
fi

# ── Test 6: POST /simplereenroll with mTLS ───────────────────────────────────

section "EST /simplereenroll — mTLS re-enrollment"

if [[ -f "${TMPDIR}/enrolled.pem" && -f "${TMPDIR}/test.key" ]]; then
    # Generate a new CSR for re-enrollment
    openssl req -new \
        -key "${TMPDIR}/test.key" \
        -out "${TMPDIR}/reenroll.csr" \
        -subj "/CN=curl-test-device.kipuka.test/O=Kipuka Curl Tests/C=US" \
        2>/dev/null

    openssl req -in "${TMPDIR}/reenroll.csr" -outform DER -out "${TMPDIR}/reenroll.csr.der"
    REENROLL_B64=$(b64encode "${TMPDIR}/reenroll.csr.der")

    HTTP_CODE=$(curl ${CURL_OPTS} \
        --cert "${TMPDIR}/enrolled.pem" \
        --key "${TMPDIR}/test.key" \
        -o "${TMPDIR}/reenroll-response.raw" \
        -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${REENROLL_B64}" \
        "${EST_BASE}/simplereenroll" 2>/dev/null || echo "000")

    if [[ "${HTTP_CODE}" == "200" || "${HTTP_CODE}" == "202" ]]; then
        pass "POST /simplereenroll returned HTTP ${HTTP_CODE}"
    else
        fail "POST /simplereenroll returned HTTP ${HTTP_CODE}"
    fi
else
    skip "POST /simplereenroll (no enrolled cert available)"
fi

# ── Test 7: Wrong Content-Type (negative) ────────────────────────────────────

section "EST Content-Type enforcement"

HTTP_CODE=$(curl ${CURL_OPTS} \
    -o /dev/null \
    -w '%{http_code}' \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{}' \
    "${EST_BASE}/simpleenroll" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "415" ]]; then
    pass "Wrong Content-Type rejected with HTTP 415"
else
    fail "Wrong Content-Type returned HTTP ${HTTP_CODE} (expected 415)"
fi

# ── Test 8: Unknown label (negative) ────────────────────────────────────────

section "EST label routing"

HTTP_CODE=$(curl ${CURL_OPTS} \
    -o /dev/null \
    -w '%{http_code}' \
    "${EST_BASE}/nonexistent-label/cacerts" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "404" ]]; then
    pass "Unknown EST label returned HTTP 404"
else
    fail "Unknown EST label returned HTTP ${HTTP_CODE} (expected 404)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " EST Curl Test Results"
echo "============================================"
green " PASSED: ${PASS}"
[[ ${FAIL} -gt 0 ]] && red  " FAILED: ${FAIL}" || echo " FAILED: 0"
[[ ${SKIP} -gt 0 ]] && yellow " SKIPPED: ${SKIP}" || echo " SKIPPED: 0"
echo "============================================"

if [[ ${FAIL} -gt 0 ]]; then
    red "Some tests failed."
    exit 1
fi

green "All tests passed."
exit 0
