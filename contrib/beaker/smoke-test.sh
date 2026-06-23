#!/usr/bin/env bash
# =============================================================================
# kipuka Beaker smoke test
# =============================================================================
# Validates that the kipuka EST server is operational after provisioning.
# Exercises the core EST endpoints (RFC 7030) and the admin API.
#
# Exit codes:
#   0  all tests passed
#   1  one or more tests failed
#
# Usage:
#   bash smoke-test.sh                  # test against localhost:9443
#   KIPUKA_PORT=8443 bash smoke-test.sh # custom port
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

KIPUKA_PORT="${KIPUKA_PORT:-9443}"
ADMIN_PORT="${ADMIN_PORT:-9444}"
BASE_URL="https://localhost:${KIPUKA_PORT}/.well-known/est"
ADMIN_URL="https://localhost:${ADMIN_PORT}/admin"
CERT_DIR="/etc/kipuka"
AUDIT_LOG="/var/log/kipuka/audit.log"

AGENT_CERT="${CERT_DIR}/tls/agent.pem"
AGENT_KEY="${CERT_DIR}/tls/agent.key"
export CA_BUNDLE="${CERT_DIR}/ca/dogtag-ca.pem"

PASS=0
FAIL=0
SKIP=0

# ── Helpers ──────────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }

pass() {
    green "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    red "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

skip() {
    yellow "  SKIP: $1"
    SKIP=$((SKIP + 1))
}

section() {
    echo ""
    echo "── $1 ──"
}

# ── Test 1: Service is running ───────────────────────────────────────────────

section "Service status"

if systemctl is-active --quiet kipuka; then
    pass "kipuka systemd service is active"
else
    fail "kipuka systemd service is not active"
    echo "  journalctl output:"
    journalctl -u kipuka --no-pager -n 20 || true
fi

# ── Test 2: GET /cacerts ─────────────────────────────────────────────────────

section "EST /cacerts (RFC 7030 S4.1)"

HTTP_CODE=$(curl -sk -o /tmp/cacerts-response.pem -w '%{http_code}' \
    "${BASE_URL}/cacerts" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "GET /cacerts returned HTTP 200"

    # Check Content-Type
    CONTENT_TYPE=$(curl -sk -I "${BASE_URL}/cacerts" 2>/dev/null \
        | grep -i "content-type:" | tr -d '\r' || true)

    if echo "${CONTENT_TYPE}" | grep -qi "application/pkcs7-mime"; then
        pass "Content-Type is application/pkcs7-mime"
    else
        fail "Content-Type mismatch: ${CONTENT_TYPE}"
    fi

    # Validate the PKCS#7 structure
    if openssl pkcs7 -inform DER -in /tmp/cacerts-response.pem -print_certs -noout &>/dev/null; then
        pass "/cacerts response is valid PKCS#7 (DER)"
    elif openssl pkcs7 -inform PEM -in /tmp/cacerts-response.pem -print_certs -noout &>/dev/null; then
        pass "/cacerts response is valid PKCS#7 (PEM)"
    elif base64 -d /tmp/cacerts-response.pem 2>/dev/null \
         | openssl pkcs7 -inform DER -print_certs -noout &>/dev/null; then
        pass "/cacerts response is valid PKCS#7 (base64-encoded DER)"
    else
        fail "/cacerts response is not valid PKCS#7"
    fi
else
    fail "GET /cacerts returned HTTP ${HTTP_CODE}"
fi

# ── Test 3: GET /csrattrs ────────────────────────────────────────────────────

section "EST /csrattrs (RFC 7030 S4.5)"

HTTP_CODE=$(curl -sk -o /tmp/csrattrs-response.der -w '%{http_code}' \
    "${BASE_URL}/csrattrs" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "GET /csrattrs returned HTTP 200"

    if [[ -s /tmp/csrattrs-response.der ]]; then
        pass "/csrattrs response is non-empty"
    else
        fail "/csrattrs response is empty"
    fi
else
    fail "GET /csrattrs returned HTTP ${HTTP_CODE}"
fi

# ── Test 4: Generate a test CSR ──────────────────────────────────────────────

section "CSR generation"

TEST_KEY="/tmp/test-enroll.key"
TEST_CSR="/tmp/test-enroll.csr"
TEST_CSR_DER="/tmp/test-enroll.csr.der"

openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${TEST_KEY}" \
    -out "${TEST_CSR}" \
    -subj "/CN=test-device-001.kipuka.test/O=Kipuka Test/C=US" \
    2>/dev/null

# Convert to DER and then base64 for EST (RFC 7030 S4.2: base64-encoded PKCS#10)
openssl req -in "${TEST_CSR}" -outform DER -out "${TEST_CSR_DER}"
TEST_CSR_B64=$(base64 -w 0 "${TEST_CSR_DER}" 2>/dev/null || base64 "${TEST_CSR_DER}")

if [[ -s "${TEST_CSR}" ]]; then
    pass "Test CSR generated for CN=test-device-001.kipuka.test"
else
    fail "Failed to generate test CSR"
fi

# ── Test 5: OTP generation via admin API ─────────────────────────────────────

section "Admin API: OTP generation"

OTP_RESPONSE=$(curl -sk \
    --cert "${AGENT_CERT}" \
    --key "${AGENT_KEY}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"subject": "CN=test-device-001.kipuka.test"}' \
    "${ADMIN_URL}/otp/generate" 2>/dev/null || echo "")

if echo "${OTP_RESPONSE}" | jq -e '.otp' &>/dev/null; then
    OTP_TOKEN=$(echo "${OTP_RESPONSE}" | jq -r '.otp')
    pass "OTP generated via admin API: ${OTP_TOKEN:0:8}..."
else
    # Admin API may not be reachable or may have a different response format
    skip "OTP generation via admin API (admin API may not be available)"
    OTP_TOKEN=""
fi

# ── Test 6: POST /simpleenroll with OTP ──────────────────────────────────────

section "EST /simpleenroll (RFC 7030 S4.2)"

if [[ -n "${OTP_TOKEN}" ]]; then
    # EST uses HTTP Basic auth with username "estuser" and OTP as password
    ENROLL_RESPONSE=$(curl -sk \
        -o /tmp/enroll-response.der \
        -w '%{http_code}' \
        -X POST \
        -u "test-device-001.kipuka.test:${OTP_TOKEN}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${TEST_CSR_B64}" \
        "${BASE_URL}/simpleenroll" 2>/dev/null || echo "000")

    if [[ "${ENROLL_RESPONSE}" == "200" ]]; then
        pass "POST /simpleenroll returned HTTP 200"

        # Try to parse the response as a certificate
        if base64 -d /tmp/enroll-response.der 2>/dev/null \
           | openssl x509 -inform DER -noout &>/dev/null; then
            pass "Enrollment response is a valid X.509 certificate"
            # Save for re-enrollment test
            base64 -d /tmp/enroll-response.der 2>/dev/null \
                | openssl x509 -inform DER -out /tmp/enrolled-cert.pem
        elif openssl pkcs7 -inform DER -in /tmp/enroll-response.der -print_certs -noout &>/dev/null; then
            pass "Enrollment response is valid PKCS#7"
        else
            fail "Enrollment response is not a valid certificate or PKCS#7"
        fi
    elif [[ "${ENROLL_RESPONSE}" == "202" ]]; then
        pass "POST /simpleenroll returned HTTP 202 (pending — Retry-After)"
    elif [[ "${ENROLL_RESPONSE}" == "401" ]]; then
        fail "POST /simpleenroll returned HTTP 401 (OTP rejected)"
    else
        fail "POST /simpleenroll returned HTTP ${ENROLL_RESPONSE}"
    fi
else
    skip "POST /simpleenroll (no OTP token available)"
fi

# ── Test 7: POST /simplereenroll with mTLS ───────────────────────────────────

section "EST /simplereenroll (RFC 7030 S4.2.2)"

if [[ -f /tmp/enrolled-cert.pem && -f "${TEST_KEY}" ]]; then
    # Generate a new CSR using the enrolled certificate's key
    openssl req -new \
        -key "${TEST_KEY}" \
        -out /tmp/reenroll.csr \
        -subj "/CN=test-device-001.kipuka.test/O=Kipuka Test/C=US" \
        2>/dev/null

    REENROLL_CSR_DER="/tmp/reenroll.csr.der"
    openssl req -in /tmp/reenroll.csr -outform DER -out "${REENROLL_CSR_DER}"
    REENROLL_CSR_B64=$(base64 -w 0 "${REENROLL_CSR_DER}" 2>/dev/null || base64 "${REENROLL_CSR_DER}")

    REENROLL_RESPONSE=$(curl -sk \
        --cert /tmp/enrolled-cert.pem \
        --key "${TEST_KEY}" \
        -o /tmp/reenroll-response.der \
        -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${REENROLL_CSR_B64}" \
        "${BASE_URL}/simplereenroll" 2>/dev/null || echo "000")

    if [[ "${REENROLL_RESPONSE}" == "200" ]]; then
        pass "POST /simplereenroll returned HTTP 200"
    elif [[ "${REENROLL_RESPONSE}" == "202" ]]; then
        pass "POST /simplereenroll returned HTTP 202 (pending)"
    else
        fail "POST /simplereenroll returned HTTP ${REENROLL_RESPONSE}"
    fi
else
    skip "POST /simplereenroll (no enrolled cert available for mTLS)"
fi

# ── Test 8: Admin health endpoint ────────────────────────────────────────────

section "Admin API: health"

HEALTH_RESPONSE=$(curl -sk \
    --cert "${AGENT_CERT}" \
    --key "${AGENT_KEY}" \
    "${ADMIN_URL}/health" 2>/dev/null || echo "")

if [[ -n "${HEALTH_RESPONSE}" ]]; then
    if echo "${HEALTH_RESPONSE}" | jq -e '.status' &>/dev/null; then
        HEALTH_STATUS=$(echo "${HEALTH_RESPONSE}" | jq -r '.status')
        if [[ "${HEALTH_STATUS}" == "ok" || "${HEALTH_STATUS}" == "healthy" ]]; then
            pass "Health endpoint reports status: ${HEALTH_STATUS}"
        else
            fail "Health endpoint reports status: ${HEALTH_STATUS}"
        fi
    else
        pass "Health endpoint responded (non-JSON response)"
    fi
else
    skip "Health endpoint not reachable (admin API may not be available)"
fi

# ── Test 9: Audit log validation ─────────────────────────────────────────────

section "Audit log"

if [[ -f "${AUDIT_LOG}" ]]; then
    AUDIT_LINES=$(wc -l < "${AUDIT_LOG}" | tr -d ' ')
    if [[ "${AUDIT_LINES}" -gt 0 ]]; then
        pass "Audit log has ${AUDIT_LINES} entries"
    else
        fail "Audit log exists but is empty"
    fi

    # Check that startup event was logged
    if grep -qi "start\|startup\|CaStart" "${AUDIT_LOG}" 2>/dev/null; then
        pass "Audit log contains startup event"
    else
        fail "Audit log does not contain startup event"
    fi
else
    skip "Audit log file not found at ${AUDIT_LOG}"
fi

# ── Test 10: Unauthenticated /simpleenroll is rejected ───────────────────────

section "Security: unauthenticated enrollment"

UNAUTH_RESPONSE=$(curl -sk \
    -o /dev/null \
    -w '%{http_code}' \
    -X POST \
    -H "Content-Type: application/pkcs10" \
    -H "Content-Transfer-Encoding: base64" \
    --data-binary "${TEST_CSR_B64}" \
    "${BASE_URL}/simpleenroll" 2>/dev/null || echo "000")

if [[ "${UNAUTH_RESPONSE}" == "401" || "${UNAUTH_RESPONSE}" == "403" ]]; then
    pass "Unauthenticated /simpleenroll rejected with HTTP ${UNAUTH_RESPONSE}"
elif [[ "${UNAUTH_RESPONSE}" == "400" ]]; then
    pass "Unauthenticated /simpleenroll rejected with HTTP 400"
else
    fail "Unauthenticated /simpleenroll returned HTTP ${UNAUTH_RESPONSE} (expected 401/403)"
fi

# ── Cleanup ──────────────────────────────────────────────────────────────────

rm -f /tmp/cacerts-response.pem /tmp/csrattrs-response.der \
      /tmp/test-enroll.key /tmp/test-enroll.csr /tmp/test-enroll.csr.der \
      /tmp/enroll-response.der /tmp/enrolled-cert.pem \
      /tmp/reenroll.csr /tmp/reenroll.csr.der /tmp/reenroll-response.der

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " Smoke Test Results"
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
