#!/usr/bin/env bash
# =============================================================================
# kipuka + ahdapa integration tests
# =============================================================================
# Validates kipuka EST enrollment when ahdapa (Rust IPA server) is configured
# as the CA backend.
#
# ahdapa: codeberg.org/freeipa/ahdapa
#
# Requirements:
#   - Running ahdapa instance with CA capability
#   - Running kipuka configured with ahdapa as CA backend
#   - curl, openssl, jq
#
# Usage:
#   ./test-ahdapa-integration.sh
#   KIPUKA_URL=https://est.example.com AHDAPA_URL=https://ipa.example.com \
#       ./test-ahdapa-integration.sh
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Configuration ────────────────────────────────────────────────────────────

KIPUKA_URL="${KIPUKA_URL:-https://localhost:8443}"
AHDAPA_URL="${AHDAPA_URL:-https://localhost:8080}"
ADMIN_URL="${ADMIN_URL:-https://localhost:8444}"
EST_BASE="${KIPUKA_URL}/.well-known/est"
CURL_OPTS="-sk --connect-timeout 10 --max-time 60"
TMPDIR="${TMPDIR:-/tmp}/kipuka-ahdapa-test-$$"

PASS=0
FAIL=0
SKIP=0

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
pass() { green "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { red   "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { yellow "  SKIP: $1"; SKIP=$((SKIP + 1)); }
section() { echo ""; echo "── $1 ──"; }

cleanup() { rm -rf "${TMPDIR}"; }
trap cleanup EXIT
mkdir -p "${TMPDIR}"

b64encode() {
    base64 -w 0 "$1" 2>/dev/null || base64 -b 0 "$1" 2>/dev/null || base64 "$1" | tr -d '\n'
}

# ── Prerequisite checks ─────────────────────────────────────────────────────

section "Prerequisites"

# Check kipuka is reachable
HTTP_CODE=$(curl ${CURL_OPTS} -o /dev/null -w '%{http_code}' "${EST_BASE}/cacerts" 2>/dev/null || echo "000")
if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "kipuka EST server is reachable"
else
    fail "kipuka EST server unreachable (HTTP ${HTTP_CODE})"
    echo "  Ensure kipuka is running and configured with ahdapa backend."
    exit 1
fi

# Check ahdapa is reachable
AHDAPA_CODE=$(curl ${CURL_OPTS} -o /dev/null -w '%{http_code}' "${AHDAPA_URL}/ipa/config" 2>/dev/null || echo "000")
if [[ "${AHDAPA_CODE}" != "000" ]]; then
    pass "ahdapa server is reachable"
else
    skip "ahdapa server not reachable at ${AHDAPA_URL} — some tests will be skipped"
fi

# ── Test 1: Verify /cacerts returns ahdapa CA cert ───────────────────────────

section "CA Certificate from ahdapa"

HTTP_CODE=$(curl ${CURL_OPTS} -o "${TMPDIR}/cacerts.raw" -w '%{http_code}' \
    "${EST_BASE}/cacerts" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "GET /cacerts returned HTTP 200"

    # Decode and inspect the CA certificate
    if base64 -d "${TMPDIR}/cacerts.raw" > "${TMPDIR}/cacerts.der" 2>/dev/null; then
        if openssl pkcs7 -inform DER -in "${TMPDIR}/cacerts.der" -print_certs \
                > "${TMPDIR}/ahdapa-ca.pem" 2>/dev/null; then
            CA_SUBJECT=$(openssl x509 -in "${TMPDIR}/ahdapa-ca.pem" -subject -noout 2>/dev/null || true)
            if [[ -n "${CA_SUBJECT}" ]]; then
                pass "CA certificate subject: ${CA_SUBJECT}"
            else
                fail "Could not extract CA certificate subject"
            fi
        fi
    fi
else
    fail "GET /cacerts returned HTTP ${HTTP_CODE}"
fi

# ── Test 2: Enroll certificate via kipuka → ahdapa ───────────────────────────

section "Certificate enrollment via kipuka → ahdapa"

# Generate CSR
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${TMPDIR}/ahdapa-test.key" \
    -out "${TMPDIR}/ahdapa-test.csr" \
    -subj "/CN=ahdapa-integ-test.ipa.test/O=ahdapa Integration Test" \
    2>/dev/null

openssl req -in "${TMPDIR}/ahdapa-test.csr" -outform DER -out "${TMPDIR}/ahdapa-test.csr.der"
CSR_B64=$(b64encode "${TMPDIR}/ahdapa-test.csr.der")
pass "Generated test CSR for CN=ahdapa-integ-test.ipa.test"

# Generate OTP
OTP_RESPONSE=$(curl ${CURL_OPTS} \
    -X POST \
    -H "Authorization: Bearer test-admin-token" \
    -H "Content-Type: application/json" \
    -d '{"subject": "CN=ahdapa-integ-test.ipa.test"}' \
    "${ADMIN_URL}/admin/otp/generate" 2>/dev/null || echo "")

OTP_TOKEN=$(echo "${OTP_RESPONSE}" | jq -r '.otp // .token // empty' 2>/dev/null || true)

if [[ -z "${OTP_TOKEN}" ]]; then
    skip "OTP generation not available — enrollment skipped"
else
    pass "OTP generated: ${OTP_TOKEN:0:8}..."

    # Enroll via kipuka (which forwards to ahdapa)
    HTTP_CODE=$(curl ${CURL_OPTS} \
        -o "${TMPDIR}/ahdapa-enrolled.raw" \
        -w '%{http_code}' \
        -X POST \
        -u ":${OTP_TOKEN}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${CSR_B64}" \
        "${EST_BASE}/simpleenroll" 2>/dev/null || echo "000")

    if [[ "${HTTP_CODE}" == "200" ]]; then
        pass "Enrollment via kipuka → ahdapa returned HTTP 200"

        # Verify the issued certificate
        if base64 -d "${TMPDIR}/ahdapa-enrolled.raw" > "${TMPDIR}/ahdapa-enrolled.der" 2>/dev/null; then
            CERT_SUBJECT=$(openssl x509 -inform DER -in "${TMPDIR}/ahdapa-enrolled.der" \
                -subject -noout 2>/dev/null || true)
            if [[ -n "${CERT_SUBJECT}" ]]; then
                pass "Issued certificate: ${CERT_SUBJECT}"
                # Save for re-enrollment test
                openssl x509 -inform DER -in "${TMPDIR}/ahdapa-enrolled.der" \
                    -out "${TMPDIR}/ahdapa-enrolled.pem" 2>/dev/null
            else
                fail "Could not parse issued certificate"
            fi
        fi
    elif [[ "${HTTP_CODE}" == "202" ]]; then
        pass "Enrollment returned HTTP 202 (deferred by ahdapa)"
    else
        fail "Enrollment returned HTTP ${HTTP_CODE}"
    fi
fi

# ── Test 3: Re-enrollment ────────────────────────────────────────────────────

section "Re-enrollment via kipuka → ahdapa"

if [[ -f "${TMPDIR}/ahdapa-enrolled.pem" && -f "${TMPDIR}/ahdapa-test.key" ]]; then
    openssl req -new \
        -key "${TMPDIR}/ahdapa-test.key" \
        -out "${TMPDIR}/ahdapa-reenroll.csr" \
        -subj "/CN=ahdapa-integ-test.ipa.test/O=ahdapa Integration Test" \
        2>/dev/null

    openssl req -in "${TMPDIR}/ahdapa-reenroll.csr" -outform DER \
        -out "${TMPDIR}/ahdapa-reenroll.csr.der"
    REENROLL_B64=$(b64encode "${TMPDIR}/ahdapa-reenroll.csr.der")

    HTTP_CODE=$(curl ${CURL_OPTS} \
        --cert "${TMPDIR}/ahdapa-enrolled.pem" \
        --key "${TMPDIR}/ahdapa-test.key" \
        -o "${TMPDIR}/ahdapa-reenroll-resp.raw" \
        -w '%{http_code}' \
        -X POST \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${REENROLL_B64}" \
        "${EST_BASE}/simplereenroll" 2>/dev/null || echo "000")

    if [[ "${HTTP_CODE}" == "200" || "${HTTP_CODE}" == "202" ]]; then
        pass "Re-enrollment via kipuka → ahdapa returned HTTP ${HTTP_CODE}"
    else
        fail "Re-enrollment returned HTTP ${HTTP_CODE}"
    fi
else
    skip "Re-enrollment (no enrolled certificate available)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " ahdapa Integration Test Results"
echo "============================================"
green " PASSED: ${PASS}"
[[ ${FAIL} -gt 0 ]] && red  " FAILED: ${FAIL}" || echo " FAILED: 0"
[[ ${SKIP} -gt 0 ]] && yellow " SKIPPED: ${SKIP}" || echo " SKIPPED: 0"
echo "============================================"

[[ ${FAIL} -gt 0 ]] && exit 1
exit 0
