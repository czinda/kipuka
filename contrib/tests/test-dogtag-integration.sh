#!/usr/bin/env bash
# =============================================================================
# kipuka + Dogtag PKI integration tests
# =============================================================================
# Validates that kipuka correctly proxies EST operations to Dogtag CA.
#
# Requirements:
#   - Running Dogtag CA instance (pki-tomcatd@pki-tomcat)
#   - Running kipuka configured with Dogtag backend
#   - Agent certificate for Dogtag admin operations
#   - curl, openssl, jq, pki CLI tools
#
# Usage:
#   ./test-dogtag-integration.sh
#   KIPUKA_URL=https://est.example.com DOGTAG_URL=https://ca.example.com:8443 \
#       ./test-dogtag-integration.sh
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Configuration ────────────────────────────────────────────────────────────

KIPUKA_URL="${KIPUKA_URL:-https://localhost:8443}"
DOGTAG_URL="${DOGTAG_URL:-https://localhost:8443}"
ADMIN_URL="${ADMIN_URL:-https://localhost:8444}"

AGENT_CERT="${AGENT_CERT:-/etc/pki/pki-tomcat/ca_admin_cert.pem}"
AGENT_KEY="${AGENT_KEY:-/etc/pki/pki-tomcat/ca_admin.key}"
CA_BUNDLE="${CA_BUNDLE:-/etc/pki/pki-tomcat/ca/signing.crt}"

EST_BASE="${KIPUKA_URL}/.well-known/est"
CURL_OPTS="-sk --connect-timeout 10 --max-time 60"
TMPDIR="${TMPDIR:-/tmp}/kipuka-dogtag-test-$$"

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

if ! command -v pki &>/dev/null; then
    skip "pki CLI not found — Dogtag-specific checks will be skipped"
    PKI_CLI=false
else
    pass "pki CLI is available"
    PKI_CLI=true
fi

# Verify kipuka is reachable
HTTP_CODE=$(curl ${CURL_OPTS} -o /dev/null -w '%{http_code}' "${EST_BASE}/cacerts" 2>/dev/null || echo "000")
if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "kipuka EST server is reachable"
else
    fail "kipuka EST server unreachable (HTTP ${HTTP_CODE})"
    echo "  Cannot continue without a running kipuka instance."
    exit 1
fi

# ── Test 1: Enroll via kipuka, verify cert in Dogtag ─────────────────────────

section "Enrollment via kipuka → Dogtag"

# Generate CSR
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${TMPDIR}/dogtag-test.key" \
    -out "${TMPDIR}/dogtag-test.csr" \
    -subj "/CN=dogtag-integ-test.kipuka.test/O=Integration Test/C=US" \
    2>/dev/null

openssl req -in "${TMPDIR}/dogtag-test.csr" -outform DER -out "${TMPDIR}/dogtag-test.csr.der"
CSR_B64=$(b64encode "${TMPDIR}/dogtag-test.csr.der")

# Generate OTP
OTP_RESPONSE=$(curl ${CURL_OPTS} \
    -X POST \
    -H "Authorization: Bearer test-admin-token" \
    -H "Content-Type: application/json" \
    -d '{"subject": "CN=dogtag-integ-test.kipuka.test"}' \
    "${ADMIN_URL}/admin/otp/generate" 2>/dev/null || echo "")

OTP_TOKEN=$(echo "${OTP_RESPONSE}" | jq -r '.otp // .token // empty' 2>/dev/null || true)

if [[ -z "${OTP_TOKEN}" ]]; then
    skip "Cannot generate OTP — enrollment test skipped"
else
    # Enroll via kipuka
    HTTP_CODE=$(curl ${CURL_OPTS} \
        -o "${TMPDIR}/dogtag-enrolled.raw" \
        -w '%{http_code}' \
        -X POST \
        -u ":${OTP_TOKEN}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${CSR_B64}" \
        "${EST_BASE}/simpleenroll" 2>/dev/null || echo "000")

    if [[ "${HTTP_CODE}" == "200" ]]; then
        pass "Enrollment via kipuka returned HTTP 200"

        # Extract the serial number from the issued certificate
        if base64 -d "${TMPDIR}/dogtag-enrolled.raw" > "${TMPDIR}/dogtag-enrolled.der" 2>/dev/null; then
            SERIAL=$(openssl x509 -inform DER -in "${TMPDIR}/dogtag-enrolled.der" -serial -noout 2>/dev/null \
                | sed 's/serial=//' || true)

            if [[ -n "${SERIAL}" ]]; then
                pass "Issued certificate serial: ${SERIAL}"

                # Verify the cert exists in Dogtag
                if [[ "${PKI_CLI}" == "true" ]]; then
                    if pki -d /root/.dogtag/nssdb -c Secret.123 ca-cert-show "${SERIAL}" &>/dev/null; then
                        pass "Certificate ${SERIAL} found in Dogtag CA"
                    else
                        fail "Certificate ${SERIAL} NOT found in Dogtag CA"
                    fi
                else
                    skip "Dogtag cert verification (pki CLI not available)"
                fi
            else
                fail "Could not extract serial from issued certificate"
            fi
        else
            fail "Could not decode enrollment response"
        fi
    elif [[ "${HTTP_CODE}" == "202" ]]; then
        pass "Enrollment returned HTTP 202 (deferred to Dogtag)"
    else
        fail "Enrollment via kipuka returned HTTP ${HTTP_CODE}"
    fi
fi

# ── Test 2: Revoke via kipuka, verify in Dogtag ─────────────────────────────

section "Revocation via kipuka → Dogtag"

if [[ -n "${SERIAL:-}" ]]; then
    HTTP_CODE=$(curl ${CURL_OPTS} \
        -o "${TMPDIR}/revoke-response.json" \
        -w '%{http_code}' \
        -X POST \
        -H "Authorization: Bearer test-admin-token" \
        -H "Content-Type: application/json" \
        -d '{"reason": "cessationOfOperation"}' \
        "${ADMIN_URL}/admin/certs/${SERIAL}/revoke" 2>/dev/null || echo "000")

    if [[ "${HTTP_CODE}" == "200" || "${HTTP_CODE}" == "204" ]]; then
        pass "Revocation via kipuka returned HTTP ${HTTP_CODE}"

        # Verify revocation in Dogtag
        if [[ "${PKI_CLI}" == "true" ]]; then
            CERT_STATUS=$(pki -d /root/.dogtag/nssdb -c Secret.123 ca-cert-show "${SERIAL}" 2>/dev/null \
                | grep -i "Status:" | awk '{print $2}' || true)
            if [[ "${CERT_STATUS}" == "REVOKED" ]]; then
                pass "Certificate ${SERIAL} is REVOKED in Dogtag"
            else
                fail "Certificate ${SERIAL} status in Dogtag: ${CERT_STATUS} (expected REVOKED)"
            fi
        else
            skip "Dogtag revocation verification (pki CLI not available)"
        fi
    else
        fail "Revocation via kipuka returned HTTP ${HTTP_CODE}"
    fi
else
    skip "Revocation test (no certificate serial available)"
fi

# ── Test 3: Profile query via /csrattrs ──────────────────────────────────────

section "Profile query (/csrattrs) → Dogtag"

HTTP_CODE=$(curl ${CURL_OPTS} -o "${TMPDIR}/csrattrs.raw" -w '%{http_code}' \
    "${EST_BASE}/csrattrs" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "GET /csrattrs returned HTTP 200"

    # Verify attributes match Dogtag profile
    if [[ "${PKI_CLI}" == "true" ]]; then
        # List Dogtag profiles to compare
        pki -d /root/.dogtag/nssdb -c Secret.123 ca-profile-find --size 5 &>/dev/null \
            && pass "Dogtag profiles accessible for comparison" \
            || skip "Cannot list Dogtag profiles"
    fi
elif [[ "${HTTP_CODE}" == "204" ]]; then
    pass "GET /csrattrs returned 204 (no attributes)"
else
    fail "GET /csrattrs returned HTTP ${HTTP_CODE}"
fi

# ── Test 4: Full CMC passthrough ─────────────────────────────────────────────

section "Full CMC passthrough → Dogtag"

# Full CMC requires a properly formatted CMC request with the CMC-request
# content type.  This test validates the content-type enforcement at minimum.

HTTP_CODE=$(curl ${CURL_OPTS} \
    -o /dev/null \
    -w '%{http_code}' \
    -X POST \
    -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
    -H "Content-Transfer-Encoding: base64" \
    --data-binary "dGVzdA==" \
    "${EST_BASE}/fullcmc" 2>/dev/null || echo "000")

# Full CMC without proper auth and valid CMC body should return 401 or 400
if [[ "${HTTP_CODE}" == "401" || "${HTTP_CODE}" == "400" || "${HTTP_CODE}" == "403" ]]; then
    pass "Full CMC endpoint accepts correct content-type (rejected for auth/content: HTTP ${HTTP_CODE})"
else
    fail "Full CMC endpoint returned unexpected HTTP ${HTTP_CODE}"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " Dogtag Integration Test Results"
echo "============================================"
green " PASSED: ${PASS}"
[[ ${FAIL} -gt 0 ]] && red  " FAILED: ${FAIL}" || echo " FAILED: 0"
[[ ${SKIP} -gt 0 ]] && yellow " SKIPPED: ${SKIP}" || echo " SKIPPED: 0"
echo "============================================"

[[ ${FAIL} -gt 0 ]] && exit 1
exit 0
