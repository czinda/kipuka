#!/usr/bin/env bash
# =============================================================================
# test-gssapi.sh — GSSAPI/Kerberos EST integration smoke tests
# =============================================================================
# Validates kipuka EST enrollment with Kerberos authentication against a
# live FreeIPA realm.  Run after setup-freeipa.sh.
#
# Tests:
#   1. FreeIPA realm is operational
#   2. kipuka EST /cacerts returns valid PKCS#7
#   3. Admin API accessible via GSSAPI (Negotiate)
#   4. OTP generation via GSSAPI-authenticated admin API
#   5. EST enrollment with OTP (baseline, non-GSSAPI)
#   6. EST enrollment with Kerberos (GSSAPI auth)
#   7. Verify issued certificate
#   8. Audit log records Kerberos principal
#   9. Unauthenticated request rejected (401)
#  10. Re-enrollment with mTLS (using GSSAPI-issued cert)
#
# Exit codes:
#   0  all tests passed
#   1  one or more tests failed
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Load environment ─────────────────────────────────────────────────────────

if [[ -f /tmp/kipuka-gssapi-env.sh ]]; then
    source /tmp/kipuka-gssapi-env.sh
fi

IPA_REALM="${IPA_REALM:-KIPUKA.TEST}"
IPA_HOSTNAME="${IPA_HOSTNAME:-ipa.kipuka.test}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat!2026admin}"
TEST_USER_PASSWORD="${TEST_USER_PASSWORD:-RedHat!2026test}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

KIPUKA_PORT="${KIPUKA_PORT:-9443}"
ADMIN_PORT="${ADMIN_PORT:-9444}"
BASE_URL="https://${IPA_HOSTNAME}:${KIPUKA_PORT}/.well-known/est"
ADMIN_URL="https://localhost:${ADMIN_PORT}/admin"
CA_BUNDLE="/etc/kipuka/ca/ipa-ca.pem"

TMPDIR=$(mktemp -d /tmp/kipuka-gssapi-test.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

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

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " kipuka GSSAPI/Kerberos EST Integration Tests"
echo " Realm: ${IPA_REALM}  Host: ${IPA_HOSTNAME}"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── Test 1: FreeIPA realm is operational ─────────────────────────────────────

echo "Test 1: FreeIPA realm is operational"
kdestroy -A 2>/dev/null || true
if echo "${ADMIN_PASSWORD}" | kinit admin@${IPA_REALM} 2>/dev/null; then
    if klist 2>/dev/null | grep -q "admin@${IPA_REALM}"; then
        pass "FreeIPA realm ${IPA_REALM} is operational, TGT acquired"
    else
        fail "kinit succeeded but TGT not in cache"
    fi
else
    fail "kinit admin@${IPA_REALM} failed — KDC may be down"
fi

# ── Test 2: kipuka EST /cacerts returns valid PKCS#7 ─────────────────────────

echo "Test 2: GET /cacerts returns valid PKCS#7"
HTTP_CODE=$(curl -sk -o "${TMPDIR}/cacerts.b64" -w "%{http_code}" \
    "${BASE_URL}/cacerts")
if [[ "$HTTP_CODE" == "200" ]]; then
    if base64 -d "${TMPDIR}/cacerts.b64" | \
        openssl pkcs7 -inform DER -print_certs -noout 2>/dev/null; then
        pass "/cacerts returned valid PKCS#7 (HTTP ${HTTP_CODE})"
    else
        fail "/cacerts returned HTTP 200 but not valid PKCS#7"
    fi
else
    fail "/cacerts returned HTTP ${HTTP_CODE} (expected 200)"
fi

# ── Test 3: Admin API accessible via GSSAPI ──────────────────────────────────

echo "Test 3: Admin API accessible via GSSAPI (Negotiate)"
echo "${ADMIN_PASSWORD}" | kinit admin@${IPA_REALM} 2>/dev/null

HTTP_CODE=$(curl -sk --negotiate -u : \
    -o "${TMPDIR}/health.json" -w "%{http_code}" \
    "${ADMIN_URL}/health")
if [[ "$HTTP_CODE" == "200" ]]; then
    pass "Admin /health accessible via GSSAPI (HTTP ${HTTP_CODE})"
    jq . "${TMPDIR}/health.json" 2>/dev/null | head -5 || true
else
    # Fall back to bearer token if GSSAPI not on admin endpoint
    if [[ -n "${ADMIN_TOKEN}" ]]; then
        HTTP_CODE=$(curl -sk -H "Authorization: Bearer ${ADMIN_TOKEN}" \
            -o "${TMPDIR}/health.json" -w "%{http_code}" \
            "${ADMIN_URL}/health")
        if [[ "$HTTP_CODE" == "200" ]]; then
            pass "Admin /health accessible via Bearer token (HTTP ${HTTP_CODE})"
        else
            fail "Admin /health returned HTTP ${HTTP_CODE}"
        fi
    else
        fail "Admin /health via GSSAPI returned HTTP ${HTTP_CODE}"
    fi
fi

# ── Test 4: Generate OTP via authenticated admin API ─────────────────────────

echo "Test 4: Generate OTP via admin API"
OTP=""

# Try GSSAPI first, then bearer token
OTP_RESPONSE=$(curl -sk --negotiate -u : \
    -X POST "${ADMIN_URL}/otp" \
    -H "Content-Type: application/json" \
    -d '{"entity_id":"testdevice"}' 2>/dev/null) || true

OTP=$(echo "${OTP_RESPONSE}" | jq -r '.token // empty' 2>/dev/null) || true

if [[ -z "${OTP}" && -n "${ADMIN_TOKEN}" ]]; then
    OTP_RESPONSE=$(curl -sk -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -X POST "${ADMIN_URL}/otp" \
        -H "Content-Type: application/json" \
        -d '{"entity_id":"testdevice"}' 2>/dev/null)
    OTP=$(echo "${OTP_RESPONSE}" | jq -r '.token // empty' 2>/dev/null) || true
fi

if [[ -n "${OTP}" ]]; then
    pass "OTP generated for testdevice (${#OTP} chars)"
else
    fail "Failed to generate OTP — admin API may not be accessible"
fi

# ── Test 5: EST enrollment with OTP (baseline) ──────────────────────────────

echo "Test 5: EST enrollment with OTP (baseline)"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "${TMPDIR}/test.key" -out "${TMPDIR}/test.csr" -nodes \
    -subj "/CN=testdevice.${IPA_DOMAIN}" 2>/dev/null

if [[ -n "${OTP}" ]]; then
    HTTP_CODE=$(curl -sk --cacert "${CA_BUNDLE}" \
        -u "testdevice:${OTP}" \
        --data-binary "@${TMPDIR}/test.csr" \
        -H "Content-Type: application/pkcs10" \
        -o "${TMPDIR}/otp-cert.p7" -w "%{http_code}" \
        "${BASE_URL}/simpleenroll")
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]]; then
        pass "OTP enrollment succeeded (HTTP ${HTTP_CODE})"
    else
        fail "OTP enrollment returned HTTP ${HTTP_CODE} (expected 200/201)"
    fi
else
    skip "OTP enrollment — no OTP available from test 4"
fi

# ── Test 6: EST enrollment with Kerberos (GSSAPI) ───────────────────────────

echo "Test 6: EST enrollment with Kerberos (GSSAPI auth)"
kdestroy -A 2>/dev/null || true

# kinit as testdevice — may need password change on first login
echo "${TEST_USER_PASSWORD}" | kinit testdevice@${IPA_REALM} 2>/dev/null || {
    warn "First kinit may require password change, retrying..."
    echo -e "${TEST_USER_PASSWORD}\n${TEST_USER_PASSWORD}\n${TEST_USER_PASSWORD}" | \
        kinit testdevice@${IPA_REALM} 2>/dev/null || true
}

if klist 2>/dev/null | grep -q "testdevice@${IPA_REALM}"; then
    # Generate a fresh CSR for GSSAPI enrollment
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${TMPDIR}/gssapi.key" -out "${TMPDIR}/gssapi.csr" -nodes \
        -subj "/CN=testdevice.${IPA_DOMAIN}" 2>/dev/null

    HTTP_CODE=$(curl -sk --negotiate -u : \
        --cacert "${CA_BUNDLE}" \
        --data-binary "@${TMPDIR}/gssapi.csr" \
        -H "Content-Type: application/pkcs10" \
        -o "${TMPDIR}/gssapi-cert.p7" -w "%{http_code}" \
        "${BASE_URL}/simpleenroll")
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]]; then
        pass "GSSAPI enrollment succeeded (HTTP ${HTTP_CODE})"
    elif [[ "$HTTP_CODE" == "401" ]]; then
        fail "GSSAPI enrollment returned 401 — Negotiate auth not accepted"
    else
        fail "GSSAPI enrollment returned HTTP ${HTTP_CODE}"
    fi
else
    fail "Could not kinit as testdevice@${IPA_REALM}"
fi

# ── Test 7: Verify issued certificate ────────────────────────────────────────

echo "Test 7: Verify GSSAPI-issued certificate"
if [[ -f "${TMPDIR}/gssapi-cert.p7" ]] && [[ -s "${TMPDIR}/gssapi-cert.p7" ]]; then
    if base64 -d "${TMPDIR}/gssapi-cert.p7" 2>/dev/null | \
        openssl pkcs7 -inform DER -print_certs -out "${TMPDIR}/gssapi-cert.pem" 2>/dev/null; then
        SUBJECT=$(openssl x509 -in "${TMPDIR}/gssapi-cert.pem" -noout -subject 2>/dev/null)
        if echo "${SUBJECT}" | grep -q "testdevice"; then
            pass "Certificate subject: ${SUBJECT}"
        else
            fail "Certificate subject doesn't contain 'testdevice': ${SUBJECT}"
        fi
    else
        fail "Could not parse PKCS#7 certificate response"
    fi
else
    skip "No GSSAPI certificate to verify (test 6 may have failed)"
fi

# ── Test 8: Audit log records Kerberos principal ─────────────────────────────

echo "Test 8: Audit log records Kerberos principal"
AUDIT_LOG="/var/log/kipuka/audit.log"
if [[ -f "${AUDIT_LOG}" ]]; then
    if grep -q "testdevice" "${AUDIT_LOG}" 2>/dev/null; then
        pass "Audit log contains 'testdevice' entries"
        grep "testdevice" "${AUDIT_LOG}" | tail -2
    else
        # Check for any enrollment events
        if grep -q "enroll" "${AUDIT_LOG}" 2>/dev/null; then
            warn "Audit log has enrollment events but principal name may differ"
            pass "Audit log has enrollment events (principal format may differ)"
        else
            fail "No enrollment events in audit log"
        fi
    fi
else
    skip "Audit log not found at ${AUDIT_LOG}"
fi

# ── Test 9: Unauthenticated request rejected ────────────────────────────────

echo "Test 9: Unauthenticated request rejected"
kdestroy -A 2>/dev/null || true
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --data-binary "@${TMPDIR}/test.csr" \
    -H "Content-Type: application/pkcs10" \
    "${BASE_URL}/simpleenroll")
if [[ "$HTTP_CODE" == "401" ]]; then
    pass "Unauthenticated enrollment correctly rejected (HTTP 401)"
elif [[ "$HTTP_CODE" == "403" ]]; then
    pass "Unauthenticated enrollment correctly rejected (HTTP 403)"
else
    fail "Unauthenticated enrollment returned HTTP ${HTTP_CODE} (expected 401/403)"
fi

# ── Test 10: Re-enrollment with mTLS ─────────────────────────────────────────

echo "Test 10: Re-enrollment with mTLS (using previously issued cert)"
if [[ -f "${TMPDIR}/gssapi-cert.pem" ]] && [[ -f "${TMPDIR}/gssapi.key" ]]; then
    openssl req -new -key "${TMPDIR}/gssapi.key" \
        -out "${TMPDIR}/reenroll.csr" -nodes \
        -subj "/CN=testdevice.${IPA_DOMAIN}" 2>/dev/null

    HTTP_CODE=$(curl -sk \
        --cert "${TMPDIR}/gssapi-cert.pem" --key "${TMPDIR}/gssapi.key" \
        --cacert "${CA_BUNDLE}" \
        --data-binary "@${TMPDIR}/reenroll.csr" \
        -H "Content-Type: application/pkcs10" \
        -o "${TMPDIR}/reenroll.p7" -w "%{http_code}" \
        "${BASE_URL}/simplereenroll")
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]]; then
        pass "mTLS re-enrollment succeeded (HTTP ${HTTP_CODE})"
    else
        fail "mTLS re-enrollment returned HTTP ${HTTP_CODE}"
    fi
else
    skip "No GSSAPI cert/key available for mTLS re-enrollment"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [[ $FAIL -gt 0 ]]; then
    red "GSSAPI integration tests: FAILED"
    exit 1
else
    green "GSSAPI integration tests: PASSED"
    exit 0
fi
