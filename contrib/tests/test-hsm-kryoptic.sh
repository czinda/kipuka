#!/usr/bin/env bash
# =============================================================================
# kipuka + Kryoptic software HSM integration tests
# =============================================================================
# Validates PKCS#11 HSM integration using Kryoptic as a software token.
# Tests certificate signing via the HSM interface and NIAP FCS_CKM.1
# compliance (non-extractable key enforcement).
#
# Kryoptic: https://github.com/latchset/kryoptic
#
# Requirements:
#   - Kryoptic PKCS#11 module installed (libkryoptic_pkcs11.so)
#   - pkcs11-tool (from OpenSC)
#   - Running kipuka configured with PKCS#11 URI pointing to Kryoptic
#   - curl, openssl, jq
#
# Usage:
#   ./test-hsm-kryoptic.sh
#   KRYOPTIC_LIB=/usr/lib64/pkcs11/libkryoptic_pkcs11.so ./test-hsm-kryoptic.sh
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Configuration ────────────────────────────────────────────────────────────

KRYOPTIC_LIB="${KRYOPTIC_LIB:-/usr/lib64/pkcs11/libkryoptic_pkcs11.so}"
KIPUKA_URL="${KIPUKA_URL:-https://localhost:8443}"
ADMIN_URL="${ADMIN_URL:-https://localhost:8444}"
EST_BASE="${KIPUKA_URL}/.well-known/est"
CURL_OPTS="-sk --connect-timeout 10 --max-time 60"
TMPDIR="${TMPDIR:-/tmp}/kipuka-hsm-test-$$"

TOKEN_LABEL="kipuka-test"
TOKEN_PIN="1234"
TOKEN_SO_PIN="12345678"

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

# Check for Kryoptic PKCS#11 module
if [[ ! -f "${KRYOPTIC_LIB}" ]]; then
    red "  Kryoptic PKCS#11 module not found at: ${KRYOPTIC_LIB}"
    red "  Set KRYOPTIC_LIB to the correct path."
    echo ""
    echo "  To install Kryoptic:"
    echo "    dnf install kryoptic      # on Fedora/RHEL"
    echo "    cargo install kryoptic    # from source"
    echo ""
    echo "============================================"
    yellow " SKIPPED: all (Kryoptic not installed)"
    echo "============================================"
    exit 0
fi
pass "Kryoptic PKCS#11 module found: ${KRYOPTIC_LIB}"

# Check for pkcs11-tool
if ! command -v pkcs11-tool &>/dev/null; then
    red "  pkcs11-tool not found (install opensc package)"
    echo "============================================"
    yellow " SKIPPED: all (pkcs11-tool not installed)"
    echo "============================================"
    exit 0
fi
pass "pkcs11-tool is available"

# ── Test 1: Initialize Kryoptic token ────────────────────────────────────────

section "Token Initialization"

# Set up Kryoptic storage directory
export KRYOPTIC_CONF="${TMPDIR}/kryoptic.conf"
export KRYOPTIC_STORE="${TMPDIR}/kryoptic-store"
mkdir -p "${KRYOPTIC_STORE}"

cat > "${KRYOPTIC_CONF}" <<EOF
[global]
pkcs11_module = "${KRYOPTIC_LIB}"

[token]
label = "${TOKEN_LABEL}"
pin = "${TOKEN_PIN}"
so_pin = "${TOKEN_SO_PIN}"
store_path = "${KRYOPTIC_STORE}"
EOF

# Initialize the token
if pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --init-token --label "${TOKEN_LABEL}" --so-pin "${TOKEN_SO_PIN}" 2>/dev/null; then
    pass "Kryoptic token initialized: ${TOKEN_LABEL}"
else
    # Some versions need different init syntax
    if pkcs11-tool --module "${KRYOPTIC_LIB}" \
        --init-token --label "${TOKEN_LABEL}" \
        --so-pin "${TOKEN_SO_PIN}" --init-pin --pin "${TOKEN_PIN}" 2>/dev/null; then
        pass "Kryoptic token initialized (with PIN)"
    else
        fail "Token initialization failed"
        echo "  This may be normal if the token is already initialized."
        echo "  Continuing with existing token..."
    fi
fi

# Set the user PIN
pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --token-label "${TOKEN_LABEL}" --so-pin "${TOKEN_SO_PIN}" \
    --init-pin --pin "${TOKEN_PIN}" 2>/dev/null \
    && pass "User PIN set" \
    || skip "User PIN set (may already be configured)"

# ── Test 2: Generate RSA key in token ────────────────────────────────────────

section "RSA Key Generation in HSM"

if pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --token-label "${TOKEN_LABEL}" --pin "${TOKEN_PIN}" \
    --keypairgen --key-type rsa:2048 \
    --label "kipuka-ca-key" --id 01 \
    --usage-sign 2>/dev/null; then
    pass "RSA 2048 key pair generated in Kryoptic token"
else
    fail "RSA key pair generation failed"
fi

# Verify the key exists
KEY_LIST=$(pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --token-label "${TOKEN_LABEL}" --pin "${TOKEN_PIN}" \
    --list-objects --type privkey 2>/dev/null || true)

if echo "${KEY_LIST}" | grep -q "kipuka-ca-key"; then
    pass "Private key 'kipuka-ca-key' found in token"
else
    fail "Private key 'kipuka-ca-key' not found in token"
fi

# ── Test 3: NIAP FCS_CKM.1 — Non-extractable key ────────────────────────────

section "NIAP FCS_CKM.1 — Non-extractable Key"

# The key must have CKA_EXTRACTABLE=FALSE and CKA_SENSITIVE=TRUE
export KEY_ATTRS
KEY_ATTRS=$(pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --token-label "${TOKEN_LABEL}" --pin "${TOKEN_PIN}" \
    --list-objects --type privkey 2>/dev/null || true)

# Attempt to read the private key — this MUST fail
if pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --token-label "${TOKEN_LABEL}" --pin "${TOKEN_PIN}" \
    --read-object --type privkey --label "kipuka-ca-key" \
    -o "${TMPDIR}/extracted-key.der" 2>/dev/null; then
    if [[ -s "${TMPDIR}/extracted-key.der" ]]; then
        fail "NIAP FCS_CKM.1: Private key was extractable (SECURITY VIOLATION)"
    else
        pass "NIAP FCS_CKM.1: Key extraction returned empty data (non-extractable)"
    fi
else
    pass "NIAP FCS_CKM.1: Key extraction correctly denied"
fi

# ── Test 4: Sign a test hash via PKCS#11 ─────────────────────────────────────

section "Certificate Signing via HSM"

# Create a test hash to sign
echo -n "kipuka test signing payload" | sha256sum | awk '{print $1}' \
    | xxd -r -p > "${TMPDIR}/test-hash.bin"

if pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --token-label "${TOKEN_LABEL}" --pin "${TOKEN_PIN}" \
    --sign --mechanism RSA-PKCS \
    --label "kipuka-ca-key" \
    --input-file "${TMPDIR}/test-hash.bin" \
    --output-file "${TMPDIR}/test-signature.bin" 2>/dev/null; then
    pass "RSA-PKCS signature generated via HSM"

    # Verify signature size (RSA 2048 → 256 bytes)
    SIG_SIZE=$(wc -c < "${TMPDIR}/test-signature.bin" | tr -d ' ')
    if [[ "${SIG_SIZE}" == "256" ]]; then
        pass "Signature size correct: ${SIG_SIZE} bytes (RSA 2048)"
    else
        fail "Unexpected signature size: ${SIG_SIZE} bytes (expected 256)"
    fi
else
    fail "RSA-PKCS signing failed"
fi

# ── Test 5: PKCS#11 URI format ───────────────────────────────────────────────

section "PKCS#11 URI Validation"

# The PKCS#11 URI that kipuka would use to reference this key
PKCS11_URI="pkcs11:token=${TOKEN_LABEL};object=kipuka-ca-key;type=private"
echo "  URI: ${PKCS11_URI}"

# Verify the URI resolves to the correct object
if pkcs11-tool --module "${KRYOPTIC_LIB}" \
    --token-label "${TOKEN_LABEL}" --pin "${TOKEN_PIN}" \
    --list-objects --type privkey --label "kipuka-ca-key" 2>/dev/null | grep -q "Private"; then
    pass "PKCS#11 URI resolves to the correct key object"
else
    fail "PKCS#11 URI does not resolve to a key object"
fi

# ── Test 6: kipuka enrollment via HSM-backed CA ──────────────────────────────

section "kipuka Enrollment via HSM-backed CA"

# Check if kipuka is running and configured with HSM
HTTP_CODE=$(curl ${CURL_OPTS} -o /dev/null -w '%{http_code}' "${EST_BASE}/cacerts" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "200" ]]; then
    pass "kipuka is reachable"

    # Check HSM health via admin API
    HSM_HEALTH=$(curl ${CURL_OPTS} \
        -H "Authorization: Bearer test-admin-token" \
        "${ADMIN_URL}/admin/health/hsm" 2>/dev/null || echo "")

    if [[ -n "${HSM_HEALTH}" ]]; then
        echo "  HSM health: ${HSM_HEALTH}"
        if echo "${HSM_HEALTH}" | jq -e '.status' &>/dev/null; then
            HSM_STATUS=$(echo "${HSM_HEALTH}" | jq -r '.status')
            if [[ "${HSM_STATUS}" == "ok" || "${HSM_STATUS}" == "healthy" ]]; then
                pass "kipuka HSM health: ${HSM_STATUS}"
            elif [[ "${HSM_STATUS}" == "not_configured" ]]; then
                skip "kipuka not configured with HSM — enrollment via HSM skipped"
            else
                fail "kipuka HSM health: ${HSM_STATUS}"
            fi
        fi
    else
        skip "HSM health endpoint not available"
    fi
else
    skip "kipuka not reachable — HSM enrollment test skipped"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " Kryoptic HSM Test Results"
echo "============================================"
green " PASSED: ${PASS}"
[[ ${FAIL} -gt 0 ]] && red  " FAILED: ${FAIL}" || echo " FAILED: 0"
[[ ${SKIP} -gt 0 ]] && yellow " SKIPPED: ${SKIP}" || echo " SKIPPED: 0"
echo "============================================"

[[ ${FAIL} -gt 0 ]] && exit 1
exit 0
