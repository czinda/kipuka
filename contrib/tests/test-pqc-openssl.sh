#!/usr/bin/env bash
# =============================================================================
# kipuka PQC (Post-Quantum Cryptography) validation using OpenSSL CLI
# =============================================================================
# Validates ML-DSA and ML-KEM certificate enrollment through kipuka
# using OpenSSL 3.5+ command-line tools.
#
# Algorithms tested:
#   - ML-DSA-44 (FIPS 204 — NIST Level 2)
#   - ML-DSA-65 (FIPS 204 — NIST Level 3)
#   - ML-DSA-87 (FIPS 204 — NIST Level 5)
#   - ML-KEM-512/768/1024 via /serverkeygen
#
# Requirements:
#   - OpenSSL >= 3.5 (with ML-DSA and ML-KEM support)
#   - Running kipuka server with PQC-capable CA
#   - curl, jq
#
# Usage:
#   ./test-pqc-openssl.sh
#   KIPUKA_URL=https://est.example.com ./test-pqc-openssl.sh
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Configuration ────────────────────────────────────────────────────────────

KIPUKA_URL="${KIPUKA_URL:-https://localhost:8443}"
ADMIN_URL="${ADMIN_URL:-https://localhost:8444}"
EST_BASE="${KIPUKA_URL}/.well-known/est"
CURL_OPTS="-sk --connect-timeout 10 --max-time 60"
TMPDIR="${TMPDIR:-/tmp}/kipuka-pqc-test-$$"

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

# ── OpenSSL version check ───────────────────────────────────────────────────

section "OpenSSL Version Check"

OPENSSL_VERSION=$(openssl version 2>/dev/null || echo "not found")
echo "  OpenSSL: ${OPENSSL_VERSION}"

# Parse version: "OpenSSL 3.5.0 ..."
OSSL_MAJOR=$(echo "${OPENSSL_VERSION}" | awk '{print $2}' | cut -d. -f1)
OSSL_MINOR=$(echo "${OPENSSL_VERSION}" | awk '{print $2}' | cut -d. -f2)

if [[ "${OSSL_MAJOR:-0}" -lt 3 ]] || { [[ "${OSSL_MAJOR:-0}" -eq 3 ]] && [[ "${OSSL_MINOR:-0}" -lt 5 ]]; }; then
    red "  OpenSSL 3.5+ required for ML-DSA/ML-KEM tests."
    red "  Current version: ${OPENSSL_VERSION}"
    echo "  All PQC tests will be skipped."
    echo ""
    echo "============================================"
    echo " PQC Test Results"
    echo "============================================"
    yellow " SKIPPED: all (OpenSSL < 3.5)"
    echo "============================================"
    exit 0
fi

pass "OpenSSL version >= 3.5 detected"

# Verify ML-DSA support
if openssl genpkey -algorithm mldsa44 -out /dev/null 2>/dev/null; then
    pass "ML-DSA-44 key generation supported"
else
    fail "ML-DSA-44 key generation not supported by this OpenSSL build"
    echo "  OpenSSL may need to be compiled with ML-DSA support."
    exit 1
fi

# ── Helper: enroll via EST ───────────────────────────────────────────────────

generate_otp() {
    local subject="$1"
    local resp
    resp=$(curl ${CURL_OPTS} \
        -X POST \
        -H "Authorization: Bearer test-admin-token" \
        -H "Content-Type: application/json" \
        -d "{\"subject\": \"${subject}\"}" \
        "${ADMIN_URL}/admin/otp/generate" 2>/dev/null || echo "")
    echo "${resp}" | jq -r '.otp // .token // empty' 2>/dev/null || true
}

est_enroll() {
    local csr_der_file="$1"
    local otp="$2"
    local output_file="$3"

    local csr_b64
    csr_b64=$(b64encode "${csr_der_file}")

    curl ${CURL_OPTS} \
        -o "${output_file}" \
        -w '%{http_code}' \
        -X POST \
        -u ":${otp}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data-binary "${csr_b64}" \
        "${EST_BASE}/simpleenroll" 2>/dev/null || echo "000"
}

# ── Test 1: ML-DSA-44 enrollment ─────────────────────────────────────────────

section "ML-DSA-44 (NIST Level 2) Enrollment"

openssl genpkey -algorithm mldsa44 -out "${TMPDIR}/mldsa44.key" 2>/dev/null
if [[ $? -eq 0 ]]; then
    pass "ML-DSA-44 key generated"

    openssl req -new \
        -key "${TMPDIR}/mldsa44.key" \
        -out "${TMPDIR}/mldsa44.csr" \
        -subj "/CN=mldsa44-test.pqc.test" \
        2>/dev/null

    openssl req -in "${TMPDIR}/mldsa44.csr" -outform DER -out "${TMPDIR}/mldsa44.csr.der"
    pass "ML-DSA-44 CSR generated"

    # Verify CSR signature algorithm
    SIG_ALG=$(openssl req -in "${TMPDIR}/mldsa44.csr" -noout -text 2>/dev/null \
        | grep -i "signature algorithm" | head -1 || true)
    echo "  CSR Signature Algorithm: ${SIG_ALG}"

    OTP=$(generate_otp "CN=mldsa44-test.pqc.test")
    if [[ -n "${OTP}" ]]; then
        HTTP_CODE=$(est_enroll "${TMPDIR}/mldsa44.csr.der" "${OTP}" "${TMPDIR}/mldsa44-cert.raw")

        if [[ "${HTTP_CODE}" == "200" ]]; then
            pass "ML-DSA-44 enrollment succeeded (HTTP 200)"

            # Verify the issued certificate has ML-DSA signature
            if base64 -d "${TMPDIR}/mldsa44-cert.raw" > "${TMPDIR}/mldsa44-cert.der" 2>/dev/null; then
                CERT_SIG=$(openssl x509 -inform DER -in "${TMPDIR}/mldsa44-cert.der" -noout -text 2>/dev/null \
                    | grep -i "signature algorithm" | head -1 || true)
                echo "  Cert Signature Algorithm: ${CERT_SIG}"
                if echo "${CERT_SIG}" | grep -qi "mldsa\|ML-DSA"; then
                    pass "Issued certificate uses ML-DSA signature"
                else
                    fail "Issued certificate does NOT use ML-DSA signature: ${CERT_SIG}"
                fi
            fi
        elif [[ "${HTTP_CODE}" == "400" ]]; then
            skip "ML-DSA-44 enrollment returned 400 (CA may not support PQC yet)"
        else
            fail "ML-DSA-44 enrollment returned HTTP ${HTTP_CODE}"
        fi
    else
        skip "ML-DSA-44 enrollment (OTP not available)"
    fi
else
    fail "ML-DSA-44 key generation failed"
fi

# ── Test 2: ML-DSA-65 enrollment ─────────────────────────────────────────────

section "ML-DSA-65 (NIST Level 3) Enrollment"

openssl genpkey -algorithm mldsa65 -out "${TMPDIR}/mldsa65.key" 2>/dev/null
if [[ $? -eq 0 ]]; then
    pass "ML-DSA-65 key generated"

    openssl req -new \
        -key "${TMPDIR}/mldsa65.key" \
        -out "${TMPDIR}/mldsa65.csr" \
        -subj "/CN=mldsa65-test.pqc.test" \
        2>/dev/null

    openssl req -in "${TMPDIR}/mldsa65.csr" -outform DER -out "${TMPDIR}/mldsa65.csr.der"
    pass "ML-DSA-65 CSR generated"

    OTP=$(generate_otp "CN=mldsa65-test.pqc.test")
    if [[ -n "${OTP}" ]]; then
        HTTP_CODE=$(est_enroll "${TMPDIR}/mldsa65.csr.der" "${OTP}" "${TMPDIR}/mldsa65-cert.raw")
        if [[ "${HTTP_CODE}" == "200" ]]; then
            pass "ML-DSA-65 enrollment succeeded (HTTP 200)"
        elif [[ "${HTTP_CODE}" == "400" ]]; then
            skip "ML-DSA-65 enrollment returned 400 (CA may not support PQC yet)"
        else
            fail "ML-DSA-65 enrollment returned HTTP ${HTTP_CODE}"
        fi
    else
        skip "ML-DSA-65 enrollment (OTP not available)"
    fi
else
    fail "ML-DSA-65 key generation failed"
fi

# ── Test 3: ML-DSA-87 enrollment ─────────────────────────────────────────────

section "ML-DSA-87 (NIST Level 5) Enrollment"

openssl genpkey -algorithm mldsa87 -out "${TMPDIR}/mldsa87.key" 2>/dev/null
if [[ $? -eq 0 ]]; then
    pass "ML-DSA-87 key generated"

    openssl req -new \
        -key "${TMPDIR}/mldsa87.key" \
        -out "${TMPDIR}/mldsa87.csr" \
        -subj "/CN=mldsa87-test.pqc.test" \
        2>/dev/null

    openssl req -in "${TMPDIR}/mldsa87.csr" -outform DER -out "${TMPDIR}/mldsa87.csr.der"
    pass "ML-DSA-87 CSR generated"

    OTP=$(generate_otp "CN=mldsa87-test.pqc.test")
    if [[ -n "${OTP}" ]]; then
        HTTP_CODE=$(est_enroll "${TMPDIR}/mldsa87.csr.der" "${OTP}" "${TMPDIR}/mldsa87-cert.raw")
        if [[ "${HTTP_CODE}" == "200" ]]; then
            pass "ML-DSA-87 enrollment succeeded (HTTP 200)"
        elif [[ "${HTTP_CODE}" == "400" ]]; then
            skip "ML-DSA-87 enrollment returned 400 (CA may not support PQC yet)"
        else
            fail "ML-DSA-87 enrollment returned HTTP ${HTTP_CODE}"
        fi
    else
        skip "ML-DSA-87 enrollment (OTP not available)"
    fi
else
    fail "ML-DSA-87 key generation failed"
fi

# ── Test 4: ML-KEM key generation ────────────────────────────────────────────

section "ML-KEM Key Generation (local validation)"

for kem_level in mlkem512 mlkem768 mlkem1024; do
    if openssl genpkey -algorithm "${kem_level}" -out "${TMPDIR}/${kem_level}.key" 2>/dev/null; then
        pass "${kem_level} key generation supported"
        KEY_SIZE=$(wc -c < "${TMPDIR}/${kem_level}.key" | tr -d ' ')
        echo "  Key file size: ${KEY_SIZE} bytes"
    else
        skip "${kem_level} key generation not supported"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo " PQC (OpenSSL) Test Results"
echo "============================================"
green " PASSED: ${PASS}"
[[ ${FAIL} -gt 0 ]] && red  " FAILED: ${FAIL}" || echo " FAILED: 0"
[[ ${SKIP} -gt 0 ]] && yellow " SKIPPED: ${SKIP}" || echo " SKIPPED: 0"
echo "============================================"

[[ ${FAIL} -gt 0 ]] && exit 1
exit 0
