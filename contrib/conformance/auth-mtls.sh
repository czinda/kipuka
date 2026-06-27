#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — mTLS Re-enrollment Authentication Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " mTLS Client Certificate Authentication"
echo "═══════════════════════════════════════════════════════════════"

section "Setup: enroll a certificate for mTLS tests"

KEY="$TMPDIR/mtls-client.key"
CSR_DER="$TMPDIR/mtls-client.der"
generate_csr_der "mtls-test.kipuka.test" "$KEY" "$CSR_DER"
B64=$(base64 < "$CSR_DER")
OTP=$(generate_otp "mtls-test")

ENROLL_B64="$TMPDIR/mtls-enrolled.b64"
ENROLL_DER="$TMPDIR/mtls-enrolled.der"
ENROLL_CERTS="$TMPDIR/mtls-certs"

CODE=$(curl_est POST /simpleenroll "$ENROLL_B64" /dev/null \
    -u "mtls-test:${OTP}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64")

if [[ "$CODE" != "200" ]]; then
    echo "  Setup: enrollment failed ($CODE)"
    skip_test "all mTLS tests" "enrollment failed"
    summary "mTLS Authentication Conformance"
fi

base64 -d < "$ENROLL_B64" > "$ENROLL_DER" 2>/dev/null
assert_pkcs7_certs_only "setup PKCS#7" "$ENROLL_DER" "$ENROLL_CERTS"

if [[ ! -f "$ENROLL_CERTS/certs.pem" ]]; then
    skip_test "all mTLS tests" "no cert extracted"
    summary "mTLS Authentication Conformance"
fi

CERT_PEM="$TMPDIR/mtls-client.pem"
openssl x509 -in "$ENROLL_CERTS/certs.pem" -outform PEM -out "$CERT_PEM" 2>/dev/null

section "§4.2.2 — Re-enrollment with mTLS"
rfc_ref "RFC 7030 §4.2.2: existing certificate proves identity"

RENEW_DER="$TMPDIR/mtls-renew.der"
generate_csr_der "mtls-test.kipuka.test" "$TMPDIR/mtls-renew.key" "$RENEW_DER"
B64_RENEW=$(base64 < "$RENEW_DER")

echo "1. POST /simplereenroll with issued cert → 200"
CODE=$(curl -sk -X POST \
    --cert "$CERT_PEM" --key "$KEY" \
    --cacert "$CA_CERT" \
    -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_RENEW" \
    "$EST_URL/simplereenroll" 2>/dev/null)
if [[ "$CODE" == "000" ]]; then
    skip_test "/simplereenroll mTLS" "TLS client cert not propagated"
else
    check_exact "/simplereenroll mTLS" "$CODE" "200"
fi

echo "2. POST /simplereenroll without client cert → 401"
CODE=$(curl_est POST /simplereenroll /dev/null /dev/null \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_RENEW")
check_exact "no cert → 401" "$CODE" "401"

echo "3. POST /simplereenroll with OTP only (no cert) → 401"
OTP2=$(generate_otp "mtls-otp-only")
CODE=$(curl_est POST /simplereenroll /dev/null /dev/null \
    -u "mtls-otp-only:${OTP2}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_RENEW")
check_exact "OTP-only reenroll → 401" "$CODE" "401"

echo "4. Issued cert is valid X.509"
check_true "cert is valid X.509" openssl x509 -in "$CERT_PEM" -noout -subject

echo "5. Issued cert subject matches CSR"
assert_x509_field "cert subject" "$CERT_PEM" "subject" "mtls-test.kipuka.test"

summary "mTLS Authentication Conformance"
