#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — EST Renewal Info Conformance (draft-ietf-lamps-est-renewal-info)
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " EST Renewal Info (draft-ietf-lamps-est-renewal-info)"
echo "═══════════════════════════════════════════════════════════════"

section "Setup: enroll a certificate"

KEY="$TMPDIR/ri-client.key"
CSR_DER="$TMPDIR/ri-client.der"
generate_csr_der "renewal-info-test.kipuka.test" "$KEY" "$CSR_DER"
B64=$(base64 < "$CSR_DER")
OTP=$(generate_otp "renewal-info-test")

ENROLL_B64="$TMPDIR/ri-enrolled.b64"
ENROLL_DER="$TMPDIR/ri-enrolled.der"
ENROLL_CERTS="$TMPDIR/ri-certs"

CODE=$(curl_est POST /simpleenroll "$ENROLL_B64" /dev/null \
    -u "renewal-info-test:${OTP}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64")

if [[ "$CODE" != "200" ]]; then
    skip_test "all renewal-info tests" "enrollment failed ($CODE)"
    summary "EST Renewal Info Conformance"
fi

base64 -d < "$ENROLL_B64" > "$ENROLL_DER" 2>/dev/null
assert_pkcs7_certs_only "setup PKCS#7" "$ENROLL_DER" "$ENROLL_CERTS"
CERT_PEM="$TMPDIR/ri-cert.pem"
openssl x509 -in "$ENROLL_CERTS/certs.pem" -outform PEM -out "$CERT_PEM" 2>/dev/null

# Build cert_id: base64url(AKI) + "." + base64url(serial)
SERIAL_HEX=$(openssl x509 -in "$CERT_PEM" -noout -serial 2>/dev/null | \
    sed 's/serial=//' | tr '[:upper:]' '[:lower:]')
AKI_HEX=$(openssl x509 -in "$CERT_PEM" -noout -text 2>/dev/null | \
    grep -A1 "Authority Key Identifier" | tail -1 | tr -d ' :' | tr '[:upper:]' '[:lower:]')

if [[ -z "$SERIAL_HEX" ]] || [[ -z "$AKI_HEX" ]]; then
    skip_test "all renewal-info tests" "could not extract serial/AKI"
    summary "EST Renewal Info Conformance"
fi

# Convert hex to binary then base64url
aki_b64url=$(echo -n "$AKI_HEX" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
serial_b64url=$(echo -n "$SERIAL_HEX" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
CERT_ID="${aki_b64url}.${serial_b64url}"
echo "  cert_id: $CERT_ID"

section "Renewal Info Endpoint"
rfc_ref "draft-ietf-lamps-est-renewal-info §3"

echo "1. GET /renewal-info/{cert_id} — valid cert → 200"
RI_HDR="$TMPDIR/ri-headers.txt"
RI_BODY="$TMPDIR/ri-body.json"
CODE=$(curl_est GET "/renewal-info/$CERT_ID" "$RI_BODY" "$RI_HDR")
check_exact "renewal-info valid cert" "$CODE" "200"

if [[ "$CODE" == "200" ]]; then
    echo "2. Content-Type: application/json"
    CT=$(get_header "$RI_HDR" "Content-Type")
    check_contains "Content-Type" "$CT" "application/json"

    echo "3. JSON has suggestedWindow.start"
    check_true "suggestedWindow.start" json_has_field "$RI_BODY" "suggestedWindow.start"

    echo "4. JSON has suggestedWindow.end"
    check_true "suggestedWindow.end" json_has_field "$RI_BODY" "suggestedWindow.end"

    echo "5. Retry-After header"
    RA=$(get_header "$RI_HDR" "Retry-After")
    if [[ -n "$RA" ]]; then
        check_true "Retry-After present ($RA)" true
    else
        skip_test "Retry-After" "optional per draft"
    fi

    cat "$RI_BODY" | python3 -m json.tool 2>/dev/null | sed 's/^/    /'
else
    for i in 2 3 4 5; do skip_test "test $i" "renewal-info returned $CODE"; done
fi

section "Error Cases"

echo "6. Malformed cert_id (no dot) → 400"
CODE=$(curl_est GET "/renewal-info/no-dot-here" /dev/null /dev/null)
check_exact "no-dot → 400" "$CODE" "400"

echo "7. Unknown cert → 404"
CODE=$(curl_est GET "/renewal-info/dW5rbm93bg.dW5rbm93bg" /dev/null /dev/null)
check_exact "unknown → 404" "$CODE" "404"

echo "8. Oversized cert_id (>256 chars) → 400"
LONG=$(python3 -c "print('A' * 300)")
CODE=$(curl_est GET "/renewal-info/$LONG" /dev/null /dev/null)
check_exact "oversized → 400" "$CODE" "400"

summary "EST Renewal Info Conformance"
