#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — Custom EST renewal (not RFC 8739 ACME STAR) STAR Certificate Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " Custom EST renewal (not RFC 8739 ACME STAR) — Short-Term Automatic Renewal (STAR)"
echo "═══════════════════════════════════════════════════════════════"

STAR_URL="$EST_URL/star"

section "STAR Order Lifecycle"
echo "Custom EST API lifecycle check; not ACME STAR conformance"

# Generate a CSR for STAR enrollment
KEY="$TMPDIR/star-client.key"
CSR_DER="$TMPDIR/star-client.der"
generate_csr_der "star-test.kipuka.test" "$KEY" "$CSR_DER"
B64_CSR=$(base64 < "$CSR_DER")
OTP=$(generate_otp "star-test")

echo "1. POST /star — create STAR order"
ORDER_HDR="$TMPDIR/star-order-headers.txt"
ORDER_BODY="$TMPDIR/star-order.b64"
CODE=$(curl -sk \
    -u "star-test:${OTP}" \
    -X POST "$STAR_URL" \
    -H "Content-Type: application/pkcs10" \
    -H "Star-Renewal-Interval: 3600" \
    -H "Star-Lifetime: 1" \
    --data-binary "$B64_CSR" \
    -D "$ORDER_HDR" \
    -o "$ORDER_BODY" \
    -w "%{http_code}")
if [[ "$CODE" == "503" ]]; then
    check_true "required STAR manager unavailable (503)" false
    ORDER_ID=""
elif [[ "$CODE" == "201" ]] || [[ "$CODE" == "200" ]]; then
    check_exact "create STAR order" "$CODE" "$CODE"
    ORDER_ID=$(awk 'tolower($1) == "star-order-id:" {gsub("\r", "", $2); print $2}' "$ORDER_HDR")
    echo "    order_id: ${ORDER_ID:-unknown}"
else
    check_exact "create STAR order" "$CODE" "201"
    ORDER_ID=""
fi

if [[ -n "$ORDER_ID" ]]; then
    echo "2. GET /star/{id} — fetch STAR certificate"
    CERT_HDR="$TMPDIR/star-cert-headers.txt"
    CERT_B64="$TMPDIR/star-cert.b64"
    CODE=$(curl -sk \
        -D "$CERT_HDR" \
        -o "$CERT_B64" \
        -w "%{http_code}" \
        "$STAR_URL/$ORDER_ID")
    check_exact "fetch STAR cert" "$CODE" "200"

    if [[ "$CODE" == "200" ]] && [[ -s "$CERT_B64" ]]; then
        echo "3. STAR response is PKCS#7 certs-only"
        CERT_DER="$TMPDIR/star-cert.der"
        base64 -d < "$CERT_B64" > "$CERT_DER" 2>/dev/null
        assert_pkcs7_certs_only "STAR cert PKCS#7" "$CERT_DER" "$TMPDIR/star-certs"
    else
        check_true "required STAR certificate body absent" false
    fi

    echo "4. GET /star/{id}/history — cert history"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$STAR_URL/$ORDER_ID/history")
    if [[ "$CODE" == "200" ]]; then
        check_exact "STAR history" "$CODE" "200"
    else
        check_exact "STAR history" "$CODE" "200"
    fi

    echo "5. DELETE /star/{id} — cancel order → 204"
    OTP=$(generate_otp "star-test")
    CODE=$(curl -sk -u "star-test:${OTP}" -X DELETE -o /dev/null -w "%{http_code}" "$STAR_URL/$ORDER_ID")
    check_exact "cancel STAR order" "$CODE" "204"

    echo "6. GET /star/{id} after cancel → 410"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$STAR_URL/$ORDER_ID")
    check_exact "canceled order → 410" "$CODE" "410"
else
    for i in 2 3 4 5 6; do check_true "STAR test $i requires an order" false; done
fi

section "Error Cases"

echo "7. GET /star/nonexistent → 404 or 503"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$STAR_URL/nonexistent-order-id")
if [[ "$CODE" == "404" ]]; then
    check_exact "nonexistent order" "$CODE" "404"
elif [[ "$CODE" == "503" ]]; then
    check_true "required STAR manager unavailable (503)" false
else
    check_exact "nonexistent order" "$CODE" "404"
fi

echo "8. DELETE /star/nonexistent → 404 or 503"
OTP=$(generate_otp "star-test")
CODE=$(curl -sk -u "star-test:${OTP}" -X DELETE -o /dev/null -w "%{http_code}" "$STAR_URL/nonexistent-order-id")
if [[ "$CODE" == "404" ]]; then
    check_exact "delete nonexistent" "$CODE" "404"
elif [[ "$CODE" == "503" ]] || [[ "$CODE" == "401" ]]; then
    check_true "STAR DELETE unavailable ($CODE)" false
else
    check_exact "delete nonexistent" "$CODE" "404"
fi

summary "Custom EST renewal (not RFC 8739 ACME STAR) STAR Conformance"
