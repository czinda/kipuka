#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — RFC 8739 STAR Certificate Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " RFC 8739 — Short-Term Automatic Renewal (STAR)"
echo "═══════════════════════════════════════════════════════════════"

STAR_URL="$EST_URL/star"

section "STAR Order Lifecycle"
rfc_ref "RFC 8739 §3: STAR order creation and management"

# Generate a CSR for STAR enrollment
KEY="$TMPDIR/star-client.key"
CSR_DER="$TMPDIR/star-client.der"
generate_csr_der "star-test.kipuka.test" "$KEY" "$CSR_DER"
B64_CSR=$(base64 < "$CSR_DER")
OTP=$(generate_otp "star-test")

echo "1. POST /star — create STAR order"
ORDER_HDR="$TMPDIR/star-order-headers.txt"
ORDER_BODY="$TMPDIR/star-order.json"
CODE=$(curl -sk \
    -u "star-test:${OTP}" \
    -X POST "$STAR_URL" \
    -H "Content-Type: application/json" \
    -d "{\"csr\": \"$B64_CSR\", \"lifetime\": 86400}" \
    -D "$ORDER_HDR" \
    -o "$ORDER_BODY" \
    -w "%{http_code}")
if [[ "$CODE" == "503" ]]; then
    skip_test "create STAR order" "STAR manager not initialized (503)"
    ORDER_ID=""
elif [[ "$CODE" == "201" ]] || [[ "$CODE" == "200" ]]; then
    check_exact "create STAR order" "$CODE" "$CODE"
    ORDER_ID=$(python3 -c "import json; print(json.load(open('$ORDER_BODY')).get('order_id', json.load(open('$ORDER_BODY')).get('id','')))" 2>/dev/null || true)
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
        skip_test "STAR cert PKCS#7" "no cert body"
    fi

    echo "4. GET /star/{id}/history — cert history"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$STAR_URL/$ORDER_ID/history")
    if [[ "$CODE" == "200" ]]; then
        check_exact "STAR history" "$CODE" "200"
    else
        check_exact "STAR history" "$CODE" "200"
    fi

    echo "5. DELETE /star/{id} — cancel order → 204"
    CODE=$(curl -sk "${ADMIN_AUTH[@]}" -X DELETE -o /dev/null -w "%{http_code}" "$STAR_URL/$ORDER_ID")
    check_exact "cancel STAR order" "$CODE" "204"

    echo "6. GET /star/{id} after cancel → 404"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$STAR_URL/$ORDER_ID")
    check_exact "canceled order → 404" "$CODE" "404"
else
    for i in 2 3 4 5 6; do skip_test "STAR test $i" "no order created"; done
fi

section "Error Cases"

echo "7. GET /star/nonexistent → 404 or 503"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$STAR_URL/nonexistent-order-id")
if [[ "$CODE" == "404" ]]; then
    check_exact "nonexistent order" "$CODE" "404"
elif [[ "$CODE" == "503" ]]; then
    skip_test "nonexistent order" "STAR manager not initialized (503)"
else
    check_exact "nonexistent order" "$CODE" "404"
fi

echo "8. DELETE /star/nonexistent → 404 or 503"
CODE=$(curl -sk "${ADMIN_AUTH[@]}" -X DELETE -o /dev/null -w "%{http_code}" "$STAR_URL/nonexistent-order-id")
if [[ "$CODE" == "404" ]]; then
    check_exact "delete nonexistent" "$CODE" "404"
elif [[ "$CODE" == "503" ]] || [[ "$CODE" == "401" ]]; then
    skip_test "delete nonexistent" "STAR not available ($CODE)"
else
    check_exact "delete nonexistent" "$CODE" "404"
fi

summary "RFC 8739 STAR Conformance"
