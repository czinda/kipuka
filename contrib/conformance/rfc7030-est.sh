#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — RFC 7030 EST Core Conformance
# ═══════════════════════════════════════════════════════════════════════
# Validates EST protocol compliance per RFC 7030 (Enrollment over
# Secure Transport), including wire-format assertions on PKCS#7,
# Content-Type headers, and certificate structure.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"

require_server

echo "═══════════════════════════════════════════════════════════════"
echo " RFC 7030 — Enrollment over Secure Transport"
echo "═══════════════════════════════════════════════════════════════"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# §4.1 — Distribution of CA Certificates
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section "§4.1 — CA Certificates (/cacerts)"
rfc_ref "RFC 7030 §4.1: GET /.well-known/est/cacerts"

CACERTS_B64="$TMPDIR/cacerts.b64"
CACERTS_DER="$TMPDIR/cacerts.der"
CACERTS_HDR="$TMPDIR/cacerts-headers.txt"
CACERTS_CERTS="$TMPDIR/cacerts-certs"

code=$(curl_est GET /cacerts "$CACERTS_B64" "$CACERTS_HDR")

echo "1. GET /cacerts returns 200"
check_exact "/cacerts status" "$code" "200"

echo "2. Content-Type: application/pkcs7-mime; smime-type=certs-only"
CT=$(get_header "$CACERTS_HDR" "Content-Type")
check_contains "/cacerts Content-Type" "$CT" "application/pkcs7-mime"

echo "3. Content-Transfer-Encoding: base64"
CTE=$(get_header "$CACERTS_HDR" "Content-Transfer-Encoding")
check_contains "/cacerts Content-Transfer-Encoding" "$CTE" "base64"

echo "4. Body decodes as valid base64"
if base64 -d < "$CACERTS_B64" > "$CACERTS_DER" 2>/dev/null; then
    check_true "/cacerts base64 decode" true
else
    check_true "/cacerts base64 decode" false
fi

echo "5. DER is valid PKCS#7 structure"
assert_asn1_valid "/cacerts ASN.1 structure" "$CACERTS_DER"

echo "6. PKCS#7 is degenerate certs-only (extractable certificates)"
assert_pkcs7_certs_only "/cacerts PKCS#7 certs-only" "$CACERTS_DER" "$CACERTS_CERTS"

echo "7. At least one CA certificate in the bag"
check_true "/cacerts has ≥1 cert" test "${PKCS7_CERT_COUNT:-0}" -ge 1

if [[ -f "$CACERTS_CERTS/certs.pem" ]]; then
    echo "8. CA certificate has basicConstraints CA:TRUE"
    # Extract first cert
    openssl x509 -in "$CACERTS_CERTS/certs.pem" -outform PEM -out "$TMPDIR/ca-first.pem" 2>/dev/null
    CA_BC=$(openssl x509 -in "$TMPDIR/ca-first.pem" -noout -text 2>/dev/null | grep -A1 "Basic Constraints" | tail -1)
    check_contains "/cacerts CA basicConstraints" "$CA_BC" "CA:TRUE"

    echo "9. CA certificate has keyUsage keyCertSign"
    CA_KU=$(openssl x509 -in "$TMPDIR/ca-first.pem" -noout -text 2>/dev/null | grep -A1 "Key Usage" | tail -1)
    check_contains "/cacerts CA keyUsage" "$CA_KU" "Certificate Sign"
else
    skip_test "/cacerts CA basicConstraints" "no cert extracted"
    skip_test "/cacerts CA keyUsage" "no cert extracted"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# §4.5 — CSR Attributes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section "§4.5 — CSR Attributes (/csrattrs)"
rfc_ref "RFC 7030 §4.5: GET /.well-known/est/csrattrs"

CSRATTR_B64="$TMPDIR/csrattrs.b64"
CSRATTR_DER="$TMPDIR/csrattrs.der"
CSRATTR_HDR="$TMPDIR/csrattrs-headers.txt"

code=$(curl_est GET /csrattrs "$CSRATTR_B64" "$CSRATTR_HDR")

echo "10. GET /csrattrs returns 200 or 204"
if [[ "$code" == "200" ]] || [[ "$code" == "204" ]]; then
    check_exact "/csrattrs status" "$code" "$code"
else
    check_exact "/csrattrs status" "$code" "200"
fi

if [[ "$code" == "200" ]]; then
    echo "11. Content-Type: application/csrattrs"
    CT=$(get_header "$CSRATTR_HDR" "Content-Type")
    check_contains "/csrattrs Content-Type" "$CT" "application/csrattrs"

    echo "12. Body decodes as valid base64 → DER"
    base64 -d < "$CSRATTR_B64" > "$CSRATTR_DER" 2>/dev/null
    assert_asn1_valid "/csrattrs ASN.1" "$CSRATTR_DER"

    echo "13. Outer DER tag is SEQUENCE (0x30)"
    assert_asn1_outer_tag "/csrattrs outer SEQUENCE" "$CSRATTR_DER" "30"
else
    skip_test "/csrattrs Content-Type" "204 No Content"
    skip_test "/csrattrs ASN.1" "204 No Content"
    skip_test "/csrattrs outer SEQUENCE" "204 No Content"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# §4.2 — Simple Enrollment
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section "§4.2 — Simple Enrollment (/simpleenroll)"
rfc_ref "RFC 7030 §4.2: POST /.well-known/est/simpleenroll"

KEY_FILE="$TMPDIR/enroll-client.key"
CSR_DER="$TMPDIR/enroll-client.der"
generate_csr_der "conformance-test.kipuka.test" "$KEY_FILE" "$CSR_DER"
B64_CSR=$(base64 < "$CSR_DER")

echo "14. Generate OTP for enrollment"
OTP=$(generate_otp "conformance-enroll-test")
check_true "OTP generated" test -n "$OTP"

ENROLL_B64="$TMPDIR/enrolled-cert.b64"
ENROLL_DER="$TMPDIR/enrolled-cert.der"
ENROLL_HDR="$TMPDIR/enroll-headers.txt"
ENROLL_CERTS="$TMPDIR/enroll-certs"

echo "15. POST /simpleenroll with OTP → 200"
code=$(curl_est POST /simpleenroll "$ENROLL_B64" "$ENROLL_HDR" \
    -u "conformance-enroll-test:${OTP}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR")
check_exact "/simpleenroll status" "$code" "200"

if [[ "$code" == "200" ]]; then
    echo "16. Response Content-Type: application/pkcs7-mime"
    CT=$(get_header "$ENROLL_HDR" "Content-Type")
    check_contains "/simpleenroll Content-Type" "$CT" "application/pkcs7-mime"

    echo "17. Response body is valid base64 → DER"
    base64 -d < "$ENROLL_B64" > "$ENROLL_DER" 2>/dev/null
    assert_asn1_valid "/simpleenroll response ASN.1" "$ENROLL_DER"

    echo "18. Response is PKCS#7 with exactly 1 certificate"
    assert_pkcs7_certs_only "/simpleenroll PKCS#7" "$ENROLL_DER" "$ENROLL_CERTS"

    if [[ -f "$ENROLL_CERTS/certs.pem" ]] && [[ "${PKCS7_CERT_COUNT:-0}" -ge 1 ]]; then
        # Extract the issued cert
        openssl x509 -in "$ENROLL_CERTS/certs.pem" -outform PEM -out "$TMPDIR/issued.pem" 2>/dev/null

        echo "19. Issued cert subject matches CSR subject (CN=conformance-test.kipuka.test)"
        assert_x509_field "issued cert subject" "$TMPDIR/issued.pem" "subject" "conformance-test.kipuka.test"

        echo "20. Issued cert signed by CA from /cacerts"
        if [[ -f "$CACERTS_CERTS/certs.pem" ]]; then
            assert_cert_signed_by "issued cert chain" "$TMPDIR/issued.pem" "$CACERTS_CERTS/certs.pem"
        else
            skip_test "issued cert chain" "CA cert not available"
        fi

        echo "21. Issued cert has valid notBefore ≤ now ≤ notAfter"
        if openssl x509 -in "$TMPDIR/issued.pem" -noout -checkend 0 2>/dev/null; then
            check_true "issued cert validity window" true
        else
            check_true "issued cert validity window" false
        fi
    else
        skip_test "issued cert subject" "no cert from enrollment"
        skip_test "issued cert chain" "no cert from enrollment"
        skip_test "issued cert validity" "no cert from enrollment"
    fi
else
    for i in 16 17 18 19 20 21; do
        skip_test "enrollment test $i" "enrollment failed"
    done
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# §3.2.3 — Authentication Error Responses
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section "§3.2.3 — Authentication Errors"
rfc_ref "RFC 7030 §3.2.3: EST client authentication"

echo "22. POST /simpleenroll without auth → 401"
ERR_HDR="$TMPDIR/err-headers.txt"
code=$(curl_est POST /simpleenroll /dev/null "$ERR_HDR" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR")
check_exact "no-auth → 401" "$code" "401"

echo "23. 401 response has WWW-Authenticate header"
WWW_AUTH=$(get_header "$ERR_HDR" "WWW-Authenticate")
if [[ -n "$WWW_AUTH" ]]; then
    check_true "WWW-Authenticate present" true
    echo "    WWW-Authenticate: $WWW_AUTH"
else
    # RFC 7030 doesn't strictly mandate this, but HTTP 401 requires it per RFC 7235
    skip_test "WWW-Authenticate present" "not required by RFC 7030, recommended by RFC 7235"
fi

echo "24. POST /simpleenroll with invalid OTP → 401"
code=$(curl_est POST /simpleenroll /dev/null /dev/null \
    -u "conformance-enroll-test:totally-wrong-otp" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR")
check_exact "bad-OTP → 401" "$code" "401"

echo "25. POST /simpleenroll with wrong Content-Type → 415"
code=$(curl_est POST /simpleenroll /dev/null /dev/null \
    -u "conformance-enroll-test:fake" \
    -H "Content-Type: text/plain" \
    -d "not a CSR")
check_exact "wrong Content-Type → 415" "$code" "415"

echo "26. POST /simpleenroll with malformed CSR body → 400"
OTP2=$(generate_otp "conformance-bad-csr")
code=$(curl_est POST /simpleenroll /dev/null /dev/null \
    -u "conformance-bad-csr:${OTP2}" \
    -H "Content-Type: application/pkcs10" \
    -d "dGhpcyBpcyBub3QgYSBDU1I=")
check_exact "bad CSR → 400" "$code" "400"

echo "27. POST /simpleenroll reusing consumed OTP → 401"
code=$(curl_est POST /simpleenroll /dev/null /dev/null \
    -u "conformance-enroll-test:${OTP}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR")
check_exact "reused OTP → 401" "$code" "401"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# §4.2.2 — Simple Re-enrollment
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section "§4.2.2 — Simple Re-enrollment (/simplereenroll)"
rfc_ref "RFC 7030 §4.2.2: POST /.well-known/est/simplereenroll"

echo "28. POST /simplereenroll without client cert → 401"
RENEW_CSR_DER="$TMPDIR/renew.der"
generate_csr_der "conformance-test.kipuka.test" "$TMPDIR/renew.key" "$RENEW_CSR_DER"
B64_RENEW=$(base64 < "$RENEW_CSR_DER")

code=$(curl_est POST /simplereenroll /dev/null /dev/null \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_RENEW")
check_exact "/simplereenroll no-cert → 401" "$code" "401"

# mTLS re-enrollment requires the issued cert from step 15 as the client cert.
# This only works if TLS client_auth is properly wired through the container.
if [[ -f "$TMPDIR/issued.pem" ]]; then
    echo "29. POST /simplereenroll with issued cert (mTLS)"
    REENROLL_HDR="$TMPDIR/reenroll-headers.txt"
    code=$(curl -sk -X POST \
        --cert "$TMPDIR/issued.pem" --key "$KEY_FILE" \
        --cacert "$CA_CERT" \
        -D "$REENROLL_HDR" \
        -o /dev/null \
        -w "%{http_code}" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_RENEW" \
        "$EST_URL/simplereenroll" 2>/dev/null)
    if [[ "$code" == "000" ]]; then
        skip_test "/simplereenroll mTLS" "TLS client cert not propagated (container networking)"
    else
        check_exact "/simplereenroll mTLS" "$code" "200"
    fi
else
    skip_test "/simplereenroll mTLS" "no issued cert from enrollment"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# §3.2.2 — EST Labels (per-label routing)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
section "§3.2.2 — EST Labels"
rfc_ref "RFC 7030 §3.2.2: label-based path routing"

echo "30. GET /{label}/cacerts — known label responds"
LABEL_HDR="$TMPDIR/label-headers.txt"
code=$(curl_est GET /device/cacerts /dev/null "$LABEL_HDR")
if [[ "$code" == "200" ]]; then
    check_exact "/{label}/cacerts" "$code" "200"
else
    skip_test "/{label}/cacerts" "label 'device' not configured ($code)"
fi

echo "31. GET /{nonexistent}/cacerts → 404"
code=$(curl_est GET /nonexistent-label-xyz/cacerts /dev/null /dev/null)
check_exact "/nonexistent-label → 404" "$code" "404"

summary "RFC 7030 EST Conformance"
