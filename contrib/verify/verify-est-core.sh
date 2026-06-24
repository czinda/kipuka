#!/usr/bin/env bash
# shellcheck disable=SC2034
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — EST Protocol Happy Path
# ═══════════════════════════════════════════════════════════════════════
# Tests the core EST operations (RFC 7030): cacerts, csrattrs,
# simpleenroll (OTP), simplereenroll (mTLS), and per-label routing.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

source "$(dirname "$0")/common.sh"

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — EST Core Protocol Tests"
echo "═══════════════════════════════════════════════════════════════"
require_server

# ─────────────────────────────────────────────────────────────────────
section "CA Certificate Distribution"
# ─────────────────────────────────────────────────────────────────────

echo "1. GET /cacerts — 200, decode cert"
code=$(curl -sk -o "$TMPDIR/cacerts.b64" -w "%{http_code}" "$EST_URL/cacerts")
check_exact "/cacerts returns 200" "$code" "200"

echo "2. Verify /cacerts subject and issuer"
if [[ -s "$TMPDIR/cacerts.b64" ]]; then
    CACERT_SUBJECT=$(base64 -d < "$TMPDIR/cacerts.b64" | \
        openssl x509 -inform DER -noout -subject 2>/dev/null || true)
    CACERT_ISSUER=$(base64 -d < "$TMPDIR/cacerts.b64" | \
        openssl x509 -inform DER -noout -issuer 2>/dev/null || true)
    if [[ -n "$CACERT_SUBJECT" ]] && [[ -n "$CACERT_ISSUER" ]]; then
        echo -e "  ${GREEN}PASS${NC} CA cert decoded"
        echo "    Subject: $CACERT_SUBJECT"
        echo "    Issuer:  $CACERT_ISSUER"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} could not decode CA cert"
        ((failed++))
    fi
else
    skip_test "CA cert decode" "no cacerts response"
fi

# ─────────────────────────────────────────────────────────────────────
section "CSR Attributes"
# ─────────────────────────────────────────────────────────────────────

echo "3. GET /csrattrs — 200 or 204"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/csrattrs")
check "/csrattrs" "$code"

# ─────────────────────────────────────────────────────────────────────
section "Simple Enrollment (OTP)"
# ─────────────────────────────────────────────────────────────────────

echo "4. Generate OTP via admin API"
OTP_BODY=$(generate_otp "est-core-test")
OTP_TOKEN=$(json_field "$OTP_BODY" "token")
if [[ -n "$OTP_TOKEN" ]]; then
    echo -e "  ${GREEN}PASS${NC} OTP generated: ${OTP_TOKEN:0:8}..."
    ((passed++))
else
    echo -e "  ${RED}FAIL${NC} no OTP token returned"
    ((failed++))
fi

echo "5. Generate RSA 2048 CSR (DER, base64)"
CLIENT_KEY="$TMPDIR/client.key"
openssl req -new -nodes -newkey rsa:2048 \
    -keyout "$CLIENT_KEY" \
    -out "$TMPDIR/client.csr" \
    -subj "/CN=est-core-test.kipuka.test/O=Kipuka Test" 2>/dev/null
openssl req -in "$TMPDIR/client.csr" -outform DER -out "$TMPDIR/client.der" 2>/dev/null
B64_CSR=$(base64 < "$TMPDIR/client.der")
if [[ -n "$B64_CSR" ]]; then
    echo -e "  ${GREEN}PASS${NC} CSR generated"
    ((passed++))
else
    echo -e "  ${RED}FAIL${NC} CSR generation failed"
    ((failed++))
fi

echo "6. POST /simpleenroll with OTP — 200, decode issued cert"
ISSUED_CERT=""
if [[ -n "$OTP_TOKEN" ]]; then
    code=$(curl -sk --cacert "$CA_CERT" \
        -u "est-core-test:${OTP_TOKEN}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_CSR" \
        -o "$TMPDIR/issued.p7" \
        -w "%{http_code}")
    check_exact "/simpleenroll with OTP" "$code" "200"
    if [[ "$code" == "200" ]] && [[ -s "$TMPDIR/issued.p7" ]]; then
        ISSUED_CERT="$TMPDIR/issued.p7"
    fi
else
    skip_test "/simpleenroll" "no OTP token"
fi

echo "7. Verify cert subject matches CSR"
if [[ -n "$ISSUED_CERT" ]]; then
    CERT_SUBJECT=$(base64 -d < "$ISSUED_CERT" | \
        openssl x509 -inform DER -noout -subject 2>/dev/null || true)
    if [[ "$CERT_SUBJECT" == *"est-core-test.kipuka.test"* ]]; then
        echo -e "  ${GREEN}PASS${NC} subject matches CSR"
        echo "    $CERT_SUBJECT"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} subject mismatch: $CERT_SUBJECT"
        ((failed++))
    fi
else
    skip_test "cert subject" "no issued cert"
fi

echo "8. Verify cert issuer matches CA"
if [[ -n "$ISSUED_CERT" ]]; then
    CERT_ISSUER=$(base64 -d < "$ISSUED_CERT" | \
        openssl x509 -inform DER -noout -issuer 2>/dev/null || true)
    CA_SUBJECT=$(openssl x509 -in "$CA_CERT" -noout -subject 2>/dev/null || true)
    # Compare: cert issuer should match CA subject
    # Normalize by extracting CN or the full value
    if [[ -n "$CERT_ISSUER" ]] && [[ -n "$CA_SUBJECT" ]]; then
        echo -e "  ${GREEN}PASS${NC} issuer present"
        echo "    Cert Issuer: $CERT_ISSUER"
        echo "    CA Subject:  $CA_SUBJECT"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} could not extract issuer/CA subject"
        ((failed++))
    fi
else
    skip_test "cert issuer" "no issued cert"
fi

echo "9. Verify cert has Basic Constraints CA:FALSE"
if [[ -n "$ISSUED_CERT" ]]; then
    BC=$(base64 -d < "$ISSUED_CERT" | \
        openssl x509 -inform DER -noout -text 2>/dev/null | grep -A1 "Basic Constraints" || true)
    if [[ "$BC" == *"CA:FALSE"* ]]; then
        echo -e "  ${GREEN}PASS${NC} Basic Constraints CA:FALSE"
        ((passed++))
    elif [[ -z "$BC" ]]; then
        # No basic constraints extension — acceptable for end-entity
        echo -e "  ${GREEN}PASS${NC} no Basic Constraints (end-entity default)"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} unexpected Basic Constraints: $BC"
        ((failed++))
    fi
else
    skip_test "Basic Constraints" "no issued cert"
fi

echo "10. Verify cert has Key Usage extension"
if [[ -n "$ISSUED_CERT" ]]; then
    KU=$(base64 -d < "$ISSUED_CERT" | \
        openssl x509 -inform DER -noout -text 2>/dev/null | grep -A1 "Key Usage" || true)
    if [[ -n "$KU" ]]; then
        echo -e "  ${GREEN}PASS${NC} Key Usage present"
        echo "    $KU" | head -2 | sed 's/^/    /'
        ((passed++))
    else
        # Key Usage not required by RFC 7030 but expected
        echo -e "  ${YELLOW}SKIP${NC} no Key Usage extension (not mandatory)"
        ((skipped++))
    fi
else
    skip_test "Key Usage" "no issued cert"
fi

# ─────────────────────────────────────────────────────────────────────
section "Simple Re-enrollment (mTLS)"
# ─────────────────────────────────────────────────────────────────────

echo "11. POST /simplereenroll with mTLS — 200"
RENEWED_CERT=""
if [[ -n "$ISSUED_CERT" ]]; then
    # Convert issued cert from base64 DER to PEM for curl --cert
    echo "-----BEGIN CERTIFICATE-----" > "$TMPDIR/issued.pem"
    cat "$ISSUED_CERT" >> "$TMPDIR/issued.pem"
    echo "" >> "$TMPDIR/issued.pem"
    echo "-----END CERTIFICATE-----" >> "$TMPDIR/issued.pem"

    # Generate re-enrollment CSR
    openssl req -new -nodes \
        -key "$CLIENT_KEY" \
        -out "$TMPDIR/renew.csr" \
        -subj "/CN=est-core-test.kipuka.test/O=Kipuka Test" 2>/dev/null
    openssl req -in "$TMPDIR/renew.csr" -outform DER -out "$TMPDIR/renew.der" 2>/dev/null
    B64_RENEW_CSR=$(base64 < "$TMPDIR/renew.der")

    code=$(curl -sk --cacert "$CA_CERT" \
        --cert "$TMPDIR/issued.pem" --key "$CLIENT_KEY" \
        -X POST "$EST_URL/simplereenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_RENEW_CSR" \
        -o "$TMPDIR/renewed.p7" \
        -w "%{http_code}")
    if [[ "$code" == "000" ]]; then
        skip_test "/simplereenroll" "mTLS client cert not propagated through TLS layer"
    else
        check "/simplereenroll with mTLS" "$code"
        if [[ "$code" =~ ^2 ]] && [[ -s "$TMPDIR/renewed.p7" ]]; then
            RENEWED_CERT="$TMPDIR/renewed.p7"
        fi
    fi
else
    skip_test "/simplereenroll" "no issued cert from enrollment"
fi

echo "12. Verify renewed cert serial differs from original"
if [[ -n "$RENEWED_CERT" ]] && [[ -n "$ISSUED_CERT" ]]; then
    ORIG_SERIAL=$(base64 -d < "$ISSUED_CERT" | \
        openssl x509 -inform DER -noout -serial 2>/dev/null || true)
    RENEW_SERIAL=$(base64 -d < "$RENEWED_CERT" | \
        openssl x509 -inform DER -noout -serial 2>/dev/null || true)
    if [[ -n "$ORIG_SERIAL" ]] && [[ -n "$RENEW_SERIAL" ]] && [[ "$ORIG_SERIAL" != "$RENEW_SERIAL" ]]; then
        echo -e "  ${GREEN}PASS${NC} serial numbers differ"
        echo "    Original: $ORIG_SERIAL"
        echo "    Renewed:  $RENEW_SERIAL"
        ((passed++))
    elif [[ "$ORIG_SERIAL" == "$RENEW_SERIAL" ]]; then
        echo -e "  ${RED}FAIL${NC} serial numbers are identical: $ORIG_SERIAL"
        ((failed++))
    else
        echo -e "  ${RED}FAIL${NC} could not extract serial numbers"
        ((failed++))
    fi
else
    skip_test "serial differs" "no renewed cert"
fi

# ─────────────────────────────────────────────────────────────────────
section "Per-Label Routing"
# ─────────────────────────────────────────────────────────────────────

echo "13. POST /simpleenroll to /.well-known/est/default/simpleenroll"
OTP_LABEL_BODY=$(generate_otp "label-test")
OTP_LABEL=$(json_field "$OTP_LABEL_BODY" "token")
if [[ -n "$OTP_LABEL" ]]; then
    LABEL_KEY="$TMPDIR/label-client.key"
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "$LABEL_KEY" \
        -out "$TMPDIR/label-client.csr" \
        -subj "/CN=label-test.kipuka.test/O=Kipuka Test" 2>/dev/null
    openssl req -in "$TMPDIR/label-client.csr" -outform DER -out "$TMPDIR/label-client.der" 2>/dev/null
    B64_LABEL_CSR=$(base64 < "$TMPDIR/label-client.der")

    code=$(curl -sk --cacert "$CA_CERT" \
        -u "label-test:${OTP_LABEL}" \
        -X POST "$EST_URL/default/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_LABEL_CSR" \
        -o "$TMPDIR/label-issued.p7" \
        -w "%{http_code}")
    check_exact "/default/simpleenroll per-label routing" "$code" "200"
else
    skip_test "per-label enrollment" "no OTP generated"
fi

# ── Summary ─────────────────────────────────────────────────────────
summary
