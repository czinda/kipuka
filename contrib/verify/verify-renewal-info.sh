#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — Verify EST Renewal Info (draft-ietf-lamps-est-renewal-info)
# ═══════════════════════════════════════════════════════════════════════
# Tests GET /.well-known/est/renewal-info/{cert_id}
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

require_server

echo "═══════════════════════════════════════════════════════════════"
echo " Renewal Info (draft-ietf-lamps-est-renewal-info)"
echo "═══════════════════════════════════════════════════════════════"

# ── Enroll a certificate so we have something to query ──────────────
section "Setup: enroll a test certificate"

KEY_FILE="$TMPDIR/renewal-test.key"
B64_CSR=$(generate_csr "renewal-test.kipuka.test" "$KEY_FILE")
OTP_BODY=$(generate_otp "renewal-test")
OTP=$(json_field "$OTP_BODY" "token")

ENROLL_RESP=$(curl -sk \
    -u "renewal-test:${OTP}" \
    -X POST "$EST_URL/simpleenroll" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64_CSR" \
    -w "\n%{http_code}")
ENROLL_CODE=$(echo "$ENROLL_RESP" | tail -1)
CERT_B64=$(echo "$ENROLL_RESP" | sed '$d')

if [[ "$ENROLL_CODE" != "200" ]]; then
    echo "  Setup failed: simpleenroll returned $ENROLL_CODE"
    summary
fi

# Decode the issued cert and extract AKI + serial for cert_id construction
CERT_DER="$TMPDIR/renewal-test-cert.der"
echo "$CERT_B64" | base64 -d > "$CERT_DER" 2>/dev/null

# Extract serial number (hex) from the issued certificate
SERIAL_HEX=$(openssl x509 -inform DER -in "$CERT_DER" -noout -serial 2>/dev/null | \
    sed 's/serial=//' | tr '[:upper:]' '[:lower:]' | sed 's/^0*//')
# Extract AKI (Authority Key Identifier) hex bytes
AKI_HEX=$(openssl x509 -inform DER -in "$CERT_DER" -noout -text 2>/dev/null | \
    grep -A1 "Authority Key Identifier" | tail -1 | tr -d ' :' | tr '[:upper:]' '[:lower:]')

if [[ -z "$SERIAL_HEX" ]] || [[ -z "$AKI_HEX" ]]; then
    echo "  Setup failed: could not extract serial or AKI from issued cert"
    echo "    serial=$SERIAL_HEX aki=$AKI_HEX"
    summary
fi

# Build cert_id: base64url(AKI_bytes) + "." + base64url(serial_bytes)
aki_bytes=$(echo "$AKI_HEX" | sed 's/../\\x&/g')
serial_bytes=$(echo "$SERIAL_HEX" | sed 's/../\\x&/g')
# shellcheck disable=SC2059
AKI_B64URL=$(printf "$aki_bytes" | base64 | tr '+/' '-_' | tr -d '=')
# shellcheck disable=SC2059
SERIAL_B64URL=$(printf "$serial_bytes" | base64 | tr '+/' '-_' | tr -d '=')
CERT_ID="${AKI_B64URL}.${SERIAL_B64URL}"

echo "  Enrolled cert: serial=$SERIAL_HEX"
echo "  cert_id: $CERT_ID"

# ── Renewal Info Tests ──────────────────────────────────────────────
section "Renewal Info endpoint tests"

echo "1. GET /renewal-info/{cert_id} — valid cert"
RESP=$(curl -sk -D "$TMPDIR/renewal-headers.txt" \
    -o "$TMPDIR/renewal-body.json" \
    -w "%{http_code}" \
    "$EST_URL/renewal-info/$CERT_ID")
check_exact "renewal-info valid cert" "$RESP" "200"

echo "2. Response is valid JSON with suggestedWindow"
if [[ -s "$TMPDIR/renewal-body.json" ]]; then
    HAS_WINDOW=$(python3 -c "
import json, sys
d = json.load(sys.stdin)
sw = d.get('suggestedWindow', {})
print('yes' if 'start' in sw and 'end' in sw else 'no')
" < "$TMPDIR/renewal-body.json" 2>/dev/null || echo "no")
    check_true "suggestedWindow has start and end" test "$HAS_WINDOW" = "yes"
    python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))" \
        < "$TMPDIR/renewal-body.json" 2>/dev/null | sed 's/^/    /'
else
    check_true "response body present" false
fi

echo "3. Retry-After header present"
if grep -qi "retry-after" "$TMPDIR/renewal-headers.txt" 2>/dev/null; then
    RETRY_AFTER=$(grep -i "retry-after" "$TMPDIR/renewal-headers.txt" | head -1 | awk '{print $2}' | tr -d '\r')
    echo -e "  ${GREEN}PASS${NC} Retry-After: $RETRY_AFTER"
    ((passed++))
else
    echo -e "  ${YELLOW}SKIP${NC} no Retry-After header (optional per draft)"
    ((skipped++))
fi

echo "4. GET /renewal-info/invalid — malformed cert_id (no dot)"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/renewal-info/invalid-no-dot")
check_exact "malformed cert_id" "$code" "400"

echo "5. GET /renewal-info/YQ.YQ — unknown certificate"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/renewal-info/YQ.YQ")
check_exact "unknown cert" "$code" "404"

echo "6. GET /renewal-info/ (empty path) — expect 404"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/renewal-info/")
check_exact "empty cert_id" "$code" "404"

LONG_ID=$(python3 -c "print('A' * 300)")
echo "7. GET /renewal-info/{oversized} — cert_id > 256 chars"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/renewal-info/$LONG_ID")
check_exact "oversized cert_id" "$code" "400"

summary
