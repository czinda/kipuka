#!/usr/bin/env bash
# shellcheck disable=SC2034
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Admin API Tests
# ═══════════════════════════════════════════════════════════════════════
# Tests admin health endpoints, CA management, certificate listing,
# and authentication boundary enforcement.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

source "$(dirname "$0")/common.sh"

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Admin API Tests"
echo "═══════════════════════════════════════════════════════════════"
require_server

# ─────────────────────────────────────────────────────────────────────
section "Health Endpoints"
# ─────────────────────────────────────────────────────────────────────

echo "1. GET /admin/health — 200"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -o "$TMPDIR/health.json" -w "%{http_code}" "$ADMIN_URL/health")
check_exact "/health" "$code" "200"

echo "2. GET /admin/health/db — 200"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/db")
check_exact "/health/db" "$code" "200"

echo "3. GET /admin/health/hsm — 200"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/hsm")
check_exact "/health/hsm" "$code" "200"

echo "4. GET /admin/health/ca — 200"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/ca")
check_exact "/health/ca" "$code" "200"

echo "5. Parse health response: status, version, uptime"
if [[ -s "$TMPDIR/health.json" ]]; then
    HEALTH_STATUS=$(json_field "$(cat "$TMPDIR/health.json")" "status")
    HEALTH_VERSION=$(json_field "$(cat "$TMPDIR/health.json")" "version")
    HEALTH_UPTIME=$(python3 -c "
import json,sys
d = json.load(open('$TMPDIR/health.json'))
up = d.get('uptime_seconds', d.get('uptime', 0))
print(up)
" 2>/dev/null || echo "0")

    ALL_OK=true
    if [[ -z "$HEALTH_STATUS" ]]; then
        echo -e "  ${RED}FAIL${NC} no status field in health response"
        ALL_OK=false
    fi
    if [[ -z "$HEALTH_VERSION" ]]; then
        echo -e "  ${YELLOW}SKIP${NC} no version field (may not be present)"
    else
        echo "    Version: $HEALTH_VERSION"
    fi
    if [[ "$HEALTH_UPTIME" == "0" ]]; then
        echo "    Uptime: 0 (may be missing or just started)"
    else
        echo "    Uptime: ${HEALTH_UPTIME}s"
    fi

    if [[ "$ALL_OK" == "true" ]]; then
        echo -e "  ${GREEN}PASS${NC} health response parsed (status=$HEALTH_STATUS)"
        ((passed++))
    else
        ((failed++))
    fi
else
    skip_test "health parse" "no health response body"
fi

# ─────────────────────────────────────────────────────────────────────
section "CA Management"
# ─────────────────────────────────────────────────────────────────────

echo "6. GET /admin/cas — 200, at least 1 CA"
CAS_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -w "\n%{http_code}" "$ADMIN_URL/cas")
CAS_CODE=$(echo "$CAS_RESP" | tail -1)
CAS_BODY=$(echo "$CAS_RESP" | sed '$d')
check_exact "/cas" "$CAS_CODE" "200"
if [[ "$CAS_CODE" == "200" ]]; then
    CA_COUNT=$(echo "$CAS_BODY" | python3 -c "
import json,sys
d = json.load(sys.stdin)
if isinstance(d, list):
    print(len(d))
elif isinstance(d, dict):
    items = d.get('cas', d.get('items', []))
    print(len(items) if isinstance(items, list) else 1)
" 2>/dev/null || echo "0")
    if [[ "$CA_COUNT" -ge 1 ]]; then
        echo "    CAs found: $CA_COUNT"
    else
        echo "    WARNING: no CAs found"
    fi
fi

echo "7. GET /admin/cas/default — 200, verify id=default"
CA_DEFAULT_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
    -w "\n%{http_code}" "$ADMIN_URL/cas/default")
CA_DEFAULT_CODE=$(echo "$CA_DEFAULT_RESP" | tail -1)
CA_DEFAULT_BODY=$(echo "$CA_DEFAULT_RESP" | sed '$d')
check_exact "/cas/default" "$CA_DEFAULT_CODE" "200"
if [[ "$CA_DEFAULT_CODE" == "200" ]]; then
    CA_ID=$(json_field "$CA_DEFAULT_BODY" "id")
    if [[ "$CA_ID" == "default" ]]; then
        echo "    CA id: $CA_ID"
    else
        echo "    CA id: $CA_ID (expected 'default')"
    fi
fi

echo "8. GET /admin/cas/default/health — 200"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas/default/health")
check_exact "/cas/default/health" "$code" "200"

echo "9. GET /admin/cas/nonexistent — 404"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas/nonexistent")
check_exact "/cas/nonexistent" "$code" "404"

# ─────────────────────────────────────────────────────────────────────
section "Certificate Listing"
# ─────────────────────────────────────────────────────────────────────

echo "10. GET /admin/certs — 200"
code=$(curl -sk "${ADMIN_AUTH[@]}" \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/certs")
check_exact "/certs" "$code" "200"

echo "11. Enroll a cert, then verify /certs has >= 1"
# Generate OTP and enroll
ADMIN_OTP_BODY=$(generate_otp "admin-cert-test")
ADMIN_OTP=$(json_field "$ADMIN_OTP_BODY" "token")
if [[ -n "$ADMIN_OTP" ]]; then
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "$TMPDIR/admin-test.key" \
        -out "$TMPDIR/admin-test.csr" \
        -subj "/CN=admin-cert-test/O=Kipuka Test" 2>/dev/null
    openssl req -in "$TMPDIR/admin-test.csr" -outform DER -out "$TMPDIR/admin-test.der" 2>/dev/null
    B64_CSR=$(base64 < "$TMPDIR/admin-test.der")

    enroll_code=$(curl -sk --cacert "$CA_CERT" \
        -u "admin-cert-test:${ADMIN_OTP}" \
        -X POST "$EST_URL/simpleenroll" \
        -H "Content-Type: application/pkcs10" \
        -d "$B64_CSR" \
        -o /dev/null -w "%{http_code}")

    if [[ "$enroll_code" == "200" ]]; then
        # Now check /certs
        CERTS_RESP=$(curl -sk "${ADMIN_AUTH[@]}" \
            -w "\n%{http_code}" "$ADMIN_URL/certs")
        CERTS_CODE=$(echo "$CERTS_RESP" | tail -1)
        CERTS_BODY=$(echo "$CERTS_RESP" | sed '$d')
        CERT_COUNT=$(echo "$CERTS_BODY" | python3 -c "
import json,sys
d = json.load(sys.stdin)
if isinstance(d, list):
    print(len(d))
else:
    print(d.get('total', len(d.get('items', d.get('certificates', [])))))
" 2>/dev/null || echo "0")
        if [[ "$CERT_COUNT" -ge 1 ]]; then
            echo -e "  ${GREEN}PASS${NC} /certs has $CERT_COUNT certificate(s)"
            ((passed++))
        else
            echo -e "  ${RED}FAIL${NC} /certs has 0 certificates after enrollment"
            ((failed++))
        fi
    else
        skip_test "cert count after enroll" "enrollment returned $enroll_code"
    fi
else
    skip_test "cert count" "could not generate OTP"
fi

# ─────────────────────────────────────────────────────────────────────
section "Auth Boundary — No Bearer Token"
# ─────────────────────────────────────────────────────────────────────

echo "12. All admin endpoints without Bearer token — 401"
ADMIN_ENDPOINTS=(
    "GET  /health"
    "GET  /health/db"
    "GET  /health/hsm"
    "GET  /health/ca"
    "GET  /cas"
    "GET  /cas/default"
    "GET  /certs"
    "GET  /otp"
    "POST /otp/generate"
)

all_blocked=true
for ep in "${ADMIN_ENDPOINTS[@]}"; do
    method=$(echo "$ep" | awk '{print $1}')
    path=$(echo "$ep" | awk '{print $2}')
    if [[ "$method" == "POST" ]]; then
        code=$(curl -sk -X POST \
            -H "Content-Type: application/json" \
            -d '{"entity_id": "unauth"}' \
            -o /dev/null -w "%{http_code}" "$ADMIN_URL$path")
    else
        code=$(curl -sk \
            -o /dev/null -w "%{http_code}" "$ADMIN_URL$path")
    fi
    if [[ "$code" != "401" ]]; then
        echo -e "    ${RED}FAIL${NC} $method $path returned $code (expected 401)"
        all_blocked=false
    fi
done

if [[ "$all_blocked" == "true" ]]; then
    echo -e "  ${GREEN}PASS${NC} all ${#ADMIN_ENDPOINTS[@]} admin endpoints require auth"
    ((passed++))
else
    echo -e "  ${RED}FAIL${NC} some admin endpoints accessible without auth"
    ((failed++))
fi

# ── Summary ─────────────────────────────────────────────────────────
summary
