#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — Admin API Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " Admin API"
echo "═══════════════════════════════════════════════════════════════"

section "Health Endpoints"

echo "1. GET /admin/health → 200 + JSON"
RESP=$(curl -sk "${ADMIN_AUTH[@]}" -w "\n%{http_code}" "$ADMIN_URL/health")
CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_exact "/health" "$CODE" "200"

echo "2. Health response has 'status' field"
STATUS=$(json_field "$BODY" "status")
check_true "status field" test "$STATUS" = "healthy"

echo "3. Health response has 'version' field"
VERSION=$(json_field "$BODY" "version")
check_true "version field present" test -n "$VERSION"

echo "4. Health response has 'ca_count' ≥ 1"
CA_COUNT=$(echo "$BODY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('ca_count',0))" 2>/dev/null)
check_true "ca_count ≥ 1" test "${CA_COUNT:-0}" -ge 1

echo "5. GET /admin/health/db → 200"
CODE=$(curl -sk "${ADMIN_AUTH[@]}" -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/db")
check_exact "/health/db" "$CODE" "200"

echo "6. GET /admin/health/ca → 200"
CODE=$(curl -sk "${ADMIN_AUTH[@]}" -o /dev/null -w "%{http_code}" "$ADMIN_URL/health/ca")
check_exact "/health/ca" "$CODE" "200"

section "CA Management"

echo "7. GET /admin/cas → 200 + JSON array"
RESP=$(curl -sk "${ADMIN_AUTH[@]}" -w "\n%{http_code}" "$ADMIN_URL/cas")
CODE=$(echo "$RESP" | tail -1)
check_exact "/cas" "$CODE" "200"

echo "8. GET /admin/cas/default → 200"
CODE=$(curl -sk "${ADMIN_AUTH[@]}" -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas/default")
check_exact "/cas/default" "$CODE" "200"

echo "9. GET /admin/cas/nonexistent → 404"
CODE=$(curl -sk "${ADMIN_AUTH[@]}" -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas/nonexistent")
check_exact "/cas/nonexistent → 404" "$CODE" "404"

section "Certificate Listing"

# Enroll a cert so we have something to list
OTP=$(generate_otp "admin-cert-test")
KEY="$TMPDIR/admin-test.key"
CSR_DER="$TMPDIR/admin-test.der"
generate_csr_der "admin-test.kipuka.test" "$KEY" "$CSR_DER"
B64=$(base64 < "$CSR_DER")
curl_est POST /simpleenroll /dev/null /dev/null \
    -u "admin-cert-test:${OTP}" \
    -H "Content-Type: application/pkcs10" \
    -d "$B64" > /dev/null

echo "10. GET /admin/certs → 200 + JSON"
RESP=$(curl -sk "${ADMIN_AUTH[@]}" -w "\n%{http_code}" "$ADMIN_URL/certs")
CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
check_exact "/certs" "$CODE" "200"

echo "11. Cert list has ≥1 entry after enrollment"
CERT_COUNT=$(echo "$BODY" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(len(d) if isinstance(d, list) else d.get('total', d.get('certificates', [])).__len__() if isinstance(d.get('certificates'), list) else 0)
" 2>/dev/null || echo 0)
check_true "≥1 cert in list ($CERT_COUNT)" test "${CERT_COUNT:-0}" -ge 1

section "Auth Boundary"

echo "12. GET /admin/health without auth → 401"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$ADMIN_URL/health")
check_exact "no auth → 401" "$CODE" "401"

echo "13. GET /admin/cas without auth → 401"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$ADMIN_URL/cas")
check_exact "no auth → 401" "$CODE" "401"

echo "14. POST /admin/otp/generate without auth → 401"
CODE=$(curl -sk -X POST -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d '{"entity_id":"unauth"}' "$ADMIN_URL/otp/generate")
check_exact "no auth → 401" "$CODE" "401"

echo "15. Bad bearer token → 401"
CODE=$(curl -sk -H "Authorization: Bearer wrong-token" \
    -o /dev/null -w "%{http_code}" "$ADMIN_URL/health")
check_exact "bad token → 401" "$CODE" "401"

summary "Admin API Conformance"
