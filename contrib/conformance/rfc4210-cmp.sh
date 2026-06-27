#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — RFC 4210 CMP Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " RFC 4210 — Certificate Management Protocol"
echo "═══════════════════════════════════════════════════════════════"

CMP_URL="https://localhost:9443/.well-known/cmp"

section "Endpoint Reachability"
rfc_ref "RFC 4210 §5 + RFC 6712: CMP over HTTP"

echo "1. POST /.well-known/cmp — endpoint exists"
CODE=$(curl -sk -X POST "$CMP_URL" \
    -H "Content-Type: application/pkixcmp" \
    -d "dGVzdA==" \
    -o /dev/null -w "%{http_code}")
if [[ "$CODE" != "404" ]]; then
    check_true "CMP endpoint reachable ($CODE)" true
else
    check_true "CMP endpoint reachable" false
fi

section "Content-Type Handling"
rfc_ref "RFC 6712 §2: Content-Type must be application/pkixcmp"

echo "2. Correct Content-Type accepted"
CODE=$(curl -sk -X POST "$CMP_URL" \
    -H "Content-Type: application/pkixcmp" \
    -d "dGVzdA==" \
    -o /dev/null -w "%{http_code}")
# Should get 400 (bad CMP message) not 415 (wrong content type)
if [[ "$CODE" != "415" ]]; then
    check_true "application/pkixcmp accepted ($CODE)" true
else
    check_true "application/pkixcmp accepted" false
fi

echo "3. Wrong Content-Type rejected (400 or 415)"
CODE=$(curl -sk -X POST "$CMP_URL" \
    -H "Content-Type: text/plain" \
    -d "not cmp" \
    -o /dev/null -w "%{http_code}")
if [[ "$CODE" == "415" ]] || [[ "$CODE" == "400" ]]; then
    check_true "wrong Content-Type rejected ($CODE)" true
else
    check_exact "wrong Content-Type rejected" "$CODE" "415"
fi

echo "4. GET /.well-known/cmp → 405 Method Not Allowed"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$CMP_URL")
check_exact "GET → 405" "$CODE" "405"

echo "5. Malformed PKIMessage body → 400"
CODE=$(curl -sk -X POST "$CMP_URL" \
    -H "Content-Type: application/pkixcmp" \
    -d "dGhpcyBpcyBub3QgYSBQS0lNZXNzYWdl" \
    -o /dev/null -w "%{http_code}")
check_exact "malformed body → 400" "$CODE" "400"

summary "RFC 4210 CMP Conformance"
