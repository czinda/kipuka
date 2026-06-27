#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — RFC 8295 CMS-EST Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " RFC 8295 — EST with CMS"
echo "═══════════════════════════════════════════════════════════════"

CMS_URL="$EST_URL/cms"

section "Endpoint Reachability"
rfc_ref "RFC 8295 §3: CMS-wrapped EST operations"

echo "1. POST /cms/simpleenroll — endpoint exists"
CODE=$(curl -sk -X POST "$CMS_URL/simpleenroll" \
    -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
    -d "dGVzdA==" \
    -o /dev/null -w "%{http_code}")
# Any response except 404 means the endpoint is mounted
if [[ "$CODE" != "404" ]]; then
    check_true "/cms/simpleenroll reachable ($CODE)" true
else
    check_true "/cms/simpleenroll reachable" false
fi

echo "2. POST /cms/simplereenroll — endpoint exists"
CODE=$(curl -sk -X POST "$CMS_URL/simplereenroll" \
    -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
    -d "dGVzdA==" \
    -o /dev/null -w "%{http_code}")
if [[ "$CODE" != "404" ]]; then
    check_true "/cms/simplereenroll reachable ($CODE)" true
else
    check_true "/cms/simplereenroll reachable" false
fi

echo "3. POST /cms/serverkeygen — endpoint exists"
CODE=$(curl -sk -X POST "$CMS_URL/serverkeygen" \
    -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
    -d "dGVzdA==" \
    -o /dev/null -w "%{http_code}")
if [[ "$CODE" != "404" ]]; then
    check_true "/cms/serverkeygen reachable ($CODE)" true
else
    check_true "/cms/serverkeygen reachable" false
fi

echo "4. POST /cms/fullcmc — endpoint exists"
CODE=$(curl -sk -X POST "$CMS_URL/fullcmc" \
    -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
    -d "dGVzdA==" \
    -o /dev/null -w "%{http_code}")
if [[ "$CODE" != "404" ]]; then
    check_true "/cms/fullcmc reachable ($CODE)" true
else
    check_true "/cms/fullcmc reachable" false
fi

section "Content-Type Handling"

echo "5. Wrong Content-Type rejected (400 or 415)"
CODE=$(curl -sk -X POST "$CMS_URL/simpleenroll" \
    -H "Content-Type: text/plain" \
    -d "not cms" \
    -o /dev/null -w "%{http_code}")
if [[ "$CODE" == "415" ]] || [[ "$CODE" == "400" ]]; then
    check_true "wrong Content-Type rejected ($CODE)" true
else
    check_exact "wrong Content-Type rejected" "$CODE" "415"
fi

echo "6. Malformed CMS body → 400"
CODE=$(curl -sk -X POST "$CMS_URL/simpleenroll" \
    -H "Content-Type: application/pkcs7-mime; smime-type=CMC-request" \
    -d "dGhpcyBpcyBub3QgdmFsaWQgQ01T" \
    -o /dev/null -w "%{http_code}")
if [[ "$CODE" == "400" ]] || [[ "$CODE" == "401" ]]; then
    check_true "malformed CMS body rejected ($CODE)" true
else
    check_true "malformed CMS body rejected ($CODE)" false
fi

summary "RFC 8295 CMS-EST Conformance"
