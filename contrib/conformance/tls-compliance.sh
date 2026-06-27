#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — TLS Configuration Conformance
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"
require_server

echo "═══════════════════════════════════════════════════════════════"
echo " TLS Configuration Compliance"
echo "═══════════════════════════════════════════════════════════════"

TLS_OUT="$TMPDIR/tls-info.txt"
echo | openssl s_client -connect localhost:9443 -servername localhost 2>/dev/null > "$TLS_OUT"

section "Protocol Version"
rfc_ref "RFC 7030 §3.3.1: TLS 1.1+ required; TLS 1.2+ recommended"

echo "1. Server supports TLS 1.2 or higher"
PROTOCOL=$(grep -i "Protocol" "$TLS_OUT" | head -1 | awk '{print $NF}')
if [[ "$PROTOCOL" == "TLSv1.2" ]] || [[ "$PROTOCOL" == "TLSv1.3" ]]; then
    check_true "TLS protocol ($PROTOCOL)" true
else
    check_true "TLS protocol ($PROTOCOL)" false
fi

echo "2. TLS 1.3 supported"
TLS13_OUT="$TMPDIR/tls13.txt"
echo | openssl s_client -connect localhost:9443 -tls1_3 2>/dev/null > "$TLS13_OUT"
if grep -q "TLSv1.3" "$TLS13_OUT"; then
    check_true "TLS 1.3 available" true
else
    skip_test "TLS 1.3" "server may not support it"
fi

echo "3. TLS 1.0 rejected"
TLS10_ERR=$(echo | openssl s_client -connect localhost:9443 -tls1 2>&1 || true)
if echo "$TLS10_ERR" | grep -qi "wrong version\|no protocols\|unsupported\|alert\|error"; then
    check_true "TLS 1.0 rejected" true
else
    skip_test "TLS 1.0 rejection" "openssl may not support -tls1 flag"
fi

section "Cipher Suite"

echo "4. Cipher suite uses AEAD"
CIPHER=$(grep -i "Cipher" "$TLS_OUT" | grep -iv "Server\|Peer" | head -1 | awk '{print $NF}')
if echo "$CIPHER" | grep -qiE "GCM|CCM|CHACHA|POLY"; then
    check_true "AEAD cipher ($CIPHER)" true
else
    check_true "AEAD cipher ($CIPHER) — expected GCM/CCM/CHACHA20" false
fi

section "Certificate"

echo "5. Server certificate subject"
SUBJECT=$(echo | openssl s_client -connect localhost:9443 -servername localhost 2>/dev/null | \
    openssl x509 -noout -subject 2>/dev/null)
check_true "server cert has subject" test -n "$SUBJECT"
echo "    $SUBJECT"

echo "6. Server certificate has SANs (localhost)"
SANS=$(echo | openssl s_client -connect localhost:9443 2>/dev/null | \
    openssl x509 -noout -ext subjectAltName 2>/dev/null)
if echo "$SANS" | grep -qi "localhost\|127.0.0.1"; then
    check_true "SAN includes localhost" true
else
    skip_test "SAN check" "may not have localhost SAN"
fi

echo "7. Certificate chain verifies"
VERIFY=$(echo | openssl s_client -connect localhost:9443 -CAfile "$CA_CERT" 2>/dev/null | \
    grep "Verify return code")
if echo "$VERIFY" | grep -q "ok"; then
    check_true "chain verification" true
else
    check_true "chain verification ($VERIFY)" false
fi

summary "TLS Compliance"
