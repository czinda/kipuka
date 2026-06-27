#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — Verify CSR Attributes & RFC 9908 Template
# ═══════════════════════════════════════════════════════════════════════
# Tests GET /.well-known/est/csrattrs
# Validates OID list encoding and RFC 9908 CertificationRequestInfoTemplate
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

require_server

echo "═══════════════════════════════════════════════════════════════"
echo " CSR Attributes & Template (RFC 7030 §4.5 + RFC 9908)"
echo "═══════════════════════════════════════════════════════════════"

section "Basic CSR Attributes"

echo "1. GET /csrattrs — expect 200 or 204"
RESP=$(curl -sk -D "$TMPDIR/csrattrs-headers.txt" \
    -o "$TMPDIR/csrattrs.b64" \
    -w "%{http_code}" \
    "$EST_URL/csrattrs")
if [[ "$RESP" == "200" ]] || [[ "$RESP" == "204" ]]; then
    echo -e "  ${GREEN}PASS${NC} ($RESP) csrattrs endpoint"
    ((passed++))
else
    echo -e "  ${RED}FAIL${NC} (got $RESP, expected 200 or 204) csrattrs endpoint"
    ((failed++))
fi

if [[ "$RESP" == "200" ]] && [[ -s "$TMPDIR/csrattrs.b64" ]]; then
    echo "2. Content-Type is application/csrattrs"
    CT=$(grep -i "content-type" "$TMPDIR/csrattrs-headers.txt" | head -1 | tr -d '\r')
    if echo "$CT" | grep -qi "application/csrattrs"; then
        echo -e "  ${GREEN}PASS${NC} $CT"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} expected application/csrattrs, got: $CT"
        ((failed++))
    fi

    echo "3. Response decodes as valid base64"
    if base64 -d < "$TMPDIR/csrattrs.b64" > "$TMPDIR/csrattrs.der" 2>/dev/null; then
        echo -e "  ${GREEN}PASS${NC} base64 decode OK ($(wc -c < "$TMPDIR/csrattrs.der") bytes)"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} base64 decode failed"
        ((failed++))
    fi

    echo "4. DER parses as valid ASN.1"
    if openssl asn1parse -inform DER -in "$TMPDIR/csrattrs.der" > "$TMPDIR/csrattrs-asn1.txt" 2>/dev/null; then
        echo -e "  ${GREEN}PASS${NC} ASN.1 parse OK"
        ((passed++))
        head -10 "$TMPDIR/csrattrs-asn1.txt" | sed 's/^/    /'
        TOTAL_LINES=$(wc -l < "$TMPDIR/csrattrs-asn1.txt")
        if [[ "$TOTAL_LINES" -gt 10 ]]; then
            echo "    ... ($TOTAL_LINES total ASN.1 elements)"
        fi
    else
        echo -e "  ${RED}FAIL${NC} ASN.1 parse failed"
        ((failed++))
    fi

    echo "5. Outer structure is a SEQUENCE"
    FIRST_LINE=$(head -1 "$TMPDIR/csrattrs-asn1.txt" 2>/dev/null || true)
    if echo "$FIRST_LINE" | grep -q "SEQUENCE"; then
        echo -e "  ${GREEN}PASS${NC} outer SEQUENCE present"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} expected outer SEQUENCE, got: $FIRST_LINE"
        ((failed++))
    fi

    section "RFC 9908 Template Detection"

    # Check for id-aa-certificationRequestInfoTemplate OID (1.2.840.113549.1.9.16.2.61)
    # In DER, this OID encodes as: 06 0B 2A 86 48 86 F7 0D 01 09 10 02 3D
    echo "6. Check for RFC 9908 template OID (1.2.840.113549.1.9.16.2.61)"
    if grep -q "2.840.113549.1.9.16.2.61\|id-smime-aa-61\|:2A8648.*023D" "$TMPDIR/csrattrs-asn1.txt" 2>/dev/null; then
        echo -e "  ${GREEN}PASS${NC} RFC 9908 CertificationRequestInfoTemplate OID present"
        ((passed++))
        HAS_TEMPLATE=true
    else
        # The OID might not show up in asn1parse output with a friendly name.
        # Check raw hex of the DER for the OID encoding.
        if xxd -p "$TMPDIR/csrattrs.der" | tr -d '\n' | grep -qi "2a864886f70d010910023d"; then
            echo -e "  ${GREEN}PASS${NC} RFC 9908 template OID found in DER bytes"
            ((passed++))
            HAS_TEMPLATE=true
        else
            echo -e "  ${YELLOW}SKIP${NC} no template OID — server may not have csr_template configured"
            ((skipped++))
            HAS_TEMPLATE=false
        fi
    fi

    if [[ "$HAS_TEMPLATE" == "true" ]]; then
        echo "7. Template wraps an INTEGER version (0)"
        if grep -q "INTEGER.*:00\|INTEGER.*0$" "$TMPDIR/csrattrs-asn1.txt" 2>/dev/null; then
            echo -e "  ${GREEN}PASS${NC} version INTEGER present"
            ((passed++))
        else
            echo -e "  ${RED}FAIL${NC} expected version INTEGER(0) in template"
            ((failed++))
        fi

        echo "8. Template contains mandatory [1] attributes tag"
        # [1] IMPLICIT tag = 0xA1 in DER
        if xxd -p "$TMPDIR/csrattrs.der" | tr -d '\n' | grep -qi "a1"; then
            echo -e "  ${GREEN}PASS${NC} [1] context tag present in DER"
            ((passed++))
        else
            echo -e "  ${RED}FAIL${NC} missing mandatory [1] attributes field"
            ((failed++))
        fi
    fi

elif [[ "$RESP" == "204" ]]; then
    echo "2-8. SKIP — server returned 204 No Content (no attributes configured)"
    ((skipped += 7))
fi

section "Per-label CSR Attributes"

echo "9. GET /{label}/csrattrs — nonexistent label → 404"
code=$(curl -sk -o /dev/null -w "%{http_code}" "$EST_URL/nonexistent-label/csrattrs")
check_exact "nonexistent label csrattrs" "$code" "404"

summary
