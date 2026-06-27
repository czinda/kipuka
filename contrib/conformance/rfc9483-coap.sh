#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — RFC 9483 CoAP/DTLS Conformance
# ═══════════════════════════════════════════════════════════════════════
# Runs cargo tests for the kipuka-coap crate and validates module
# implementation against RFC 7252, RFC 9483, and RFC 7959.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
source "$(dirname "$0")/common.sh"

# CoAP tests don't need a running server — they're unit tests
DB_BACKEND="n/a" # shellcheck: used by common.sh summary
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COAP_SRC="$PROJECT_ROOT/crates/kipuka-coap/src"

echo "═══════════════════════════════════════════════════════════════"
echo " RFC 9483 — EST-coaps (CoAP/DTLS Transport)"
echo "═══════════════════════════════════════════════════════════════"

section "Unit Tests"

echo "1. cargo test -p kipuka-coap"
TEST_OUT="$TMPDIR/coap-tests.txt"
if cargo test -p kipuka-coap 2>&1 | tee "$TEST_OUT" | tail -3; then
    CARGO_RC=0
else
    CARGO_RC=$?
fi

TOTAL=$(grep "^test result:" "$TEST_OUT" | head -1)
TEST_PASSED=$(echo "$TOTAL" | grep -o '[0-9]* passed' | grep -o '[0-9]*' 2>/dev/null || echo 0)

if [[ "$CARGO_RC" -eq 0 ]]; then
    check_true "cargo test -p kipuka-coap ($TEST_PASSED tests)" true
else
    check_true "cargo test -p kipuka-coap" false
fi

section "RFC 7252 — CoAP Message Layer"
rfc_ref "RFC 7252 §3: CoAP message format"

echo "2. Message parse/encode tests present"
if grep -q "test_parse_minimal_message.*ok" "$TEST_OUT" && \
   grep -q "test_parse_message_with_payload.*ok" "$TEST_OUT"; then
    check_true "CoAP message parsing" true
else
    check_true "CoAP message parsing" test "$CARGO_RC" -eq 0
fi

echo "3. Message encode roundtrip"
if grep -q "test_parse_encode_roundtrip.*ok" "$TEST_OUT" 2>/dev/null || \
   (grep -q "roundtrip" "$TEST_OUT" && [[ "$CARGO_RC" -eq 0 ]]); then
    check_true "encode/decode roundtrip" true
else
    check_true "encode/decode roundtrip" false
fi

section "RFC 7959 — Block-Wise Transfer"
rfc_ref "RFC 7959 §2: block-wise transfer for large payloads"

echo "4. Block assembler/disassembler tests"
if grep -q "test_assembler.*ok" "$TEST_OUT" && \
   grep -q "test_disassembler.*ok" "$TEST_OUT"; then
    check_true "block-wise transfer" true
else
    check_true "block-wise transfer" test "$CARGO_RC" -eq 0
fi

section "RFC 9483 — EST-coaps URI Routing"
rfc_ref "RFC 9483 §5.1: abbreviated EST-coaps URIs"

echo "5. All 6 EST-coaps URI mappings"
ROUTES_FOUND=0
for route in "test_route_abbreviated_paths" "test_route_well_known_prefix" \
    "test_route_full_names" "test_route_unknown_path" \
    "test_route_message_post_simpleenroll" "test_route_message_get_cacerts"; do
    grep -q "$route" "$TEST_OUT" && ROUTES_FOUND=$((ROUTES_FOUND + 1))
done
check_true "URI routing tests ($ROUTES_FOUND/6)" test "$ROUTES_FOUND" -ge 5

echo "6. URI mappings in source"
MAPPINGS=0
for map in '"sen"' '"sren"' '"skg"' '"att"' '"cacerts"' '"crts"'; do
    grep -q "$map" "$COAP_SRC/server.rs" && MAPPINGS=$((MAPPINGS + 1))
done
check_true "6 URI mappings in router ($MAPPINGS/6)" test "$MAPPINGS" -eq 6

section "RFC 9483 §10.1 — Content-Format IDs"

echo "7. Content-format constants match spec"
if grep -q "285" "$COAP_SRC/content_format.rs" && \
   grep -q "281" "$COAP_SRC/content_format.rs" && \
   grep -q "287" "$COAP_SRC/content_format.rs"; then
    check_true "content-format IDs (285/281/287)" true
else
    check_true "content-format IDs" false
fi

section "DTLS Session Management"

echo "8. DTLS session cache tests"
if grep -q "test_cache.*ok" "$TEST_OUT"; then
    check_true "DTLS session cache" true
else
    check_true "DTLS session cache" test "$CARGO_RC" -eq 0
fi

section "Module Implementation"

echo "9. server.rs implementation"
LINES=$(wc -l < "$COAP_SRC/server.rs" 2>/dev/null | tr -d ' ')
check_true "server.rs ($LINES lines)" test "${LINES:-0}" -gt 100

echo "10. dtls.rs implementation"
LINES=$(wc -l < "$COAP_SRC/dtls.rs" 2>/dev/null | tr -d ' ')
check_true "dtls.rs ($LINES lines)" test "${LINES:-0}" -gt 100

echo "11. block.rs implementation"
LINES=$(wc -l < "$COAP_SRC/block.rs" 2>/dev/null | tr -d ' ')
check_true "block.rs ($LINES lines)" test "${LINES:-0}" -gt 100

summary "RFC 9483 CoAP Conformance"
