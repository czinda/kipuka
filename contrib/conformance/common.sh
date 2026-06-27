#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka RFC Conformance Suite — Shared Test Helpers
# ═══════════════════════════════════════════════════════════════════════
# Source this from every conformance script:
#   source "$(dirname "$0")/common.sh"
# ═══════════════════════════════════════════════════════════════════════

# ── Color output ────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Counters ────────────────────────────────────────────────────────────
passed=0
failed=0
skipped=0

# ── API configuration ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

export EST_URL="https://localhost:9443/.well-known/est"
export ADMIN_URL="https://localhost:9443/admin"
ADMIN_AUTH=(-H "Authorization: Bearer conformance-test-token")
CA_CERT="$REPO_DIR/contrib/local-dev/ca/ca.pem"
export CA_CERT
AGENT_CERT="$REPO_DIR/contrib/local-dev/tls/agent.pem"
export AGENT_CERT
AGENT_KEY="$REPO_DIR/contrib/local-dev/tls/agent-key.pem"
export AGENT_KEY
TMPDIR="${TMPDIR:-/tmp}/kipuka-conformance-$$"
mkdir -p "$TMPDIR"

trap 'rm -rf "$TMPDIR"' EXIT

# ── Basic test assertions ──────────────────────────────────────────────

check_exact() {
    local name="$1" http_code="$2" expected="$3"
    if [[ "$http_code" == "$expected" ]]; then
        echo -e "  ${GREEN}PASS${NC} $name"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name (got $http_code, expected $expected)"
        ((failed++))
    fi
}

check_true() {
    local name="$1"
    shift
    if "$@"; then
        echo -e "  ${GREEN}PASS${NC} $name"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name"
        ((failed++))
    fi
}

check_contains() {
    local name="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qi "$needle"; then
        echo -e "  ${GREEN}PASS${NC} $name"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name (expected to contain: $needle)"
        ((failed++))
    fi
}

skip_test() {
    local name="$1" reason="${2:-}"
    if [[ -n "$reason" ]]; then
        echo -e "  ${YELLOW}SKIP${NC} $name ($reason)"
    else
        echo -e "  ${YELLOW}SKIP${NC} $name"
    fi
    ((skipped++))
}

section() {
    echo ""
    echo -e "${CYAN}── $1 ──────────────────────────────────────────────────────${NC}"
}

rfc_ref() {
    echo -e "  ${CYAN}RFC ref: $1${NC}"
}

summary() {
    local label="${1:-Conformance}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    local total=$((passed + failed + skipped))
    echo -e " $label: ${GREEN}${passed} passed${NC}, ${RED}${failed} failed${NC}, ${YELLOW}${skipped} skipped${NC}  (total: $total)"
    echo "═══════════════════════════════════════════════════════════════"
    exit $(( failed > 125 ? 125 : failed ))
}

# ── Server check ────────────────────────────────────────────────────────

require_server() {
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "$EST_URL/cacerts" 2>/dev/null || true)
    if [[ "$code" == "000" ]] || [[ -z "$code" ]]; then
        echo -e "${RED}ERROR: Kipuka server is not responding at $EST_URL${NC}"
        echo "Start the server:"
        echo "  podman compose --profile conformance up -d"
        exit 1
    fi
}

# ── HTTP helpers ────────────────────────────────────────────────────────

# curl_est — perform a curl request, save headers + body + status code
# Usage: curl_est GET /cacerts output.b64 headers.txt
#        curl_est POST /simpleenroll output.p7 headers.txt -u "user:pass" -d "$body" -H "Content-Type: ..."
curl_est() {
    local method="$1" path="$2" body_file="$3" header_file="$4"
    shift 4
    curl -sk -X "$method" \
        -D "$header_file" \
        -o "$body_file" \
        -w "%{http_code}" \
        "$@" \
        "$EST_URL$path" 2>/dev/null
}

# get_header — extract a header value (case-insensitive)
get_header() {
    local header_file="$1" name="$2"
    grep -i "^${name}:" "$header_file" 2>/dev/null | head -1 | sed "s/^[^:]*: *//" | tr -d '\r'
}

# ── JSON helpers ────────────────────────────────────────────────────────

json_field() {
    local json="$1" field="$2"
    echo "$json" | python3 -c "import json,sys; print(json.load(sys.stdin).get(sys.argv[1],''))" "$field" 2>/dev/null || true
}

json_has_field() {
    local file="$1" field="$2"
    python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
for p in sys.argv[2].split('.'):
    if isinstance(d, dict) and p in d:
        d = d[p]
    else:
        sys.exit(1)
" "$file" "$field" 2>/dev/null
}

# ── OTP + CSR helpers ──────────────────────────────────────────────────

generate_otp() {
    local entity_id="$1"
    curl -sk "${ADMIN_AUTH[@]}" \
        -X POST "$ADMIN_URL/otp/generate" \
        -H "Content-Type: application/json" \
        -d "{\"entity_id\": \"$entity_id\"}" 2>/dev/null | \
        python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true
}

generate_csr_der() {
    local cn="$1" keyfile="$2" derfile="$3"
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "$keyfile" \
        -subj "/CN=${cn}/O=Kipuka Conformance Test" 2>/dev/null | \
        openssl req -outform DER -out "$derfile" 2>/dev/null
}

# ── ASN.1 / DER validation helpers ────────────────────────────────────

# assert_asn1_valid — check that a file is valid DER-encoded ASN.1
assert_asn1_valid() {
    local name="$1" der_file="$2"
    if openssl asn1parse -inform DER -in "$der_file" > /dev/null 2>&1; then
        echo -e "  ${GREEN}PASS${NC} $name — valid ASN.1 DER"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name — invalid ASN.1 DER"
        ((failed++))
    fi
}

# assert_asn1_outer_tag — check the outer tag of a DER structure
# Tags: 30=SEQUENCE, 31=SET, 06=OID, 02=INTEGER
assert_asn1_outer_tag() {
    local name="$1" der_file="$2" expected_hex="$3"
    local actual_hex
    actual_hex=$(xxd -p -l 1 "$der_file" 2>/dev/null)
    if [[ "$actual_hex" == "$expected_hex" ]]; then
        echo -e "  ${GREEN}PASS${NC} $name — outer tag 0x$expected_hex"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name — expected outer tag 0x$expected_hex, got 0x$actual_hex"
        ((failed++))
    fi
}

# assert_der_contains_oid — check that a DER file contains a specific OID
# OID hex is the encoded OID bytes (without the 06 <len> prefix)
assert_der_contains_oid_hex() {
    local name="$1" der_file="$2" oid_hex="$3"
    if xxd -p "$der_file" | tr -d '\n' | grep -qi "$oid_hex"; then
        echo -e "  ${GREEN}PASS${NC} $name"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name — OID hex $oid_hex not found in DER"
        ((failed++))
    fi
}

# assert_pkcs7_certs_only — validate a PKCS#7 degenerate certs-only structure
# Sets PKCS7_CERT_COUNT to the number of certificates extracted.
assert_pkcs7_certs_only() {
    local name="$1" der_file="$2" output_dir="$3"
    mkdir -p "$output_dir"
    local cert_pem="$output_dir/certs.pem"
    PKCS7_CERT_COUNT=0
    if openssl pkcs7 -inform DER -in "$der_file" -print_certs -out "$cert_pem" 2>/dev/null; then
        PKCS7_CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$cert_pem" 2>/dev/null || echo 0)
        if [[ "$PKCS7_CERT_COUNT" -gt 0 ]]; then
            echo -e "  ${GREEN}PASS${NC} $name — $PKCS7_CERT_COUNT certificate(s) extracted"
            ((passed++))
        else
            echo -e "  ${RED}FAIL${NC} $name — PKCS#7 parsed but contains 0 certificates"
            ((failed++))
        fi
    else
        echo -e "  ${RED}FAIL${NC} $name — not valid PKCS#7 DER"
        ((failed++))
    fi
}

# assert_x509_field — validate a field of an X.509 certificate
assert_x509_field() {
    local name="$1" cert_file="$2" field="$3" expected="$4" format="${5:-PEM}"
    local actual
    actual=$(openssl x509 -inform "$format" -in "$cert_file" -noout "-$field" 2>/dev/null | sed "s/^[^=]*= *//")
    if echo "$actual" | grep -qi "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $name — $field contains '$expected'"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name — $field: expected '$expected', got '$actual'"
        ((failed++))
    fi
}

# assert_cert_signed_by — verify a certificate was signed by a CA
assert_cert_signed_by() {
    local name="$1" cert_file="$2" ca_file="$3"
    if openssl verify -CAfile "$ca_file" "$cert_file" > /dev/null 2>&1; then
        echo -e "  ${GREEN}PASS${NC} $name — signature verified"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} $name — signature verification failed"
        ((failed++))
    fi
}
