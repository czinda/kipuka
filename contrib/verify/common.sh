#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Shared Test Helpers
# ═══════════════════════════════════════════════════════════════════════
# Source this from every verify script:
#   source "$(dirname "$0")/common.sh"
# ═══════════════════════════════════════════════════════════════════════

# ── Color output ────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'  # No color

# ── Counters ────────────────────────────────────────────────────────────
passed=0
failed=0
skipped=0

# ── API configuration ──────────────────────────────────────────────────
EST_URL="https://localhost:9443/.well-known/est"
ADMIN_URL="https://localhost:9443/admin"
ADMIN_AUTH=(-H "Authorization: Bearer admin-dev-token")
CA_CERT="$(cd "$(dirname "$0")/../local-dev" && pwd)/ca/ca.pem"
AGENT_CERT="$(cd "$(dirname "$0")/../local-dev" && pwd)/tls/agent.pem"
AGENT_KEY="$(cd "$(dirname "$0")/../local-dev" && pwd)/tls/agent-key.pem"
TMPDIR="${TMPDIR:-/tmp}/kipuka-verify-$$"
mkdir -p "$TMPDIR"

# ── Cleanup trap ────────────────────────────────────────────────────────
trap 'rm -rf "$TMPDIR"' EXIT

# ── Database backend auto-detection ─────────────────────────────────────
if podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-pg; then
    DB_BACKEND="postgres"
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-my; then
    DB_BACKEND="mariadb"
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-hsm; then
    DB_BACKEND="hsm"
else
    DB_BACKEND="sqlite"
fi

# ── Test helpers ────────────────────────────────────────────────────────

# check — any 2xx is pass
check() {
    local name="$1" http_code="$2"
    if [[ "$http_code" =~ ^2 ]]; then
        echo -e "  ${GREEN}PASS${NC} ($http_code) $name"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} ($http_code) $name"
        ((failed++))
    fi
}

# check_exact — specific expected HTTP status code
check_exact() {
    local name="$1" http_code="$2" expected="$3"
    if [[ "$http_code" == "$expected" ]]; then
        echo -e "  ${GREEN}PASS${NC} ($http_code) $name"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} (got $http_code, expected $expected) $name"
        ((failed++))
    fi
}

# check_responds — any non-zero HTTP response
check_responds() {
    local name="$1" http_code="$2"
    if [[ "$http_code" =~ ^[0-9]+$ ]] && [[ "$http_code" -gt 0 ]]; then
        echo -e "  ${GREEN}PASS${NC} (responds $http_code) $name"
        ((passed++))
    else
        echo -e "  ${RED}FAIL${NC} (no response) $name"
        ((failed++))
    fi
}

# check_true — boolean condition with message
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

# skip_test — mark a test as skipped
skip_test() {
    local name="$1" reason="${2:-}"
    if [[ -n "$reason" ]]; then
        echo -e "  ${YELLOW}SKIP${NC} $name ($reason)"
    else
        echo -e "  ${YELLOW}SKIP${NC} $name"
    fi
    ((skipped++))
}

# section — prints section header
section() {
    echo ""
    echo "── $1 ──────────────────────────────────────────────────────"
}

# summary — prints pass/fail/skip totals, exits with fail count
summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    local total=$((passed + failed + skipped))
    echo -e " Results: ${GREEN}${passed} passed${NC}, ${RED}${failed} failed${NC}, ${YELLOW}${skipped} skipped${NC}  (total: $total, backend: $DB_BACKEND)"
    echo "═══════════════════════════════════════════════════════════════"
    exit $failed
}

# ── JSON helper ─────────────────────────────────────────────────────────
# json_field — extract a JSON field via python3
# Usage: json_field "$json_string" "field_name"
json_field() {
    local json="$1" field="$2"
    echo "$json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('$field',''))" 2>/dev/null || true
}

# ── Server check ────────────────────────────────────────────────────────
# require_server — check kipuka is responding, exit if not
require_server() {
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "$EST_URL/cacerts" 2>/dev/null || true)
    if [[ "$code" == "000" ]] || [[ -z "$code" ]]; then
        echo -e "${RED}ERROR: Kipuka server is not responding at $EST_URL${NC}"
        echo "Start the server first:"
        echo "  podman compose --profile sqlite up"
        exit 1
    fi
    echo "Server responding ($DB_BACKEND backend)"
}

# ── OTP helper ──────────────────────────────────────────────────────────
# generate_otp — generate an OTP and return the full JSON response body
# Usage: local body; body=$(generate_otp "entity-name")
#        local token; token=$(json_field "$body" "token")
generate_otp() {
    local entity_id="$1"
    local ttl="${2:-}"
    local payload
    if [[ -n "$ttl" ]]; then
        payload="{\"entity_id\": \"$entity_id\", \"ttl_seconds\": $ttl}"
    else
        payload="{\"entity_id\": \"$entity_id\"}"
    fi
    local response
    response=$(curl -sk "${ADMIN_AUTH[@]}" \
        -X POST "$ADMIN_URL/otp/generate" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        -w "\n%{http_code}")
    local code body
    code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')
    echo "$body"
    return 0
}

# ── CSR helper ──────────────────────────────────────────────────────────
# generate_csr — generate RSA 2048 CSR, returns base64-encoded DER
# Usage: local b64_csr; b64_csr=$(generate_csr "test-client.kipuka.test" "/tmp/key.pem")
generate_csr() {
    local cn="$1" keyfile="$2"
    local csrder="$TMPDIR/csr-$$.der"
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "$keyfile" \
        -subj "/CN=${cn}/O=Kipuka Test" 2>/dev/null | \
        openssl req -outform DER -out "$csrder" 2>/dev/null
    base64 < "$csrder"
}
