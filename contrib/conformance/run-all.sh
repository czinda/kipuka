#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka — RFC Conformance Suite Runner
# ═══════════════════════════════════════════════════════════════════════
# Runs all conformance test scripts and reports combined results.
#
# Usage:
#   ./contrib/conformance/run-all.sh              # test running server
#   ./contrib/conformance/run-all.sh --deploy      # destroy, deploy, test, teardown
#   ./contrib/conformance/run-all.sh rfc7030       # run a single suite
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DEPLOY=false
FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deploy) DEPLOY=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--deploy] [suite-name]"
            echo ""
            echo "  --deploy   Tear down, redeploy with conformance config, then test"
            echo "  suite-name Run only matching suites (e.g., 'rfc7030', 'auth')"
            exit 0 ;;
        *) FILTER="$1"; shift ;;
    esac
done

# ── Deploy lifecycle ───────────────────────────────────────────────────
if [[ "$DEPLOY" == "true" ]]; then
    echo -e "${BOLD}Destroying existing deployment...${NC}"
    cd "$REPO_DIR"
    podman compose --profile sqlite down -v 2>/dev/null || true
    podman compose --profile conformance down -v 2>/dev/null || true
    podman ps -a --filter name=kipuka --format '{{.ID}}' | xargs -r podman rm -f 2>/dev/null || true

    echo -e "${BOLD}Regenerating test PKI...${NC}"
    "$REPO_DIR/contrib/local-dev/setup-ca.sh" --clean

    echo -e "${BOLD}Pulling fresh image...${NC}"
    podman pull registry.kipuka.dev/heebus/kipuka:latest-arm64 2>&1 | tail -1

    echo -e "${BOLD}Starting kipuka with conformance config...${NC}"
    # Use the conformance config via volume mount
    podman run -d --name kipuka-conformance \
        -p 9443:9443 \
        -v "$REPO_DIR/contrib/conformance/kipuka-conformance.toml:/etc/kipuka/kipuka.toml:ro" \
        -v "$REPO_DIR/contrib/local-dev/tls:/etc/kipuka/tls:ro" \
        -v "$REPO_DIR/contrib/local-dev/ca:/etc/kipuka/ca:ro" \
        -v "$REPO_DIR/web:/var/www/kipuka/web:ro" \
        -e RUST_LOG=info \
        registry.kipuka.dev/heebus/kipuka:latest-arm64

    echo "Waiting for server health..."
    MAX_WAIT=30; WAITED=0
    while [[ $WAITED -lt $MAX_WAIT ]]; do
        code=$(curl -sk -H "Authorization: Bearer conformance-test-token" \
            -o /dev/null -w "%{http_code}" --connect-timeout 2 \
            "https://localhost:9443/admin/health" 2>/dev/null || true)
        if [[ "$code" == "200" ]]; then
            echo -e "${GREEN}Server healthy after ${WAITED}s${NC}"
            break
        fi
        sleep 1
        WAITED=$((WAITED + 1))
    done
    if [[ $WAITED -ge $MAX_WAIT ]]; then
        echo -e "${RED}Server did not become healthy within ${MAX_WAIT}s${NC}"
        podman logs kipuka-conformance --tail 20 2>&1
        exit 1
    fi
fi

cleanup() {
    if [[ "$DEPLOY" == "true" ]]; then
        echo ""
        echo -e "${BOLD}Tearing down conformance container...${NC}"
        podman rm -f kipuka-conformance 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Discover and run suites ────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo -e " ${BOLD}Kipuka — RFC Conformance Test Suite${NC}"
echo "═══════════════════════════════════════════════════════════════════"

SUITES=(
    rfc7030-est
    rfc9908-csrattrs
    auth-otp
    auth-mtls
    admin-api
    tls-compliance
    est-renewal-info
    rfc8739-star
    rfc8295-cms-est
    rfc4210-cmp
    rfc9483-coap
    audit-niap
)

scripts_run=0
scripts_passed=0
scripts_failed=0
scripts_skipped=0

for suite in "${SUITES[@]}"; do
    script="$SCRIPT_DIR/${suite}.sh"

    # Apply filter
    if [[ -n "$FILTER" ]] && ! echo "$suite" | grep -qi "$FILTER"; then
        continue
    fi

    if [[ ! -f "$script" ]]; then
        echo -e "\n${YELLOW}SKIP${NC} ${suite} (not yet implemented)"
        ((scripts_skipped++))
        continue
    fi
    if [[ ! -x "$script" ]]; then
        chmod +x "$script"
    fi

    echo ""
    echo -e "${BOLD}━━━ ${suite} ━━━${NC}"

    set +e
    bash "$script"
    rc=$?
    set -e

    ((scripts_run++))
    if [[ $rc -eq 0 ]]; then
        ((scripts_passed++))
    else
        ((scripts_failed++))
    fi
done

echo ""
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo -e " ${BOLD}Combined Results${NC}"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "  Suites run:     $scripts_run"
echo -e "  Suites passed:  ${GREEN}$scripts_passed${NC}"
echo -e "  Suites failed:  ${RED}$scripts_failed${NC}"
echo -e "  Suites pending: ${YELLOW}$scripts_skipped${NC}"
echo ""

if [[ $scripts_failed -eq 0 ]] && [[ $scripts_run -gt 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL SUITES PASSED${NC}"
else
    echo -e "  ${RED}${BOLD}$scripts_failed SUITE(S) HAD FAILURES${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"

exit $scripts_failed
