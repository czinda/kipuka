#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Master Verification Runner
# ═══════════════════════════════════════════════════════════════════════
# Runs all verify-*.sh scripts in order, collecting results.
#
# Usage:
#   ./contrib/verify/run-all.sh                          # uses running server
#   ./contrib/verify/run-all.sh --profile sqlite         # start + test + teardown
#   ./contrib/verify/run-all.sh --profile postgres
#   ./contrib/verify/run-all.sh --profile mariadb
#   ./contrib/verify/run-all.sh --profile hsm
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Color output ────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

# ── Parse arguments ─────────────────────────────────────────────────────
PROFILE=""
MANAGE_COMPOSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            MANAGE_COMPOSE=true
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--profile sqlite|postgres|mariadb|hsm]"
            echo ""
            echo "Without --profile: runs tests against an already-running server."
            echo "With --profile:    starts compose, waits for health, runs tests, tears down."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--profile sqlite|postgres|mariadb|hsm]"
            exit 1
            ;;
    esac
done

# ── Compose management ──────────────────────────────────────────────────
COMPOSE_CMD=""
if [[ "$MANAGE_COMPOSE" == "true" ]]; then
    # Detect container runtime
    if command -v podman &>/dev/null && podman compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="podman compose"
    elif command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    else
        echo -e "${RED}ERROR: Neither 'podman compose' nor 'docker compose' found${NC}"
        exit 1
    fi

    echo -e "${BOLD}Starting kipuka with profile: $PROFILE${NC}"
    cd "$REPO_DIR"
    $COMPOSE_CMD --profile "$PROFILE" up -d

    # Wait for server health
    echo "Waiting for server to become healthy..."
    ADMIN_URL="https://localhost:9443/admin"
    ADMIN_AUTH=(-H "Authorization: Bearer admin-dev-token")
    MAX_WAIT=60
    WAITED=0
    while [[ $WAITED -lt $MAX_WAIT ]]; do
        code=$(curl -sk "${ADMIN_AUTH[@]}" \
            -o /dev/null -w "%{http_code}" --connect-timeout 2 "$ADMIN_URL/health" 2>/dev/null || true)
        if [[ "$code" == "200" ]]; then
            echo -e "${GREEN}Server healthy after ${WAITED}s${NC}"
            break
        fi
        sleep 2
        WAITED=$((WAITED + 2))
        printf "."
    done
    echo ""

    if [[ $WAITED -ge $MAX_WAIT ]]; then
        echo -e "${RED}ERROR: Server did not become healthy within ${MAX_WAIT}s${NC}"
        $COMPOSE_CMD --profile "$PROFILE" logs --tail 50
        $COMPOSE_CMD --profile "$PROFILE" down -v
        exit 1
    fi
fi

# ── Cleanup on exit ─────────────────────────────────────────────────────
cleanup() {
    if [[ "$MANAGE_COMPOSE" == "true" ]] && [[ -n "$COMPOSE_CMD" ]]; then
        echo ""
        echo -e "${BOLD}Tearing down compose (profile: $PROFILE)...${NC}"
        cd "$REPO_DIR"
        $COMPOSE_CMD --profile "$PROFILE" down -v
    fi
}
trap cleanup EXIT

# ── Discover and run verify scripts ─────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo -e " ${BOLD}Kipuka EST Server — Full Verification Suite${NC}"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

SCRIPTS=(
    "$SCRIPT_DIR/verify-admin.sh"
    "$SCRIPT_DIR/verify-est-core.sh"
    "$SCRIPT_DIR/verify-otp.sh"
    "$SCRIPT_DIR/verify-error-handling.sh"
)

total_passed=0
total_failed=0
total_skipped=0
scripts_run=0
scripts_failed=0

for script in "${SCRIPTS[@]}"; do
    script_name=$(basename "$script" .sh)

    if [[ ! -x "$script" ]]; then
        echo -e "${YELLOW}SKIP${NC} $script_name (not executable)"
        continue
    fi

    echo ""
    echo -e "${BOLD}Running: $script_name${NC}"
    echo "───────────────────────────────────────────────────────────────"

    # Run the script and capture its exit code (which is the fail count)
    set +e
    "$script"
    exit_code=$?
    set -e

    ((scripts_run++))
    if [[ $exit_code -gt 0 ]]; then
        ((scripts_failed++))
        total_failed=$((total_failed + exit_code))
    fi

    # Parse the summary line from the script output to get counts
    # The scripts exit with $failed, so exit_code = failures for that script
done

echo ""
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo -e " ${BOLD}Combined Results${NC}"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "  Scripts run:    $scripts_run"
echo "  Scripts failed: $scripts_failed"
echo ""

if [[ $scripts_failed -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL SCRIPTS PASSED${NC}"
else
    echo -e "  ${RED}${BOLD}$scripts_failed SCRIPT(S) HAD FAILURES${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"

exit $scripts_failed
