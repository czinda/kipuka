#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Multi-Database Verification
# ═══════════════════════════════════════════════════════════════════════
# Runs the core EST test suite against all three database backends
# sequentially (SQLite, PostgreSQL, MariaDB) and prints a comparison
# table of results.
#
# Each backend is started fresh: the script tears down any running
# compose services, removes volumes to ensure a clean database, brings
# up the target profile, waits for health, runs the core test suite,
# captures the result, and tears down again.
#
# Prerequisites:
#   - contrib/local-dev/setup-ca.sh was run (certs generated)
#   - No other kipuka compose services running on port 9443
#
# Usage:
#   ./contrib/verify/verify-databases.sh
#
# Options:
#   --skip-teardown   Leave the last profile running after tests
#   --core-script PATH  Use a different core test script (default:
#                        contrib/local-dev/test-est.sh)
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

source "$(dirname "$0")/common.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CORE_SCRIPT="$REPO_DIR/contrib/local-dev/test-est.sh"
SKIP_TEARDOWN=false
COMPOSE_FILE="$REPO_DIR/compose.yaml"
HEALTH_URL="https://localhost:9443/admin/health"
ADMIN_AUTH=(-H "Authorization: Bearer admin-dev-token")
MAX_WAIT=60  # seconds to wait for health check

# ── Parse arguments ────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --skip-teardown) SKIP_TEARDOWN=true ;;
        --core-script=*) CORE_SCRIPT="${arg#*=}" ;;
        --core-script)
            shift
            CORE_SCRIPT="$1"
            ;;
    esac
done

if [[ ! -f "$CORE_SCRIPT" ]]; then
    echo "ERROR: Core test script not found: $CORE_SCRIPT"
    echo "Run from the repository root or specify --core-script=PATH"
    exit 1
fi

# ── Profiles and their compose service names ──────────────────────
declare -A PROFILES=(
    [sqlite]="kipuka"
    [postgres]="kipuka-pg"
    [mariadb]="kipuka-my"
)

# ── Volume names for clean-slate resets ────────────────────────────
# These match the volume definitions in compose.yaml.
COMMON_VOLUMES=(kipuka-data)
declare -A PROFILE_VOLUMES=(
    [sqlite]=""
    [postgres]="kipuka-pgdata"
    [mariadb]="kipuka-mydata"
)

# ── Results storage ───────────────────────────────────────────────
declare -A RESULTS
declare -A EXIT_CODES

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Multi-Database Verification"
echo "═══════════════════════════════════════════════════════════════"
echo "Core test: $CORE_SCRIPT"
echo "Profiles:  sqlite, postgres, mariadb"
echo ""

# ── Helper: tear down all profiles ─────────────────────────────────
teardown_all() {
    echo "  Tearing down all compose services..."
    for profile in sqlite postgres mariadb; do
        podman compose -f "$COMPOSE_FILE" --profile "$profile" down 2>/dev/null || true
    done
}

# ── Helper: remove volumes for clean slate ─────────────────────────
remove_volumes() {
    local profile="$1"
    echo "  Removing volumes for clean-slate $profile..."
    for vol in "${COMMON_VOLUMES[@]}"; do
        podman volume rm "$vol" 2>/dev/null || true
    done
    local extra="${PROFILE_VOLUMES[$profile]:-}"
    if [[ -n "$extra" ]]; then
        podman volume rm "$extra" 2>/dev/null || true
    fi
}

# ── Helper: wait for server health ─────────────────────────────────
wait_for_health() {
    local elapsed=0
    echo "  Waiting for server health (up to ${MAX_WAIT}s)..."
    while [[ $elapsed -lt $MAX_WAIT ]]; do
        local code
        code=$(curl -sk "${ADMIN_AUTH[@]}" \
          -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || echo "000")
        if [[ "$code" == "200" ]]; then
            echo "  Server healthy after ${elapsed}s"
            return 0
        fi
        sleep 2
        ((elapsed += 2))
    done
    echo "  WARNING: Server did not become healthy within ${MAX_WAIT}s"
    return 1
}

# ── Run tests for each profile ─────────────────────────────────────
for profile in sqlite postgres mariadb; do
    echo "─────────────────────────────────────────────────────────"
    echo " Testing: $profile"
    echo "─────────────────────────────────────────────────────────"

    # 1. Tear down any running services.
    teardown_all

    # 2. Remove volumes for clean slate.
    remove_volumes "$profile"

    # 3. Start the target profile.
    echo "  Starting compose profile: $profile"
    podman compose -f "$COMPOSE_FILE" --profile "$profile" up -d 2>&1 | \
        sed 's/^/    /'

    # 4. Wait for health.
    if ! wait_for_health; then
        RESULTS[$profile]="STARTUP FAILED"
        EXIT_CODES[$profile]="999"
        echo "  SKIPPING tests for $profile — server did not start"
        continue
    fi

    # 5. Run the core test suite and capture output.
    echo "  Running core tests..."
    echo ""
    test_output=$("$CORE_SCRIPT" 2>&1) || true
    test_exit=$?

    # Extract the pass/fail counts from the last summary line.
    summary=$(echo "$test_output" | grep -E "Results:.*passed.*failed" | tail -1)
    if [[ -n "$summary" ]]; then
        RESULTS[$profile]="$summary"
    else
        RESULTS[$profile]="exit code $test_exit"
    fi
    EXIT_CODES[$profile]="$test_exit"

    # Print condensed test output.
    echo "$test_output" | grep -E '(PASS|FAIL|SKIP|Results:)' | sed 's/^/    /'
    echo ""

    # 6. Tear down (unless this is the last profile and --skip-teardown).
    if [[ "$profile" != "mariadb" ]] || [[ "$SKIP_TEARDOWN" == "false" ]]; then
        echo "  Tearing down $profile..."
        podman compose -f "$COMPOSE_FILE" --profile "$profile" down 2>/dev/null || true
    else
        echo "  Leaving $profile running (--skip-teardown)"
    fi

    echo ""
done

# ── Comparison Table ──────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " Multi-Database Comparison"
echo "═══════════════════════════════════════════════════════════════"
printf "  %-12s  %-6s  %s\n" "BACKEND" "EXIT" "RESULT"
printf "  %-12s  %-6s  %s\n" "───────────" "──────" "────────────────────────────"
for profile in sqlite postgres mariadb; do
    printf "  %-12s  %-6s  %s\n" \
        "$profile" \
        "${EXIT_CODES[$profile]:-N/A}" \
        "${RESULTS[$profile]:-NOT RUN}"
done
echo ""

# ── Overall exit code ─────────────────────────────────────────────
overall_exit=0
for profile in sqlite postgres mariadb; do
    code="${EXIT_CODES[$profile]:-999}"
    if [[ "$code" -ne 0 ]]; then
        overall_exit=1
    fi
done

if [[ $overall_exit -eq 0 ]]; then
    echo "All backends passed."
else
    echo "One or more backends had failures."
fi

exit $overall_exit
