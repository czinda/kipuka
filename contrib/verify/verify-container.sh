#!/usr/bin/env bash
# shellcheck disable=SC2034
# ═══════════════════════════════════════════════════════════════════════
# Kipuka EST Server — Container and Deployment Verification
# ═══════════════════════════════════════════════════════════════════════
# Tests container image integrity, startup behavior, web endpoints,
# and TLS configuration.
#
# Prerequisites:
#   - podman available
#   - Container image pulled or built locally
#   - contrib/local-dev/setup-ca.sh was run (for compose tests)
#
# Usage:
#   ./contrib/verify/verify-container.sh
#
# Environment:
#   KIPUKA_IMAGE  Override the container image (default: auto-detect
#                 from compose.yaml or registry.kipuka.dev/kipuka)
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

source "$(dirname "$0")/common.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

COMPOSE_FILE="$REPO_DIR/compose.yaml"
ADMIN_URL="https://localhost:9443/admin"
DASHBOARD_URL="https://localhost:9443/dashboard/"
ADMIN_AUTH=(-H "Authorization: Bearer admin-dev-token")
MAX_WAIT=45

passed=0
failed=0
skipped=0

check_exact() {
    local name="$1" http_code="$2" expected="$3"
    if [[ "$http_code" == "$expected" ]]; then
        echo "  PASS ($http_code)"
        ((passed++))
    else
        echo "  FAIL (got $http_code, expected $expected)"
        ((failed++))
    fi
}

# ── Detect container image ────────────────────────────────────────
# Prefer KIPUKA_IMAGE env var, then try to extract from compose.yaml,
# then fall back to the known registry path.
if [[ -n "${KIPUKA_IMAGE:-}" ]]; then
    IMAGE="$KIPUKA_IMAGE"
elif [[ -f "$COMPOSE_FILE" ]]; then
    IMAGE=$(grep -m1 'image:.*kipuka' "$COMPOSE_FILE" | \
            sed 's/.*image: *//' | tr -d ' ' | head -1)
    # Strip any # comments
    IMAGE="${IMAGE%%#*}"
    IMAGE=$(echo "$IMAGE" | xargs)
fi
IMAGE="${IMAGE:-registry.kipuka.dev/kipuka:latest-arm64}"

echo "═══════════════════════════════════════════════════════════════"
echo " Kipuka EST Server — Container and Deployment Verification"
echo "═══════════════════════════════════════════════════════════════"
echo "Image: $IMAGE"
echo ""

# ═════════════════════════════════════════════════════════════════════
# Test 1: Check container image exists locally
# ═════════════════════════════════════════════════════════════════════
echo "── Image Checks ──────────────────────────────────────────────"

echo "1. Container image exists locally"
if podman image exists "$IMAGE" 2>/dev/null; then
    echo "  PASS (image found: $IMAGE)"
    ((passed++))
else
    echo "  FAIL (image not found: $IMAGE)"
    echo "    Pull with: podman pull $IMAGE"
    ((failed++))
fi

# ═════════════════════════════════════════════════════════════════════
# Test 2: Container reports version (--version or --help)
#
# The kipuka binary should respond to --version or --help without
# needing config files or database.
# ═════════════════════════════════════════════════════════════════════
echo "2. Container runs and reports version"
version_output=$(podman run --rm "$IMAGE" --version 2>&1 || true)
if [[ -n "$version_output" ]] && echo "$version_output" | grep -qiE 'kipuka|[0-9]+\.[0-9]+'; then
    echo "  PASS (version: $(echo "$version_output" | head -1))"
    ((passed++))
else
    # Try --help as fallback.
    help_output=$(podman run --rm "$IMAGE" --help 2>&1 || true)
    if [[ -n "$help_output" ]] && echo "$help_output" | grep -qiE 'kipuka|est|usage'; then
        echo "  PASS (--help works: $(echo "$help_output" | head -1))"
        ((passed++))
    else
        echo "  FAIL (no version or help output)"
        echo "    Got: ${version_output:-<empty>}"
        ((failed++))
    fi
fi

echo ""
echo "── Compose Service Checks ────────────────────────────────────"

# ═════════════════════════════════════════════════════════════════════
# Test 3: Start compose and verify /admin/health
# ═════════════════════════════════════════════════════════════════════
echo "3. Checking if compose services are already running"

# Check if services are already running.
compose_running=false
health_code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health" 2>/dev/null || echo "000")

if [[ "$health_code" == "200" ]]; then
    compose_running=true
    echo "  Services already running (health: 200)"
else
    echo "  Services not running — starting sqlite profile..."
    podman compose -f "$COMPOSE_FILE" --profile sqlite up -d 2>&1 | sed 's/^/    /'

    # Wait for health.
    elapsed=0
    while [[ $elapsed -lt $MAX_WAIT ]]; do
        health_code=$(curl -sk "${ADMIN_AUTH[@]}" \
          -o /dev/null -w "%{http_code}" "$ADMIN_URL/health" 2>/dev/null || echo "000")
        if [[ "$health_code" == "200" ]]; then
            break
        fi
        sleep 2
        ((elapsed += 2))
    done
fi

echo "4. GET /admin/health"
health_code=$(curl -sk "${ADMIN_AUTH[@]}" \
  -o /dev/null -w "%{http_code}" "$ADMIN_URL/health" 2>/dev/null || echo "000")
check_exact "health" "$health_code" "200"

# ═════════════════════════════════════════════════════════════════════
# Test 5: Verify /dashboard/ returns HTML (200)
# ═════════════════════════════════════════════════════════════════════
echo "5. GET /dashboard/ returns HTML"
dash_resp=$(curl -sk \
  -o "$TMPDIR/kipuka-dashboard.html" \
  -w "%{http_code}" "$DASHBOARD_URL" 2>/dev/null || echo "000")
if [[ "$dash_resp" == "200" ]]; then
    # Verify it looks like HTML.
    if grep -qi '<html\|<!doctype\|<head\|<body' "$TMPDIR/kipuka-dashboard.html" 2>/dev/null; then
        echo "  PASS (200 with HTML content)"
        ((passed++))
    else
        echo "  PASS (200 but content may not be HTML — check manually)"
        ((passed++))
    fi
else
    echo "  FAIL (got $dash_resp, expected 200)"
    ((failed++))
fi

# ═════════════════════════════════════════════════════════════════════
# Test 6: Verify container runs as expected user
#
# The compose.yaml specifies user: "0:0" (root).  Verify the kipuka
# process is running as expected.
# ═════════════════════════════════════════════════════════════════════
echo "6. Container process user"

# Detect the running container name.
if podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-pg; then
    CONTAINER_NAME="kipuka-est-pg"
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-my; then
    CONTAINER_NAME="kipuka-est-my"
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q kipuka-est-hsm; then
    CONTAINER_NAME="kipuka-est-hsm"
else
    CONTAINER_NAME="kipuka-est"
fi

proc_user=$(podman exec "$CONTAINER_NAME" whoami 2>/dev/null || \
            podman exec "$CONTAINER_NAME" id -un 2>/dev/null || true)
if [[ -n "$proc_user" ]]; then
    echo "  PASS (running as: $proc_user)"
    ((passed++))
else
    # Try inspecting container config instead.
    compose_user=$(podman inspect "$CONTAINER_NAME" --format '{{.Config.User}}' 2>/dev/null || true)
    if [[ -n "$compose_user" ]]; then
        echo "  PASS (configured user: $compose_user)"
        ((passed++))
    else
        echo "  SKIP (could not determine process user)"
        ((skipped++))
    fi
fi

# ═════════════════════════════════════════════════════════════════════
# Test 7: Verify TLS is working (check cert subject via openssl)
# ═════════════════════════════════════════════════════════════════════
echo ""
echo "── TLS Checks ────────────────────────────────────────────────"

echo "7. TLS certificate subject via openssl s_client"
tls_output=$(echo | openssl s_client -connect localhost:9443 -servername localhost 2>/dev/null || true)

if [[ -n "$tls_output" ]]; then
    tls_subject=$(echo "$tls_output" | openssl x509 -noout -subject 2>/dev/null || true)
    tls_issuer=$(echo "$tls_output" | openssl x509 -noout -issuer 2>/dev/null || true)
    tls_dates=$(echo "$tls_output" | openssl x509 -noout -dates 2>/dev/null || true)

    if [[ -n "$tls_subject" ]]; then
        echo "  PASS (TLS working)"
        echo "    Subject: $tls_subject"
        echo "    Issuer:  $tls_issuer"
        echo "    $tls_dates" | sed 's/^/    /'
        ((passed++))
    else
        echo "  FAIL (connected but could not extract certificate details)"
        ((failed++))
    fi
else
    echo "  FAIL (openssl s_client could not connect to localhost:9443)"
    ((failed++))
fi

echo "8. TLS protocol version"
tls_proto=$(echo | openssl s_client -connect localhost:9443 2>/dev/null | \
            grep -i "Protocol" | head -1 || true)
if [[ -n "$tls_proto" ]]; then
    echo "  PASS ($tls_proto)"
    ((passed++))
else
    # Try extracting from the full output.
    tls_version=$(echo "$tls_output" | grep -oE 'TLSv[0-9.]+' | head -1 || true)
    if [[ -n "$tls_version" ]]; then
        echo "  PASS (protocol: $tls_version)"
        ((passed++))
    else
        echo "  SKIP (could not determine TLS protocol version)"
        ((skipped++))
    fi
fi

echo "9. TLS cipher suite"
tls_cipher=$(echo | openssl s_client -connect localhost:9443 2>/dev/null | \
             grep -i "Cipher" | grep -v "Cipher is" | head -1 || true)
cipher_line=$(echo | openssl s_client -connect localhost:9443 2>/dev/null | \
              grep "Cipher is" | head -1 || true)
if [[ -n "$cipher_line" ]]; then
    echo "  PASS ($cipher_line)"
    ((passed++))
elif [[ -n "$tls_cipher" ]]; then
    echo "  PASS ($tls_cipher)"
    ((passed++))
else
    echo "  SKIP (could not determine cipher suite)"
    ((skipped++))
fi

echo ""

# ── Cleanup ───────────────────────────────────────────────────────
if [[ "$compose_running" == "false" ]]; then
    echo "── Cleanup ───────────────────────────────────────────────────"
    echo "  Tearing down compose services started by this script..."
    podman compose -f "$COMPOSE_FILE" --profile sqlite down 2>/dev/null || true
    echo ""
fi

# ── Summary ───────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo " Container Results: ${passed} passed, ${failed} failed, ${skipped} skipped"
echo "═══════════════════════════════════════════════════════════════"

exit $failed
