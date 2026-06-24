#!/usr/bin/env bash
# ── setup-ca-hsm.sh — Generate test PKI using Kryoptic HSM CA key ────
#
# Prerequisites:
#   - Kryoptic container must be running (podman compose --profile hsm up)
#   - The Kryoptic entrypoint generates the CA cert from the HSM key
#
# This script:
#   1. Copies the HSM-generated CA cert from the kryoptic-data volume
#   2. Generates TLS server and agent certs using OpenSSL (these don't
#      need HSM — only the CA signing key is HSM-protected)
#
# The CA private key NEVER leaves the Kryoptic container — kipuka accesses
# it via the shared PKCS#11 library and token database.
#
# Usage:
#   podman compose --profile hsm up -d   # start Kryoptic
#   ./contrib/local-dev/setup-ca-hsm.sh  # generate TLS certs
#   podman compose --profile hsm up      # start kipuka with HSM
# ────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_DIR="${SCRIPT_DIR}/ca"
TLS_DIR="${SCRIPT_DIR}/tls"

CONTAINER_NAME="${KRYOPTIC_CONTAINER:-kipuka-kryoptic-1}"
KRYOPTIC_CA_PATH="/var/lib/kryoptic/ca.pem"

# ── Step 1: Verify Kryoptic container is running ─────────────────────
echo "Checking Kryoptic container..."
if ! podman inspect "$CONTAINER_NAME" &>/dev/null 2>&1; then
    echo "ERROR: Kryoptic container '${CONTAINER_NAME}' is not running."
    echo ""
    echo "Start it with:  podman compose --profile hsm up -d"
    echo ""
    echo "If the container name differs, set KRYOPTIC_CONTAINER:"
    echo "  KRYOPTIC_CONTAINER=my-kryoptic ./setup-ca-hsm.sh"
    exit 1
fi
echo "  Container '${CONTAINER_NAME}' found."

# ── Step 2: Copy the HSM-generated CA cert ───────────────────────────
mkdir -p "$CA_DIR" "$TLS_DIR"

echo "Copying CA certificate from Kryoptic container..."
if ! podman cp "${CONTAINER_NAME}:${KRYOPTIC_CA_PATH}" "${CA_DIR}/ca.pem" 2>/dev/null; then
    echo "ERROR: CA certificate not found in container."
    echo ""
    echo "The Kryoptic entrypoint should generate it automatically."
    echo "Check container logs:  podman logs ${CONTAINER_NAME}"
    echo ""
    echo "You can also generate it manually inside the container:"
    echo "  podman exec ${CONTAINER_NAME} openssl req -new -x509 \\"
    echo "    -engine pkcs11 -keyform engine \\"
    echo "    -key 'pkcs11:token=kipuka-hsm;object=kipuka-ca-key;type=private;pin-value=1234' \\"
    echo "    -out /var/lib/kryoptic/ca.pem -days 3650 \\"
    echo "    -subj '/CN=Kipuka HSM CA/O=Kipuka/C=US' \\"
    echo "    -addext 'basicConstraints=critical,CA:TRUE' \\"
    echo "    -addext 'keyUsage=critical,keyCertSign,cRLSign'"
    exit 1
fi
echo "  CA cert: ${CA_DIR}/ca.pem"
openssl x509 -in "${CA_DIR}/ca.pem" -noout -subject -dates 2>/dev/null || true

# ── Step 3: Generate TLS server certificate ──────────────────────────
# The TLS cert is signed by a temporary OpenSSL CA key (not the HSM key)
# since TLS certs don't need HSM protection. For production, use a
# separate TLS CA or the same HSM.
#
# For local dev, we generate a self-signed TLS cert using the
# HSM CA cert as the trust anchor.

if [ -f "${TLS_DIR}/server.pem" ] && [ -f "${TLS_DIR}/server-key.pem" ]; then
    echo "TLS server cert already exists — skipping."
else
    echo "Generating TLS server certificate..."

    # Generate server key
    openssl genrsa -out "${TLS_DIR}/server-key.pem" 2048 2>/dev/null

    # Generate CSR
    openssl req -new \
        -key "${TLS_DIR}/server-key.pem" \
        -out "${TLS_DIR}/server.csr" \
        -subj "/CN=localhost/O=Kipuka Dev"

    # Self-sign with the CA cert (for local dev, we use a simplified
    # approach — the CA cert is the trust anchor but doesn't actually
    # sign the TLS cert since the CA key is in the HSM).
    # Instead, self-sign the TLS cert.
    openssl req -new -x509 \
        -key "${TLS_DIR}/server-key.pem" \
        -out "${TLS_DIR}/server.pem" \
        -days 365 \
        -subj "/CN=localhost/O=Kipuka Dev" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth"

    rm -f "${TLS_DIR}/server.csr"
    echo "  TLS server cert: ${TLS_DIR}/server.pem"
fi

# ── Step 4: Generate mTLS agent certificate ──────────────────────────
if [ -f "${TLS_DIR}/agent.pem" ] && [ -f "${TLS_DIR}/agent-key.pem" ]; then
    echo "mTLS agent cert already exists — skipping."
else
    echo "Generating mTLS agent certificate..."

    openssl req -new -x509 \
        -newkey rsa:2048 -nodes \
        -keyout "${TLS_DIR}/agent-key.pem" \
        -out "${TLS_DIR}/agent.pem" \
        -days 365 \
        -subj "/CN=kipuka-agent/O=Kipuka Dev" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=clientAuth"

    echo "  Agent cert: ${TLS_DIR}/agent.pem"
fi

echo ""
echo "=== HSM PKI Setup Complete ==="
echo ""
echo "CA certificate (HSM-backed): ${CA_DIR}/ca.pem"
echo "TLS server cert:             ${TLS_DIR}/server.pem"
echo "mTLS agent cert:             ${TLS_DIR}/agent.pem"
echo ""
echo "The CA private key remains in the Kryoptic HSM."
echo "Kipuka will sign certificates via PKCS#11."
echo ""
echo "Start kipuka:  podman compose --profile hsm up"
