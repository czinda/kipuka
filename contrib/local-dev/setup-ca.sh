#!/usr/bin/env bash
# ── setup-ca.sh — Generate test PKI for kipuka local development ───────
#
# Creates:
#   contrib/local-dev/ca/
#     ca.pem          — self-signed CA certificate (3072-bit RSA, 10 years)
#     ca-key.pem      — CA private key
#
#   contrib/local-dev/tls/
#     server.pem      — TLS server certificate (SANs: localhost, 127.0.0.1)
#     server-key.pem  — TLS server private key
#     agent.pem       — mTLS agent certificate (for admin API access)
#     agent-key.pem   — agent private key
#
# Idempotent: skips generation if certs already exist.
# Use --clean to remove existing certs and regenerate from scratch.
# ────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_DIR="${SCRIPT_DIR}/ca"
TLS_DIR="${SCRIPT_DIR}/tls"

# ── Handle --clean flag ────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]] || [[ "${1:-}" == "-c" ]]; then
    echo "Cleaning existing certificates..."
    rm -rf "${CA_DIR}" "${TLS_DIR}"
    echo "Cleaned. Regenerating..."
fi

# ── Colors (if terminal) ────────────────────────────────────────────────
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    GREEN='' YELLOW='' CYAN='' RESET=''
fi

info()  { echo -e "${CYAN}[info]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[skip]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[ok]${RESET}    $*"; }

# ── Check for openssl ───────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl is required but not found in PATH" >&2
    exit 1
fi

# ── Create directories ──────────────────────────────────────────────────
mkdir -p "${CA_DIR}" "${TLS_DIR}"

# ── CA Certificate ──────────────────────────────────────────────────────
if [ -f "${CA_DIR}/ca.pem" ] && [ -f "${CA_DIR}/ca-key.pem" ]; then
    warn "CA certificate already exists, skipping"
else
    info "Generating self-signed CA (3072-bit RSA, 10-year validity)..."
    openssl req -x509 -newkey rsa:3072 \
        -keyout "${CA_DIR}/ca-key.pem" \
        -out "${CA_DIR}/ca.pem" \
        -sha256 -days 3650 -nodes \
        -subj "/O=Kipuka Development/CN=Kipuka Local Dev CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        2>/dev/null
    chmod 600 "${CA_DIR}/ca-key.pem"
    ok "CA certificate created"
fi

# ── Server TLS Certificate ──────────────────────────────────────────────
if [ -f "${TLS_DIR}/server.pem" ] && [ -f "${TLS_DIR}/server-key.pem" ]; then
    warn "Server TLS certificate already exists, skipping"
else
    info "Generating server TLS certificate (SANs: localhost, 127.0.0.1)..."

    # Create CSR
    openssl req -newkey rsa:2048 -nodes \
        -keyout "${TLS_DIR}/server-key.pem" \
        -out "${TLS_DIR}/server.csr" \
        -subj "/O=Kipuka Development/CN=localhost" \
        2>/dev/null

    # Sign with CA
    openssl x509 -req \
        -in "${TLS_DIR}/server.csr" \
        -CA "${CA_DIR}/ca.pem" \
        -CAkey "${CA_DIR}/ca-key.pem" \
        -CAcreateserial \
        -out "${TLS_DIR}/server.pem" \
        -days 825 -sha256 \
        -extfile <(cat <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:kipuka, IP:127.0.0.1, IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
        ) 2>/dev/null

    rm -f "${TLS_DIR}/server.csr"
    chmod 600 "${TLS_DIR}/server-key.pem"
    ok "Server TLS certificate created"
fi

# ── Agent mTLS Certificate ──────────────────────────────────────────────
if [ -f "${TLS_DIR}/agent.pem" ] && [ -f "${TLS_DIR}/agent-key.pem" ]; then
    warn "Agent mTLS certificate already exists, skipping"
else
    info "Generating agent mTLS certificate (for admin API access)..."

    # Create CSR
    openssl req -newkey rsa:2048 -nodes \
        -keyout "${TLS_DIR}/agent-key.pem" \
        -out "${TLS_DIR}/agent.csr" \
        -subj "/O=Kipuka Development/CN=admin/emailAddress=admin@localhost" \
        2>/dev/null

    # Sign with CA
    openssl x509 -req \
        -in "${TLS_DIR}/agent.csr" \
        -CA "${CA_DIR}/ca.pem" \
        -CAkey "${CA_DIR}/ca-key.pem" \
        -CAcreateserial \
        -out "${TLS_DIR}/agent.pem" \
        -days 825 -sha256 \
        -extfile <(cat <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
        ) 2>/dev/null

    rm -f "${TLS_DIR}/agent.csr"
    chmod 600 "${TLS_DIR}/agent-key.pem"
    ok "Agent mTLS certificate created"
fi

# ── ML-DSA-65 CA (Post-Quantum, FIPS 204) ─────────────────────────────
# Requires OpenSSL 3.5+ with PQC provider.
if [[ ! -f "${CA_DIR}/mldsa65-ca.pem" ]]; then
    info "Generating ML-DSA-65 CA (post-quantum)..."
    if openssl genpkey -algorithm mldsa65 -out /dev/null 2>/dev/null; then
        openssl genpkey -algorithm mldsa65 \
            -out "${CA_DIR}/mldsa65-ca-key.pem" 2>/dev/null

        openssl req -new -x509 \
            -key "${CA_DIR}/mldsa65-ca-key.pem" \
            -out "${CA_DIR}/mldsa65-ca.pem" \
            -days 3650 \
            -subj "/CN=Kipuka ML-DSA-65 Test CA/O=Kipuka EST/C=US" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectKeyIdentifier=hash" 2>/dev/null

        chmod 600 "${CA_DIR}/mldsa65-ca-key.pem"
        ok "ML-DSA-65 CA created"
    else
        warn "OpenSSL does not support ML-DSA (requires 3.5+), skipping PQC CA"
    fi
fi

# ── Cleanup serial file ─────────────────────────────────────────────────
rm -f "${CA_DIR}/ca.srl"

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
echo "=========================================="
echo "  Kipuka Local Dev PKI — Summary"
echo "=========================================="
echo ""
echo "  CA certificate:     ${CA_DIR}/ca.pem"
echo "  CA private key:     ${CA_DIR}/ca-key.pem"
if [[ -f "${CA_DIR}/mldsa65-ca.pem" ]]; then
echo "  ML-DSA-65 CA cert:  ${CA_DIR}/mldsa65-ca.pem"
echo "  ML-DSA-65 CA key:   ${CA_DIR}/mldsa65-ca-key.pem"
fi
echo ""
echo "  Server TLS cert:    ${TLS_DIR}/server.pem"
echo "  Server TLS key:     ${TLS_DIR}/server-key.pem"
echo ""
echo "  Agent mTLS cert:    ${TLS_DIR}/agent.pem"
echo "  Agent mTLS key:     ${TLS_DIR}/agent-key.pem"
echo ""
echo "  Next steps:"
echo "    podman compose up"
echo "    curl -sk https://localhost:9443/.well-known/est/cacerts"
echo ""
