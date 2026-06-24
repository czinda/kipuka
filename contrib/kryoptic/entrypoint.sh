#!/bin/bash
# Kryoptic PKCS#11 token initialization for kipuka
#
# Initializes a token, creates a CA signing key, and keeps the
# container running so kipuka can access the PKCS#11 library.

set -uo pipefail

TOKEN_LABEL="${TOKEN_LABEL:-kipuka-hsm}"
SO_PIN="${SO_PIN:-12345678}"
USER_PIN="${USER_PIN:-1234}"
KEY_LABEL="${KEY_LABEL:-kipuka-ca-key}"
KEY_TYPE="${KEY_TYPE:-rsa:3072}"
MODULE="/usr/lib/pkcs11/libkryoptic_pkcs11.so"
TOKEN_DIR="/var/lib/kryoptic"

# Write Kryoptic configuration — must exist before any PKCS#11 call
mkdir -p "${TOKEN_DIR}/tokens"
cat > "${TOKEN_DIR}/token.conf" << EOF
[global]
token_dir = ${TOKEN_DIR}/tokens
EOF

export KRYOPTIC_CONF="${TOKEN_DIR}/token.conf"

echo "Kryoptic config: ${KRYOPTIC_CONF}"
echo "Token dir: ${TOKEN_DIR}/tokens"
echo "Module: ${MODULE}"

# Verify the module loads
if ! pkcs11-tool --module "$MODULE" --show-info 2>/dev/null; then
    echo "ERROR: Kryoptic PKCS#11 module failed to load"
    echo "Checking library..."
    ls -la "$MODULE" 2>/dev/null || echo "Module not found at $MODULE"
    ldd "$MODULE" 2>/dev/null || echo "Cannot check dependencies"
    exit 1
fi

# Initialize token if not already done
if pkcs11-tool --module "$MODULE" --list-token-slots 2>/dev/null | grep -q "$TOKEN_LABEL"; then
    echo "Token ${TOKEN_LABEL} already initialized."
else
    echo "Initializing Kryoptic token: ${TOKEN_LABEL}"
    pkcs11-tool --module "$MODULE" \
        --init-token --label "$TOKEN_LABEL" --so-pin "$SO_PIN" || {
        echo "ERROR: Token initialization failed. Listing available slots:"
        pkcs11-tool --module "$MODULE" --list-slots 2>&1 || true
        exit 1
    }

    pkcs11-tool --module "$MODULE" \
        --token-label "$TOKEN_LABEL" --so-pin "$SO_PIN" \
        --init-pin --pin "$USER_PIN"

    echo "Token initialized."
fi

# Generate CA key if not already present
if ! pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
    --list-objects --type privkey 2>/dev/null | grep -q "$KEY_LABEL"; then
    echo "Generating CA signing key: ${KEY_LABEL} (${KEY_TYPE})"
    pkcs11-tool --module "$MODULE" \
        --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
        --keypairgen --key-type "$KEY_TYPE" \
        --label "$KEY_LABEL" --id 01 \
        --usage-sign
    echo "Key generated."
else
    echo "Key ${KEY_LABEL} already exists."
fi

# Show token info
echo ""
echo "=== Kryoptic Token Info ==="
pkcs11-tool --module "$MODULE" --list-token-slots 2>/dev/null || true
echo ""
echo "=== Objects ==="
pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
    --list-objects 2>/dev/null || true
echo ""
echo "PKCS#11 module: ${MODULE}"
echo "Token label:    ${TOKEN_LABEL}"
echo "PKCS#11 URI:    pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=private"
echo ""
echo "Kryoptic ready. Container will stay running."

# Keep container alive so kipuka can access the shared library
exec sleep infinity
