#!/usr/bin/env bash
# =============================================================================
# setup-freeipa.sh — Provision FreeIPA + kipuka with GSSAPI for Beaker testing
# =============================================================================
# Installs a FreeIPA server (MIT KDC, 389 DS, Dogtag CA, DNS), builds kipuka
# with --features gssapi, creates a service keytab, and starts the EST server
# with Kerberos authentication.
#
# Run on a fresh RHEL 10.0 Beaker machine. Requires CRB + AppStream repos.
#
# After this script completes, run test-gssapi.sh for validation.
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Configuration ────────────────────────────────────────────────────────────

KIPUKA_REPO="${KIPUKA_REPO:-https://gitlab.cee.redhat.com/czinda/kipuka.git}"
KIPUKA_BRANCH="${KIPUKA_BRANCH:-main}"
KIPUKA_DIR="/opt/kipuka"

IPA_REALM="KIPUKA.TEST"
IPA_DOMAIN="kipuka.test"
IPA_HOSTNAME="ipa.kipuka.test"
DS_PASSWORD="RedHat!2026ds"
ADMIN_PASSWORD="RedHat!2026admin"
TEST_USER_PASSWORD="RedHat!2026test"
ADMIN_TOKEN="kipuka-beaker-gssapi-token-$(date +%s)"

KIPUKA_USER="kipuka"
KIPUKA_GROUP="kipuka"
CONFIG_DIR="/etc/kipuka"
DATA_DIR="/var/lib/kipuka"
LOG_DIR="/var/log/kipuka"

# ── Colors ───────────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    GREEN='\033[0;32m' YELLOW='\033[0;33m' CYAN='\033[0;36m'
    RED='\033[0;31m' RESET='\033[0m'
else
    GREEN='' YELLOW='' CYAN='' RED='' RESET=''
fi

step()  { echo -e "\n${CYAN}══ $* ══${RESET}"; }
info()  { echo -e "${CYAN}[info]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[ok]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${RESET}  $*"; }
err()   { echo -e "${RED}[err]${RESET}   $*" >&2; }
die()   { err "$*"; exit 1; }

# ── Step 1: Set hostname ────────────────────────────────────────────────────

step "Setting hostname to ${IPA_HOSTNAME}"
hostnamectl set-hostname "${IPA_HOSTNAME}"

# Add to /etc/hosts (FreeIPA needs forward+reverse resolution)
IP=$(hostname -I | awk '{print $1}')
if ! grep -q "${IPA_HOSTNAME}" /etc/hosts; then
    echo "${IP} ${IPA_HOSTNAME} ipa" >> /etc/hosts
fi
ok "Hostname: $(hostname -f)"

# ── Step 2: Install packages ────────────────────────────────────────────────

step "Installing FreeIPA server and build dependencies"
dnf install -y \
    freeipa-server freeipa-server-dns \
    krb5-devel krb5-workstation \
    openssl openssl-devel \
    gcc gcc-c++ make pkg-config clang cmake libclang-devel \
    git curl jq \
    policycoreutils-python-utils \
    2>&1 | tail -3
ok "Packages installed"

# ── Step 3: Install FreeIPA realm ────────────────────────────────────────────

step "Installing FreeIPA realm: ${IPA_REALM}"
ipa-server-install --unattended \
    --realm "${IPA_REALM}" \
    --domain "${IPA_DOMAIN}" \
    --ds-password "${DS_PASSWORD}" \
    --admin-password "${ADMIN_PASSWORD}" \
    --hostname "${IPA_HOSTNAME}" \
    --setup-dns --auto-forwarders --auto-reverse \
    --no-ntp \
    --no-hbac-allow 2>&1 | tail -10
ok "FreeIPA realm installed: ${IPA_REALM}"

# Verify KDC is running
systemctl is-active krb5kdc || die "krb5kdc not running"
ok "MIT KDC is active"

# ── Step 4: Create kipuka service principal and keytab ───────────────────────

step "Creating kipuka service principal and keytab"
echo "${ADMIN_PASSWORD}" | kinit admin@${IPA_REALM}
klist

ipa service-add "HTTP/${IPA_HOSTNAME}@${IPA_REALM}" 2>/dev/null || \
    warn "Service principal already exists"

mkdir -p "${CONFIG_DIR}"
ipa-getkeytab \
    -s "${IPA_HOSTNAME}" \
    -p "HTTP/${IPA_HOSTNAME}@${IPA_REALM}" \
    -k "${CONFIG_DIR}/kipuka.keytab"

ok "Service keytab: ${CONFIG_DIR}/kipuka.keytab"

# Verify keytab
klist -k "${CONFIG_DIR}/kipuka.keytab"

# ── Step 5: Create test user for enrollment ──────────────────────────────────

step "Creating test user: testdevice"
ipa user-add testdevice --first=Test --last=Device 2>/dev/null || \
    warn "User testdevice already exists"

# Set password (requires two changes due to IPA password policy)
echo -e "${TEST_USER_PASSWORD}\n${TEST_USER_PASSWORD}" | \
    ipa user-mod testdevice --password 2>/dev/null || true

ok "Test user created: testdevice@${IPA_REALM}"

# ── Step 6: Install Rust toolchain ───────────────────────────────────────────

step "Installing Rust toolchain"
if command -v rustc &>/dev/null && [[ "$(printf '%s\n1.85.0\n' "$(rustc --version | awk '{print $2}')" | sort -V | head -1)" == "1.85.0" ]]; then
    info "System Rust $(rustc --version) is sufficient"
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable 2>&1 | tail -3
    source "$HOME/.cargo/env"
fi
rustc --version
cargo --version
ok "Rust toolchain ready"

# ── Step 7: Clone and build kipuka with GSSAPI ───────────────────────────────

step "Building kipuka with --features gssapi"
if [[ -d "${KIPUKA_DIR}" ]]; then
    cd "${KIPUKA_DIR}" && git pull
else
    git clone --branch "${KIPUKA_BRANCH}" "${KIPUKA_REPO}" "${KIPUKA_DIR}"
    cd "${KIPUKA_DIR}"
fi

cargo build --release --features gssapi 2>&1 | tail -5
cp target/release/kipuka /usr/local/bin/kipuka
kipuka --version 2>/dev/null || kipuka --help 2>/dev/null | head -1
ok "kipuka binary installed: /usr/local/bin/kipuka"

# ── Step 8: Create kipuka user and directories ───────────────────────────────

step "Creating kipuka user and directories"
useradd -r -s /sbin/nologin "${KIPUKA_USER}" 2>/dev/null || true
mkdir -p "${CONFIG_DIR}/tls" "${CONFIG_DIR}/ca" "${DATA_DIR}" "${LOG_DIR}"

# ── Step 9: Extract IPA CA certificate ───────────────────────────────────────

step "Extracting IPA CA certificate"
cp /etc/ipa/ca.crt "${CONFIG_DIR}/ca/ipa-ca.pem"
ok "IPA CA cert: ${CONFIG_DIR}/ca/ipa-ca.pem"

# ── Step 10: Generate TLS server certificate from IPA CA ─────────────────────

step "Requesting TLS server certificate from FreeIPA CA"

# Generate a key and CSR for kipuka's TLS endpoint
openssl req -newkey rsa:2048 -nodes \
    -keyout "${CONFIG_DIR}/tls/server-key.pem" \
    -out /tmp/kipuka-server.csr \
    -subj "/CN=${IPA_HOSTNAME}/O=${IPA_REALM}" 2>/dev/null

# Submit to IPA CA via certmonger or direct pki CLI
# Using ipa-getcert for seamless IPA integration
ipa-getcert request \
    -K "HTTP/${IPA_HOSTNAME}" \
    -f "${CONFIG_DIR}/tls/server.pem" \
    -k "${CONFIG_DIR}/tls/server-key.pem" \
    -D "${IPA_HOSTNAME}" \
    -N "CN=${IPA_HOSTNAME}" \
    -w 2>/dev/null || {
    # Fallback: self-signed cert if certmonger isn't available
    warn "ipa-getcert failed, generating self-signed TLS cert"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${CONFIG_DIR}/tls/server-key.pem" \
        -out "${CONFIG_DIR}/tls/server.pem" \
        -days 365 -sha256 \
        -subj "/CN=${IPA_HOSTNAME}/O=Kipuka Test" \
        -addext "subjectAltName=DNS:${IPA_HOSTNAME},DNS:localhost,IP:127.0.0.1" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null
}

# Also generate a self-signed CA key for direct signing (non-Dogtag mode)
if [[ ! -f "${CONFIG_DIR}/ca/ipa-ca-key.pem" ]]; then
    openssl req -x509 -newkey rsa:3072 -nodes \
        -keyout "${CONFIG_DIR}/ca/ipa-ca-key.pem" \
        -out "${CONFIG_DIR}/ca/ipa-ca-local.pem" \
        -days 3650 -sha256 \
        -subj "/CN=Kipuka GSSAPI Test CA/O=${IPA_REALM}" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    ok "Local signing CA generated for EST issuance"
fi

ok "TLS certificates configured"

# ── Step 11: Deploy kipuka configuration ─────────────────────────────────────

step "Deploying kipuka configuration"
cp "${KIPUKA_DIR}/contrib/beaker/kipuka-freeipa.toml" "${CONFIG_DIR}/kipuka.toml"

# Set admin token
export KIPUKA_ADMIN_TOKEN="${ADMIN_TOKEN}"

# Fix ownership
chown -R "${KIPUKA_USER}:${KIPUKA_GROUP}" "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chmod 600 "${CONFIG_DIR}/kipuka.keytab"
chmod 600 "${CONFIG_DIR}/tls/server-key.pem"
chmod 600 "${CONFIG_DIR}/ca/ipa-ca-key.pem" 2>/dev/null || true

ok "Configuration deployed: ${CONFIG_DIR}/kipuka.toml"

# ── Step 12: Install systemd service ─────────────────────────────────────────

step "Installing systemd service"
cat > /etc/systemd/system/kipuka.service <<'UNIT'
[Unit]
Description=Kipuka EST Server (RFC 7030) — FreeIPA GSSAPI Integration
Documentation=https://kipuka.dev
After=network-online.target ipa.service
Wants=network-online.target

[Service]
Type=simple
User=kipuka
Group=kipuka
ExecStart=/usr/local/bin/kipuka --config /etc/kipuka/kipuka.toml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

Environment=RUST_LOG=info
Environment=KRB5_KTNAME=/etc/kipuka/kipuka.keytab

PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/kipuka /var/log/kipuka

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
ok "systemd service installed"

# ── Step 13: Start kipuka ────────────────────────────────────────────────────

step "Starting kipuka EST server"
systemctl start kipuka
sleep 3

if systemctl is-active kipuka; then
    ok "kipuka is running"
    journalctl -u kipuka --no-pager -n 10
else
    err "kipuka failed to start"
    journalctl -u kipuka --no-pager -n 30
    die "Check journal for details"
fi

# ── Step 14: Write test environment file ─────────────────────────────────────

step "Writing test environment"
cat > /tmp/kipuka-gssapi-env.sh <<EOF
export IPA_REALM="${IPA_REALM}"
export IPA_HOSTNAME="${IPA_HOSTNAME}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD}"
export TEST_USER_PASSWORD="${TEST_USER_PASSWORD}"
export ADMIN_TOKEN="${ADMIN_TOKEN}"
export CONFIG_DIR="${CONFIG_DIR}"
EOF
chmod 600 /tmp/kipuka-gssapi-env.sh

ok "Test env: source /tmp/kipuka-gssapi-env.sh"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "  Kipuka + FreeIPA GSSAPI — Ready"
echo "=========================================="
echo ""
echo "  FreeIPA realm:     ${IPA_REALM}"
echo "  KDC:               krb5kdc (MIT)"
echo "  Dogtag CA:         https://${IPA_HOSTNAME}:8443/ca/"
echo ""
echo "  kipuka EST:        https://${IPA_HOSTNAME}:9443"
echo "  kipuka admin:      https://localhost:9444"
echo "  Service keytab:    ${CONFIG_DIR}/kipuka.keytab"
echo ""
echo "  Admin principal:   admin@${IPA_REALM}"
echo "  Test user:         testdevice@${IPA_REALM}"
echo ""
echo "  Next: bash test-gssapi.sh"
echo ""
