#!/usr/bin/env bash
# =============================================================================
# kipuka Beaker post-provisioning setup
# =============================================================================
# Installs Dogtag PKI (CA + KRA), 389 Directory Server, builds kipuka from
# source, generates test PKI material, and starts the EST server.
#
# Assumptions:
#   - RHEL 10.x system provisioned by Beaker (OpenSSL 3.5+ for PQC)
#   - CRB and AppStream repos already configured (see kipuka-beaker.xml)
#   - Internet access for cloning the kipuka repo
#
# Usage:
#   bash setup.sh           # full setup (default)
#   bash setup.sh --no-test # skip the smoke test at the end
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# ── Configuration ────────────────────────────────────────────────────────────

KIPUKA_REPO="https://codeberg.org/czinda/kipuka.git"
KIPUKA_BRANCH="main"
KIPUKA_SRC="/opt/kipuka"
KIPUKA_CONF="/etc/kipuka"
KIPUKA_DATA="/var/lib/kipuka"
KIPUKA_LOG="/var/log/kipuka"
KIPUKA_USER="kipuka"
KIPUKA_GROUP="kipuka"

DS_INSTANCE="kipuka-ds"
DS_SUFFIX="dc=kipuka,dc=test"
DS_ROOT_DN="cn=Directory Manager"
DS_ROOT_PW="Secret.123"

PKI_INSTANCE="pki-tomcat"
PKI_ADMIN_PW="Secret.123"
PKI_DS_PW="Secret.123"
PKI_CLIENT_DB_PW="Secret.123"
PKI_HTTPS_PORT=8443
PKI_HTTP_PORT=8080

# kipuka listens on a different port to avoid conflicting with Dogtag
KIPUKA_PORT=9443

HOSTNAME="$(hostname -f)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUN_SMOKE_TEST=true
if [[ "${1:-}" == "--no-test" ]]; then
    RUN_SMOKE_TEST=false
fi

log() {
    echo "==> [$(date '+%H:%M:%S')] $*"
}

die() {
    echo "FATAL: $*" >&2
    exit 1
}

# ── Step 1: Install system packages ─────────────────────────────────────────

log "Installing system packages"
dnf install -y \
    pki-ca \
    pki-kra \
    389-ds-base \
    openssl \
    openssl-devel \
    gcc \
    gcc-c++ \
    make \
    pkg-config \
    git \
    curl \
    jq \
    policycoreutils-python-utils

# ── Step 2: Install Rust toolchain ───────────────────────────────────────────

log "Installing Rust toolchain"
# RHEL 10 ships Rust 1.88+ (edition 2024) in AppStream — prefer system packages.
# Fall back to rustup only if the system Rust is too old or missing.
if command -v rustc &>/dev/null; then
    SYSTEM_RUST_VER=$(rustc --version | awk '{print $2}')
    log "System Rust: ${SYSTEM_RUST_VER}"
    # kipuka requires rust-version = "1.88"
    if [[ "$(printf '%s\n1.88.0\n' "${SYSTEM_RUST_VER}" | sort -V | head -1)" == "1.88.0" ]]; then
        log "System Rust ${SYSTEM_RUST_VER} meets minimum 1.88 — using system toolchain"
    else
        log "System Rust ${SYSTEM_RUST_VER} too old; installing via rustup"
        dnf install -y rust cargo 2>/dev/null || true
        if ! rustc --version 2>/dev/null | grep -qE '1\.(8[5-9]|9[0-9])'; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88.0
            source "$HOME/.cargo/env"
        fi
    fi
else
    log "No Rust found; installing from AppStream"
    dnf install -y rust cargo || {
        log "AppStream Rust not available; falling back to rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88.0
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
    }
fi
rustc --version
cargo --version

# Verify OpenSSL 3.5+ for PQC (ML-DSA/ML-KEM) support
OPENSSL_VER=$(openssl version | awk '{print $2}')
log "OpenSSL version: ${OPENSSL_VER}"
if [[ "$(printf '%s\n3.5.0\n' "${OPENSSL_VER}" | sort -V | head -1)" == "3.5.0" ]]; then
    log "OpenSSL ${OPENSSL_VER} supports PQC (ML-DSA/ML-KEM via oqsprovider)"
else
    log "WARNING: OpenSSL ${OPENSSL_VER} may not support PQC algorithms"
fi

# ── Step 3: Set up 389 Directory Server ─────────────────────────────────────

log "Setting up 389 Directory Server instance: ${DS_INSTANCE}"

# Create the DS instance configuration
cat > /tmp/ds-setup.inf <<EOF
[general]
config_version = 2
full_machine_name = ${HOSTNAME}
strict_host_checking = false

[slapd]
instance_name = ${DS_INSTANCE}
root_dn = ${DS_ROOT_DN}
root_password = ${DS_ROOT_PW}
port = 389
secure_port = 636

[backend-userroot]
suffix = ${DS_SUFFIX}
create_suffix_entry = true
sample_entries = no
EOF

# Remove any existing instance
if dsctl "${DS_INSTANCE}" status &>/dev/null; then
    log "Removing existing DS instance"
    dsctl "${DS_INSTANCE}" remove --do-it
fi

# Create and start the instance
dscreate from-file /tmp/ds-setup.inf
dsctl "${DS_INSTANCE}" status
rm -f /tmp/ds-setup.inf

log "389 Directory Server is running"

# ── Step 4: Install Dogtag CA ────────────────────────────────────────────────

log "Installing Dogtag CA subsystem"

# Copy pkispawn configuration or use the one from the repo
if [[ -f "${SCRIPT_DIR}/pkispawn-ca.cfg" ]]; then
    cp "${SCRIPT_DIR}/pkispawn-ca.cfg" /tmp/pkispawn-ca.cfg
else
    cat > /tmp/pkispawn-ca.cfg <<EOF
[DEFAULT]
pki_instance_name = ${PKI_INSTANCE}
pki_https_port = ${PKI_HTTPS_PORT}
pki_http_port = ${PKI_HTTP_PORT}

pki_admin_password = ${PKI_ADMIN_PW}
pki_client_database_password = ${PKI_CLIENT_DB_PW}
pki_client_pkcs12_password = ${PKI_CLIENT_DB_PW}

pki_ds_hostname = localhost
pki_ds_ldap_port = 389
pki_ds_password = ${PKI_DS_PW}
pki_ds_bind_dn = ${DS_ROOT_DN}
pki_ds_base_dn = dc=ca,${DS_SUFFIX}
pki_ds_create_new_db = True
pki_ds_remove_data = True

pki_security_domain_name = KIPUKA-TEST

[CA]
pki_admin_cert_file = /root/.dogtag/${PKI_INSTANCE}/ca_admin.cert
pki_admin_nickname = PKI CA Administrator

pki_ca_signing_nickname = ca_signing
pki_ca_signing_subject_dn = CN=Test CA Authority,O=Kipuka Test,C=US
pki_ca_signing_key_size = 3072
pki_ca_signing_key_type = rsa
pki_ca_signing_signing_algorithm = SHA256withRSA

pki_ocsp_signing_nickname = ca_ocsp_signing
pki_audit_signing_nickname = ca_audit_signing

pki_serial_number_range_start = 1
pki_serial_number_range_end = 10000000

pki_request_number_range_start = 1
pki_request_number_range_end = 10000000

pki_import_admin_cert = False
EOF
fi

# Remove any existing PKI instance
if pki-server instance-find 2>/dev/null | grep -q "${PKI_INSTANCE}"; then
    log "Removing existing PKI instance"
    pkidestroy -i "${PKI_INSTANCE}" -s CA --force || true
fi

pkispawn -f /tmp/pkispawn-ca.cfg -s CA -v
log "Dogtag CA installed successfully"

# Wait for Dogtag CA to fully start
log "Waiting for Dogtag CA to be ready"
for i in $(seq 1 30); do
    if curl -sk "https://localhost:${PKI_HTTPS_PORT}/ca/admin/ca/getStatus" 2>/dev/null | grep -q '"Status":"running"'; then
        log "Dogtag CA is running"
        break
    fi
    if [[ $i -eq 30 ]]; then
        die "Dogtag CA did not start within 30 seconds"
    fi
    sleep 1
done

# ── Step 5: Install Dogtag KRA ───────────────────────────────────────────────

log "Installing Dogtag KRA subsystem"

if [[ -f "${SCRIPT_DIR}/pkispawn-kra.cfg" ]]; then
    cp "${SCRIPT_DIR}/pkispawn-kra.cfg" /tmp/pkispawn-kra.cfg
else
    cat > /tmp/pkispawn-kra.cfg <<EOF
[DEFAULT]
pki_instance_name = ${PKI_INSTANCE}
pki_https_port = ${PKI_HTTPS_PORT}
pki_http_port = ${PKI_HTTP_PORT}

pki_admin_password = ${PKI_ADMIN_PW}
pki_client_database_password = ${PKI_CLIENT_DB_PW}
pki_client_pkcs12_password = ${PKI_CLIENT_DB_PW}

pki_ds_hostname = localhost
pki_ds_ldap_port = 389
pki_ds_password = ${PKI_DS_PW}
pki_ds_bind_dn = ${DS_ROOT_DN}
pki_ds_base_dn = dc=kra,${DS_SUFFIX}
pki_ds_create_new_db = True
pki_ds_remove_data = True

pki_security_domain_hostname = localhost
pki_security_domain_https_port = ${PKI_HTTPS_PORT}
pki_security_domain_password = ${PKI_ADMIN_PW}

[KRA]
pki_admin_cert_file = /root/.dogtag/${PKI_INSTANCE}/ca_admin.cert
pki_admin_nickname = PKI KRA Administrator

pki_import_admin_cert = True
EOF
fi

pkispawn -f /tmp/pkispawn-kra.cfg -s KRA -v
log "Dogtag KRA installed successfully"

# Clean up pkispawn configs (contain passwords)
rm -f /tmp/pkispawn-ca.cfg /tmp/pkispawn-kra.cfg

# ── Step 6: Clone and build kipuka ───────────────────────────────────────────

log "Cloning kipuka repository"
if [[ -d "${KIPUKA_SRC}" ]]; then
    cd "${KIPUKA_SRC}" && git pull
else
    git clone --branch "${KIPUKA_BRANCH}" "${KIPUKA_REPO}" "${KIPUKA_SRC}"
fi

log "Building kipuka (release mode)"
cd "${KIPUKA_SRC}"
cargo build --release 2>&1

# Install the binary
install -m 0755 target/release/kipuka /usr/local/bin/kipuka
kipuka --version || log "kipuka binary installed (version flag may not be implemented yet)"

# ── Step 7: Create kipuka system user and directories ────────────────────────

log "Creating kipuka user and directories"

if ! id "${KIPUKA_USER}" &>/dev/null; then
    useradd --system --home-dir "${KIPUKA_DATA}" --shell /sbin/nologin "${KIPUKA_USER}"
fi

mkdir -p "${KIPUKA_CONF}/tls"
mkdir -p "${KIPUKA_CONF}/ca"
mkdir -p "${KIPUKA_DATA}"
mkdir -p "${KIPUKA_LOG}"

chown -R "${KIPUKA_USER}:${KIPUKA_GROUP}" "${KIPUKA_DATA}" "${KIPUKA_LOG}"

# ── Step 8: Generate test certificates ───────────────────────────────────────

log "Generating test PKI material"
CERT_DIR="${KIPUKA_CONF}"

# 8a. Extract the Dogtag CA certificate for kipuka to use as its trust anchor
pki-server cert-export ca_signing \
    --cert-file "${CERT_DIR}/ca/dogtag-ca.pem" \
    -i "${PKI_INSTANCE}"
log "Exported Dogtag CA cert to ${CERT_DIR}/ca/dogtag-ca.pem"

# 8b. Generate a TLS server certificate for kipuka using Dogtag
# First, generate a key and CSR for the kipuka EST server
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${CERT_DIR}/tls/server.key" \
    -out /tmp/kipuka-server.csr \
    -subj "/CN=${HOSTNAME}/O=Kipuka Test/C=US" \
    -addext "subjectAltName=DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1"

# Submit the CSR to Dogtag and get the certificate
pki -d /root/.dogtag/"${PKI_INSTANCE}"/ca/alias \
    -c "${PKI_CLIENT_DB_PW}" \
    -n "PKI CA Administrator" \
    -U "https://localhost:${PKI_HTTPS_PORT}" \
    ca-cert-request-submit --profile caServerCert \
    --csr-file /tmp/kipuka-server.csr \
    --subject "CN=${HOSTNAME},O=Kipuka Test,C=US" \
    > /tmp/cert-request-output.txt 2>&1 || true

# Extract the request ID and approve it
REQUEST_ID=$(grep "Request ID:" /tmp/cert-request-output.txt | awk '{print $NF}' | head -1)
if [[ -n "${REQUEST_ID}" ]]; then
    log "Certificate request ID: ${REQUEST_ID}"

    # Approve the request
    pki -d /root/.dogtag/"${PKI_INSTANCE}"/ca/alias \
        -c "${PKI_CLIENT_DB_PW}" \
        -n "PKI CA Administrator" \
        -U "https://localhost:${PKI_HTTPS_PORT}" \
        ca-cert-request-approve "${REQUEST_ID}" --force || true

    # Retrieve the certificate
    CERT_ID=$(pki -d /root/.dogtag/"${PKI_INSTANCE}"/ca/alias \
        -c "${PKI_CLIENT_DB_PW}" \
        -n "PKI CA Administrator" \
        -U "https://localhost:${PKI_HTTPS_PORT}" \
        ca-cert-request-show "${REQUEST_ID}" 2>/dev/null | grep "Certificate ID:" | awk '{print $NF}' || true)

    if [[ -n "${CERT_ID}" ]]; then
        pki -d /root/.dogtag/"${PKI_INSTANCE}"/ca/alias \
            -c "${PKI_CLIENT_DB_PW}" \
            -n "PKI CA Administrator" \
            -U "https://localhost:${PKI_HTTPS_PORT}" \
            ca-cert-show "${CERT_ID}" --output "${CERT_DIR}/tls/server.pem"
        log "Server TLS certificate issued: ${CERT_DIR}/tls/server.pem"
    fi
fi

# Fallback: if Dogtag cert issuance failed, generate self-signed certs
if [[ ! -s "${CERT_DIR}/tls/server.pem" ]]; then
    log "Dogtag cert issuance via CLI failed; generating self-signed test certs"

    # Self-signed CA
    openssl req -x509 -new -nodes -newkey rsa:3072 \
        -keyout "${CERT_DIR}/ca/test-ca.key" \
        -out "${CERT_DIR}/ca/test-ca.pem" \
        -days 3650 \
        -subj "/CN=Kipuka Test CA/O=Kipuka Test/C=US" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    # Server TLS cert signed by the test CA
    openssl req -new -nodes -newkey rsa:2048 \
        -keyout "${CERT_DIR}/tls/server.key" \
        -out /tmp/kipuka-server.csr \
        -subj "/CN=${HOSTNAME}/O=Kipuka Test/C=US"

    openssl x509 -req -in /tmp/kipuka-server.csr \
        -CA "${CERT_DIR}/ca/test-ca.pem" \
        -CAkey "${CERT_DIR}/ca/test-ca.key" \
        -CAcreateserial \
        -out "${CERT_DIR}/tls/server.pem" \
        -days 200 \
        -extfile <(printf "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n" "${HOSTNAME}")

    # Use test-ca as the CA cert for kipuka
    cp "${CERT_DIR}/ca/test-ca.pem" "${CERT_DIR}/ca/dogtag-ca.pem"
fi

# 8c. Client CA bundle for mTLS (trust the Dogtag CA for re-enrollment)
cp "${CERT_DIR}/ca/dogtag-ca.pem" "${CERT_DIR}/tls/client-ca-bundle.pem"

# 8d. Generate an admin/agent certificate for admin API access
openssl req -new -nodes -newkey rsa:2048 \
    -keyout "${CERT_DIR}/tls/agent.key" \
    -out /tmp/agent.csr \
    -subj "/CN=kipuka-agent/O=Kipuka Test/C=US"

# Sign with the same CA
CA_CERT="${CERT_DIR}/ca/test-ca.pem"
CA_KEY="${CERT_DIR}/ca/test-ca.key"
if [[ ! -f "${CA_KEY}" ]]; then
    # If we used Dogtag certs, we do not have the CA key on disk;
    # generate a separate admin CA for the agent cert.
    openssl req -x509 -new -nodes -newkey rsa:3072 \
        -keyout "${CA_KEY}" \
        -out "${CA_CERT}" \
        -days 3650 \
        -subj "/CN=Kipuka Test CA/O=Kipuka Test/C=US" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

openssl x509 -req -in /tmp/agent.csr \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${CERT_DIR}/tls/agent.pem" \
    -days 200 \
    -extfile <(printf "extendedKeyUsage=clientAuth\n")

log "Agent certificate generated: ${CERT_DIR}/tls/agent.pem"

# Clean up temp files
rm -f /tmp/kipuka-server.csr /tmp/agent.csr /tmp/cert-request-output.txt

# Fix permissions
chmod 640 "${CERT_DIR}/tls/server.key"
chown root:"${KIPUKA_GROUP}" "${CERT_DIR}/tls/server.key"
chmod 644 "${CERT_DIR}/tls/server.pem"
chmod 644 "${CERT_DIR}/ca/"*.pem

# ── Step 9: Create kipuka configuration ──────────────────────────────────────

log "Creating kipuka configuration"

if [[ -f "${SCRIPT_DIR}/kipuka-test.toml" ]]; then
    cp "${SCRIPT_DIR}/kipuka-test.toml" "${KIPUKA_CONF}/kipuka.toml"
else
    cat > "${KIPUKA_CONF}/kipuka.toml" <<EOF
# kipuka Beaker test configuration
# Generated by setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)

[server]
listen_addr = "0.0.0.0:${KIPUKA_PORT}"

[tls]
enabled = true
cert_file = "${CERT_DIR}/tls/server.pem"
key_file = "${CERT_DIR}/tls/server.key"
client_auth = "optional"
ca_file = "${CERT_DIR}/tls/client-ca-bundle.pem"

[database]
url = "sqlite://${KIPUKA_DATA}/kipuka.db"
run_migrations = true

[ca]
id = "dogtag"
is_default = true
key_file = "${CERT_DIR}/ca/test-ca.key"
cert_file = "${CERT_DIR}/ca/dogtag-ca.pem"
validity_days = 200

[otp]
enabled = true
entropy_bits = 128
ttl_seconds = 3600
max_usage = 1
storage_backend = "db"

[admin]
enabled = true
listen_addr = "127.0.0.1:9444"
auth_method = "mtls"
admin_ca_file = "${CERT_DIR}/ca/test-ca.pem"
allowed_operators = ["CN=kipuka-agent,O=Kipuka Test,C=US"]

[audit]
enabled = true
log_path = "${KIPUKA_LOG}/audit.log"
rotation_policy = "daily"
overflow_policy = "halt"

[est]
simpleenroll = true
simplereenroll = true
csrattrs = true
fullcmc = false
serverkeygen = false
EOF
fi

# Substitute any placeholder paths in the test config
sed -i "s|__KIPUKA_PORT__|${KIPUKA_PORT}|g" "${KIPUKA_CONF}/kipuka.toml" || true
chown -R root:"${KIPUKA_GROUP}" "${KIPUKA_CONF}"

# ── Step 10: Install systemd service ─────────────────────────────────────────

log "Installing kipuka systemd service"

if [[ -f "${SCRIPT_DIR}/kipuka.service" ]]; then
    cp "${SCRIPT_DIR}/kipuka.service" /etc/systemd/system/kipuka.service
else
    cat > /etc/systemd/system/kipuka.service <<EOF
[Unit]
Description=Kipuka EST Enrollment Server
After=network-online.target pki-tomcatd@pki-tomcat.service
Wants=network-online.target

[Service]
Type=simple
User=${KIPUKA_USER}
Group=${KIPUKA_GROUP}
ExecStart=/usr/local/bin/kipuka --config /etc/kipuka/kipuka.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable kipuka

# ── Step 11: Start kipuka ────────────────────────────────────────────────────

log "Starting kipuka EST server"
systemctl start kipuka

# Wait for kipuka to be ready
for i in $(seq 1 15); do
    if curl -sk "https://localhost:${KIPUKA_PORT}/.well-known/est/cacerts" &>/dev/null; then
        log "kipuka is responding on port ${KIPUKA_PORT}"
        break
    fi
    if [[ $i -eq 15 ]]; then
        log "WARNING: kipuka may not be fully ready yet (continuing)"
        systemctl status kipuka --no-pager || true
        journalctl -u kipuka --no-pager -n 30 || true
    fi
    sleep 1
done

# ── Step 12: Run smoke tests ────────────────────────────────────────────────

if [[ "${RUN_SMOKE_TEST}" == "true" ]]; then
    log "Running smoke tests"
    if [[ -f "${SCRIPT_DIR}/smoke-test.sh" ]]; then
        bash "${SCRIPT_DIR}/smoke-test.sh"
    elif [[ -f "${KIPUKA_SRC}/contrib/beaker/smoke-test.sh" ]]; then
        bash "${KIPUKA_SRC}/contrib/beaker/smoke-test.sh"
    else
        log "No smoke-test.sh found; skipping"
    fi
fi

log "Setup complete."
log "  kipuka EST:  https://localhost:${KIPUKA_PORT}/.well-known/est/"
log "  Dogtag CA:   https://localhost:${PKI_HTTPS_PORT}/ca/"
log "  Dogtag KRA:  https://localhost:${PKI_HTTPS_PORT}/kra/"
log "  Config:      ${KIPUKA_CONF}/kipuka.toml"
log "  Logs:        journalctl -u kipuka -f"
