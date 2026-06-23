# HSM Compatibility Matrix

This document details PKCS#11 HSM compatibility with kipuka, including
per-vendor configuration, supported mechanisms, and known limitations.

## Compatibility Matrix

| Feature | Entrust nShield | Utimaco CryptoServer | Kryoptic | Thales Luna 7 |
|---------|----------------|---------------------|----------|---------------|
| PKCS#11 version | 2.40 | 2.40 | 2.40 | 2.40 |
| **Key Generation** | | | | |
| RSA 2048 | Yes | Yes | Yes | Yes |
| RSA 3072 | Yes | Yes | Yes | Yes |
| RSA 4096 | Yes | Yes | Yes | Yes |
| EC P-256 | Yes | Yes | Yes | Yes |
| EC P-384 | Yes | Yes | Yes | Yes |
| EC P-521 | Yes | Yes | Yes | Yes |
| **Signing** | | | | |
| CKM_RSA_PKCS | Yes | Yes | Yes | Yes |
| CKM_RSA_PKCS_PSS | Yes | Yes | Yes | Yes |
| CKM_ECDSA | Yes | Yes | Yes | Yes |
| CKM_ECDSA_SHA256 | Yes | Yes | Yes | Yes |
| CKM_ECDSA_SHA384 | Yes | Yes | Yes | Yes |
| CKM_SHA256_RSA_PKCS | Yes | Yes | Yes | Yes |
| CKM_SHA384_RSA_PKCS | Yes | Yes | Yes | Yes |
| **Key Wrapping** | | | | |
| CKM_AES_KEY_WRAP | Yes | Yes | Yes | Yes |
| CKM_RSA_PKCS_OAEP | Yes | Partial (1) | Yes | Yes |
| **Random Generation** | | | | |
| C_GenerateRandom | Yes | Yes | Yes | Yes |
| **Session Management** | | | | |
| Concurrent sessions | Yes (16+) | Yes (32+) | Yes | Yes (16+) |
| RW sessions | Yes | Yes | Yes | Yes |
| **FIPS 140 Level** | Level 3 | Level 3 | N/A (2) | Level 3 |

Notes:
1. Utimaco CKM_RSA_PKCS_OAEP: supported with SHA-256 MGF only. SHA-384/SHA-512 MGF
   requires firmware >= 5.2.
2. Kryoptic is a software token for development and testing. Not FIPS-validated.

## Per-Vendor Configuration

### Entrust nShield Connect / Solo

```toml
[hsm]
library = "/opt/nfast/toolkits/pkcs11/libcknfast.so"
token_label = "kipuka-production"
pin_env = "KIPUKA_HSM_PIN"
```

**Prerequisites:**
- nShield Security World created and initialized
- `module` command available in PATH
- Application partition created for kipuka
- For HA: nShield Connect with multiple module support

**Environment variables:**
- `NFAST_HOME=/opt/nfast` (usually pre-set by nShield installation)
- `CKNFAST_OVERRIDE_SECURITY_ASSURANCES` -- do NOT set in production

**Known limitations:**
- Maximum object label length: 32 characters
- Session timeout: configurable via Security World settings
- Key export requires module-protected (OCS) key authorization

**Key generation:**
```bash
# Generate RSA key pair
/opt/nfast/bin/generatekey pkcs11 \
  --protect=module \
  --type=RSA --size=4096 \
  --plainname=kipuka-ca-rsa \
  --nvram=no

# Generate EC key pair
/opt/nfast/bin/generatekey pkcs11 \
  --protect=module \
  --type=EC --curve=NISTP384 \
  --plainname=kipuka-ca-ec
```

### Utimaco CryptoServer Se / CP5

```toml
[hsm]
library = "/usr/lib/libcs_pkcs11_R3.so"
slot = 0
pin_env = "KIPUKA_HSM_PIN"
```

**Prerequisites:**
- CryptoServer administration tools installed
- Device initialized with a Security Officer
- User created with appropriate key generation and signing permissions

**Configuration file** (`/etc/utimaco/cs_pkcs11_R3.cfg`):
```ini
[Global]
Logpath = /var/log/utimaco
Logfile = kipuka_pkcs11.log
Loglevel = 3

[CryptoServer]
Device = 192.168.1.100
Timeout = 30000
```

**Known limitations:**
- Firmware versions before 5.0 do not support CKM_ECDSA_SHA384
- Session limit depends on license (default: 32 concurrent)
- Network latency affects signing throughput (use local CryptoServer for high volume)

**Key generation:**
```bash
p11tool2 -l /usr/lib/libcs_pkcs11_R3.so \
  LoginUser=kipuka LoginPWD=$PIN \
  GenerateKeyPair=RSA Keysize=4096 \
  KeyLabel=kipuka-ca-rsa Modifiable=false Extractable=false
```

### Kryoptic (Development / Testing)

```toml
[hsm]
library = "/usr/lib/libkryoptic_pkcs11.so"
token_label = "kipuka-dev"
pin = "1234"  # OK for development only
```

**Prerequisites:**
- Kryoptic installed (`dnf install kryoptic` on Fedora/RHEL)
- Token initialized

**Setup:**
```bash
# Initialize token
kryoptic-init --token-label kipuka-dev --pin 1234 --so-pin 12345678

# Generate test keys
pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
  --login --pin 1234 \
  --keypairgen --key-type EC:secp384r1 \
  --label "dev-ca-ec" --id 01

pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
  --login --pin 1234 \
  --keypairgen --key-type rsa:4096 \
  --label "dev-ca-rsa" --id 02
```

**Known limitations:**
- Software-only: no hardware protection for keys
- Not FIPS 140-3 validated
- Token state stored on filesystem (default: `~/.local/share/kryoptic/`)
- Suitable for CI and development only

**CI integration:**
```bash
export KRYOPTIC_TOKEN_DIR=$(mktemp -d)
kryoptic-init --token-label ci-test --pin 1234 --so-pin 12345678
export KIPUKA_HSM_PIN=1234
cargo test --features hsm-tests
rm -rf "$KRYOPTIC_TOKEN_DIR"
```

### Thales Luna 7 (CSP11 / TCT)

```toml
[hsm]
library = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
slot = 0
pin_env = "KIPUKA_HSM_PIN"
```

**Prerequisites:**
- Luna client software installed
- Network HSM registered and partition assigned
- Client certificate registered with the Luna appliance

**Configuration** (`/etc/Chrystoki.conf`):
```ini
Chrystoki2 = {
  LibUNIX64 = /usr/safenet/lunaclient/lib/libCryptoki2_64.so;
}
Luna = {
  DefaultTimeOut = 500000;
  PEDTimeout1 = 100000;
  PEDTimeout2 = 200000;
  KeypairGenTimeOut = 2700000;
}
LunaSA Client = {
  ServerName00 = luna-hsm.example.com;
  ServerPort00 = 1792;
  ServerCAFile00 = /usr/safenet/lunaclient/cert/server/luna-ca.pem;
  ClientCertFile00 = /usr/safenet/lunaclient/cert/client/client-cert.pem;
  ClientPrivKeyFile00 = /usr/safenet/lunaclient/cert/client/client-key.pem;
}
```

**Known limitations:**
- Luna Network HSM: network latency affects signing throughput
- Concurrent session limit depends on partition configuration (default: 16)
- For HA: use Luna HA groups (configured in `Chrystoki.conf`, transparent to kipuka)
- TCT (Trusted Connect Toolkit) variant has different library path:
  `/opt/thales/dpodclient/lib/libCryptoki2_64.so`

**Key generation:**
```bash
/usr/safenet/lunaclient/bin/cmu generatekeypair \
  -keyType=EC -curvetype=NISTP384 \
  -labelPublic=kipuka-ca-ec-pub -labelPrivate=kipuka-ca-ec-priv \
  -sign=true -verify=true -extractable=false
```

## Key Wrapping for /serverkeygen

When `/serverkeygen` is used, kipuka generates a key pair on behalf of the
client and must return the private key encrypted. The key wrapping mechanism
depends on the HSM capabilities:

| Method | Mechanism | Use Case |
|--------|-----------|----------|
| AES Key Wrap | CKM_AES_KEY_WRAP (RFC 3394) | Preferred. Wraps the generated private key with a symmetric AES key. The AES key is then encrypted with the client's public key. |
| RSA-OAEP | CKM_RSA_PKCS_OAEP | Alternative. Directly wraps the generated private key with the client's RSA public key. Limited by RSA key size. |
| Software wrap | Synta PKCS#7 EnvelopedData | Fallback when HSM does not support key wrapping. Key is exported from HSM and wrapped in software. Less secure -- HSM extraction policy must allow export. |

## Testing Instructions

### Automated HSM tests

```bash
# Run HSM integration tests (requires a configured PKCS#11 token)
KIPUKA_HSM_LIBRARY=/usr/lib/libkryoptic_pkcs11.so \
KIPUKA_HSM_PIN=1234 \
KIPUKA_HSM_TOKEN_LABEL=kipuka-dev \
cargo test --features hsm-tests -- hsm

# Test a specific HSM operation
cargo test --features hsm-tests -- hsm::test_sign_rsa
cargo test --features hsm-tests -- hsm::test_sign_ecdsa
cargo test --features hsm-tests -- hsm::test_key_wrap
```

### Manual verification

```bash
# List objects in the HSM token
pkcs11-tool --module $LIBRARY --login --pin $PIN --list-objects

# Test signing with the CA key
echo "test data" | pkcs11-tool --module $LIBRARY --login --pin $PIN \
  --sign --mechanism ECDSA-SHA384 --label kipuka-ca-ec

# Verify the PKCS#11 library is accessible
pkcs11-tool --module $LIBRARY --show-info
pkcs11-tool --module $LIBRARY --list-slots
pkcs11-tool --module $LIBRARY --list-mechanisms --slot 0
```
