# Running Kipuka Tests via idm-ci

This directory contains helper scripts for running Kipuka EST/CMC/CMP tests through the [idm-ci](https://gitlab.example.com/identity-management/idm-ci) test infrastructure.

## Prerequisites

1. **Clone idm-ci**:
   ```bash
   git clone git@gitlab.example.com:identity-management/idm-ci.git ~/git/idm-ci
   ```

2. **Install mrack** (VM provisioning):
   ```bash
   pip install mrack
   ```

3. **Configure cloud credentials**:
   - **AWS**: Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables
   - **Beaker**: Configure `~/.beaker_client/config` per [Beaker docs](https://beaker-project.org/docs/user-guide/)
   - **OpenStack**: Set `OS_AUTH_URL`, `OS_USERNAME`, `OS_PASSWORD`, `OS_PROJECT_NAME` environment variables

4. **Verify idm-ci setup**:
   ```bash
   cd ~/git/idm-ci
   ./scripts/te --help
   ```

## Beaker Deployment

The Beaker topology provisions a RHEL 10 VM with the following components:

- **Dogtag CA** -- Certificate Authority backend for EST enrollment
- **Dogtag KRA** -- Key Recovery Authority for `/serverkeygen` key generation and archival
- **kipuka EST server** -- configured against the Dogtag CA/KRA backends

This enables end-to-end testing of all EST operations including Dogtag-backed
enrollment, server-side key generation with KRA integration, and Full CMC
proxying through the Dogtag CMC infrastructure.

## Quick Start

### Run Full Test Suite

```bash
# AWS (default)
./run-tests.sh aws

# Beaker (includes Dogtag CA + KRA)
./run-tests.sh beaker

# OpenStack
./run-tests.sh openstack
```

### Provision VM Only (No Tests)

```bash
./provision-only.sh
```

This provisions a RHEL 10 VM and prints SSH details. Use this when you want to manually run tests or debug the environment.

### Teardown

```bash
./teardown.sh
```

Destroys all provisioned VMs and cleans up resources.

## Test Coverage

The smoke test suite validates the following kipuka capabilities:

| Category | Tests |
|---|---|
| **EST Core** | `/cacerts`, `/simpleenroll`, `/simplereenroll`, `/csrattrs` |
| **Full CMC** | `/fullcmc` endpoint (RFC 5272/6402 CMC-over-EST) |
| **Server Keygen** | `/serverkeygen` with KRA-backed key generation and archival |
| **CMP** | CMP protocol handler (RFC 4210) with signature and MAC protection |
| **OTP Enrollment** | OTP generation, consumption, expiration, and rate limiting |
| **Dogtag Health** | CA and KRA subsystem connectivity and health checks |
| **mTLS** | Client certificate authentication and POP linking |
| **CMS-EST** | RFC 8295 CMS-EST endpoints |
| **GSSAPI/Kerberos** | GSSAPI authentication (when KDC is available) |
| **Admin API** | Health, OTP management, CA status, audit endpoints |

## Topology Files

Kipuka test topologies are defined in idm-ci metadata files:
- `metadata/kipuka-est.yaml` - Generic EST/CMC/CMP test topology
- `metadata/kipuka-est-aws.yaml` - AWS-specific topology
- `metadata/kipuka-est-beaker.yaml` - Beaker-specific topology (Dogtag CA + KRA)

See the [idm-ci metadata directory](https://gitlab.example.com/identity-management/idm-ci/-/tree/main/metadata) for full topology definitions.

## Environment Variables

- `IDM_CI_DIR`: Path to idm-ci clone (default: `$HOME/git/idm-ci`)

## Manual Testing Workflow

For iterative development and debugging:

1. **Provision once**:
   ```bash
   ./provision-only.sh
   ```

2. **SSH into the VM**:
   ```bash
   # SSH details printed by provision-only.sh
   ssh root@<vm-ip>
   ```

3. **Run tests manually**:
   ```bash
   cd /path/to/kipuka
   pytest tests/test_est.py -v
   ```

4. **Iterate** (edit code, re-run tests)

5. **Teardown when done**:
   ```bash
   ./teardown.sh
   ```

## Troubleshooting

- **mrack command not found**: Ensure mrack is installed in your active Python environment
- **Cloud credentials errors**: Verify credentials are exported in your shell session
- **VM provisioning timeout**: Check cloud provider quotas and network connectivity
- **idm-ci not found**: Set `IDM_CI_DIR` to point to your clone location
- **Dogtag not responding**: On Beaker, verify `pki-server status` shows CA and KRA as running
- **KRA errors**: Ensure the KRA subsystem is enabled and the EST config includes `[dogtag]` with `kra_url`

## References

- [idm-ci GitLab](https://gitlab.example.com/identity-management/idm-ci)
- [mrack documentation](https://github.com/neoave/mrack)
- [Kipuka test suite](../../tests/)
- [RFC 7030 -- EST](https://www.rfc-editor.org/rfc/rfc7030)
- [RFC 5272 -- CMC](https://www.rfc-editor.org/rfc/rfc5272)
- [RFC 4210 -- CMP](https://www.rfc-editor.org/rfc/rfc4210)
