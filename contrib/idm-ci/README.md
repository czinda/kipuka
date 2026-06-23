# Running Kipuka Tests via idm-ci

This directory contains helper scripts for running Kipuka EST/CMC tests through the [idm-ci](https://gitlab.cee.redhat.com/identity-management/idm-ci) test infrastructure.

## Prerequisites

1. **Clone idm-ci**:
   ```bash
   git clone git@gitlab.cee.redhat.com:identity-management/idm-ci.git ~/git/idm-ci
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

## Quick Start

### Run Full Test Suite

```bash
# AWS (default)
./run-tests.sh aws

# Beaker
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

## Topology Files

Kipuka test topologies are defined in idm-ci metadata files:
- `metadata/kipuka-est.yaml` - Generic EST/CMC test topology
- `metadata/kipuka-est-aws.yaml` - AWS-specific EST/CMC topology
- `metadata/kipuka-est-beaker.yaml` - Beaker-specific EST/CMC topology

See the [idm-ci metadata directory](https://gitlab.cee.redhat.com/identity-management/idm-ci/-/tree/main/metadata) for full topology definitions.

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

## References

- [idm-ci GitLab](https://gitlab.cee.redhat.com/identity-management/idm-ci)
- [mrack documentation](https://github.com/neoave/mrack)
- [Kipuka test suite](../../tests/)
