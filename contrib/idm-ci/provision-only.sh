#!/usr/bin/env bash
# Provision a RHEL 10 VM via idm-ci/mrack and print SSH details
# Does not run tests - useful for manual testing and debugging
set -euo pipefail

IDM_CI_DIR="${IDM_CI_DIR:-$HOME/git/idm-ci}"
PROVIDER="${1:-aws}"
METADATA="metadata/kipuka-est.yaml"

# Validate provider
case "$PROVIDER" in
    aws)
        METADATA="metadata/kipuka-est-aws.yaml"
        echo "Provisioning VM with AWS provider..."
        ;;
    beaker)
        METADATA="metadata/kipuka-est-beaker.yaml"
        echo "Provisioning VM with Beaker provider..."
        ;;
    openstack)
        METADATA="metadata/kipuka-est.yaml"
        echo "Provisioning VM with OpenStack provider..."
        ;;
    *)
        echo "Error: Unknown provider '$PROVIDER'" >&2
        echo "Usage: $0 [aws|beaker|openstack]" >&2
        exit 1
        ;;
esac

# Verify idm-ci directory exists
if [[ ! -d "$IDM_CI_DIR" ]]; then
    echo "Error: idm-ci directory not found at $IDM_CI_DIR" >&2
    echo "Set IDM_CI_DIR environment variable or clone idm-ci to $HOME/git/idm-ci" >&2
    exit 1
fi

# Provision VM (runs prep phase only, stops before tests)
cd "$IDM_CI_DIR"
echo "Running: scripts/te --upto prep $METADATA"
scripts/te --upto prep "$METADATA"

echo ""
echo "======================================"
echo "VM provisioned successfully!"
echo "======================================"
echo ""
echo "SSH details (also in testrunner directory):"
mrack list

echo ""
echo "To manually run tests:"
echo "  1. SSH to the VM using details above"
echo "  2. cd /path/to/kipuka"
echo "  3. pytest tests/test_est.py -v"
echo ""
echo "To teardown: ./teardown.sh"
