#!/usr/bin/env bash
# Run Kipuka EST/CMC tests via idm-ci test infrastructure
set -euo pipefail

IDM_CI_DIR="${IDM_CI_DIR:-$HOME/git/idm-ci}"
PROVIDER="${1:-aws}"  # aws, beaker, or openstack
METADATA="metadata/kipuka-est.yaml"

# Validate provider
case "$PROVIDER" in
    aws)
        METADATA="metadata/kipuka-est-aws.yaml"
        echo "Running tests with AWS provider..."
        ;;
    beaker)
        METADATA="metadata/kipuka-est-beaker.yaml"
        echo "Running tests with Beaker provider..."
        ;;
    openstack)
        METADATA="metadata/kipuka-est.yaml"
        echo "Running tests with OpenStack provider..."
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

# Run tests via test executioner (te)
cd "$IDM_CI_DIR"
echo "Running: scripts/te $METADATA"
scripts/te "$METADATA"
