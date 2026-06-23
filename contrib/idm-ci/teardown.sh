#!/usr/bin/env bash
# Clean up VMs and resources provisioned by idm-ci/mrack
set -euo pipefail

IDM_CI_DIR="${IDM_CI_DIR:-$HOME/git/idm-ci}"

# Verify idm-ci directory exists
if [[ ! -d "$IDM_CI_DIR" ]]; then
    echo "Error: idm-ci directory not found at $IDM_CI_DIR" >&2
    echo "Set IDM_CI_DIR environment variable or clone idm-ci to $HOME/git/idm-ci" >&2
    exit 1
fi

cd "$IDM_CI_DIR"

# Show current VMs before destruction
echo "Current VMs:"
mrack list || echo "No VMs found or mrack not available"

echo ""
echo "Destroying all provisioned VMs..."
mrack destroy

echo ""
echo "======================================"
echo "Teardown complete!"
echo "======================================"
echo ""
echo "All VMs and resources have been destroyed."
