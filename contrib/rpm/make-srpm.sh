#!/bin/bash
# Generate SRPM for Fedora COPR from the kipuka workspace.
#
# Usage:
#   ./contrib/rpm/make-srpm.sh
#
# Outputs:
#   rpmbuild/SRPMS/kipuka-*.src.rpm
#
# Requirements:
#   - cargo, rust >= 1.88
#   - rpm-build, rpmdevtools
set -euo pipefail

CRATE=kipuka
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*= *"\(.*\)"/\1/')
TOPDIR="$(pwd)/rpmbuild"

echo "=== Building SRPM for ${CRATE}-${VERSION} ==="

# Clean previous builds
rm -rf "${TOPDIR}"
mkdir -p "${TOPDIR}"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}

# 1. Create source tarball (exclude target/, .git/)
echo "--- Creating source tarball ---"
git archive --format=tar.gz --prefix="${CRATE}-${VERSION}/" HEAD \
    -o "${TOPDIR}/SOURCES/${CRATE}-${VERSION}.tar.gz"

# 2. Vendor all dependencies
echo "--- Vendoring dependencies ---"
cargo vendor --versioned-dirs vendor/

# 3. Create vendor tarball
echo "--- Creating vendor tarball ---"
tar czf "${TOPDIR}/SOURCES/${CRATE}-${VERSION}-vendor.tar.gz" vendor/

# 4. Clean up vendor directory
rm -rf vendor/

# 5. Copy spec file
cp kipuka.spec "${TOPDIR}/SPECS/"

# 6. Build SRPM
echo "--- Building SRPM ---"
rpmbuild -bs \
    --define "_topdir ${TOPDIR}" \
    "${TOPDIR}/SPECS/kipuka.spec"

echo ""
echo "=== SRPM ready ==="
ls -la "${TOPDIR}/SRPMS/"*.src.rpm
echo ""
echo "Upload to COPR:"
echo "  copr-cli build kipuka ${TOPDIR}/SRPMS/${CRATE}-${VERSION}-*.src.rpm"
