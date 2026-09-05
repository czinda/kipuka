#!/usr/bin/env bash
# Compatibility filename: RFC 9483 is the Lightweight CMP Profile, not CoAP.
# These are implementation regression tests for CoAP/EST-over-CoAP (RFC 9148).
# They do not establish independent protocol conformance or interoperability.
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"
echo "CoAP implementation regression tests (RFC 7252/7959/9148 references)"
echo "Independent authenticated DTLS client/server interoperability is required separately."
cargo test --locked -p kipuka-coap
