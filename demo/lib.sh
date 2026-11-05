#!/usr/bin/env bash
# demo/lib.sh — shared helpers for the kipuka executive demo.
#
# Sourced by setup.sh and run.sh. Provides colours, a presenter-friendly
# "pause / narrate" workflow, and the shared paths/ports the demo uses.
#
# Nothing here talks to the network or mutates state; it only defines helpers.

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
# DEMO_DIR is the absolute path to this demo/ directory regardless of CWD.
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${DEMO_DIR}/.." && pwd)"
PKI_DIR="${DEMO_DIR}/pki"
STATE_DIR="${DEMO_DIR}/state"
CONFIG_FILE="${DEMO_DIR}/kipuka-demo.toml"
DB_FILE="${STATE_DIR}/kipuka.db"
SERVER_LOG="${STATE_DIR}/kipuka-server.log"
PID_FILE="${STATE_DIR}/kipuka.pid"

# ── Network ───────────────────────────────────────────────────────────────────
# High, unprivileged port to avoid collisions with a real 8443 listener.
HOST="127.0.0.1"
PORT="${KIPUKA_DEMO_PORT:-18443}"
BASE_URL="https://${HOST}:${PORT}"
EST_BASE="${BASE_URL}/.well-known/est"
ADMIN_BASE="${BASE_URL}/admin"

# Demo-only credentials. NOT secrets — regenerated on every setup. The audit
# integrity key keys the tamper-evident HMAC-SHA256 chain; the bearer token
# authenticates the admin/auditor API for this local demo only.
export KIPUKA_AUDIT_KEY="demo-audit-integrity-key-not-a-secret"
# Exported so the config can reference it as env:KIPUKA_ADMIN_TOKEN — modelling
# the same "no plaintext secrets in config" posture the product enforces.
export KIPUKA_ADMIN_TOKEN="demo-operator-token-not-a-secret"
ADMIN_BEARER_TOKEN="${KIPUKA_ADMIN_TOKEN}"

# ── Presentation controls ─────────────────────────────────────────────────────
# PAUSE=1 (default) waits for Enter between acts, so a presenter controls pace.
# Set PAUSE=0 (or pass --no-pause) to run start-to-finish unattended.
PAUSE="${PAUSE:-1}"

# Colours (disabled when stdout is not a TTY).
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
  BLUE=$'\033[38;5;39m'; GREEN=$'\033[38;5;42m'; YELLOW=$'\033[38;5;220m'
  RED=$'\033[38;5;203m'; CYAN=$'\033[38;5;51m'; MAGENTA=$'\033[38;5;207m'
else
  BOLD=""; DIM=""; RESET=""; BLUE=""; GREEN=""; YELLOW=""; RED=""; CYAN=""; MAGENTA=""
fi

# act "Title" — big section banner announcing the next demo beat.
act() {
  echo
  echo "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════════${RESET}"
  echo "${BOLD}${BLUE}  $*${RESET}"
  echo "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════════${RESET}"
}

# say "text" — presenter narration (what to tell the executive audience).
say()  { echo "${CYAN}▸ $*${RESET}"; }
# note "text" — an honest caveat / scope boundary the presenter should own.
note() { echo "${YELLOW}⚠ $*${RESET}"; }
ok()   { echo "${GREEN}✔ $*${RESET}"; }
bad()  { echo "${RED}✘ $*${RESET}"; }
# cmd "..." — echo the command we are about to run, so the audience sees it.
cmd()  { echo "${DIM}\$ $*${RESET}"; }

# pause — wait for the presenter unless PAUSE=0.
pause() {
  [[ "${PAUSE}" == "1" ]] || return 0
  echo
  read -r -p "${MAGENTA}   [Enter] to continue…${RESET}" _ || true
}

# require <bin> [<bin>...] — fail fast with a clear message if a tool is missing.
require() {
  local missing=0 b
  for b in "$@"; do
    if ! command -v "$b" >/dev/null 2>&1; then
      bad "required tool not found: $b"
      missing=1
    fi
  done
  [[ "$missing" == "0" ]] || { bad "install the missing tool(s) and re-run"; exit 1; }
}
