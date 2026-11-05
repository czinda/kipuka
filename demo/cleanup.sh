#!/usr/bin/env bash
# demo/cleanup.sh — tear down everything the demo created.
#
# Stops any server started with --keep, and removes generated state. By default
# it leaves the demo PKI + config in place (cheap to keep, slow-ish to rebuild);
# pass --all to remove those too and return demo/ to a pristine checkout.
#
# Usage:
#   ./demo/cleanup.sh          # stop server, remove demo/state/
#   ./demo/cleanup.sh --all    # also remove demo/pki/ and demo/kipuka-demo.toml

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

ALL=0
[[ "${1:-}" == "--all" ]] && ALL=1

# Stop a server left running by `run.sh --keep`.
if [[ -f "${PID_FILE}" ]]; then
  PID="$(cat "${PID_FILE}" 2>/dev/null || true)"
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    say "Stopping demo server (PID ${PID})…"
    kill "${PID}" 2>/dev/null || true
    ok "Server stopped."
  fi
fi

# Belt-and-suspenders: kill anything still bound to the demo port.
if command -v lsof >/dev/null 2>&1; then
  STRAGGLERS="$(lsof -ti "tcp:${PORT}" 2>/dev/null || true)"
  if [[ -n "${STRAGGLERS}" ]]; then
    say "Reaping stray listener(s) on port ${PORT}…"
    # shellcheck disable=SC2086
    kill ${STRAGGLERS} 2>/dev/null || true
  fi
fi

say "Removing run state (${STATE_DIR})…"
rm -rf "${STATE_DIR}"
ok "Run state removed."

if [[ "${ALL}" == "1" ]]; then
  say "Removing demo PKI and config (--all)…"
  rm -rf "${PKI_DIR}"
  rm -f  "${CONFIG_FILE}"
  ok "demo/ returned to a pristine state. Re-run ./demo/setup.sh to rebuild."
else
  note "Kept demo PKI + config. Use --all to remove them too."
fi
