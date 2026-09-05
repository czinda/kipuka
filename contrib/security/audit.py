#!/usr/bin/env python3
"""Fail on advisories except a reviewed, version-scoped, expiring exception."""
import datetime
import json
import subprocess
import sys

result = subprocess.run(["cargo", "audit", "--json"], capture_output=True, text=True)
if result.returncode not in (0, 1):
    sys.stderr.write(result.stderr)
    sys.exit(result.returncode)
try:
    report = json.loads(result.stdout)
except ValueError:
    sys.stderr.write(result.stderr + result.stdout)
    sys.exit(1)
exceptions = {
    # sqlx-mysql 0.8.6 only calls RSA PUBLIC-KEY encryption during authentication.
    # No RSA private-key operation from this crate is reachable in Kipuka.
    # Reassess on any SQLx/RSA change. See docs/dependency-exceptions.md.
    ("RUSTSEC-2023-0071", "rsa", "0.9.10"): datetime.date(2026, 10, 5),
}
failed = False
for issue in report.get("vulnerabilities", {}).get("list", []):
    key = (issue["advisory"]["id"], issue["package"]["name"], issue["package"]["version"])
    expires = exceptions.get(key)
    if expires and datetime.date.today() < expires:
        print(f"REVIEWED EXCEPTION {key}: expires {expires}")
    else:
        print(f"UNACCEPTED ADVISORY {key}")
        failed = True
for category, warnings in report.get("warnings", {}).items():
    for warning in warnings:
        package = warning["package"]
        print(f"WARNING {category}: {package['name']} {package['version']}")
        if category == "unsound":
            failed = True
sys.exit(1 if failed else 0)
