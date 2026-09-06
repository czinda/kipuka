#!/usr/bin/env python3
"""Fail on advisories except a reviewed, version-scoped, expiring exception."""
import datetime
import json
from pathlib import Path
import subprocess
import sys

# sqlx-mysql 0.8.6 only calls RSA PUBLIC-KEY encryption during authentication.
# Reassess on any SQLx/RSA change. See docs/dependency-exceptions.md.
EXCEPTIONS = {
    ("RUSTSEC-2023-0071", "rsa", "0.9.10"): datetime.date(2026, 10, 5),
}


def evaluate(report, today):
    """Return nonzero for findings or incomplete/filtered audit reports."""
    try:
        settings = report["settings"]
        if any(settings.get(key) for key in ("ignore", "target_arch", "target_os", "severity")):
            raise ValueError("cargo-audit report filters must be empty")
        if "unsound" not in settings["informational_warnings"]:
            raise ValueError("cargo-audit must report unsoundness warnings")
        issues = report["vulnerabilities"]["list"]
        warnings = report["warnings"]
        if not isinstance(issues, list) or not isinstance(warnings, dict):
            raise ValueError("invalid advisory report structure")
        if report["vulnerabilities"]["count"] != len(issues):
            raise ValueError("inconsistent vulnerability count")
        failed = False
        for issue in issues:
            key = (issue["advisory"]["id"], issue["package"]["name"], issue["package"]["version"])
            expires = EXCEPTIONS.get(key)
            if expires and today < expires:
                print(f"REVIEWED EXCEPTION {key}: expires {expires}")
            else:
                print(f"UNACCEPTED ADVISORY {key}")
                failed = True
        for category, findings in warnings.items():
            for warning in findings:
                package = warning["package"]
                advisory = warning.get("advisory") or {}
                print(f"WARNING {category}: {package['name']} {package['version']} {advisory.get('id', '')}")
                if category not in ("unmaintained", "notice", "yanked"):
                    failed = True
        return int(failed)
    except (KeyError, TypeError, ValueError) as error:
        print(f"INVALID AUDIT REPORT: {error}", file=sys.stderr)
        return 1


def main():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["cargo", "audit", "--json", "--file", str(root / "Cargo.lock")],
        cwd=root, capture_output=True, text=True,
    )
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode not in (0, 1):
        return result.returncode
    try:
        report = json.loads(result.stdout)
    except ValueError:
        sys.stderr.write(result.stdout)
        return 1
    return evaluate(report, datetime.datetime.now(datetime.timezone.utc).date())


if __name__ == "__main__":
    sys.exit(main())
