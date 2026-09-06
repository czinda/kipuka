"""Exercise advisory exceptions without network access or clock overrides in CI."""
import contextlib
import datetime
import io
import unittest
import audit


class AuditPolicyTests(unittest.TestCase):
    def report(self):
        return {
            "settings": {"ignore": [], "target_arch": [], "target_os": [],
                         "severity": None, "informational_warnings": ["unsound"]},
            "vulnerabilities": {"count": 1, "list": [{
                "advisory": {"id": "RUSTSEC-2023-0071"},
                "package": {"name": "rsa", "version": "0.9.10"},
            }]},
            "warnings": {},
        }

    def evaluate(self, report, day=datetime.date(2026, 9, 5)):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return audit.evaluate(report, day)

    def test_exception_expires_on_deadline(self):
        self.assertEqual(self.evaluate(self.report()), 0)
        self.assertEqual(self.evaluate(self.report(), datetime.date(2026, 10, 5)), 1)

    def test_exception_is_exact_version_and_advisory(self):
        for field, value in [("version", "0.9.11"), ("name", "other")]:
            report = self.report()
            report["vulnerabilities"]["list"][0]["package"][field] = value
            self.assertEqual(self.evaluate(report), 1)
        report = self.report()
        report["vulnerabilities"]["list"][0]["advisory"]["id"] = "RUSTSEC-2099-0001"
        self.assertEqual(self.evaluate(report), 1)

    def test_unsoundness_fails_but_informational_findings_remain_visible(self):
        for category, expected in [("unsound", 1), ("unmaintained", 0), ("yanked", 0)]:
            report = self.report()
            report["warnings"] = {category: [{"package": {"name": "example", "version": "1.0"}}]}
            self.assertEqual(self.evaluate(report), expected)

    def test_filtered_and_incomplete_reports_fail(self):
        self.assertEqual(self.evaluate({}), 1)
        for field, value in [("ignore", ["RUSTSEC-2023-0071"]),
                             ("target_os", ["linux"]), ("informational_warnings", [])]:
            report = self.report()
            report["settings"][field] = value
            self.assertEqual(self.evaluate(report), 1)


if __name__ == "__main__":
    unittest.main()
