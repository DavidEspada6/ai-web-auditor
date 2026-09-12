import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.dashboard import build_audit_dashboard, render_dashboard_console


SCAN_DATA = {
    "tool": "ai-web-auditor",
    "version": "0.25.0",
    "generated_at": "2026-09-12T12:00:00Z",
    "status": "completed",
    "target": {"normalized_url": "https://example.com/", "scheme": "https", "host": "example.com", "port": 443},
    "modules": [
        {"name": "scope", "status": "passed", "summary": "Target validated."},
        {"name": "http", "status": "passed", "summary": "HTTP checked."},
        {"name": "security_headers", "status": "warning", "summary": "CSP missing."},
        {"name": "cookies", "status": "passed", "summary": "Cookies checked."},
        {"name": "basic_auth", "status": "passed", "summary": "No Basic Auth."},
        {"name": "http_methods", "status": "passed", "summary": "Methods checked."},
        {"name": "tls", "status": "passed", "summary": "TLS checked."},
        {
            "name": "fingerprinting",
            "status": "passed",
            "summary": "Fingerprinting complete.",
            "artifacts": {"technologies": [{"name": "nginx", "confidence": "high"}]},
        },
        {
            "name": "crawler",
            "status": "passed",
            "summary": "Crawler complete.",
            "artifacts": {"pages": [{"url": "https://example.com/login", "status_code": 200, "forms_found": 1}]},
        },
        {
            "name": "javascript",
            "status": "passed",
            "summary": "JavaScript complete.",
            "artifacts": {"discovered_endpoints": [{"url": "https://example.com/api/profile", "method": "POST"}]},
        },
    ],
    "findings": [
        {
            "id": "HEADER-CSP-MISSING",
            "title": "Content Security Policy is missing",
            "severity": "medium",
            "category": "security-headers",
            "description": "Missing CSP.",
            "recommendation": "Define CSP.",
            "module": "security_headers",
            "target": "https://example.com/",
            "evidence": [],
        }
    ],
}


class DashboardTests(unittest.TestCase):
    def test_build_dashboard_contains_operational_sections(self):
        dashboard = build_audit_dashboard(SCAN_DATA)

        self.assertEqual(dashboard["summary"]["risk_level"], "medium")
        self.assertGreater(dashboard["summary"]["coverage_score"], 0)
        self.assertGreater(dashboard["summary"]["pending_count"], 0)
        self.assertEqual(dashboard["changes"]["status"], "baseline_required")
        self.assertTrue(any(item["id"] == "entrypoints" for item in dashboard["checklist"]))
        self.assertTrue(any(item["id"] == "baseline-comparison" for item in dashboard["pending"]))

    def test_dashboard_accepts_comparison_summary(self):
        comparison = {"summary": {"new": 2, "resolved": 1, "persistent": 4, "severity_changed": 1}}

        dashboard = build_audit_dashboard(SCAN_DATA, comparison=comparison)

        self.assertEqual(dashboard["summary"]["change_status"], "compared")
        self.assertEqual(dashboard["changes"]["summary"]["new"], 2)
        self.assertFalse(any(item["id"] == "baseline-comparison" for item in dashboard["pending"]))

    def test_render_dashboard_console(self):
        dashboard = build_audit_dashboard(SCAN_DATA)
        output = render_dashboard_console(dashboard)

        self.assertIn("Audit Dashboard", output)
        self.assertIn("Risk:", output)
        self.assertIn("Pending", output)

    def test_dashboard_cli_writes_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "dashboard.json"
            scan_path.write_text(json.dumps(SCAN_DATA), encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(["dashboard", str(scan_path), "--output", str(output)])

            dashboard = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertIn("Dashboard JSON written", stdout.getvalue())
        self.assertIn("coverage", dashboard)
        self.assertIn("checklist", dashboard)


if __name__ == "__main__":
    unittest.main()
