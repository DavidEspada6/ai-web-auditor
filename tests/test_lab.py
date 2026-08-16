import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan
from ai_web_auditor.lab import lab_scan_defaults, start_lab_server


class LabTests(unittest.TestCase):
    def test_lab_serves_expected_demo_routes(self):
        lab = start_lab_server(port=0)
        try:
            with urllib.request.urlopen(lab.url, timeout=5) as response:
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("AI Web Auditor Lab", body)
                self.assertIn("PHP/5.6.40", response.headers.get("X-Powered-By", ""))

            request = urllib.request.Request(lab.target_url, method="GET")
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(raised.exception.code, 401)
            self.assertIn("Basic", raised.exception.headers.get("WWW-Authenticate", ""))

            options = urllib.request.Request(lab.target_url, method="OPTIONS")
            with urllib.request.urlopen(options, timeout=5) as response:
                self.assertIn("TRACE", response.headers.get("Allow", ""))
        finally:
            lab.stop()

    def test_scan_against_lab_finds_controlled_issues(self):
        lab = start_lab_server(port=0)
        try:
            config = AuditConfig()
            defaults = lab_scan_defaults(lab.status())
            config.scope.allowed_hosts = [defaults["allowed_hosts"]]
            config.scope.allow_private_networks = True
            config.scope.resolve_dns = False
            config.scope.include_paths = ["/"]
            config.scope.exclude_paths = []
            config.http.check_http_counterpart = False
            config.modules.tls = False
            config.crawler.max_depth = 1
            config.crawler.max_pages = 20

            result = run_scan(lab.target_url, config)
            finding_ids = {finding.id for finding in result.findings}
            result_data = result.to_dict()
            inventory = result_data["inventory"]
            assessment = result_data["assessment"]

        finally:
            lab.stop()

        self.assertIn("AUTH-BASIC-OVER-HTTP", finding_ids)
        self.assertIn("HTTP-NO-HTTPS-REDIRECT", finding_ids)
        self.assertIn("HEADER-CONTENT_SECURITY_POLICY-MISSING", finding_ids)
        self.assertIn("COOKIE-HTTPONLY-MISSING", finding_ids)
        self.assertIn("METHOD-TRACE-ADVERTISED", finding_ids)
        self.assertGreaterEqual(inventory["summary"]["forms"], 1)
        self.assertTrue(any("login_path" in item["reasons"] for item in inventory["interesting_paths"]))
        self.assertEqual(assessment["summary"]["risk_level"], "high")
        self.assertGreaterEqual(assessment["summary"]["priority_count"], 1)


if __name__ == "__main__":
    unittest.main()
