import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.assessment import build_assessment, render_assessment_console


SCAN_DATA = {
    "target": {"scheme": "http", "host": "127.0.0.1", "normalized_url": "http://127.0.0.1:8080/members/"},
    "modules": [
        {"name": "basic_auth", "status": "warning", "summary": "Basic Auth detected."},
        {"name": "ports", "status": "warning", "summary": "Open ports detected.", "artifacts": {"open_count": 1}},
        {"name": "crawler", "status": "passed", "summary": "Crawled 2 pages."},
    ],
    "inventory": {
        "summary": {"total_urls": 2, "fetched_urls": 2, "forms": 1, "interesting_urls": 1},
        "urls": [{"url": "http://127.0.0.1:8080/members/", "status_code": 401}],
        "forms": [{"page_url": "http://127.0.0.1:8080/login", "input_count": 2}],
    },
    "findings": [
        {
            "id": "AUTH-BASIC-OVER-HTTP",
            "title": "HTTP Basic Authentication over HTTP",
            "severity": "high",
            "category": "authentication",
            "description": "Credentials may be exposed.",
            "recommendation": "Force HTTPS before authentication.",
            "module": "basic_auth",
            "target": "http://127.0.0.1:8080/members/",
            "evidence": [{"label": "www-authenticate", "value": "Basic realm=\"Member\""}],
        },
        {
            "id": "HEADER-CONTENT_SECURITY_POLICY-MISSING",
            "title": "Content Security Policy is missing",
            "severity": "medium",
            "category": "security-headers",
            "description": "CSP is missing.",
            "recommendation": "Define a CSP.",
            "module": "security_headers",
            "target": "http://127.0.0.1:8080/",
            "evidence": [{"label": "header", "value": "missing"}],
        },
    ],
}


class AssessmentTests(unittest.TestCase):
    def test_build_assessment_prioritizes_high_risk_findings(self):
        assessment = build_assessment(SCAN_DATA)

        self.assertEqual(assessment["summary"]["risk_level"], "high")
        self.assertGreaterEqual(assessment["summary"]["risk_score"], 80)
        self.assertEqual(assessment["summary"]["coverage"]["forms"], 1)
        self.assertEqual(assessment["summary"]["coverage"]["open_ports"], 1)
        self.assertEqual(assessment["priorities"][0]["finding_id"], "AUTH-BASIC-OVER-HTTP")
        self.assertTrue(any(item["finding_id"].startswith("HEADER-") for item in assessment["quick_wins"]))

    def test_render_assessment_console_contains_score(self):
        assessment = build_assessment(SCAN_DATA)

        rendered = render_assessment_console(assessment)

        self.assertIn("Risk: high", rendered)
        self.assertIn("/100", rendered)
        self.assertIn("Priorities:", rendered)


if __name__ == "__main__":
    unittest.main()
