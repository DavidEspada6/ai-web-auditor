import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.rules import build_rule_evaluation, render_rules_console


SCAN_DATA = {
    "target": {"scheme": "http", "host": "example.com", "normalized_url": "http://example.com/"},
    "modules": [
        {
            "name": "fingerprinting",
            "status": "passed",
            "summary": "Identified technologies.",
            "artifacts": {
                "technologies": [
                    {"name": "nginx", "version": "1.24.0", "category": "server", "confidence": "high"}
                ],
                "public_files": [{"path": "/robots.txt", "url": "http://example.com/robots.txt", "present": True}],
            },
        },
        {
            "name": "crawler",
            "status": "passed",
            "summary": "Crawled pages.",
            "artifacts": {
                "pages": [
                    {
                        "url": "http://example.com/login",
                        "status_code": 200,
                        "content_type": "text/html",
                        "forms_found": 1,
                        "forms": [
                            {
                                "action": "http://example.com/session",
                                "method": "post",
                                "password_fields": 1,
                                "fields": [{"name": "password", "type": "password"}],
                            }
                        ],
                    }
                ],
                "out_of_scope_urls": ["https://outside.example/"],
            },
        },
        {
            "name": "javascript",
            "status": "passed",
            "summary": "Extracted endpoints.",
            "artifacts": {
                "discovered_endpoints": [
                    {
                        "url": "http://example.com/api/profile?session_id=%5Bredacted%5D",
                        "method": "POST",
                        "parameter_names": ["session_id"],
                        "sensitive_parameter_names": ["session_id"],
                        "route_types": ["api", "account"],
                    }
                ],
                "out_of_scope_endpoints": [{"url": "https://outside.example/collect"}],
            },
        },
        {
            "name": "subdomains",
            "status": "warning",
            "summary": "Resolved one host.",
            "artifacts": {
                "resolved_count": 1,
                "resolved": [{"host": "api.example.com", "ip_addresses": ["192.0.2.10"], "in_scope": True}],
            },
        },
        {
            "name": "ports",
            "status": "warning",
            "summary": "Found open ports.",
            "artifacts": {
                "open_count": 1,
                "results": [{"host": "example.com", "port": 80, "status": "open", "service": "http"}],
            },
        },
    ],
    "findings": [
        {
            "id": "AUTH-BASIC-OVER-HTTP",
            "title": "HTTP Basic Authentication over HTTP",
            "severity": "high",
            "module": "basic_auth",
            "category": "authentication",
            "target": "http://example.com/members/",
            "evidence": [{"label": "www-authenticate", "value": "Basic realm=Member"}],
        },
        {
            "id": "HEADER-CONTENT_SECURITY_POLICY-MISSING",
            "title": "Content Security Policy is missing",
            "severity": "medium",
            "module": "security_headers",
            "category": "security-headers",
            "target": "http://example.com/",
            "evidence": [{"label": "header", "value": "missing"}],
        },
        {
            "id": "CUSTOM-OBSERVATION",
            "title": "Custom observation",
            "severity": "info",
            "module": "custom",
            "category": "unknown",
        },
    ],
}


class PassiveRulesTests(unittest.TestCase):
    def test_build_rule_evaluation_maps_findings_signals_and_frameworks(self):
        evaluation = build_rule_evaluation(SCAN_DATA)
        rule_ids = {item["rule_id"] for item in evaluation["matches"]}
        control_ids = {item["control_id"] for item in evaluation["framework_index"]}
        unmapped = {item["finding_id"] for item in evaluation["unmapped_findings"]}

        self.assertEqual(evaluation["engine"], "passive-rules")
        self.assertIn("RULE-TRANSPORT-ENFORCE-TLS", rule_ids)
        self.assertIn("RULE-FRONTEND-BROWSER-SECURITY-HEADERS", rule_ids)
        self.assertIn("RULE-INFO-ENTRY-POINTS", rule_ids)
        self.assertIn("RULE-INFO-JAVASCRIPT-SURFACE", rule_ids)
        self.assertIn("RULE-INFRA-DISCOVERY-SURFACE", rule_ids)
        self.assertIn("WSTG-CRYP-03", control_ids)
        self.assertIn("WSTG-CONF-12", control_ids)
        self.assertIn("WSTG-INFO-06", control_ids)
        self.assertIn("V3.4", control_ids)
        self.assertIn("CUSTOM-OBSERVATION", unmapped)
        self.assertGreater(evaluation["summary"]["framework_controls_matched"], 0)

    def test_render_rules_console_summarizes_evaluation(self):
        rendered = render_rules_console(build_rule_evaluation(SCAN_DATA))

        self.assertIn("Rules:", rendered)
        self.assertIn("Mapped findings:", rendered)
        self.assertIn("Framework controls:", rendered)

    def test_rules_command_writes_rule_evaluation_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "rules.json"
            scan_path.write_text(json.dumps(SCAN_DATA), encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(["rules", str(scan_path), "--output", str(output)])

            evaluation = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(evaluation["engine"], "passive-rules")
        self.assertIn("Rule evaluation JSON written", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
