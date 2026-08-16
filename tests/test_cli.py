import sys
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.config import AuditConfig


class CliTests(unittest.TestCase):
    def test_init_scope_writes_config_with_defaults(self):
        answers = iter([""] * 30)

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "audit.json"
            with patch("builtins.input", side_effect=lambda *_args: next(answers)):
                with redirect_stdout(StringIO()):
                    exit_code = main(["init-scope", "https://example.com", "--output", str(output)])

            config = AuditConfig.load(output)

        self.assertEqual(exit_code, 0)
        self.assertEqual(config.target.url, "https://example.com/")
        self.assertEqual(config.scope.allowed_hosts, ["example.com"])
        self.assertTrue(config.modules.fingerprinting)
        self.assertTrue(config.modules.crawler)
        self.assertFalse(config.modules.subdomains)
        self.assertFalse(config.modules.ports)
        self.assertEqual(config.crawler.max_depth, 1)
        self.assertEqual(config.subdomains.max_candidates, 25)
        self.assertEqual(config.subdomains.timeout_seconds, 2.0)
        self.assertEqual(config.ports.ports, [80, 443, 8080, 8443, 8000, 3000, 5000, 9000])
        self.assertEqual(config.ports.max_ports, 20)
        self.assertEqual(config.ports.timeout_seconds, 1.0)

    def test_inventory_command_writes_csv(self):
        scan_data = {
            "target": {"normalized_url": "https://example.com/", "host": "example.com"},
            "modules": [
                {
                    "name": "crawler",
                    "artifacts": {
                        "pages": [
                            {
                                "url": "https://example.com/",
                                "status_code": 200,
                                "content_type": "text/html",
                                "links_found": 1,
                                "forms_found": 0,
                            }
                        ],
                        "discovered_urls": ["https://example.com/login"],
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "inventory.csv"
            scan_path.write_text(json.dumps(scan_data), encoding="utf-8")

            with redirect_stdout(StringIO()):
                exit_code = main(["inventory", str(scan_path), "--output", str(output)])

            content = output.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertIn("url,status_code,content_type", content)
        self.assertIn("https://example.com/login", content)

    def test_assess_command_writes_assessment_json(self):
        scan_data = {
            "target": {"scheme": "http", "host": "example.com", "normalized_url": "http://example.com/"},
            "modules": [{"name": "basic_auth", "status": "warning", "summary": "Basic Auth detected."}],
            "findings": [
                {
                    "id": "AUTH-BASIC-OVER-HTTP",
                    "title": "HTTP Basic Authentication over HTTP",
                    "severity": "high",
                    "category": "authentication",
                    "description": "Credentials may be exposed.",
                    "recommendation": "Force HTTPS before authentication.",
                    "module": "basic_auth",
                    "target": "http://example.com/",
                    "evidence": [],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "assessment.json"
            scan_path.write_text(json.dumps(scan_data), encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(["assess", str(scan_path), "--output", str(output)])

            assessment = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(assessment["summary"]["risk_level"], "high")
        self.assertEqual(assessment["priorities"][0]["finding_id"], "AUTH-BASIC-OVER-HTTP")
        self.assertIn("Assessment JSON written", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
