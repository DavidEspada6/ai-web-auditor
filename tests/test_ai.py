import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.ai.analyzer import analyze_scan_file
from ai_web_auditor.ai.redaction import redact_scan_data, redact_text
from ai_web_auditor.cli import main
from ai_web_auditor.config import AuditConfig


class FakeProvider:
    name = "fake"

    def analyze(self, prompt, *, model=None):
        self.prompt = prompt
        return (
            json.dumps(
                {
                    "executive_summary": "Resumen defensivo.",
                    "risk_level": "medium",
                    "risk_rationale": "Hay hallazgos priorizables.",
                    "priority_findings": [],
                    "safe_next_steps": ["Revisar HTTPS."],
                    "report_notes": [],
                    "limitations": [],
                }
            ),
            {},
        )


class AITests(unittest.TestCase):
    def test_redacts_sensitive_keys_and_query_values(self):
        data = {
            "url": "https://example.com/?token=abc123&public=yes",
            "headers": {
                "Authorization": "Bearer secret",
                "Server": "nginx",
            },
            "cookies": [
                {
                    "name": "sid",
                    "secure": True,
                    "httponly": True,
                }
            ],
        }

        redacted = redact_scan_data(data)

        self.assertEqual(redacted["url"], "https://example.com/?token=[REDACTED]&public=yes")
        self.assertEqual(redacted["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(redacted["headers"]["Server"], "nginx")
        self.assertEqual(redacted["cookies"][0]["name"], "sid")

    def test_redact_text_handles_common_secret_parameters(self):
        self.assertEqual(
            redact_text("https://example.test/?api_key=abc&password=secret"),
            "https://example.test/?api_key=[REDACTED]&password=[REDACTED]",
        )

    def test_analyze_scan_file_with_fake_provider(self):
        provider = FakeProvider()
        config = AuditConfig()

        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({"findings": [], "url": "https://example.test/?token=abc"}), encoding="utf-8")
            result = analyze_scan_file(scan_path, config, provider_name="fake", model="fake-model", provider=provider)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.analysis["risk_level"], "medium")
        self.assertIn("token=[REDACTED]", provider.prompt)
        self.assertNotIn("token=abc", provider.prompt)

    def test_cli_analyze_dry_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            scan_path.write_text(json.dumps({"findings": [], "url": "https://example.test"}), encoding="utf-8")
            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(["analyze", str(scan_path), "--dry-run", "--json"])

        self.assertEqual(exit_code, 0)
        self.assertIn('"status": "dry_run"', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
