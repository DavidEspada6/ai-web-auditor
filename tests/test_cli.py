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
        answers = iter([""] * 20)

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
        self.assertEqual(config.crawler.max_depth, 1)

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


if __name__ == "__main__":
    unittest.main()
