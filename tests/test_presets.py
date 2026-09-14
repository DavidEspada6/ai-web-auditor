import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.auth import upsert_auth_profile
from ai_web_auditor.cli import main
from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan
from ai_web_auditor.errors import ScopeError
from ai_web_auditor.planning import build_scan_plan
from ai_web_auditor.presets import PRESET_NAMES, apply_preset, list_presets
from ai_web_auditor.web.server import build_config_from_gui_payload


class PresetTests(unittest.TestCase):
    def test_presets_preserve_scope_auth_and_independent_values(self):
        config = AuditConfig()
        config.target.url = "https://example.test/team"
        config.scope.allowed_hosts = ["example.test"]
        config.scope.include_paths = ["/team"]
        config.scope.exclude_paths = ["/team/private"]
        config.scope.allow_subdomains = False
        config.ports.ports = [443, 8443]
        config.modules.ports = True
        config.modules.subdomains = True
        config.crawler.well_known_paths = ["/.well-known/custom"]
        upsert_auth_profile(config, profile_id="employee", headers={"Authorization": "Bearer private-value"})
        original = config.to_dict()
        for name in PRESET_NAMES:
            with self.subTest(preset=name):
                result = apply_preset(config, name)
                result.validate()
                for section in ("target", "scope", "auth", "ports", "ai", "evidence"):
                    self.assertEqual(result.to_dict()[section], original[section])
                self.assertFalse(result.modules.ports)
                self.assertFalse(result.modules.subdomains)
                self.assertEqual(result.crawler.well_known_paths, ["/.well-known/custom"])
                result.scope.allowed_hosts.append("other.test")
                self.assertEqual(config.to_dict(), original)

    def test_catalog_is_independent_and_unknown_preset_fails(self):
        list_presets()[0]["settings"]["modules"]["ports"] = True
        self.assertFalse(list_presets()[0]["settings"]["modules"]["ports"])
        with self.assertRaisesRegex(ValueError, "Unknown audit preset"):
            apply_preset(AuditConfig(), "unknown")

    def test_dry_run_no_network_or_outputs_and_config_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.json"
            output = Path(tmp) / "must-not-be-created.json"
            config = AuditConfig()
            config.target.url = "https://example.test/"
            config.modules.ports = True
            config.write_json(path)
            with patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS")), \
                 patch("socket.create_connection", side_effect=AssertionError("Unexpected TCP")), \
                 patch("ai_web_auditor.cli.run_scan", side_effect=AssertionError("Unexpected scan")), \
                 redirect_stdout(StringIO()) as stdout:
                code = main(["scan", "--config", str(path), "--preset", "quick", "--dry-run", "-o", str(output)])
            plan = json.loads(stdout.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(plan["validation"], "offline")
            self.assertNotIn("crawler", plan["modules"])
            self.assertNotIn("ports", plan["modules"])
            self.assertFalse(output.exists())
            self.assertTrue(AuditConfig.load(path).modules.ports)

    def test_scope_rejected_without_network_even_when_scope_module_disabled(self):
        config = AuditConfig()
        config.modules.scope = False
        config.scope.allowed_hosts = ["example.test"]
        config.scope.exclude_paths = ["/private"]
        with patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS")):
            for url in ("https://outside.test/", "https://example.test/private", "http://127.0.0.1/"):
                with self.subTest(url=url), self.assertRaises(ScopeError):
                    build_scan_plan(url, config)

    def test_plan_redacts_secrets_and_rejects_unknown_auth_profile(self):
        config = AuditConfig()
        upsert_auth_profile(config, profile_id="member", headers={"Authorization": "Bearer secret-123"}, cookies={"session": "hidden-456"})
        text = json.dumps(build_scan_plan("https://example.test/?token=url-secret", config))
        for secret in ("secret-123", "hidden-456", "url-secret"):
            self.assertNotIn(secret, text)
        config.auth.active_profile = "missing"
        with self.assertRaisesRegex(ValueError, "unknown profile"):
            build_scan_plan("https://example.test/", config)

    def test_invalid_config_fails_before_network(self):
        for section, field, value in [
            ("http", "timeout_seconds", float("nan")),
            ("ports", "timeout_seconds", float("inf")),
            ("ports", "timeout_seconds", 0.1),
            ("crawler", "max_pages", 2.5),
            ("crawler", "delay_seconds", -1),
            ("modules", "ports", "false"),
            ("scope", "allow_private_networks", "false"),
            ("scope", "allowed_hosts", "example.test"),
            ("ports", "ports", [True]),
        ]:
            with self.subTest(field=f"{section}.{field}", value=value):
                config = AuditConfig()
                setattr(getattr(config, section), field, value)
                with patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS")), self.assertRaises(ValueError):
                    run_scan("https://example.test/", config)

    def test_malformed_config_section_is_readable_cli_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('{"scope": null}', encoding="utf-8")
            with redirect_stderr(StringIO()) as stderr:
                code = main(["scan", "https://example.test/", "--config", str(path), "--dry-run"])
            self.assertEqual(code, 2)
            self.assertIn("scope: expected a configuration object", stderr.getvalue())

    def test_gui_decimal_comma_and_nonfinite_numbers(self):
        config = build_config_from_gui_payload({"ports": {"timeout_seconds": "0,5"}})
        self.assertEqual(config.ports.timeout_seconds, 0.5)
        for value in ("NaN", "Infinity", "-Infinity", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_config_from_gui_payload({"ports": {"timeout_seconds": value}})
        for value in (1.5, float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_config_from_gui_payload({"crawler": {"max_pages": value}})

    def test_preset_questionnaire_uses_preset_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.json"
            with patch("builtins.input", return_value=""), redirect_stdout(StringIO()):
                self.assertEqual(main(["init-scope", "https://example.test", "--preset", "quick", "-o", str(path)]), 0)
            config = AuditConfig.load(path)
            self.assertFalse(config.modules.crawler)
            self.assertFalse(config.modules.javascript)
            self.assertEqual(config.crawler.max_pages, 5)


if __name__ == "__main__":
    unittest.main()
