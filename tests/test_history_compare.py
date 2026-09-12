import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.compare import compare_scans
from ai_web_auditor.history import list_history, load_scan_reference, save_analysis_for_history, save_scan_history


BASELINE_SCAN = {
    "tool": "ai-web-auditor",
    "version": "0.14.0",
    "generated_at": "2026-08-16T00:00:00Z",
    "status": "completed",
    "target": {"normalized_url": "https://example.com/", "host": "example.com"},
    "findings": [
        {
            "id": "HEADER-CSP-MISSING",
            "title": "CSP missing",
            "severity": "medium",
            "module": "security_headers",
            "target": "https://example.com/",
        },
        {
            "id": "COOKIE-HTTPONLY-MISSING",
            "title": "HttpOnly missing",
            "severity": "low",
            "module": "cookies",
            "target": "https://example.com/",
        },
    ],
}


CURRENT_SCAN = {
    "tool": "ai-web-auditor",
    "version": "0.14.0",
    "generated_at": "2026-08-16T01:00:00Z",
    "status": "completed",
    "target": {"normalized_url": "https://example.com/", "host": "example.com"},
    "findings": [
        {
            "id": "HEADER-CSP-MISSING",
            "title": "CSP missing",
            "severity": "high",
            "module": "security_headers",
            "target": "https://example.com/",
        },
        {
            "id": "HEADER-HSTS-MISSING",
            "title": "HSTS missing",
            "severity": "medium",
            "module": "security_headers",
            "target": "https://example.com/",
        },
    ],
}


class HistoryCompareTests(unittest.TestCase):
    def test_save_list_and_load_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            history_dir = Path(tmpdir)
            entry = save_scan_history(BASELINE_SCAN, history_dir=history_dir, label="demo")
            entries = list_history(history_dir)
            loaded = load_scan_reference(entry.id, history_dir=history_dir)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].id, entry.id)
        self.assertEqual(entries[0].host, "example.com")
        self.assertEqual(entries[0].finding_count, 2)
        self.assertEqual(loaded["target"]["host"], "example.com")
        self.assertEqual(loaded["_history"]["label"], "demo")

    def test_save_analysis_for_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            history_dir = Path(tmpdir)
            entry = save_scan_history(BASELINE_SCAN, history_dir=history_dir, label="demo")
            updated = save_analysis_for_history(
                entry.id,
                {"status": "completed", "analysis": {"risk_level": "medium"}},
                history_dir=history_dir,
            )
            entries = list_history(history_dir)

        self.assertEqual(updated["ai_analysis"]["analysis"]["risk_level"], "medium")
        self.assertTrue(entries[0].has_ai_analysis)

    def test_compare_scans_detects_changes(self):
        comparison = compare_scans(BASELINE_SCAN, CURRENT_SCAN)

        self.assertEqual(comparison["summary"]["new"], 1)
        self.assertEqual(comparison["summary"]["resolved"], 1)
        self.assertEqual(comparison["summary"]["persistent"], 1)
        self.assertEqual(comparison["summary"]["severity_changed"], 1)
        self.assertEqual(comparison["new_findings"][0]["id"], "HEADER-HSTS-MISSING")
        self.assertEqual(comparison["resolved_findings"][0]["id"], "COOKIE-HTTPONLY-MISSING")

    def test_cli_compare_outputs_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "baseline.json"
            current = Path(tmpdir) / "current.json"
            output = Path(tmpdir) / "comparison.json"
            baseline.write_text(json.dumps(BASELINE_SCAN), encoding="utf-8")
            current.write_text(json.dumps(CURRENT_SCAN), encoding="utf-8")

            with redirect_stdout(StringIO()):
                exit_code = main(["compare", str(baseline), str(current), "--json-output", str(output)])

            comparison = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(comparison["summary"]["new"], 1)

    def test_cli_role_compare_outputs_json(self):
        public_scan = {
            "target": {"normalized_url": "http://127.0.0.1:8080/members/", "host": "127.0.0.1"},
            "auth_profile": {"id": "public", "name": "Publico", "authenticated": False},
            "inventory": {"urls": [{"url": "http://127.0.0.1:8080/members/", "status_code": 401}]},
            "entry_points": {"endpoints": [{"url": "http://127.0.0.1:8080/members/", "methods": ["GET"]}]},
            "assessment": {"summary": {"risk_score": 70}},
        }
        member_scan = {
            "target": {"normalized_url": "http://127.0.0.1:8080/members/", "host": "127.0.0.1"},
            "auth_profile": {"id": "member", "name": "Usuario demo", "authenticated": True},
            "inventory": {
                "urls": [
                    {"url": "http://127.0.0.1:8080/members/", "status_code": 200},
                    {"url": "http://127.0.0.1:8080/account", "status_code": 200},
                ]
            },
            "entry_points": {
                "endpoints": [
                    {"url": "http://127.0.0.1:8080/members/", "methods": ["GET"]},
                    {"url": "http://127.0.0.1:8080/account", "methods": ["GET"]},
                ]
            },
            "assessment": {"summary": {"risk_score": 76}},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = Path(tmpdir) / "public.json"
            current = Path(tmpdir) / "member.json"
            output = Path(tmpdir) / "role-comparison.json"
            baseline.write_text(json.dumps(public_scan), encoding="utf-8")
            current.write_text(json.dumps(member_scan), encoding="utf-8")

            with redirect_stdout(StringIO()):
                exit_code = main(["role-compare", str(baseline), str(current), "--json-output", str(output)])

            comparison = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(comparison["summary"]["new_urls"], 1)
        self.assertEqual(comparison["summary"]["new_entry_points"], 1)


if __name__ == "__main__":
    unittest.main()
