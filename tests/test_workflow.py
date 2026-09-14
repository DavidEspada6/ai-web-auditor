import json
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.auth import upsert_auth_profile
from ai_web_auditor.engine import run_scan
from ai_web_auditor.evidence import build_evidence_package
from ai_web_auditor.history import save_scan_history, load_scan_reference
from ai_web_auditor.lab import lab_scan_defaults, start_lab_server
from ai_web_auditor.presets import apply_preset
from ai_web_auditor.reporting import generate_html_report, generate_markdown_report, generate_pdf_report
from ai_web_auditor.role_compare import compare_role_scans
from ai_web_auditor.web.server import build_config_from_gui_payload


class WorkflowTests(unittest.TestCase):
    def test_local_lab_to_history_role_comparison_and_deliverables(self):
        lab = start_lab_server(port=0)
        try:
            config = apply_preset(build_config_from_gui_payload(lab_scan_defaults(lab.status())), "standard")
            config.crawler.delay_seconds = 0
            public = run_scan(lab.target_url, config).to_dict()
            upsert_auth_profile(config, profile_id="member", headers={"X-Lab-Role": "member", "Authorization": "Bearer workflow-secret"})
            member = run_scan(lab.target_url, config).to_dict()
        finally:
            lab.stop()

        self.assertEqual(public["status"], "completed")
        self.assertEqual(member["status"], "completed")
        self.assertIn("AUTH-BASIC-OVER-HTTP", [finding["id"] for finding in public["findings"]])
        self.assertGreater(public["inventory"]["summary"]["forms"], 0)
        self.assertGreater(public["inventory"]["summary"]["javascript_endpoints"], 0)
        self.assertEqual(public["execution"]["crawler"]["max_pages"], 25)
        self.assertNotIn("ports", public["execution"]["modules"])
        self.assertTrue(all(request["method"] in ("GET", "HEAD", "OPTIONS") for request in member["requests"]))
        self.assertNotIn("workflow-secret", json.dumps(member))

        with tempfile.TemporaryDirectory() as tmp:
            entry = save_scan_history(member, history_dir=Path(tmp), label="v026-regression")
            loaded = load_scan_reference(entry.id, history_dir=Path(tmp))
            self.assertEqual(loaded["execution"], member["execution"])
            comparison = compare_role_scans(public, loaded)
            self.assertGreater(comparison["summary"]["status_code_changes"], 0)
            self.assertTrue(any(item["baseline_status"] == 401 and item["current_status"] == 200
                                for item in comparison["status_code_changes"]))
            self.assertIn("<html", generate_html_report(loaded))
            self.assertIn("#", generate_markdown_report(loaded))
            self.assertTrue(generate_pdf_report(loaded).startswith(b"%PDF"))
            with ZipFile(BytesIO(build_evidence_package(loaded))) as archive:
                self.assertIsNone(archive.testzip())
                self.assertIn("dashboard/dashboard.json", archive.namelist())
                self.assertIn("rules/rule-evaluation.json", archive.namelist())
                snapshot = json.loads(archive.read("scan-result.json"))
                self.assertEqual(snapshot["execution"], member["execution"])


if __name__ == "__main__":
    unittest.main()
