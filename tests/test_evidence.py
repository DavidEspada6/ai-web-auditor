import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO, StringIO
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan
from ai_web_auditor.evidence import build_evidence_package


class SensitiveEvidenceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sessionid=super-secret; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(b"<html><body>token=abc123secret password=hunter2 sessionid=rawsession</body></html>")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, *args):
        return


class EvidenceTests(unittest.TestCase):
    def test_http_evidence_capture_redacts_sensitive_values(self):
        server = HTTPServer(("127.0.0.1", 0), SensitiveEvidenceHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        config = AuditConfig()
        config.scope.allow_private_networks = True
        config.scope.resolve_dns = False
        config.modules.crawler = False

        result = run_scan(f"http://127.0.0.1:{server.server_port}/?token=abc123secret", config)
        data = result.to_dict()
        first_request = data["requests"][0]
        body_capture = next(
            request["response_body"]
            for request in data["requests"]
            if request.get("response_body", {}).get("captured") is True
        )

        self.assertIn("token=%5Bredacted%5D", first_request["url"])
        self.assertNotIn("abc123secret", json.dumps(data))
        self.assertNotIn("rawsession", json.dumps(data))
        self.assertNotIn("super-secret", json.dumps(data))
        self.assertIn("sessionid=[redacted]", json.dumps(first_request["response_headers"]))
        self.assertIn("[redacted]", body_capture["sample"])
        self.assertLessEqual(body_capture["sample_chars"], config.evidence.max_body_chars)

    def test_evidence_package_contains_manifest_and_requests(self):
        scan_data = {
            "tool": "ai-web-auditor",
            "version": "0.19.0",
            "generated_at": "2026-08-27T10:00:00Z",
            "status": "completed",
            "target": {"normalized_url": "https://example.com/", "host": "example.com"},
            "modules": [
                {"name": "http", "status": "passed", "summary": "ok"},
                {
                    "name": "javascript",
                    "status": "passed",
                    "summary": "ok",
                    "artifacts": {
                        "discovered_endpoints": [
                            {"url": "https://example.com/api/profile?session_id=%5Bredacted%5D", "method": "POST"}
                        ]
                    },
                },
            ],
            "findings": [{"id": "TEST", "severity": "info"}],
            "requests": [
                {
                    "id": "req-0001",
                    "method": "GET",
                    "url": "https://example.com/",
                    "status_code": 200,
                    "elapsed_ms": 10,
                    "response_body": {"captured": False, "reason": "empty"},
                }
            ],
            "inventory": {"summary": {"total_urls": 1}, "urls": []},
            "entry_points": {"summary": {"total_endpoints": 1}, "endpoints": [{"id": "ep_1", "url": "https://example.com/"}]},
            "assessment": {"summary": {"risk_level": "informational"}},
            "external_sources": {
                "summary": {"source_count": 1, "finding_count": 1, "url_count": 1, "port_count": 0, "open_port_count": 0},
                "sources": [
                    {
                        "filename": "zap-report.json",
                        "source_format": "zap-json",
                        "source_tool": "zap",
                        "finding_count": 1,
                        "url_count": 1,
                        "port_count": 0,
                        "open_port_count": 0,
                    }
                ],
            },
        }

        package = build_evidence_package(scan_data)
        with ZipFile(BytesIO(package)) as archive:
            names = set(archive.namelist())
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            request = json.loads(archive.read("http/req-0001.json").decode("utf-8"))

        self.assertIn("scan-result.json", names)
        self.assertIn("http/requests.json", names)
        self.assertIn("findings/findings.json", names)
        self.assertIn("dashboard/dashboard.json", names)
        self.assertIn("visuals/visual-evidence.json", names)
        self.assertIn("visuals/audit-overview.svg", names)
        self.assertIn("visuals/fingerprint-map.svg", names)
        self.assertIn("visuals/coverage-matrix.svg", names)
        self.assertIn("entry-points/entry-points.json", names)
        self.assertIn("javascript/javascript.json", names)
        self.assertIn("javascript/endpoints.json", names)
        self.assertIn("rules/rule-evaluation.json", names)
        self.assertIn("rules/matches.json", names)
        self.assertIn("external/external-sources.json", names)
        self.assertIn("external/sources.json", names)
        self.assertEqual(manifest["counts"]["requests"], 1)
        self.assertEqual(manifest["counts"]["entry_points"], 1)
        self.assertEqual(manifest["counts"]["javascript_endpoints"], 1)
        self.assertGreaterEqual(manifest["counts"]["rules_matched"], 1)
        self.assertGreaterEqual(manifest["counts"]["framework_controls_matched"], 1)
        self.assertEqual(manifest["counts"]["external_sources"], 1)
        self.assertEqual(manifest["counts"]["external_findings"], 1)
        self.assertGreaterEqual(manifest["counts"]["dashboard_pending_items"], 1)
        self.assertGreaterEqual(manifest["counts"]["dashboard_checklist_items"], 1)
        self.assertEqual(manifest["counts"]["visual_snapshots"], 3)
        self.assertTrue(manifest["safety"]["sanitized"])
        self.assertEqual(request["id"], "req-0001")

    def test_evidence_cli_writes_zip(self):
        scan_data = {
            "version": "0.19.0",
            "generated_at": "2026-08-27T10:00:00Z",
            "target": {"normalized_url": "https://example.com/", "host": "example.com"},
            "modules": [],
            "findings": [],
            "requests": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "evidence.zip"
            scan_path.write_text(json.dumps(scan_data), encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(["evidence", str(scan_path), "--output", str(output)])

            with ZipFile(output) as archive:
                names = set(archive.namelist())

        self.assertEqual(exit_code, 0)
        self.assertIn("Evidence package written", stdout.getvalue())
        self.assertIn("manifest.json", names)

    def test_scan_command_can_write_evidence_package(self):
        server = HTTPServer(("127.0.0.1", 0), SensitiveEvidenceHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        with tempfile.TemporaryDirectory() as tmpdir:
            evidence_output = Path(tmpdir) / "scan-evidence.zip"
            json_output = Path(tmpdir) / "scan.json"
            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(
                    [
                        "scan",
                        f"http://127.0.0.1:{server.server_port}/",
                        "--allow-private",
                        "--json-output",
                        str(json_output),
                        "--evidence-output",
                        str(evidence_output),
                    ]
                )

            with ZipFile(evidence_output) as archive:
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            json_exists = json_output.exists()

        self.assertEqual(exit_code, 0)
        self.assertTrue(json_exists)
        self.assertIn("Evidence package written", stdout.getvalue())
        self.assertGreaterEqual(manifest["counts"]["requests"], 1)


if __name__ == "__main__":
    unittest.main()
