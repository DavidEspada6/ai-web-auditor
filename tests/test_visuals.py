import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.visuals import build_visual_evidence, write_visual_evidence


SCAN_DATA = {
    "tool": "ai-web-auditor",
    "version": "0.24.0",
    "generated_at": "2026-09-12T10:00:00Z",
    "status": "completed",
    "target": {
        "normalized_url": "https://example.com/",
        "scheme": "https",
        "host": "example.com",
        "port": 443,
    },
    "auth_profile": {"id": "public", "name": "Publico", "authenticated": False},
    "modules": [
        {
            "name": "fingerprinting",
            "status": "passed",
            "summary": "Identified technology signals.",
            "artifacts": {
                "technologies": [
                    {
                        "name": "nginx",
                        "version": "1.24.0",
                        "category": "server",
                        "confidence": "high",
                        "signals": ["header:server"],
                    },
                    {
                        "name": "<script>alert(1)</script>",
                        "category": "test",
                        "confidence": "low",
                        "signals": ["html"],
                    },
                ],
                "public_files": [{"path": "/robots.txt", "status_code": 200, "present": True}],
            },
        },
        {
            "name": "crawler",
            "status": "passed",
            "summary": "Crawled pages.",
            "artifacts": {"metadata_discovered_urls": ["https://example.com/sitemap.xml"]},
        },
        {
            "name": "javascript",
            "status": "passed",
            "summary": "Analyzed scripts.",
            "artifacts": {"discovered_endpoints": [{"url": "https://example.com/api/profile"}]},
        },
        {
            "name": "ports",
            "status": "warning",
            "summary": "Checked ports.",
            "artifacts": {"open_count": 1},
        },
    ],
    "findings": [{"id": "HEADER-CSP-MISSING", "severity": "medium", "title": "CSP missing"}],
    "inventory": {"summary": {"total_urls": 4, "fetched_urls": 2, "interesting_urls": 1, "forms": 1}},
    "entry_points": {"summary": {"total_endpoints": 2, "parameters": 3}},
    "rule_evaluation": {"summary": {"rules_matched": 2, "framework_controls_matched": 3}},
    "assessment": {"summary": {"risk_level": "medium", "risk_score": 35, "coverage": {"modules_run": 4}}},
}


class VisualEvidenceTests(unittest.TestCase):
    def test_build_visual_evidence_generates_expected_snapshots(self):
        visual = build_visual_evidence(SCAN_DATA)

        self.assertEqual(visual["summary"]["screenshot_count"], 3)
        self.assertEqual(visual["fingerprint"]["risk"]["level"], "medium")
        self.assertEqual(visual["fingerprint"]["surface"]["urls"], 4)
        self.assertEqual(visual["fingerprint"]["surface"]["open_ports"], 1)
        self.assertEqual(visual["fingerprint"]["technologies"][0]["label"], "nginx 1.24.0")
        self.assertEqual([item["filename"] for item in visual["screenshots"]], [
            "visuals/audit-overview.svg",
            "visuals/fingerprint-map.svg",
            "visuals/coverage-matrix.svg",
        ])
        for screenshot in visual["screenshots"]:
            self.assertTrue(screenshot["svg"].startswith("<svg"))
            self.assertIn("</svg>", screenshot["svg"])

    def test_visual_svg_escapes_untrusted_text(self):
        visual = build_visual_evidence(SCAN_DATA)
        svg = "\n".join(screenshot["svg"] for screenshot in visual["screenshots"])

        self.assertNotIn("<script>alert(1)</script>", svg)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", svg)

    def test_write_visual_evidence_writes_json_and_svg_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "visual-evidence.json"
            svg_dir = Path(tmpdir) / "svg"
            visual = build_visual_evidence(SCAN_DATA)

            write_visual_evidence(visual, output, svg_dir=svg_dir)

            written = json.loads(output.read_text(encoding="utf-8"))
            svg_files = sorted(path.name for path in svg_dir.glob("*.svg"))

        self.assertEqual(written["summary"]["screenshot_count"], 3)
        self.assertEqual(svg_files, ["audit-overview.svg", "coverage-matrix.svg", "fingerprint-map.svg"])

    def test_visuals_cli_writes_json_and_svg_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            output = Path(tmpdir) / "visual-evidence.json"
            svg_dir = Path(tmpdir) / "svg"
            scan_path.write_text(json.dumps(SCAN_DATA), encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(["visuals", str(scan_path), "--output", str(output), "--svg-dir", str(svg_dir)])

            svg_files = sorted(path.name for path in svg_dir.glob("*.svg"))

        self.assertEqual(exit_code, 0)
        self.assertIn("Visual evidence JSON written", stdout.getvalue())
        self.assertEqual(svg_files, ["audit-overview.svg", "coverage-matrix.svg", "fingerprint-map.svg"])


if __name__ == "__main__":
    unittest.main()
