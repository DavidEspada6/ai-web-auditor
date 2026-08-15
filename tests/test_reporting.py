import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.reporting import generate_markdown_report


SCAN_DATA = {
    "tool": "ai-web-auditor",
    "version": "0.6.0",
    "generated_at": "2026-08-16T00:00:00Z",
    "status": "completed",
    "target": {
        "original_url": "https://example.com",
        "normalized_url": "https://example.com/",
        "scheme": "https",
        "host": "example.com",
        "port": 443,
    },
    "modules": [
        {
            "name": "fingerprinting",
            "status": "passed",
            "summary": "Identified 2 technology signal(s).",
            "artifacts": {
                "technologies": [
                    {
                        "name": "nginx",
                        "category": "server",
                        "confidence": "high",
                        "signals": ["header:server"],
                        "version": "1.24.0",
                    }
                ],
                "public_files": [
                    {
                        "path": "/robots.txt",
                        "status_code": 200,
                        "present": True,
                    }
                ],
            },
        },
        {
            "name": "crawler",
            "status": "passed",
            "summary": "Crawled 2 page(s).",
            "artifacts": {
                "seed_url": "https://example.com/",
                "max_depth": 1,
                "max_pages": 25,
                "fetched_urls": ["https://example.com/"],
                "discovered_urls": ["https://example.com/", "https://example.com/about"],
                "out_of_scope_urls": ["https://outside.example/"],
                "excluded_urls": ["https://example.com/admin"],
            },
        },
    ],
    "findings": [
        {
            "id": "HEADER-CSP-MISSING",
            "title": "Content Security Policy is missing",
            "severity": "medium",
            "category": "security-headers",
            "description": "The response does not include a CSP header.",
            "recommendation": "Define a CSP.",
            "module": "security_headers",
            "target": "https://example.com/",
            "evidence": [{"label": "header", "value": "missing"}],
        }
    ],
}


AI_DATA = {
    "analysis": {
        "executive_summary": "AI summary.",
        "risk_level": "medium",
        "risk_rationale": "One medium finding.",
        "priority_findings": [
            {
                "rank": 1,
                "severity": "medium",
                "title": "Prioritized CSP",
                "why_it_matters": "Browser-side hardening matters.",
                "evidence": ["HEADER-CSP-MISSING"],
                "recommended_action": "Add CSP.",
            }
        ],
        "safe_next_steps": ["Validate CSP in report-only mode."],
        "report_notes": ["AI notes are based on JSON evidence."],
        "limitations": ["No authenticated testing."],
    }
}


class ReportingTests(unittest.TestCase):
    def test_generate_markdown_report_includes_core_sections(self):
        markdown = generate_markdown_report(SCAN_DATA, ai_analysis=AI_DATA, title="Demo Report")

        self.assertIn("# Demo Report", markdown)
        self.assertIn("## Executive Summary", markdown)
        self.assertIn("AI summary.", markdown)
        self.assertIn("## Findings", markdown)
        self.assertIn("HEADER-CSP-MISSING", markdown)
        self.assertIn("## Technology Fingerprinting", markdown)
        self.assertIn("nginx 1.24.0", markdown)
        self.assertIn("## Crawler", markdown)
        self.assertIn("https://example.com/about", markdown)
        self.assertIn("## AI Prioritization", markdown)

    def test_cli_report_writes_markdown_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            ai_path = Path(tmpdir) / "analysis.json"
            output_path = Path(tmpdir) / "report.md"
            scan_path.write_text(json.dumps(SCAN_DATA), encoding="utf-8")
            ai_path.write_text(json.dumps(AI_DATA), encoding="utf-8")

            with redirect_stdout(StringIO()):
                exit_code = main(
                    [
                        "report",
                        str(scan_path),
                        "--ai-analysis",
                        str(ai_path),
                        "--output",
                        str(output_path),
                    ]
                )

            markdown = output_path.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertIn("Web Audit Report - example.com", markdown)
        self.assertIn("AI summary.", markdown)


if __name__ == "__main__":
    unittest.main()
