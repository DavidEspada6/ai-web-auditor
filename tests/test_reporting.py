import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.reporting import generate_html_report, generate_markdown_report, generate_pdf_report


SCAN_DATA = {
    "tool": "ai-web-auditor",
    "version": "0.15.0",
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
        {
            "name": "subdomains",
            "status": "warning",
            "summary": "Checked 2 candidate subdomain(s), resolved 1 in-scope host(s).",
            "artifacts": {
                "root_domains": ["example.com"],
                "candidate_count": 2,
                "resolved_count": 1,
                "unresolved_count": 1,
                "out_of_scope_count": 0,
                "out_of_scope": [],
                "resolved": [
                    {
                        "host": "api.example.com",
                        "ip_addresses": ["93.184.216.35"],
                        "source": "dns_candidate",
                        "in_scope": True,
                    }
                ],
            },
        },
        {
            "name": "ports",
            "status": "warning",
            "summary": "Checked 3 TCP port(s), found 1 open port(s).",
            "artifacts": {
                "host": "example.com",
                "ports_checked": [80, 443, 8080],
                "open_count": 1,
                "closed_count": 1,
                "filtered_count": 1,
                "error_count": 0,
                "results": [
                    {"host": "example.com", "port": 80, "status": "open", "service": "http", "elapsed_ms": 1},
                    {"host": "example.com", "port": 443, "status": "closed", "service": "https", "elapsed_ms": 1},
                    {"host": "example.com", "port": 8080, "status": "filtered", "service": "http-alt", "elapsed_ms": 200},
                ],
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
        markdown = generate_markdown_report(
            SCAN_DATA,
            ai_analysis=AI_DATA,
            title="Demo Report",
            metadata={"client": "Client A", "auditor": "Auditor B"},
        )

        self.assertIn("# Demo Report", markdown)
        self.assertIn("## Engagement", markdown)
        self.assertIn("Client A", markdown)
        self.assertIn("## Executive Summary", markdown)
        self.assertIn("AI summary.", markdown)
        self.assertIn("## Risk Assessment", markdown)
        self.assertIn("### Remediation Plan", markdown)
        self.assertIn("## Findings", markdown)
        self.assertIn("HEADER-CSP-MISSING", markdown)
        self.assertIn("## Technology Fingerprinting", markdown)
        self.assertIn("nginx 1.24.0", markdown)
        self.assertIn("## Crawler", markdown)
        self.assertIn("https://example.com/about", markdown)
        self.assertIn("## Web Inventory", markdown)
        self.assertIn("https://example.com/admin", markdown)
        self.assertIn("## Subdomain Discovery", markdown)
        self.assertIn("api.example.com", markdown)
        self.assertIn("## TCP Port Check", markdown)
        self.assertIn("| 80 | http | open | 1 ms |", markdown)
        self.assertIn("## AI Prioritization", markdown)

    def test_generate_html_report_escapes_content_and_includes_metadata(self):
        data = json.loads(json.dumps(SCAN_DATA))
        data["findings"][0]["title"] = "<script>alert(1)</script>"

        html = generate_html_report(
            data,
            ai_analysis=AI_DATA,
            title="HTML Report",
            metadata={"client": "Client A", "scope_summary": "Public web"},
        )

        self.assertIn("<!doctype html>", html)
        self.assertIn("HTML Report", html)
        self.assertIn("Client A", html)
        self.assertIn("Public web", html)
        self.assertIn("Risk Assessment", html)
        self.assertIn("Remediation Plan", html)
        self.assertIn("Web Inventory", html)
        self.assertIn("Subdomain Discovery", html)
        self.assertIn("TCP Port Check", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_generate_pdf_report_returns_pdf_bytes(self):
        pdf = generate_pdf_report(SCAN_DATA, ai_analysis=AI_DATA, title="PDF Report")

        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", pdf)

    def test_embedded_ai_analysis_is_used_by_report(self):
        data = json.loads(json.dumps(SCAN_DATA))
        data["ai_analysis"] = AI_DATA

        markdown = generate_markdown_report(data)

        self.assertIn("AI summary.", markdown)
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

    def test_cli_report_writes_html_and_pdf_by_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_path = Path(tmpdir) / "scan.json"
            html_path = Path(tmpdir) / "report.html"
            pdf_path = Path(tmpdir) / "report.pdf"
            scan_path.write_text(json.dumps(SCAN_DATA), encoding="utf-8")

            with redirect_stdout(StringIO()):
                html_exit = main(
                    [
                        "report",
                        str(scan_path),
                        "--output",
                        str(html_path),
                        "--client",
                        "Client A",
                    ]
                )
                pdf_exit = main(["report", str(scan_path), "--output", str(pdf_path), "--format", "pdf"])

            html = html_path.read_text(encoding="utf-8")
            pdf = pdf_path.read_bytes()

        self.assertEqual(html_exit, 0)
        self.assertEqual(pdf_exit, 0)
        self.assertIn("<!doctype html>", html)
        self.assertIn("Client A", html)
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
