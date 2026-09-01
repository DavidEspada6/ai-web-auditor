import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.importers import detect_import_format, import_external_text, merge_external_scan


class ImporterTests(unittest.TestCase):
    def test_zap_json_import_maps_findings_inventory_and_rules(self):
        content = json.dumps(
            {
                "@programName": "OWASP ZAP",
                "site": [
                    {
                        "@name": "http://example.test/",
                        "alerts": [
                            {
                                "pluginid": "10021",
                                "alert": "X-Content-Type-Options Header Missing",
                                "riskdesc": "Medium (Medium)",
                                "confidence": "Medium",
                                "desc": "<p>The header is missing.</p>",
                                "solution": "<p>Set X-Content-Type-Options: nosniff.</p>",
                                "instances": [
                                    {
                                        "uri": "http://example.test/login?token=abc123secret",
                                        "method": "GET",
                                        "param": "token",
                                        "evidence": "missing header",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )

        scan = import_external_text(content, filename="zap-report.json")
        finding_ids = {finding["id"] for finding in scan["findings"]}
        inventory_urls = {item["url"] for item in scan["inventory"]["urls"]}
        rule_ids = {item["rule_id"] for item in scan["rule_evaluation"]["matches"]}

        self.assertEqual(scan["status"], "imported")
        self.assertEqual(scan["external_sources"]["summary"]["source_count"], 1)
        self.assertEqual(scan["external_sources"]["summary"]["tools"], ["zap"])
        self.assertIn("HEADER-NOSNIFF-MISSING", finding_ids)
        self.assertIn("http://example.test/login?token=%5Bredacted%5D", inventory_urls)
        self.assertIn("RULE-FRONTEND-BROWSER-SECURITY-HEADERS", rule_ids)
        self.assertNotIn("abc123secret", json.dumps(scan))

    def test_burp_xml_import_detects_basic_auth_and_cleans_html(self):
        content = """<?xml version="1.0"?>
<issues>
  <issue>
    <serialNumber>1</serialNumber>
    <type>524288</type>
    <name>Basic authentication over HTTP</name>
    <host>http://example.test</host>
    <path>/members/?password=letmein</path>
    <location>http://example.test/members/?password=letmein</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[<p>Credentials may be exposed.</p>]]></issueBackground>
    <remediationBackground><![CDATA[<p>Use HTTPS before authentication.</p>]]></remediationBackground>
  </issue>
</issues>
"""

        scan = import_external_text(content, filename="burp.xml")
        finding = scan["findings"][0]

        self.assertEqual(finding["id"], "AUTH-BASIC-OVER-HTTP")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("Credentials may be exposed.", finding["description"])
        self.assertIn("password=%5Bredacted%5D", finding["target"])
        self.assertNotIn("<p>", json.dumps(scan))
        self.assertNotIn("letmein", json.dumps(scan))

    def test_nmap_xml_import_builds_ports_module(self):
        content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4" />
    <hostnames><hostname name="lab.local" /></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" />
        <service name="ssh" />
      </port>
    </ports>
  </host>
</nmaprun>
"""

        scan = import_external_text(content, filename="nmap.xml", target="http://lab.local/")
        ports_module = next(module for module in scan["modules"] if module["name"] == "ports")

        self.assertEqual(detect_import_format(content, filename="nmap.xml"), "nmap-xml")
        self.assertEqual(scan["external_sources"]["summary"]["open_port_count"], 1)
        self.assertEqual(ports_module["artifacts"]["open_count"], 1)
        self.assertEqual(ports_module["artifacts"]["results"][0]["service"], "http")
        self.assertIn("PORTS-OPEN-TCP-PORTS", {finding["id"] for finding in scan["findings"]})

    def test_merge_external_scan_recomputes_inventory_assessment_and_sources(self):
        base_scan = {
            "tool": "ai-web-auditor",
            "version": "0.21.0",
            "generated_at": "2026-08-30T10:00:00Z",
            "status": "completed",
            "target": {"normalized_url": "https://example.test/", "host": "example.test", "scheme": "https", "port": 443},
            "modules": [],
            "findings": [],
            "requests": [],
        }
        imported = import_external_text(
            "url,severity,finding,description\nhttps://example.test/admin,Medium,Content Security Policy Missing,No CSP\n",
            filename="findings.csv",
            target="https://example.test/",
        )

        merged = merge_external_scan(base_scan, imported)
        enriched = import_external_text(
            "https://example.test/login\n",
            filename="urls.txt",
            target="https://example.test/",
            merge_scan=merged,
        )

        self.assertEqual(enriched["status"], "completed")
        self.assertEqual(enriched["external_sources"]["summary"]["source_count"], 2)
        self.assertGreaterEqual(enriched["inventory"]["summary"]["total_urls"], 2)
        self.assertIn("assessment", enriched)
        self.assertIn("rule_evaluation", enriched)

    def test_cli_import_writes_normalized_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "urls.txt"
            output_path = Path(tmpdir) / "imported.json"
            input_path.write_text("https://example.test/\nhttps://example.test/login\n", encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                exit_code = main(
                    [
                        "import",
                        str(input_path),
                        "--target",
                        "https://example.test/",
                        "--output",
                        str(output_path),
                    ]
                )

            data = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertIn("Imported sources:", stdout.getvalue())
        self.assertEqual(data["external_sources"]["summary"]["url_count"], 2)


if __name__ == "__main__":
    unittest.main()
