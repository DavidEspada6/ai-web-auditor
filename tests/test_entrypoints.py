import csv
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.entrypoints import build_entry_points_from_scan, entry_points_to_csv


class EntryPointTests(unittest.TestCase):
    def test_build_entry_points_from_inventory_forms_and_methods(self):
        scan_data = {
            "target": {
                "normalized_url": "https://example.com/search?q=test&token=abc",
                "host": "example.com",
                "scheme": "https",
            },
            "modules": [
                {
                    "name": "http_methods",
                    "artifacts": {"methods": ["GET", "POST", "OPTIONS"]},
                },
                {
                    "name": "crawler",
                    "artifacts": {
                        "pages": [
                            {
                                "url": "https://example.com/login",
                                "status_code": 200,
                                "content_type": "text/html",
                                "links_found": 1,
                                "forms_found": 1,
                                "forms": [
                                    {
                                        "action": "https://example.com/session?next=/account",
                                        "method": "post",
                                        "fields": [
                                            {"name": "csrf_token", "type": "hidden"},
                                            {"name": "user", "type": "text"},
                                            {"name": "password", "type": "password"},
                                        ],
                                    }
                                ],
                            }
                        ],
                        "metadata_discovered_urls": ["https://example.com/api/users?role=admin"],
                        "excluded_urls": ["https://example.com/admin"],
                    },
                },
            ],
        }

        entry_points = build_entry_points_from_scan(scan_data)
        endpoints = {item["url"]: item for item in entry_points["endpoints"]}
        parameters = {item["name"]: item for item in entry_points["parameters"]}

        self.assertGreaterEqual(entry_points["summary"]["total_endpoints"], 5)
        self.assertEqual(entry_points["summary"]["forms"], 1)
        self.assertGreaterEqual(entry_points["summary"]["parameters"], 6)
        self.assertIn("POST", entry_points["summary"]["methods"])
        self.assertIn("q", parameters)
        self.assertIn("role", parameters)
        self.assertIn("next", parameters)
        self.assertTrue(parameters["token"]["sensitive_hint"])
        self.assertTrue(parameters["password"]["sensitive_hint"])
        self.assertTrue(parameters["csrf_token"]["sensitive_hint"])

        session = endpoints["https://example.com/session?next=/account"]
        self.assertTrue(session["state_changing"])
        self.assertTrue(session["review_candidate"])
        self.assertIn("POST", session["methods"])
        self.assertIn("form_action", session["sources"])
        self.assertIn("login", endpoints["https://example.com/login"]["route_types"])
        self.assertEqual(endpoints["https://example.com/admin"]["state"], "excluded")

    def test_entry_points_to_csv_exports_endpoint_rows(self):
        entry_points = build_entry_points_from_scan(
            {
                "target": {"normalized_url": "https://example.com/login?next=/home", "host": "example.com"},
                "modules": [],
            }
        )

        content = entry_points_to_csv(entry_points)
        rows = list(csv.DictReader(io.StringIO(content)))

        self.assertEqual(rows[0]["url"], "https://example.com/login?next=/home")
        self.assertIn("next", rows[0]["parameters"])
        self.assertIn("login", rows[0]["route_types"])


if __name__ == "__main__":
    unittest.main()
