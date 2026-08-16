import csv
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.inventory import build_inventory_from_scan, inventory_to_csv


SCAN_DATA = {
    "target": {
        "original_url": "https://example.com",
        "normalized_url": "https://example.com/",
        "host": "example.com",
    },
    "modules": [
        {
            "name": "crawler",
            "artifacts": {
                "pages": [
                    {
                        "url": "https://example.com/",
                        "depth": 0,
                        "status_code": 200,
                        "content_type": "text/html; charset=utf-8",
                        "title": "Home",
                        "links_found": 2,
                        "forms_found": 1,
                        "forms": [
                            {
                                "action": "https://example.com/login",
                                "method": "POST",
                                "input_count": 3,
                                "password_fields": 1,
                                "hidden_fields": 1,
                                "csrf_candidates": ["csrf_token"],
                                "fields": [
                                    {"name": "csrf_token", "type": "hidden"},
                                    {"name": "username", "type": "text"},
                                    {"name": "password", "type": "password"},
                                ],
                            }
                        ],
                    }
                ],
                "fetched_urls": ["https://example.com/"],
                "discovered_urls": ["https://example.com/", "https://example.com/about"],
                "out_of_scope_urls": ["https://outside.example/path"],
                "excluded_urls": ["https://example.com/admin"],
            },
        }
    ],
    "requests": [
        {
            "method": "OPTIONS",
            "url": "https://example.com/",
            "status_code": 204,
            "elapsed_ms": 4,
            "final_url": "https://example.com/",
        }
    ],
}


class InventoryTests(unittest.TestCase):
    def test_build_inventory_from_scan_collects_urls_forms_and_interest(self):
        inventory = build_inventory_from_scan(SCAN_DATA)
        urls = {item["url"]: item for item in inventory["urls"]}

        self.assertEqual(inventory["summary"]["total_urls"], 5)
        self.assertEqual(inventory["summary"]["forms"], 1)
        self.assertEqual(inventory["summary"]["external_urls"], 1)
        self.assertEqual(inventory["summary"]["excluded_urls"], 1)
        self.assertIn("form_detected", urls["https://example.com/"]["reasons"])
        self.assertIn("login_path", urls["https://example.com/login"]["reasons"])
        self.assertIn("admin_path", urls["https://example.com/admin"]["reasons"])
        self.assertEqual(inventory["forms"][0]["password_fields"], 1)

    def test_inventory_to_csv_exports_url_rows(self):
        inventory = build_inventory_from_scan(SCAN_DATA)
        csv_text = inventory_to_csv(inventory)
        rows = list(csv.DictReader(io.StringIO(csv_text)))

        self.assertEqual(len(rows), 5)
        self.assertIn("https://example.com/login", {row["url"] for row in rows})
        self.assertIn("reasons", rows[0])


if __name__ == "__main__":
    unittest.main()
