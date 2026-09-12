import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.role_compare import compare_role_scans


PUBLIC_SCAN = {
    "tool": "ai-web-auditor",
    "version": "0.23.0",
    "generated_at": "2026-09-02T08:00:00Z",
    "status": "completed",
    "target": {"normalized_url": "http://127.0.0.1:8080/members/", "host": "127.0.0.1"},
    "auth_profile": {"id": "public", "name": "Publico", "authenticated": False},
    "inventory": {
        "urls": [
            {"url": "http://127.0.0.1:8080/members/", "status_code": 401, "sources": ["target"], "route_types": ["auth"]},
        ]
    },
    "entry_points": {
        "endpoints": [
            {"id": "ep-public", "url": "http://127.0.0.1:8080/members/", "methods": ["GET"], "status_code": 401},
        ]
    },
    "assessment": {"summary": {"risk_score": 70}},
}


MEMBER_SCAN = {
    "tool": "ai-web-auditor",
    "version": "0.23.0",
    "generated_at": "2026-09-02T08:05:00Z",
    "status": "completed",
    "target": {"normalized_url": "http://127.0.0.1:8080/members/", "host": "127.0.0.1"},
    "auth_profile": {"id": "member", "name": "Usuario demo", "authenticated": True},
    "inventory": {
        "urls": [
            {"url": "http://127.0.0.1:8080/members/", "status_code": 200, "sources": ["target"], "route_types": ["auth"]},
            {"url": "http://127.0.0.1:8080/account", "status_code": 200, "sources": ["html_link"], "route_types": ["account"]},
        ]
    },
    "entry_points": {
        "endpoints": [
            {"id": "ep-public", "url": "http://127.0.0.1:8080/members/", "methods": ["GET"], "status_code": 200},
            {"id": "ep-account", "url": "http://127.0.0.1:8080/account", "methods": ["GET"], "status_code": 200},
        ]
    },
    "assessment": {"summary": {"risk_score": 76}},
}


class RoleCompareTests(unittest.TestCase):
    def test_role_compare_detects_authenticated_surface(self):
        comparison = compare_role_scans(PUBLIC_SCAN, MEMBER_SCAN)

        self.assertEqual(comparison["baseline"]["auth_profile"]["name"], "Publico")
        self.assertEqual(comparison["current"]["auth_profile"]["name"], "Usuario demo")
        self.assertEqual(comparison["summary"]["new_urls"], 1)
        self.assertEqual(comparison["summary"]["new_entry_points"], 1)
        self.assertEqual(comparison["summary"]["status_code_changes"], 1)
        self.assertEqual(comparison["summary"]["risk_delta"], 6)
        self.assertEqual(comparison["new_urls"][0]["url"], "http://127.0.0.1:8080/account")
        self.assertTrue(comparison["review_notes"])


if __name__ == "__main__":
    unittest.main()
