import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.web.server import build_config_from_gui_payload


class WebConfigTests(unittest.TestCase):
    def test_build_config_from_gui_payload(self):
        config = build_config_from_gui_payload(
            {
                "target": "https://example.com",
                "allowed_hosts": "example.com, app.example.com",
                "include_paths": "/, api",
                "exclude_paths": "admin, /private",
                "allow_subdomains": False,
                "allow_private_networks": True,
                "resolve_dns": False,
                "check_http_counterpart": False,
                "timeout_seconds": "12",
                "max_redirects": "4",
                "crawler": {
                    "max_depth": "2",
                    "max_pages": "40",
                    "delay_seconds": "0.5",
                },
                "modules": {
                    "crawler": False,
                    "tls": True,
                },
            }
        )

        self.assertEqual(config.target.url, "https://example.com")
        self.assertEqual(config.scope.allowed_hosts, ["example.com", "app.example.com"])
        self.assertEqual(config.scope.include_paths, ["/", "/api"])
        self.assertEqual(config.scope.exclude_paths, ["/admin", "/private"])
        self.assertFalse(config.scope.allow_subdomains)
        self.assertTrue(config.scope.allow_private_networks)
        self.assertFalse(config.scope.resolve_dns)
        self.assertFalse(config.http.check_http_counterpart)
        self.assertEqual(config.http.timeout_seconds, 12)
        self.assertEqual(config.http.max_redirects, 4)
        self.assertEqual(config.crawler.max_depth, 2)
        self.assertEqual(config.crawler.max_pages, 40)
        self.assertEqual(config.crawler.delay_seconds, 0.5)
        self.assertFalse(config.modules.crawler)
        self.assertTrue(config.modules.tls)

    def test_build_config_rejects_excessive_crawler_limit(self):
        with self.assertRaises(ValueError):
            build_config_from_gui_payload(
                {
                    "target": "https://example.com",
                    "crawler": {
                        "max_pages": "1000",
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
