import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.config import ScopeConfig
from ai_web_auditor.errors import ScopeError
from ai_web_auditor.scope import is_path_allowed, normalize_target, validate_target


class ScopeTests(unittest.TestCase):
    def test_normalize_adds_https_and_trailing_slash(self):
        target = normalize_target("example.com")

        self.assertEqual(target.normalized_url, "https://example.com/")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 443)

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ScopeError):
            normalize_target("ftp://example.com")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ScopeError):
            normalize_target("https://user:pass@example.com")

    def test_allows_configured_subdomain_without_dns_resolution(self):
        config = ScopeConfig(allowed_hosts=["example.com"], resolve_dns=False)

        target = validate_target("https://www.example.com/path", config)

        self.assertEqual(target.host, "www.example.com")
        self.assertEqual(target.ip_addresses, [])

    def test_rejects_ip_private_target_by_default(self):
        config = ScopeConfig(resolve_dns=False)

        with self.assertRaises(ScopeError):
            validate_target("http://127.0.0.1:8080", config)

    def test_allows_private_target_when_enabled(self):
        config = ScopeConfig(resolve_dns=False, allow_private_networks=True)

        target = validate_target("http://127.0.0.1:8080", config)

        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 8080)

    def test_path_rules_allow_included_paths(self):
        config = ScopeConfig(include_paths=["/app"], exclude_paths=[])

        self.assertTrue(is_path_allowed("/app/dashboard", config))
        self.assertFalse(is_path_allowed("/admin", config))

    def test_path_rules_reject_excluded_paths(self):
        config = ScopeConfig(include_paths=["/"], exclude_paths=["/admin"])

        self.assertTrue(is_path_allowed("/public", config))
        self.assertFalse(is_path_allowed("/admin/panel", config))

    def test_path_rules_normalize_dot_segments(self):
        config = ScopeConfig(include_paths=["/public"], exclude_paths=["/admin"])

        self.assertFalse(is_path_allowed("/public/../admin/panel", config))


if __name__ == "__main__":
    unittest.main()
