import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan


def fake_getaddrinfo(host, *_args, **_kwargs):
    records = {
        "example.com": ["93.184.216.34"],
        "www.example.com": ["93.184.216.34"],
        "api.example.com": ["93.184.216.35"],
    }
    if host not in records:
        raise socket.gaierror()
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in records[host]]


class SubdomainDiscoveryTests(unittest.TestCase):
    def test_subdomain_module_resolves_in_scope_candidates(self):
        config = _subdomain_only_config()
        config.subdomains.candidates = ["www", "api", "admin"]
        config.subdomains.max_candidates = 3

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            result = run_scan("https://example.com", config)

        module = next(item for item in result.modules if item.name == "subdomains")
        hosts = {item["host"] for item in module.artifacts["resolved"]}
        finding_ids = {finding.id for finding in module.findings}

        self.assertEqual(module.status, "warning")
        self.assertEqual(hosts, {"www.example.com", "api.example.com"})
        self.assertEqual(module.artifacts["unresolved_count"], 1)
        self.assertIn("SUBDOMAIN-DISCOVERY-RESOLVED", finding_ids)

    def test_subdomain_module_respects_allow_subdomains_scope(self):
        config = _subdomain_only_config()
        config.scope.allow_subdomains = False
        config.subdomains.candidates = ["www"]

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            result = run_scan("https://example.com", config)

        module = next(item for item in result.modules if item.name == "subdomains")

        self.assertEqual(module.artifacts["resolved_count"], 0)
        self.assertEqual(module.artifacts["out_of_scope"], ["www.example.com"])


def _subdomain_only_config() -> AuditConfig:
    config = AuditConfig()
    config.scope.allowed_hosts = ["example.com"]
    config.scope.resolve_dns = True
    config.modules.http = False
    config.modules.security_headers = False
    config.modules.cookies = False
    config.modules.basic_auth = False
    config.modules.http_methods = False
    config.modules.tls = False
    config.modules.fingerprinting = False
    config.modules.crawler = False
    config.modules.subdomains = True
    return config


if __name__ == "__main__":
    unittest.main()
