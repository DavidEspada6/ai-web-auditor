import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan


class _OpenSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def fake_create_connection(address, timeout=0):
    _host, port = address
    if port == 80:
        return _OpenSocket()
    if port == 443:
        raise ConnectionRefusedError()
    if port == 8080:
        raise TimeoutError()
    raise OSError("network unreachable")


class PortScanTests(unittest.TestCase):
    def test_ports_module_records_open_closed_and_filtered_ports(self):
        config = _ports_only_config()
        config.ports.ports = [80, 443, 8080]
        config.ports.max_ports = 5
        config.ports.timeout_seconds = 0.2

        with patch("socket.create_connection", side_effect=fake_create_connection):
            result = run_scan("https://example.com", config)

        module = next(item for item in result.modules if item.name == "ports")
        statuses = {item["port"]: item["status"] for item in module.artifacts["results"]}
        finding_ids = {finding.id for finding in module.findings}

        self.assertEqual(module.status, "warning")
        self.assertEqual(statuses[80], "open")
        self.assertEqual(statuses[443], "closed")
        self.assertEqual(statuses[8080], "filtered")
        self.assertEqual(module.artifacts["open_count"], 1)
        self.assertIn("PORTS-OPEN-TCP-PORTS", finding_ids)

    def test_ports_module_respects_max_ports_limit(self):
        config = _ports_only_config()
        config.ports.ports = [80, 443, 8080]
        config.ports.max_ports = 2

        with patch("socket.create_connection", side_effect=fake_create_connection):
            result = run_scan("https://example.com", config)

        module = next(item for item in result.modules if item.name == "ports")

        self.assertEqual(module.artifacts["ports_checked"], [80, 443])
        self.assertEqual(len(module.artifacts["results"]), 2)


def _ports_only_config() -> AuditConfig:
    config = AuditConfig()
    config.scope.allowed_hosts = ["example.com"]
    config.scope.resolve_dns = False
    config.modules.http = False
    config.modules.security_headers = False
    config.modules.cookies = False
    config.modules.basic_auth = False
    config.modules.http_methods = False
    config.modules.tls = False
    config.modules.subdomains = False
    config.modules.fingerprinting = False
    config.modules.crawler = False
    config.modules.ports = True
    return config


if __name__ == "__main__":
    unittest.main()
