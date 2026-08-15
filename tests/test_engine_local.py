import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.config import AuditConfig
from ai_web_auditor.engine import run_scan


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE")
        self.end_headers()

    def log_message(self, *args):
        return


class ExternalRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "https://outside.example/")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, *args):
        return


class LocalEngineTests(unittest.TestCase):
    def test_local_http_scan_generates_expected_findings(self):
        server = HTTPServer(("127.0.0.1", 0), DemoHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        config = AuditConfig()
        config.scope.allow_private_networks = True
        config.scope.resolve_dns = False

        result = run_scan(f"http://127.0.0.1:{server.server_port}", config)
        finding_ids = {finding.id for finding in result.findings}
        module_statuses = {module.name: module.status for module in result.modules}

        self.assertEqual(result.status, "completed")
        self.assertEqual(module_statuses["http"], "warning")
        self.assertEqual(module_statuses["tls"], "skipped")
        self.assertIn("HTTP-NO-HTTPS-REDIRECT", finding_ids)
        self.assertIn("COOKIE-HTTPONLY-MISSING", finding_ids)
        self.assertIn("COOKIE-SAMESITE-MISSING", finding_ids)
        self.assertIn("METHOD-TRACE-ADVERTISED", finding_ids)

    def test_redirect_outside_scope_is_not_followed(self):
        server = HTTPServer(("127.0.0.1", 0), ExternalRedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        config = AuditConfig()
        config.scope.allow_private_networks = True
        config.scope.resolve_dns = False

        result = run_scan(f"http://127.0.0.1:{server.server_port}", config)
        finding_ids = {finding.id for finding in result.findings}
        request_hosts = {urlsplit(record.url).hostname for record in result.requests}

        self.assertIn("HTTP-REDIRECT-OUT-OF-SCOPE", finding_ids)
        self.assertEqual(request_hosts, {"127.0.0.1"})


if __name__ == "__main__":
    unittest.main()
