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


class ExcludedRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/admin/panel")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"admin")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, *args):
        return


class CrawlHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"""
            <html>
              <body>
                <a href="/about">About</a>
                <a href="/admin/panel">Admin</a>
                <a href="/assets/logo.png">Logo</a>
                <a href="https://outside.example/path">External</a>
              </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/about":
            body = b'<html><body><a href="/deep">Deep</a></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"not found")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, *args):
        return


class FingerprintHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self):
        if self.path == "/":
            body = b"""
            <html>
              <head>
                <meta name="generator" content="WordPress 6.4">
              </head>
              <body>
                <script id="__NEXT_DATA__" type="application/json">{}</script>
                <img src="/wp-content/uploads/logo.png">
              </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Powered-By", "PHP/8.2.1")
            self.send_header("Set-Cookie", "laravel_session=abc; Path=/; HttpOnly")
            self.send_header("Set-Cookie", "PHPSESSID=def; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /wp-admin/\nSitemap: /sitemap.xml\n")
            return

        if self.path == "/.well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00Z\n")
            return

        if self.path == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(b"<urlset><url><loc>https://example.test/</loc></url></urlset>")
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"not found")

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

    def test_redirect_to_excluded_path_is_not_followed(self):
        server = HTTPServer(("127.0.0.1", 0), ExcludedRedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        config = AuditConfig()
        config.scope.allow_private_networks = True
        config.scope.resolve_dns = False
        config.scope.exclude_paths = ["/admin"]

        result = run_scan(f"http://127.0.0.1:{server.server_port}", config)
        requested_paths = {urlsplit(record.url).path for record in result.requests}

        self.assertIn("/", requested_paths)
        self.assertNotIn("/admin/panel", requested_paths)

    def test_crawler_discovers_internal_urls_without_leaving_scope(self):
        server = HTTPServer(("127.0.0.1", 0), CrawlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        config = AuditConfig()
        config.scope.allow_private_networks = True
        config.scope.resolve_dns = False
        config.scope.exclude_paths = ["/admin"]
        config.crawler.max_depth = 1
        config.crawler.max_pages = 10

        base_url = f"http://127.0.0.1:{server.server_port}"
        result = run_scan(base_url, config)
        crawler = next(module for module in result.modules if module.name == "crawler")
        artifacts = crawler.artifacts
        request_hosts = {urlsplit(record.url).hostname for record in result.requests}

        self.assertIn(f"{base_url}/", artifacts["fetched_urls"])
        self.assertIn(f"{base_url}/about", artifacts["fetched_urls"])
        self.assertIn(f"{base_url}/deep", artifacts["discovered_urls"])
        self.assertNotIn(f"{base_url}/admin/panel", artifacts["fetched_urls"])
        self.assertIn(f"{base_url}/admin/panel", artifacts["excluded_urls"])
        self.assertIn("https://outside.example/path", artifacts["out_of_scope_urls"])
        self.assertEqual(artifacts["ignored_urls_count"], 1)
        self.assertEqual(request_hosts, {"127.0.0.1"})

    def test_fingerprinting_detects_technologies_and_public_files(self):
        server = HTTPServer(("127.0.0.1", 0), FingerprintHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        config = AuditConfig()
        config.scope.allow_private_networks = True
        config.scope.resolve_dns = False
        config.modules.crawler = False

        result = run_scan(f"http://127.0.0.1:{server.server_port}", config)
        fingerprinting = next(module for module in result.modules if module.name == "fingerprinting")
        tech_names = {item["name"] for item in fingerprinting.artifacts["technologies"]}
        public_files = {item["path"]: item for item in fingerprinting.artifacts["public_files"]}
        finding_ids = {finding.id for finding in fingerprinting.findings}

        self.assertIn("nginx", tech_names)
        self.assertIn("PHP", tech_names)
        self.assertIn("Laravel", tech_names)
        self.assertIn("WordPress", tech_names)
        self.assertIn("Next.js", tech_names)
        self.assertTrue(public_files["/robots.txt"]["present"])
        self.assertTrue(public_files["/.well-known/security.txt"]["present"])
        self.assertEqual(public_files["/sitemap.xml"]["url_count"], 1)
        self.assertIn("FINGERPRINT-SERVER-VERSION-DISCLOSED", finding_ids)
        self.assertIn("FINGERPRINT-POWERED-BY-DISCLOSED", finding_ids)
        self.assertIn("FINGERPRINT-GENERATOR-DISCLOSED", finding_ids)


if __name__ == "__main__":
    unittest.main()
